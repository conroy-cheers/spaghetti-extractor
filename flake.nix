{
  description = "Windows clean-room catalog, coverage, and oracle-spec toolkit";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    nix-haloce.url = "git+file:../nix-haloce";
  };

  nixConfig = {
    allowInsecure = true;
    extra-substituters = [
      "https://cache.corncheese.org/nix-cache"
      "https://nix-gaming.cachix.org"
    ];
    extra-trusted-public-keys = [
      "nix-cache:kWK431WqAGFMswlTp4Y6XEC3eNTE0awBqtI/PWylnTg="
      "nix-gaming.cachix.org-1:nbjlureqMbRAxR1gJ/f3hxemL9svXaZF/Ees8vCUUs4="
    ];
  };

  outputs =
    inputs@{
      flake-parts,
      nix-haloce,
      nixpkgs,
      ...
    }:
    let
      systems = [ "x86_64-linux" ];

      overlays.default = import ./nix/overlays;
    in
    flake-parts.lib.mkFlake { inherit inputs; } {
      inherit systems;

      flake.overlays = overlays;

      perSystem =
        { system, ... }:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ overlays.default ];
          };

          python = pkgs.python3.withPackages (
            ps: with ps; [
              capstone
              keystone-engine
              lief
              pefile
              pytest
              unicorn
            ]
          );

          haloce-reference = nix-haloce.packages.${system}.halo-custom-edition or nix-haloce.packages.${system}.default;
          nix-haloce-source-info-json =
            let
              lock = builtins.fromJSON (builtins.readFile ./flake.lock);
            in
            builtins.toJSON lock.nodes.nix-haloce.locked;
          dynamorio64 = pkgs.dynamorio;
          dynamorio32 = pkgs.pkgsi686Linux.callPackage ./nix/pkgs/dynamorio { };
          dynamorioWindowsVersion = "11.91.20630";
          dynamorio8Version = "8.0.0-1";
          dynamorio8-linux-tarball = pkgs.fetchurl {
            url = "https://github.com/DynamoRIO/dynamorio/releases/download/release_${dynamorio8Version}/DynamoRIO-Linux-${dynamorio8Version}.tar.gz";
            hash = "sha256-ZSXvVITtPmOXcY06FhkuBR9uYxuyZpZVeS3l2SHXMF8=";
          };
          dynamorio8-linux = pkgs.stdenv.mkDerivation {
            pname = "dynamorio-linux";
            version = dynamorio8Version;
            src = dynamorio8-linux-tarball;

            nativeBuildInputs = [
              pkgs.patchelf
            ];

            dontConfigure = true;
            dontBuild = true;

            installPhase = ''
              runHook preInstall
              mkdir -p "$out"
              cp -R . "$out/"
              chmod -R u+w "$out"
              rm -rf "$out/drmemory"

              i686_interp="${pkgs.pkgsi686Linux.glibc}/lib/ld-linux.so.2"
              i686_rpath="$out/lib32:$out/lib32/release:$out/ext/lib32:$out/ext/lib32/release:${pkgs.pkgsi686Linux.glibc}/lib:${pkgs.pkgsi686Linux.stdenv.cc.cc.lib}/lib"
              for path in "$out"/bin32/* "$out"/lib32/*.so "$out"/lib32/release/*.so "$out"/ext/bin32/*.so.debug "$out"/ext/lib32/release/*.so; do
                [ -e "$path" ] || continue
                if file "$path" | grep -q 'ELF 32-bit'; then
                  patchelf --set-rpath "$i686_rpath" "$path" || true
                  if patchelf --print-interpreter "$path" >/dev/null 2>&1; then
                    patchelf --set-interpreter "$i686_interp" "$path"
                  fi
                fi
              done
              runHook postInstall
            '';

            doInstallCheck = true;
            installCheckPhase = ''
              runHook preInstallCheck
              "$out/bin32/drrun" -version | grep -F "drrun version 8.0.0"
              runHook postInstallCheck
            '';
          };
          dynamorio-windows-zip = pkgs.fetchurl {
            url = "https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-${dynamorioWindowsVersion}/DynamoRIO-Windows-${dynamorioWindowsVersion}.zip";
            hash = "sha256-oiBNmQThMbzKHknycYEqyu36sWSU9KyKBdOlatS4Wn8=";
          };
          dynamorio-windows = pkgs.runCommand "dynamorio-windows-${dynamorioWindowsVersion}"
            {
              nativeBuildInputs = [ pkgs.unzip ];
            }
            ''
              mkdir -p "$out"
              unzip -q ${dynamorio-windows-zip} -d "$TMPDIR"
              cp -R "$TMPDIR/DynamoRIO-Windows-${dynamorioWindowsVersion}/." "$out/"
            '';

          dynamorio-combined = pkgs.runCommand "dynamorio-combined-${dynamorio64.version}"
            {
              nativeBuildInputs = [ pkgs.makeWrapper ];
            }
            ''
              mkdir -p "$out"
              cp -R "${dynamorio64}/." "$out/"
              chmod -R u+w "$out"

              cp -R "${dynamorio32}/bin32" "$out/bin32"
              cp -R "${dynamorio32}/lib32" "$out/lib32"
              cp -R "${dynamorio32}/ext/bin32" "$out/ext/bin32"
              cp -R "${dynamorio32}/tools/bin32" "$out/tools/bin32"
              cp -R "${dynamorio32}/samples/bin32" "$out/samples/bin32"
              cp -R "${dynamorio32}/cmake/DynamoRIOTarget32.cmake" "$out/cmake/"
              cp -R "${dynamorio32}/cmake/DynamoRIOTarget32-release.cmake" "$out/cmake/"
              cp -R "${dynamorio32}"/tools/*.drrun32 "$out/tools/"

              chmod -R u+w "$out"
              mkdir -p "$out/lib32/debug" "$out/lib64/debug"
              ln -s ../release/libdynamorio.so "$out/lib32/debug/libdynamorio.so"
              ln -s ../release/libdynamorio.so "$out/lib64/debug/libdynamorio.so"

              rm -f "$out/bin/drrun" "$out/bin/drconfig" "$out/bin/drdeploy" "$out/bin/drinject" "$out/bin/dynamorio"
              mkdir -p "$out/bin"
              for tool in drrun drconfig drdeploy drinject; do
                makeWrapper "$out/bin64/$tool" "$out/bin/$tool" \
                  --set DYNAMORIO_HOME "$out"
              done
              ln -s "$out/bin/drrun" "$out/bin/dynamorio"
            '';

          mk-halo-trace-client =
            pkgsFor: dynamorioFor:
            pkgsFor.stdenv.mkDerivation {
              pname = "halo-trace-client";
              version = "0.1.0";
              src = ./tools/dynamorio;

              nativeBuildInputs = [
                pkgsFor.cmake
                pkgsFor.ninja
              ];

              cmakeFlags = [
                "-DDynamoRIO_DIR=${dynamorioFor}/cmake"
              ];
            };

          halo-trace-win32-smoke = pkgs.pkgsCross.mingw32.stdenv.mkDerivation {
            pname = "halo-trace-win32-smoke";
            version = "0.1.0";
            src = ./tools/trace-fixtures;

            dontConfigure = true;

            buildPhase = ''
              runHook preBuild
              $CC -O0 -g0 -fno-inline -fno-omit-frame-pointer -Wall -Wextra \
                -static-libgcc -o halo-trace-win32-smoke.exe win32-smoke.c
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall
              mkdir -p "$out/bin"
              cp halo-trace-win32-smoke.exe "$out/bin/"
              runHook postInstall
            '';
          };

          wincr-3d-reference-game = pkgs.pkgsCross.mingw32.stdenv.mkDerivation {
            pname = "wincr-3d-reference-game";
            version = "0.1.0";
            src = ./tools/reference-games/wincr-3d-game;

            dontConfigure = true;

            buildPhase = ''
              runHook preBuild
              $CC -Os -g0 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
                -fno-stack-protector -nostdlib -Wl,--gc-sections -Wl,--subsystem,console \
                -Wl,-e,_mainCRTStartup \
                -o wincr-3d-game.exe wincr_3d_game.c -lkernel32
              $CC -Os -g0 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
                -fno-stack-protector -nostdlib -Wl,--gc-sections -Wl,--subsystem,console \
                -Wl,-e,_mainCRTStartup -DWINCR_WINDOWED \
                -o wincr-3d-game-window.exe wincr_3d_game.c -lgdi32 -luser32 -lkernel32
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall
              mkdir -p "$out/bin" "$out/share/wincr/reference-games/wincr-3d-game"
              cp wincr-3d-game.exe wincr-3d-game-window.exe "$out/bin/"
              cp README.md behavior-contract.json cleanroom_candidate.py target.toml \
                "$out/share/wincr/reference-games/wincr-3d-game/"
              cp -R expected "$out/share/wincr/reference-games/wincr-3d-game/"
              runHook postInstall
            '';
          };

          haloce-tools = pkgs.python3Packages.buildPythonApplication {
            pname = "haloce-decomp-tools";
            version = "0.1.0";
            src = ./.;
            pyproject = true;

            build-system = with pkgs.python3Packages; [
              setuptools
            ];

            dependencies = with pkgs.python3Packages; [
              capstone
              lief
              pefile
              unicorn
            ];

            nativeCheckInputs = with pkgs.python3Packages; [
              pytestCheckHook
            ];

            pythonImportsCheck = [
              "haloce_catalog"
              "wincr"
            ];

            preCheck = ''
              export PYTHONPATH="$PWD/src:$PYTHONPATH"
            '';
          };

          haloce-reference-root = pkgs.writeShellApplication {
            name = "haloce-reference-root";
            text = ''
              printf '%s\n' "${haloce-reference}/basePackage"
            '';
          };

          haloce-reference-provenance = pkgs.writeShellApplication {
            name = "haloce-reference-provenance";
            text = ''
              printf '%s\n' '${nix-haloce-source-info-json}'
            '';
          };

          halo-trace-win32-smoke-root = pkgs.writeShellApplication {
            name = "halo-trace-win32-smoke-root";
            text = ''
              printf '%s\n' "${halo-trace-win32-smoke}"
            '';
          };

          wincr-3d-reference-source-info-json = builtins.toJSON {
            source = "tools/reference-games/wincr-3d-game";
            target = "wincr-3d-reference-game";
            package = "wincr-3d-reference-game";
            version = "0.1.0";
          };

          wincr-3d-reference-root = pkgs.writeShellApplication {
            name = "wincr-3d-reference-root";
            text = ''
              printf '%s\n' "${wincr-3d-reference-game}"
            '';
          };

          ghidra-headless = pkgs.writeShellApplication {
            name = "analyzeHeadless";
            text = ''
              exec ${pkgs.ghidra}/lib/ghidra/support/analyzeHeadless "$@"
            '';
          };

          halo-trace-client64 = mk-halo-trace-client pkgs dynamorio64;
          halo-trace-client32 = mk-halo-trace-client pkgs.pkgsi686Linux dynamorio32;
          halo-trace-client32-dr8 = mk-halo-trace-client pkgs.pkgsi686Linux dynamorio8-linux;
          halo-trace-client-win32 = pkgs.pkgsCross.mingw32.stdenv.mkDerivation {
            pname = "halo-trace-client-win32";
            version = "0.1.0";
            src = ./tools/dynamorio;

            dontConfigure = true;

            buildInputs = [
              pkgs.pkgsCross.mingw32.windows.mcfgthreads
            ];

            buildPhase = ''
              runHook preBuild
              $CC -shared -O2 -Wall -Wextra \
                -DWINDOWS -DX86_32 \
                -I${dynamorio-windows}/include \
                -I${dynamorio-windows}/ext/include \
                halo_trace.c \
                ${dynamorio-windows}/lib32/release/dynamorio.lib \
                ${dynamorio-windows}/ext/lib32/release/drmgr.lib \
                -o halo_trace.dll
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall
              mkdir -p "$out/bin"
              cp halo_trace.dll "$out/bin/"
              runHook postInstall
            '';
          };
          halo-trace-client = pkgs.runCommand "halo-trace-client-0.1.0" { } ''
            mkdir -p "$out/lib" "$out/lib32" "$out/lib64"
            ln -s "${halo-trace-client64}/lib/libhalo_trace.so" "$out/lib64/libhalo_trace.so"
            ln -s "${halo-trace-client32}/lib/libhalo_trace.so" "$out/lib32/libhalo_trace.so"
            ln -s "$out/lib64/libhalo_trace.so" "$out/lib/libhalo_trace.so"
          '';

          halo-trace-run = pkgs.writeShellApplication {
            name = "halo-trace-run";
            runtimeInputs = [
              dynamorio-combined
              pkgs.file
            ];
            text = ''
              usage() {
                echo "usage: halo-trace-run --out trace.jsonl --test-id TEST [--arch auto|32|64] -- app [args...]" >&2
              }

              out=""
              test_id=""
              arch="auto"
              semantic_profile=0
              semantic_max_records=128
              if [ "''${1:-}" = "--version" ]; then
                echo "halo-trace-run 0.1.0"
                exit 0
              fi
              while [ "$#" -gt 0 ]; do
                case "$1" in
                  --out)
                    out="''${2:-}"
                    shift 2
                    ;;
                  --test-id)
                    test_id="''${2:-}"
                    shift 2
                    ;;
                  --arch)
                    arch="''${2:-}"
                    shift 2
                    ;;
                  --semantic-profile)
                    semantic_profile=1
                    shift
                    ;;
                  --semantic-max-records)
                    semantic_max_records="''${2:-128}"
                    shift 2
                    ;;
                  --)
                    shift
                    break
                    ;;
                  *)
                    usage
                    exit 2
                    ;;
                esac
              done

              if [ -z "$out" ] || [ -z "$test_id" ] || [ "$#" -eq 0 ]; then
                usage
                exit 2
              fi
              case "$out" in
                /*) ;;
                *) out="$PWD/$out" ;;
              esac

              dr_arch=""
              case "$arch" in
                auto)
                  if file -L "$1" | grep -q "ELF 32-bit"; then
                    dr_arch="-32"
                  elif file -L "$1" | grep -q "ELF 64-bit"; then
                    dr_arch="-64"
                  fi
                  ;;
                32)
                  dr_arch="-32"
                  ;;
                64)
                  dr_arch="-64"
                  ;;
                *)
                  usage
                  exit 2
                  ;;
              esac

              mkdir -p "$(dirname "$out")"
              rm -f "$out" "$out".*
              client_args=(-out "$out" -test_id "$test_id")
              case "$semantic_profile" in
                1|true|yes|on) client_args+=(-semantic_values -semantic_max_records "$semantic_max_records") ;;
              esac
              if [ -n "$dr_arch" ]; then
                drrun "$dr_arch" \
                  -follow_children \
                  -c32 "${halo-trace-client}/lib32/libhalo_trace.so" \
                    "''${client_args[@]}" -- \
                  -c64 "${halo-trace-client}/lib64/libhalo_trace.so" \
                    "''${client_args[@]}" -- \
                  "$@" || status="$?"
              else
                drrun \
                  -follow_children \
                  -c32 "${halo-trace-client}/lib32/libhalo_trace.so" \
                    "''${client_args[@]}" -- \
                  -c64 "${halo-trace-client}/lib64/libhalo_trace.so" \
                    "''${client_args[@]}" -- \
                  "$@" || status="$?"
              fi

              status="''${status:-0}"
              : > "$out"
              for part in "$out".*; do
                [ -e "$part" ] || continue
                cat "$part" >> "$out"
              done
              exit "$status"
            '';
          };

          halo-trace-run-i386-late = pkgs.writeShellApplication {
            name = "halo-trace-run-i386-late";
            runtimeInputs = [
              pkgs.file
            ];
            text = ''
              usage() {
                echo "usage: halo-trace-run-i386-late --out trace.jsonl --test-id TEST [--follow-children] -- app [args...]" >&2
              }

              out=""
              test_id=""
              follow_children="''${HALOCE_TRACE_FOLLOW_CHILDREN:-0}"
              semantic_profile=0
              semantic_max_records=128
              if [ "''${1:-}" = "--version" ]; then
                echo "halo-trace-run-i386-late 0.1.0"
                exit 0
              fi
              while [ "$#" -gt 0 ]; do
                case "$1" in
                  --out)
                    out="''${2:-}"
                    shift 2
                    ;;
                  --test-id)
                    test_id="''${2:-}"
                    shift 2
                    ;;
                  --arch)
                    [ "''${2:-}" = "32" ] || [ "''${2:-}" = "auto" ] || {
                      echo "halo-trace-run-i386-late only supports i386/32-bit apps" >&2
                      exit 2
                    }
                    shift 2
                    ;;
                  --follow-children)
                    follow_children=1
                    shift
                    ;;
                  --semantic-profile)
                    semantic_profile=1
                    shift
                    ;;
                  --semantic-max-records)
                    semantic_max_records="''${2:-128}"
                    shift 2
                    ;;
                  --)
                    shift
                    break
                    ;;
                  *)
                    usage
                    exit 2
                    ;;
                esac
              done

              if [ -z "$out" ] || [ -z "$test_id" ] || [ "$#" -eq 0 ]; then
                usage
                exit 2
              fi
              if ! file -L "$1" | grep -q "ELF 32-bit"; then
                echo "halo-trace-run-i386-late requires a real 32-bit Linux app: $1" >&2
                file -L "$1" >&2 || true
                exit 2
              fi
              case "$out" in
                /*) ;;
                *) out="$PWD/$out" ;;
              esac
              export GLIBC_TUNABLES="''${GLIBC_TUNABLES:-glibc.pthread.rseq=0}"

              mkdir -p "$(dirname "$out")"
              rm -f "$out" "$out".*
              dr_args=(-late)
              case "$follow_children" in
                1|true|yes|on) dr_args+=(-follow_children) ;;
              esac
              client_args=(-out "$out" -test_id "$test_id")
              case "$semantic_profile" in
                1|true|yes|on) client_args+=(-semantic_values -semantic_max_records "$semantic_max_records") ;;
              esac
              ${dynamorio-combined}/bin32/drrun \
                "''${dr_args[@]}" \
                -c "${halo-trace-client32}/lib/libhalo_trace.so" \
                  "''${client_args[@]}" -- \
                "$@" || status="$?"

              status="''${status:-0}"
              : > "$out"
              for part in "$out".*; do
                [ -e "$part" ] || continue
                cat "$part" >> "$out"
              done
              exit "$status"
            '';
          };

          halo-trace-run-dr8-i386-late = pkgs.writeShellApplication {
            name = "halo-trace-run-dr8-i386-late";
            runtimeInputs = [
              pkgs.file
            ];
            text = ''
              usage() {
                echo "usage: halo-trace-run-dr8-i386-late --out trace.jsonl --test-id TEST -- app [args...]" >&2
              }

              out=""
              test_id=""
              semantic_profile=0
              semantic_max_records=128
              if [ "''${1:-}" = "--version" ]; then
                echo "halo-trace-run-dr8-i386-late 0.1.0"
                exit 0
              fi
              while [ "$#" -gt 0 ]; do
                case "$1" in
                  --out)
                    out="''${2:-}"
                    shift 2
                    ;;
                  --test-id)
                    test_id="''${2:-}"
                    shift 2
                    ;;
                  --arch)
                    [ "''${2:-}" = "32" ] || [ "''${2:-}" = "auto" ] || {
                      echo "halo-trace-run-dr8-i386-late only supports i386/32-bit apps" >&2
                      exit 2
                    }
                    shift 2
                    ;;
                  --semantic-profile)
                    semantic_profile=1
                    shift
                    ;;
                  --semantic-max-records)
                    semantic_max_records="''${2:-128}"
                    shift 2
                    ;;
                  --)
                    shift
                    break
                    ;;
                  *)
                    usage
                    exit 2
                    ;;
                esac
              done

              if [ -z "$out" ] || [ -z "$test_id" ] || [ "$#" -eq 0 ]; then
                usage
                exit 2
              fi
              if ! file -L "$1" | grep -q "ELF 32-bit"; then
                echo "halo-trace-run-dr8-i386-late requires a real 32-bit Linux app: $1" >&2
                file -L "$1" >&2 || true
                exit 2
              fi
              case "$out" in
                /*) ;;
                *) out="$PWD/$out" ;;
              esac
              export GLIBC_TUNABLES="''${GLIBC_TUNABLES:-glibc.pthread.rseq=0}"

              mkdir -p "$(dirname "$out")"
              rm -f "$out" "$out".*
              client_args=(-out "$out" -test_id "$test_id")
              case "$semantic_profile" in
                1|true|yes|on) client_args+=(-semantic_values -semantic_max_records "$semantic_max_records") ;;
              esac
              ${dynamorio8-linux}/bin32/drrun \
                -late \
                -follow_children \
                -c "${halo-trace-client32-dr8}/lib/libhalo_trace.so" \
                  "''${client_args[@]}" -- \
                "$@" || status="$?"

              status="''${status:-0}"
              : > "$out"
              for part in "$out".*; do
                [ -e "$part" ] || continue
                cat "$part" >> "$out"
              done
              exit "$status"
            '';
          };

          wincr-trace-run = pkgs.writeShellApplication {
            name = "wincr-trace-run";
            runtimeInputs = [ halo-trace-run ];
            text = ''
              if [ "''${1:-}" = "--version" ]; then
                echo "wincr-trace-run 0.1.0"
                exit 0
              fi
              exec halo-trace-run "$@"
            '';
          };

          wincr-trace-run-i386-late = pkgs.writeShellApplication {
            name = "wincr-trace-run-i386-late";
            runtimeInputs = [ halo-trace-run-i386-late ];
            text = ''
              if [ "''${1:-}" = "--version" ]; then
                echo "wincr-trace-run-i386-late 0.1.0"
                exit 0
              fi
              exec halo-trace-run-i386-late "$@"
            '';
          };

          wincr-trace-run-dr8-i386-late = pkgs.writeShellApplication {
            name = "wincr-trace-run-dr8-i386-late";
            runtimeInputs = [ halo-trace-run-dr8-i386-late ];
            text = ''
              if [ "''${1:-}" = "--version" ]; then
                echo "wincr-trace-run-dr8-i386-late 0.1.0"
                exit 0
              fi
              exec halo-trace-run-dr8-i386-late "$@"
            '';
          };

          halo-trace-wine-probe = pkgs.writeShellApplication {
            name = "halo-trace-wine-probe";
            text = ''
              out_dir="''${HALOCE_WINE_TRACE_PROBE_DIR:-build/wine-trace-probes}"
              timeout_seconds="''${HALOCE_WINE_TRACE_TIMEOUT:-30}"
              export WINEDEBUG="''${WINEDEBUG:--all}"

              exec ${haloce-tools}/bin/haloce-catalog probe-wine-trace \
                --smoke-root "${halo-trace-win32-smoke}" \
                --out-dir "$out_dir" \
                --trace-runner "${halo-trace-run}/bin/halo-trace-run" \
                --timeout-seconds "$timeout_seconds" \
                --wine-debug "" \
                --isolate-catalog-build \
                --isolate-trace-proof \
                --wine-command "${pkgs.winePackages.stable}/bin/wine" \
                --wine-command "${pkgs.wineWow64Packages.stable}/bin/wine" \
                "$@"
            '';
          };

          halo-trace-wine-probe-i386-late = pkgs.writeShellApplication {
            name = "halo-trace-wine-probe-i386-late";
            text = ''
              out_dir="''${HALOCE_WINE_TRACE_PROBE_DIR:-build/wine-trace-probes-i386-late}"
              case "$out_dir" in
                /*) ;;
                *) out_dir="$PWD/$out_dir" ;;
              esac
              timeout_seconds="''${HALOCE_WINE_TRACE_TIMEOUT:-30}"
              export WINEARCH="''${WINEARCH:-win32}"
              export GLIBC_TUNABLES="''${GLIBC_TUNABLES:-glibc.pthread.rseq=0}"
              export HALO_TRACE_SMOKE_SLEEP_MS="''${HALO_TRACE_SMOKE_SLEEP_MS:-4000}"
              export WINEDEBUG="''${WINEDEBUG:--all}"

              exec ${haloce-tools}/bin/haloce-catalog probe-wine-trace \
                --smoke-root "${halo-trace-win32-smoke}" \
                --out-dir "$out_dir" \
                --trace-runner "${halo-trace-run-i386-late}/bin/halo-trace-run-i386-late" \
                --arch 32 \
                --timeout-seconds "$timeout_seconds" \
                --wine-debug "" \
                --isolate-catalog-build \
                --isolate-trace-proof \
                --wine-command "${pkgs.winePackages.stable}/bin/wine" \
                "$@"
            '';
          };

          halo-trace-wine-probe-dr8-i386-late = pkgs.writeShellApplication {
            name = "halo-trace-wine-probe-dr8-i386-late";
            text = ''
              out_dir="''${HALOCE_WINE_TRACE_PROBE_DIR:-build/wine-trace-probes-dr8-i386-late}"
              case "$out_dir" in
                /*) ;;
                *) out_dir="$PWD/$out_dir" ;;
              esac
              timeout_seconds="''${HALOCE_WINE_TRACE_TIMEOUT:-30}"
              export WINEARCH="''${WINEARCH:-win32}"
              export GLIBC_TUNABLES="''${GLIBC_TUNABLES:-glibc.pthread.rseq=0}"
              export WINEDEBUG="''${WINEDEBUG:--all}"

              exec ${haloce-tools}/bin/haloce-catalog probe-wine-trace \
                --smoke-root "${halo-trace-win32-smoke}" \
                --out-dir "$out_dir" \
                --trace-runner "${halo-trace-run-dr8-i386-late}/bin/halo-trace-run-dr8-i386-late" \
                --arch 32 \
                --timeout-seconds "$timeout_seconds" \
                --wine-debug "" \
                --isolate-catalog-build \
                --isolate-trace-proof \
                --wine-command "${pkgs.winePackages.stable}/bin/wine" \
                "$@"
            '';
          };

          wincr-3d-reference-observe = pkgs.writeShellApplication {
            name = "wincr-3d-reference-observe";
            runtimeInputs = [
              haloce-tools
              ghidra-headless
              wincr-trace-run
              halo-trace-run
              pkgs.jq
              pkgs.llvm
              pkgs.rizin
              pkgs.sqlite
              pkgs.xvfb
            ];
            text = ''
              root="${wincr-3d-reference-game}"
              target_config="$root/share/wincr/reference-games/wincr-3d-game/target.toml"
              contract_json="$root/share/wincr/reference-games/wincr-3d-game/behavior-contract.json"
              candidate_py="$root/share/wincr/reference-games/wincr-3d-game/cleanroom_candidate.py"
              expected_dir="$root/share/wincr/reference-games/wincr-3d-game/expected"
              db="''${WINCR_3D_REFERENCE_DB:-build/reference-games/wincr-3d-game/catalog.db}"
              report_dir="''${WINCR_3D_REFERENCE_REPORT_DIR:-build/reference-games/wincr-3d-game/reports}"
              artifact_dir="''${WINCR_3D_REFERENCE_ARTIFACT_DIR:-build/reference-games/wincr-3d-game/behavior}"
              process_artifact_dir="''${WINCR_3D_REFERENCE_PROCESS_ARTIFACT_DIR:-build/reference-games/wincr-3d-game/process-behavior}"
              trace_dir="''${WINCR_3D_REFERENCE_TRACE_DIR:-build/reference-games/wincr-3d-game/traces}"
              compare_dir="''${WINCR_3D_REFERENCE_COMPARE_DIR:-build/reference-games/wincr-3d-game/cleanroom-compare}"
              mutation_dir="''${WINCR_3D_REFERENCE_MUTATION_DIR:-build/reference-games/wincr-3d-game/mutation}"
              oracle_dir="''${WINCR_3D_REFERENCE_ORACLE_DIR:-build/reference-games/wincr-3d-game/oracle}"
              ghidra_export_dir="''${WINCR_3D_REFERENCE_GHIDRA_EXPORT_DIR:-build/reference-games/wincr-3d-game/ghidra/exports}"
              ghidra_project_dir="''${WINCR_3D_REFERENCE_GHIDRA_PROJECT_DIR:-build/reference-games/wincr-3d-game/ghidra/projects}"
              private_artifact_dir="''${WINCR_3D_REFERENCE_PRIVATE_ARTIFACT_DIR:-private/reference-games/wincr-3d-game/artifacts}"
              clean_spec_dir="''${WINCR_3D_REFERENCE_CLEAN_SPEC_DIR:-build/reference-games/wincr-3d-game/clean-derived}"
              wineprefix="''${WINCR_3D_REFERENCE_WINEPREFIX:-build/reference-games/wincr-3d-game/wineprefix}"
              trace_wineprefix="''${WINCR_3D_REFERENCE_TRACE_WINEPREFIX:-build/reference-games/wincr-3d-game/trace-wineprefix}"
              wine_cmd="''${WINCR_3D_REFERENCE_WINE:-${pkgs.winePackages.stable}/bin/wine}"
              python_cmd="${pkgs.python3}/bin/python"

              case "$db" in /*) ;; *) db="$PWD/$db" ;; esac
              case "$report_dir" in /*) ;; *) report_dir="$PWD/$report_dir" ;; esac
              case "$artifact_dir" in /*) ;; *) artifact_dir="$PWD/$artifact_dir" ;; esac
              case "$process_artifact_dir" in /*) ;; *) process_artifact_dir="$PWD/$process_artifact_dir" ;; esac
              case "$trace_dir" in /*) ;; *) trace_dir="$PWD/$trace_dir" ;; esac
              case "$compare_dir" in /*) ;; *) compare_dir="$PWD/$compare_dir" ;; esac
              case "$mutation_dir" in /*) ;; *) mutation_dir="$PWD/$mutation_dir" ;; esac
              case "$oracle_dir" in /*) ;; *) oracle_dir="$PWD/$oracle_dir" ;; esac
              case "$ghidra_export_dir" in /*) ;; *) ghidra_export_dir="$PWD/$ghidra_export_dir" ;; esac
              case "$ghidra_project_dir" in /*) ;; *) ghidra_project_dir="$PWD/$ghidra_project_dir" ;; esac
              case "$private_artifact_dir" in /*) ;; *) private_artifact_dir="$PWD/$private_artifact_dir" ;; esac
              case "$clean_spec_dir" in /*) ;; *) clean_spec_dir="$PWD/$clean_spec_dir" ;; esac
              case "$wineprefix" in /*) ;; *) wineprefix="$PWD/$wineprefix" ;; esac
              case "$trace_wineprefix" in /*) ;; *) trace_wineprefix="$PWD/$trace_wineprefix" ;; esac

              export WINEPREFIX="$wineprefix"
              export WINEARCH="''${WINEARCH:-win32}"
              export WINEDEBUG="''${WINEDEBUG:--all}"
              export GLIBC_TUNABLES="''${GLIBC_TUNABLES:-glibc.pthread.rseq=0}"
              export WINCR_3D_REFERENCE_PACKAGE="$root"
              export WINCR_3D_REFERENCE_SOURCE_INFO='${wincr-3d-reference-source-info-json}'

              mkdir -p "$(dirname "$db")" "$report_dir" "$artifact_dir" "$process_artifact_dir" "$trace_dir" "$compare_dir" "$mutation_dir" "$oracle_dir" "$ghidra_export_dir" "$ghidra_project_dir" "$private_artifact_dir" "$wineprefix" "$trace_wineprefix"
              wincr build \
                --target-config "$target_config" \
                --install-root "$root" \
                --db "$db" \
                --report-dir "$report_dir" \
                --static-depth included \
                --max-disassembly-bytes 1048576 \
                >/dev/null

              wincr cross-check-static \
                --db "$db" \
                --scope included \
                --tool llvm-readobj \
                --tool rizin \
                --report-dir "$report_dir" \
                >/dev/null

              wincr export-ghidra \
                --db "$db" \
                --out-dir "$ghidra_export_dir" \
                --project-dir "$ghidra_project_dir" \
                --project-name wincr-3d-reference \
                --filename wincr-3d-game.exe \
                --timeout-seconds 600 \
                --report-dir "$report_dir" \
                >/dev/null

              wincr classify-functions \
                --db "$db" \
                --scope included \
                --filename wincr-3d-game.exe \
                --source ghidra \
                --subsystem "deterministic reference game routines" \
                --purity mixed \
                --side-effects "Routines combine deterministic game-state math, command-line parsing, projection, and stdout helper behavior; routine packets carry private Ghidra evidence for per-routine review." \
                --confidence medium \
                --test-status covered \
                --clean-room-status ready \
                --evidence "Ghidra function recovery, public behavior observations, trace coverage, oracle checks, and mutation tests make these recovered routines ready for private clean-room review." \
                --report-dir "$report_dir" \
                >/dev/null

              wincr classify-functions \
                --db "$db" \
                --scope included \
                --filename wincr-3d-game.exe \
                --name entrypoint \
                --source pe-entrypoint \
                --subsystem "stateful engine logic" \
                --purity stateful \
                --side-effects "Win32 process startup, deterministic simulation, JSON transcript emission, and optional GDI window rendering" \
                --calling-convention cdecl \
                --signature "int mainCRTStartup(void)" \
                --confidence high \
                --test-status specified \
                --clean-room-status ready \
                --evidence "public behavior contract, original PE oracle fixtures, clean-room candidate comparison, and mutation evidence classify the reference game entrypoint" \
                --report-dir "$report_dir" \
                >/dev/null

              contract_label="$(
                wincr upsert-behavior-contract \
                  --db "$db" \
                  --contract-id wincr.reference.3d-game \
                  --title "WinCR 3D reference game deterministic transcript" \
                  --scope "deterministic JSON transcript" \
                  --version 1 \
                  --contract-json "$contract_json" \
                  --evidence "public reference behavior contract" \
                  --report-dir "$report_dir" \
                | jq -r '.behavior_contract.label'
              )"

              entry_function_label="$(
                sqlite3 "$db" "
                  SELECT f.label
                  FROM functions f
                  JOIN binaries b ON b.id = f.binary_id
                  WHERE b.filename = 'wincr-3d-game.exe'
                    AND f.name = 'entrypoint'
                    AND f.source = 'pe-entrypoint'
                  ORDER BY f.rva
                  LIMIT 1
                "
              )"
              wincr upsert-internal-routine-contract \
                --db "$db" \
                --label routine_wincr_reference_transcript_entrypoint_v1 \
                --function-label "$entry_function_label" \
                --public-name reference_transcript_entrypoint_v1 \
                --purpose-summary "Runs the reference game deterministic transcript mode from process command-line inputs and emits JSON observations." \
                --calling-convention cdecl \
                --signature "int mainCRTStartup(void)" \
                --input-shape-json '{"argv":["--json","--scenario <name>","--frames <n>","--seed <n>"]}' \
                --output-shape-json '{"stdout":"wincr-3d-game-transcript-v1 JSON object","exit_code":0}' \
                --precondition "process command line is readable" \
                --precondition "frame count is clamped to the public contract range" \
                --postcondition "stdout contains one deterministic transcript JSON object" \
                --postcondition "exit code is zero for transcript mode" \
                --side-effect "reads Win32 process command line" \
                --side-effect "writes stdout through KERNEL32 WriteFile" \
                --state-transition "advances fixed-step simulation for the requested frame count" \
                --fixture "$expected_dir/orbit-seed7-180.json" \
                --fixture "$expected_dir/collect-seed2-64.json" \
                --fixture "$expected_dir/dive-seed7-64.json" \
                --fixture "$expected_dir/orbit-seed1-64.json" \
                --fixture "$expected_dir/burnout-seed7-360.json" \
                --fixture "$expected_dir/aim-miss-seed1-4.json" \
                --evidence-label "$contract_label" \
                --evidence-source human_review \
                --confidence high \
                --taint-level behavioral_public \
                --review-status reviewed \
                --report-dir "$report_dir" \
                >/dev/null

              wincr run-json-behavior-test \
                --db "$db" \
                --behavior-contract-label "$contract_label" \
                --test-id orbit-seed7-180 \
                --artifact-dir "$artifact_dir" \
                --input-json "$contract_json" \
                --report-dir "$report_dir" \
                -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                  --json --scenario orbit --frames 180 --seed 7

              wincr run-json-behavior-test \
                --db "$db" \
                --behavior-contract-label "$contract_label" \
                --test-id collect-seed11-150 \
                --artifact-dir "$artifact_dir" \
                --input-json "$contract_json" \
                --report-dir "$report_dir" \
                -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                  --json --scenario collect --frames 150 --seed 11

              wincr run-json-behavior-test \
                --db "$db" \
                --behavior-contract-label "$contract_label" \
                --test-id collect-seed2-64 \
                --artifact-dir "$artifact_dir" \
                --input-json "$contract_json" \
                --report-dir "$report_dir" \
                -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                  --json --scenario collect --frames 64 --seed 2

              wincr run-json-behavior-test \
                --db "$db" \
                --behavior-contract-label "$contract_label" \
                --test-id dive-seed7-64 \
                --artifact-dir "$artifact_dir" \
                --input-json "$contract_json" \
                --report-dir "$report_dir" \
                -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                  --json --scenario dive --frames 64 --seed 7

              wincr run-json-behavior-test \
                --db "$db" \
                --behavior-contract-label "$contract_label" \
                --test-id orbit-seed1-64 \
                --artifact-dir "$artifact_dir" \
                --input-json "$contract_json" \
                --report-dir "$report_dir" \
                -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                  --json --scenario orbit --frames 64 --seed 1

              wincr run-json-behavior-test \
                --db "$db" \
                --behavior-contract-label "$contract_label" \
                --test-id burnout-seed7-360 \
                --artifact-dir "$artifact_dir" \
                --input-json "$contract_json" \
                --report-dir "$report_dir" \
                -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                  --json --scenario burnout --frames 360 --seed 7

              wincr run-json-behavior-test \
                --db "$db" \
                --behavior-contract-label "$contract_label" \
                --test-id aim-miss-seed1-4 \
                --artifact-dir "$artifact_dir" \
                --input-json "$contract_json" \
                --report-dir "$report_dir" \
                -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                  --json --scenario aim_miss --frames 4 --seed 1

              process_input_dir="$process_artifact_dir/inputs"
              mkdir -p "$process_input_dir"
              printf '%s\n' '{"argv":["--help"]}' > "$process_input_dir/help.json"
              printf '%s\n' '{"argv":[]}' > "$process_input_dir/noargs-error.json"
              printf '%s\n' '{"argv":["--json"]}' > "$process_input_dir/default-json.json"
              printf '%s\n' '{"argv":["--json","--unknown-option"]}' > "$process_input_dir/unknown-option.json"
              printf '%s\n' '{"argv":["--json","--scenario"]}' > "$process_input_dir/missing-scenario-value.json"
              printf '%s\n' '{"argv":["--json","--scenario","collect-with-a-name-that-is-longer-than-storage","--frames","not-a-number","--seed","-1"]}' > "$process_input_dir/parser-edge-cases.json"
              long_scenario="scenario-name-longer-than-the-parser-output-buffer-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              printf '{"argv":["--json","--scenario","%s","--frames","","--seed","-"]}\n' "$long_scenario" > "$process_input_dir/parser-empty-sign-long.json"
              wine_stderr_noise_regex='^WARNING: radv is not a conformant Vulkan implementation, testing use only\.$'

              wincr run-process-behavior-test \
                --db "$db" \
                --behavior-contract-label "$contract_label" \
                --test-id help \
                --artifact-dir "$process_artifact_dir" \
                --input-json "$process_input_dir/help.json" \
                --expect-exit-code 0 \
                --stdout-contains "usage: wincr-3d-game.exe" \
                --strip-stderr-line-regex "$wine_stderr_noise_regex" \
                --report-dir "$report_dir" \
                -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                  --help

              wincr run-process-behavior-test \
                --db "$db" \
                --behavior-contract-label "$contract_label" \
                --test-id noargs-error \
                --artifact-dir "$process_artifact_dir" \
                --input-json "$process_input_dir/noargs-error.json" \
                --expect-exit-code 4 \
                --stderr-contains "pass --json for deterministic transcript output" \
                --strip-stderr-line-regex "$wine_stderr_noise_regex" \
                --report-dir "$report_dir" \
                -- "$wine_cmd" "$root/bin/wincr-3d-game.exe"

              wincr run-process-behavior-test \
                --db "$db" \
                --behavior-contract-label "$contract_label" \
                --test-id default-json \
                --artifact-dir "$process_artifact_dir" \
                --input-json "$process_input_dir/default-json.json" \
                --expect-exit-code 0 \
                --stdout-contains "wincr-3d-game-transcript-v1" \
                --strip-stderr-line-regex "$wine_stderr_noise_regex" \
                --report-dir "$report_dir" \
                -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                  --json

              wincr run-process-behavior-test \
                --db "$db" \
                --behavior-contract-label "$contract_label" \
                --test-id unknown-option \
                --artifact-dir "$process_artifact_dir" \
                --input-json "$process_input_dir/unknown-option.json" \
                --expect-exit-code 0 \
                --stdout-contains "wincr-3d-game-transcript-v1" \
                --strip-stderr-line-regex "$wine_stderr_noise_regex" \
                --report-dir "$report_dir" \
                -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                  --json --unknown-option

              wincr run-process-behavior-test \
                --db "$db" \
                --behavior-contract-label "$contract_label" \
                --test-id missing-scenario-value \
                --artifact-dir "$process_artifact_dir" \
                --input-json "$process_input_dir/missing-scenario-value.json" \
                --expect-exit-code 0 \
                --stdout-contains "wincr-3d-game-transcript-v1" \
                --strip-stderr-line-regex "$wine_stderr_noise_regex" \
                --report-dir "$report_dir" \
                -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                  --json --scenario

              wincr run-process-behavior-test \
                --db "$db" \
                --behavior-contract-label "$contract_label" \
                --test-id parser-edge-cases \
                --artifact-dir "$process_artifact_dir" \
                --input-json "$process_input_dir/parser-edge-cases.json" \
                --expect-exit-code 0 \
                --stdout-contains "collect-with-a-name-that-is-lon" \
                --strip-stderr-line-regex "$wine_stderr_noise_regex" \
                --report-dir "$report_dir" \
                -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                  --json --scenario collect-with-a-name-that-is-longer-than-storage --frames not-a-number --seed -1

              wincr run-process-behavior-test \
                --db "$db" \
                --behavior-contract-label "$contract_label" \
                --test-id parser-empty-sign-long \
                --artifact-dir "$process_artifact_dir" \
                --input-json "$process_input_dir/parser-empty-sign-long.json" \
                --expect-exit-code 0 \
                --stdout-contains "scenario-name-longer-than-the-p" \
                --strip-stderr-line-regex "$wine_stderr_noise_regex" \
                --report-dir "$report_dir" \
                -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                  --json --scenario "$long_scenario" --frames "" --seed -

              (
                export WINEPREFIX="$trace_wineprefix"
                "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                  --json --scenario orbit --frames 180 --seed 7 \
                  > "$trace_dir/warmup-orbit.stdout.txt" \
                  2> "$trace_dir/warmup-orbit.stderr.txt"

                wincr prove-trace \
                  --db "$db" \
                  --out "$trace_dir/orbit-seed7-180.jsonl" \
                  --test-id reference-orbit-seed7-180-coverage \
                  --expected-filename wincr-3d-game.exe \
                  --arch 32 \
                  --trace-runner "${halo-trace-run-i386-late}/bin/halo-trace-run-i386-late" \
                  --timeout-seconds 120 \
                  --fail-on-timeout \
                  --semantic-profile \
                  --semantic-max-records 256 \
                  --suite reference-coverage \
                  --report-dir "$report_dir" \
                  -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                    --json --scenario orbit --frames 180 --seed 7 \
                  >/dev/null

                wincr prove-trace \
                  --db "$db" \
                  --out "$trace_dir/collect-seed11-150.jsonl" \
                  --test-id reference-collect-seed11-150-coverage \
                  --expected-filename wincr-3d-game.exe \
                  --arch 32 \
                  --trace-runner "${halo-trace-run-i386-late}/bin/halo-trace-run-i386-late" \
                  --timeout-seconds 120 \
                  --fail-on-timeout \
                  --suite reference-coverage \
                  --report-dir "$report_dir" \
                  -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                    --json --scenario collect --frames 150 --seed 11 \
                  >/dev/null

                wincr prove-trace \
                  --db "$db" \
                  --out "$trace_dir/collect-seed2-64.jsonl" \
                  --test-id reference-collect-seed2-64-coverage \
                  --expected-filename wincr-3d-game.exe \
                  --arch 32 \
                  --trace-runner "${halo-trace-run-i386-late}/bin/halo-trace-run-i386-late" \
                  --timeout-seconds 120 \
                  --fail-on-timeout \
                  --suite reference-coverage \
                  --report-dir "$report_dir" \
                  -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                    --json --scenario collect --frames 64 --seed 2 \
                  >/dev/null

                wincr prove-trace \
                  --db "$db" \
                  --out "$trace_dir/dive-seed7-64.jsonl" \
                  --test-id reference-dive-seed7-64-coverage \
                  --expected-filename wincr-3d-game.exe \
                  --arch 32 \
                  --trace-runner "${halo-trace-run-i386-late}/bin/halo-trace-run-i386-late" \
                  --timeout-seconds 120 \
                  --fail-on-timeout \
                  --suite reference-coverage \
                  --report-dir "$report_dir" \
                  -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                    --json --scenario dive --frames 64 --seed 7 \
                  >/dev/null

                wincr prove-trace \
                  --db "$db" \
                  --out "$trace_dir/orbit-seed1-64.jsonl" \
                  --test-id reference-orbit-seed1-64-coverage \
                  --expected-filename wincr-3d-game.exe \
                  --arch 32 \
                  --trace-runner "${halo-trace-run-i386-late}/bin/halo-trace-run-i386-late" \
                  --timeout-seconds 120 \
                  --fail-on-timeout \
                  --suite reference-coverage \
                  --report-dir "$report_dir" \
                  -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                    --json --scenario orbit --frames 64 --seed 1 \
                  >/dev/null

                wincr prove-trace \
                  --db "$db" \
                  --out "$trace_dir/burnout-seed7-360.jsonl" \
                  --test-id reference-burnout-seed7-360-coverage \
                  --expected-filename wincr-3d-game.exe \
                  --arch 32 \
                  --trace-runner "${halo-trace-run-i386-late}/bin/halo-trace-run-i386-late" \
                  --timeout-seconds 120 \
                  --fail-on-timeout \
                  --suite reference-coverage \
                  --report-dir "$report_dir" \
                  -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                    --json --scenario burnout --frames 360 --seed 7 \
                  >/dev/null

                wincr prove-trace \
                  --db "$db" \
                  --out "$trace_dir/aim-miss-seed1-4.jsonl" \
                  --test-id reference-aim-miss-seed1-4-coverage \
                  --expected-filename wincr-3d-game.exe \
                  --arch 32 \
                  --trace-runner "${halo-trace-run-i386-late}/bin/halo-trace-run-i386-late" \
                  --timeout-seconds 120 \
                  --fail-on-timeout \
                  --suite reference-coverage \
                  --report-dir "$report_dir" \
                  -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                    --json --scenario aim_miss --frames 4 --seed 1 \
                  >/dev/null

                wincr prove-trace \
                  --db "$db" \
                  --out "$trace_dir/idle-seed5-64.jsonl" \
                  --test-id reference-idle-seed5-64-coverage \
                  --expected-filename wincr-3d-game.exe \
                  --arch 32 \
                  --trace-runner "${halo-trace-run-i386-late}/bin/halo-trace-run-i386-late" \
                  --timeout-seconds 120 \
                  --fail-on-timeout \
                  --suite reference-coverage \
                  --report-dir "$report_dir" \
                  -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                    --json --scenario idle --frames 64 --seed 5 \
                  >/dev/null

                wincr prove-trace \
                  --db "$db" \
                  --out "$trace_dir/window-smoke-json.jsonl" \
                  --test-id reference-window-smoke-json-coverage \
                  --expected-filename wincr-3d-game.exe \
                  --arch 32 \
                  --trace-runner "${halo-trace-run-i386-late}/bin/halo-trace-run-i386-late" \
                  --timeout-seconds 120 \
                  --fail-on-timeout \
                  --suite reference-coverage \
                  --report-dir "$report_dir" \
                  -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                    --window-smoke --json --scenario orbit --frames 4 --seed 7 \
                  >/dev/null

                wincr prove-trace \
                  --db "$db" \
                  --out "$trace_dir/parser-edge-cases.jsonl" \
                  --test-id reference-parser-edge-coverage \
                  --expected-filename wincr-3d-game.exe \
                  --arch 32 \
                  --trace-runner "${halo-trace-run-i386-late}/bin/halo-trace-run-i386-late" \
                  --timeout-seconds 120 \
                  --fail-on-timeout \
                  --suite reference-coverage \
                  --report-dir "$report_dir" \
                  -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                    --json --scenario collect-with-a-name-that-is-longer-than-storage --frames not-a-number --seed -1 \
                  >/dev/null

                long_scenario="scenario-name-longer-than-the-parser-output-buffer-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                wincr prove-trace \
                  --db "$db" \
                  --out "$trace_dir/parser-empty-sign-long.jsonl" \
                  --test-id reference-parser-empty-sign-long-coverage \
                  --expected-filename wincr-3d-game.exe \
                  --arch 32 \
                  --trace-runner "${halo-trace-run-i386-late}/bin/halo-trace-run-i386-late" \
                  --timeout-seconds 120 \
                  --fail-on-timeout \
                  --suite reference-coverage \
                  --report-dir "$report_dir" \
                  -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                    --json --scenario "$long_scenario" --frames "" --seed - \
                  >/dev/null

                for parser_case in \
                  "missing-scenario-value:--json --scenario" \
                  "missing-frames-value:--json --frames" \
                  "missing-seed-value:--json --seed" \
                  "unknown-option:--json --unknown-option"
                do
                  case_name="''${parser_case%%:*}"
                  case_args="''${parser_case#*:}"
                  # shellcheck disable=SC2086
                  wincr prove-trace \
                    --db "$db" \
                    --out "$trace_dir/$case_name.jsonl" \
                    --test-id "reference-$case_name-coverage" \
                    --expected-filename wincr-3d-game.exe \
                    --arch 32 \
                    --trace-runner "${halo-trace-run-i386-late}/bin/halo-trace-run-i386-late" \
                    --timeout-seconds 120 \
                    --fail-on-timeout \
                    --suite reference-coverage \
                    --report-dir "$report_dir" \
                    -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                      $case_args \
                    >/dev/null
                done

                wincr prove-trace \
                  --db "$db" \
                  --out "$trace_dir/noargs-error.jsonl" \
                  --test-id reference-noargs-error-coverage \
                  --expected-filename wincr-3d-game.exe \
                  --arch 32 \
                  --trace-runner "${halo-trace-run-i386-late}/bin/halo-trace-run-i386-late" \
                  --timeout-seconds 120 \
                  --fail-on-timeout \
                  --expected-returncode 4 \
                  --suite reference-coverage \
                  --report-dir "$report_dir" \
                  -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                  >/dev/null

                wincr prove-trace \
                  --db "$db" \
                  --out "$trace_dir/window-smoke-error.jsonl" \
                  --test-id reference-window-smoke-error-coverage \
                  --expected-filename wincr-3d-game.exe \
                  --arch 32 \
                  --trace-runner "${halo-trace-run-i386-late}/bin/halo-trace-run-i386-late" \
                  --timeout-seconds 120 \
                  --fail-on-timeout \
                  --expected-returncode 4 \
                  --suite reference-coverage \
                  --report-dir "$report_dir" \
                  -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                    --window-smoke \
                  >/dev/null

                wincr prove-trace \
                  --db "$db" \
                  --out "$trace_dir/help.jsonl" \
                  --test-id reference-help-coverage \
                  --expected-filename wincr-3d-game.exe \
                  --arch 32 \
                  --trace-runner "${halo-trace-run-i386-late}/bin/halo-trace-run-i386-late" \
                  --timeout-seconds 120 \
                  --fail-on-timeout \
                  --suite reference-coverage \
                  --report-dir "$report_dir" \
                  -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                    --help \
                  >/dev/null
              )

              included_sha="$(
                sqlite3 "$db" "
                  SELECT sha256
                  FROM binaries
                  WHERE filename = 'wincr-3d-game.exe'
                    AND scope = 'included'
                  LIMIT 1
                "
              )"
              wincr add-waiver \
                --db "$db" \
                --binary-sha256 "$included_sha" \
                --rva-start 0x1f8e \
                --rva-end 0x1f9a \
                --category unreachable-dead-code \
                --reason "str_equal null-input guard is unreachable from the public process contract" \
                --evidence "All observed command-line and scenario comparisons pass concrete non-null string buffers; no public API accepts a null string pointer." \
                --reviewer wincr-reference-observer \
                --revalidation-trigger "reference PE hash, command-line parser contract, or str_equal callsite set changes" \
                --report-dir "$report_dir" \
                >/dev/null

              wincr add-waiver \
                --db "$db" \
                --binary-sha256 "$included_sha" \
                --rva-start 0x1e2a \
                --rva-end 0x1e2b \
                --category unreachable-dead-code \
                --reason "next_arg tab-as-leading-separator branch is outside the reference process contract" \
                --evidence "The public reference contract is expressed as argv-style command invocations; all observer, oracle, and target traces pass ordinary process arguments through Wine and do not expose a raw tab-delimited GetCommandLineA contract." \
                --reviewer wincr-reference-observer \
                --revalidation-trigger "reference command-line contract or raw CreateProcessA launcher support changes" \
                --report-dir "$report_dir" \
                >/dev/null

              wincr add-waiver \
                --db "$db" \
                --binary-sha256 "$included_sha" \
                --rva-start 0x1e69 \
                --rva-end 0x1e6a \
                --category unreachable-dead-code \
                --reason "next_arg tab-as-token-terminator branch is outside the reference process contract" \
                --evidence "The public reference contract is expressed as argv-style command invocations; quoted, empty, long, missing, numeric, and unknown-option paths are traced, but raw tab token separators are not part of the declared process API." \
                --reviewer wincr-reference-observer \
                --revalidation-trigger "reference command-line contract or raw CreateProcessA launcher support changes" \
                --report-dir "$report_dir" \
                >/dev/null

              wincr add-waiver \
                --db "$db" \
                --binary-sha256 "$included_sha" \
                --rva-start 0x1fe0 \
                --rva-end 0x1fe1 \
                --category unreachable-dead-code \
                --reason "write_handle_text null-buffer guard has no public caller" \
                --evidence "All public output callsites pass static non-null strings or number-format buffers; no process argument or fixture can request a null output pointer." \
                --reviewer wincr-reference-observer \
                --revalidation-trigger "write_handle_text callsite set or public output API changes" \
                --report-dir "$report_dir" \
                >/dev/null

              wincr add-waiver \
                --db "$db" \
                --binary-sha256 "$included_sha" \
                --rva-start 0x1fed \
                --rva-end 0x1fee \
                --category unreachable-dead-code \
                --reason "write_handle_text empty-string fast return has no public caller" \
                --evidence "All public output callsites emit non-empty literals or formatted numbers in the traced transcript, usage, error, and window-smoke paths." \
                --reviewer wincr-reference-observer \
                --revalidation-trigger "write_handle_text callsite set or public output API changes" \
                --report-dir "$report_dir" \
                >/dev/null

              wincr run-oracle-process-test \
                --db "$db" \
                --suite-id reference-json-transcript \
                --test-id orbit-seed7-180 \
                --artifact-dir "$oracle_dir" \
                --stdout-contains wincr-3d-game-transcript-v1 \
                --report-dir "$report_dir" \
                -- "$wine_cmd" "$root/bin/wincr-3d-game.exe" \
                  --json --scenario orbit --frames 180 --seed 7

              wincr run-oracle-process-test \
                --db "$db" \
                --suite-id reference-windowed-startup \
                --test-id window-smoke-8 \
                --artifact-dir "$oracle_dir" \
                --timeout-seconds 30 \
                --offscreen-display x11 \
                --report-dir "$report_dir" \
                -- "$wine_cmd" "$root/bin/wincr-3d-game-window.exe" \
                  --window-smoke --scenario orbit --frames 8 --seed 7

              wincr record-observed-interface-suite \
                --db "$db" \
                --scope included \
                --evidence "reference target mock/shim suite covers observed Win32, GDI, USER32, and KERNEL32 endpoint success, failure, and error-path behavior" \
                --fixture-path "$oracle_dir/reference-windowed-startup/window-smoke-8/result.json" \
                --report-dir "$report_dir"

              wincr compare-json-behavior \
                --expected-json "$expected_dir/orbit-seed7-180.json" \
                --test-id cleanroom-orbit-seed7-180 \
                --artifact-dir "$compare_dir" \
                -- "$python_cmd" "$candidate_py" \
                  --contract "$contract_json" --json --scenario orbit --frames 180 --seed 7 \
                > "$compare_dir/cleanroom-orbit-seed7-180.json"

              wincr compare-json-behavior \
                --expected-json "$expected_dir/collect-seed11-150.json" \
                --test-id cleanroom-collect-seed11-150 \
                --artifact-dir "$compare_dir" \
                -- "$python_cmd" "$candidate_py" \
                  --contract "$contract_json" --json --scenario collect --frames 150 --seed 11 \
                > "$compare_dir/cleanroom-collect-seed11-150.json"

              wincr compare-json-behavior \
                --expected-json "$expected_dir/collect-seed2-64.json" \
                --test-id cleanroom-collect-seed2-64 \
                --artifact-dir "$compare_dir" \
                -- "$python_cmd" "$candidate_py" \
                  --contract "$contract_json" --json --scenario collect --frames 64 --seed 2 \
                > "$compare_dir/cleanroom-collect-seed2-64.json"

              wincr compare-json-behavior \
                --expected-json "$expected_dir/dive-seed7-64.json" \
                --test-id cleanroom-dive-seed7-64 \
                --artifact-dir "$compare_dir" \
                -- "$python_cmd" "$candidate_py" \
                  --contract "$contract_json" --json --scenario dive --frames 64 --seed 7 \
                > "$compare_dir/cleanroom-dive-seed7-64.json"

              wincr compare-json-behavior \
                --expected-json "$expected_dir/orbit-seed1-64.json" \
                --test-id cleanroom-orbit-seed1-64 \
                --artifact-dir "$compare_dir" \
                -- "$python_cmd" "$candidate_py" \
                  --contract "$contract_json" --json --scenario orbit --frames 64 --seed 1 \
                > "$compare_dir/cleanroom-orbit-seed1-64.json"

              wincr compare-json-behavior \
                --expected-json "$expected_dir/burnout-seed7-360.json" \
                --test-id cleanroom-burnout-seed7-360 \
                --artifact-dir "$compare_dir" \
                -- "$python_cmd" "$candidate_py" \
                  --contract "$contract_json" --json --scenario burnout --frames 360 --seed 7 \
                > "$compare_dir/cleanroom-burnout-seed7-360.json"

              wincr compare-json-behavior \
                --expected-json "$expected_dir/aim-miss-seed1-4.json" \
                --test-id cleanroom-aim-miss-seed1-4 \
                --artifact-dir "$compare_dir" \
                -- "$python_cmd" "$candidate_py" \
                  --contract "$contract_json" --json --scenario aim_miss --frames 4 --seed 1 \
                > "$compare_dir/cleanroom-aim-miss-seed1-4.json"

              wincr compare-json-spec-observations \
                --spec-json "$report_dir/specs.json" \
                --contract-id wincr.reference.3d-game \
                --artifact-dir "$compare_dir/spec-observations" \
                -- "$python_cmd" "$candidate_py" \
                  --contract "{contract_json}" --json \
                  --scenario "{observed.scenario}" \
                  --frames "{observed.frames}" \
                  --seed "{observed.seed}" \
                > "$compare_dir/spec-observations.json"

              wincr compare-process-spec-observations \
                --spec-json "$report_dir/specs.json" \
                --contract-id wincr.reference.3d-game \
                --artifact-dir "$compare_dir/process-spec-observations" \
                -- "$python_cmd" "$candidate_py" \
                  --contract "{contract_json}" "{input.argv}" \
                > "$compare_dir/process-spec-observations.json"

              for mutation_kind in \
                wrong_state_transition \
                bad_projection \
                bad_input_schedule \
                bad_frame_hash \
                bad_target_generation
              do
                wincr run-json-mutation-test \
                  --db "$db" \
                  --mutation-kind "$mutation_kind" \
                  --target-label "$contract_label" \
                  --test-id "$mutation_kind-orbit-seed7-180" \
                  --expected-json "$expected_dir/orbit-seed7-180.json" \
                  --artifact-dir "$mutation_dir" \
                  --report-dir "$report_dir" \
                  -- "$python_cmd" "$candidate_py" \
                    --contract "$contract_json" --json --scenario orbit --frames 180 --seed 7 \
                    --mutant "$mutation_kind"
              done

              record_structure() {
                wincr upsert-data-structure \
                  --db "$db" \
                  --name "$1" \
                  --structure-kind "$2" \
                  --spec-status complete \
                  --fixture-status complete \
                  --description "$3" \
                  --report-dir "$report_dir" \
                  | jq -r '.data_structure.label'
              }

              record_state_case() {
                wincr record-data-state-test \
                  --db "$db" \
                  --data-structure-label "$1" \
                  --case-kind "$2" \
                  --test-id "$3" \
                  --evidence "$4" \
                  --fixture-path "$5" \
                  --report-dir "$report_dir" \
                  >/dev/null
              }

              transcript_label="$(record_structure \
                reference_json_transcript \
                transcript \
                "JSON transcript schema, sample policy, final state, and aggregate hash")"
              record_state_case "$transcript_label" fixture transcript-fixtures \
                "original PE transcripts captured under Wine and stored as public expected JSON fixtures" \
                "$expected_dir/orbit-seed7-180.json"
              record_state_case "$transcript_label" malformed_input transcript-negative-fixtures \
                "JSON comparison and mutation artifacts reject missing, changed, or inconsistent transcript fields" \
                "$mutation_dir/bad_frame_hash-orbit-seed7-180/result.json"
              record_state_case "$transcript_label" round_trip transcript-cleanroom-round-trip \
                "clean-room candidate validated directly against every public behavior observation in specs.json" \
                "$compare_dir/spec-observations/summary.json"

              game_state_label="$(record_structure \
                reference_game_state \
                game_state \
                "fixed-step position, velocity, yaw, pitch, score, energy, health, cooldown, collection mask, and collision damage")"
              record_state_case "$game_state_label" fixture game-state-fixtures \
                "sample and final game-state vectors, including collection and damage state, are present in original PE transcript fixtures" \
                "$expected_dir/dive-seed7-64.json"
              record_state_case "$game_state_label" malformed_input game-state-negative-fixtures \
                "wrong state transition mutant changes state vectors and is killed by the public JSON comparison" \
                "$mutation_dir/wrong_state_transition-orbit-seed7-180/result.json"
              record_state_case "$game_state_label" round_trip game-state-cleanroom-round-trip \
                "clean-room candidate reproduces game-state vectors for orbit, collect, collection-hit, dive, burnout, and aim-miss scenarios" \
                "$compare_dir/spec-observations/summary.json"

              scenario_label="$(record_structure \
                reference_scenario_schedule \
                scenario \
                "idle, orbit, collect, dive, burnout, aim-miss, and fallback scripted input schedules")"
              record_state_case "$scenario_label" fixture scenario-fixtures \
                "scenario inputs are visible in sampled original PE transcript frames" \
                "$expected_dir/collect-seed2-64.json"
              record_state_case "$scenario_label" malformed_input scenario-negative-fixtures \
                "bad input schedule mutant is killed by the public JSON comparison" \
                "$mutation_dir/bad_input_schedule-orbit-seed7-180/result.json"
              record_state_case "$scenario_label" round_trip scenario-cleanroom-round-trip \
                "clean-room candidate reproduces scripted scenario schedules from the public behavior contract" \
                "$compare_dir/spec-observations/summary.json"

              projection_label="$(record_structure \
                reference_projection \
                projection \
                "integer screen projection and visibility contract used by aiming, target display, and frame hashes")"
              record_state_case "$projection_label" fixture projection-fixtures \
                "projected target and cube values are included in every sampled frame hash from the original PE" \
                "$expected_dir/orbit-seed7-180.json"
              record_state_case "$projection_label" malformed_input projection-negative-fixtures \
                "bad projection mutant is killed by the public JSON comparison" \
                "$mutation_dir/bad_projection-orbit-seed7-180/result.json"
              record_state_case "$projection_label" round_trip projection-cleanroom-round-trip \
                "clean-room candidate reproduces projection-dependent hashes for original transcript fixtures" \
                "$compare_dir/spec-observations/summary.json"

              simulation_label="$(record_structure \
                reference_fixed_step_simulation \
                fixed_step_simulation \
                "per-frame deterministic transition rules connecting scenario input to state, score, collection, damage, and hash output")"
              record_state_case "$simulation_label" fixture simulation-fixtures \
                "original PE fixtures contain sampled and final fixed-step simulation states" \
                "$expected_dir/orbit-seed7-180.json"
              record_state_case "$simulation_label" malformed_input simulation-negative-fixtures \
                "bad target generation mutant is killed by the public JSON comparison" \
                "$mutation_dir/bad_target_generation-orbit-seed7-180/result.json"
              record_state_case "$simulation_label" transition simulation-cleanroom-transition \
                "clean-room candidate implements the public transition rules and matches original PE behavior exactly" \
                "$compare_dir/spec-observations/summary.json"

              process_contract_label="$(record_structure \
                reference_process_contract \
                process_contract \
                "command-line parser, defaults, help text, error exits, ignored unknown options, numeric coercion, and scenario truncation")"
              record_state_case "$process_contract_label" fixture process-contract-fixtures \
                "original PE process observations capture help, default transcript, unknown-option fallback, missing-value fallback, and parser edge cases" \
                "$process_artifact_dir/help/result.json"
              record_state_case "$process_contract_label" malformed_input process-contract-error-fixtures \
                "no-argument process observation records the public error exit and stderr contract" \
                "$process_artifact_dir/noargs-error/result.json"
              record_state_case "$process_contract_label" round_trip process-contract-cleanroom-round-trip \
                "clean-room candidate validates byte-for-byte against public process observations in specs.json" \
                "$compare_dir/process-spec-observations/summary.json"

              wincr export-private-artifacts \
                --db "$db" \
                --out-dir "$private_artifact_dir" \
                --artifact-set-id wincr-reference-3d-game-dirty-evidence \
                --scope included \
                --report-dir "$report_dir" \
                >/dev/null

              wincr validate-dirty-corpus \
                --corpus-dir "$private_artifact_dir" \
                --report-json "$report_dir/dirty-corpus-validation.json" \
                --report-md "$report_dir/dirty-corpus-validation.md" \
                >/dev/null

              if [ "''${WINCR_3D_REFERENCE_DERIVE_CLEAN:-0}" = "1" ]; then
                mkdir -p "$clean_spec_dir"
                wincr promote-clean-templates \
                  --corpus-dir "$private_artifact_dir" \
                  --reviewer wincr-reference-observer \
                  --note "Reference target uses repo-owned public behavior contracts and fixtures as reviewed clean template content." \
                  >/dev/null

                wincr derive-clean-specs \
                  --corpus-dir "$private_artifact_dir" \
                  --out-dir "$clean_spec_dir" \
                  >/dev/null

                wincr validate-clean-specs \
                  --spec-json "$clean_spec_dir/specs.json" \
                  --tests-json "$clean_spec_dir/tests.json" \
                  >/dev/null

                clean_json_template="$(jq -nc \
                  --arg python "$python_cmd" \
                  --arg candidate "$candidate_py" \
                  '[$python,$candidate,"--contract","{contract_json}","--json","--scenario","{observed.scenario}","--frames","{observed.frames}","--seed","{observed.seed}"]')"
                clean_process_template="$(jq -nc \
                  --arg python "$python_cmd" \
                  --arg candidate "$candidate_py" \
                  '[$python,$candidate,"--contract","{contract_json}","{input.argv}"]')"

                wincr run-clean-spec-suite \
                  --spec-json "$clean_spec_dir/specs.json" \
                  --contract-id wincr.reference.3d-game \
                  --artifact-dir "$compare_dir/clean-derived-suite" \
                  --json-command-template-json "$clean_json_template" \
                  --process-command-template-json "$clean_process_template" \
                  > "$compare_dir/clean-derived-suite.json"
              fi
            '';
          };

          haloce-reference-analyze = pkgs.writeShellApplication {
            name = "haloce-reference-analyze";
            runtimeInputs = [
              haloce-tools
              ghidra-headless
              pkgs.llvm
              pkgs.rizin
              pkgs.radare2
              pkgs.sqlite
              pkgs.jq
            ];
            text = ''
              db="''${HALOCE_ANALYZE_DB:-build/catalog/catalog.db}"
              report_dir="''${HALOCE_ANALYZE_REPORT_DIR:-build/reports}"
              ghidra_out="''${HALOCE_ANALYZE_GHIDRA_OUT:-build/ghidra/exports}"
              ghidra_projects="''${HALOCE_ANALYZE_GHIDRA_PROJECTS:-build/ghidra/projects}"
              ghidra_timeout="''${HALOCE_ANALYZE_GHIDRA_TIMEOUT:-240}"

              export HALOCE_REFERENCE_PACKAGE="${haloce-reference}"
              export HALOCE_NIX_HALOCE_SOURCE_INFO='${nix-haloce-source-info-json}'
              export HALOCE_GHIDRA_HEADLESS="${ghidra-headless}/bin/analyzeHeadless"

              exec haloce-catalog analyze-reference \
                --install-root "${haloce-reference}/basePackage" \
                --db "$db" \
                --report-dir "$report_dir" \
                --ghidra-out-dir "$ghidra_out" \
                --ghidra-project-dir "$ghidra_projects" \
                --ghidra-timeout-seconds "$ghidra_timeout" \
                "$@"
            '';
          };

          haloce-reference-traced = pkgs.runCommand "haloce-reference-traced-${haloce-reference.version or "1.0.10"}"
            {
              nativeBuildInputs = [ pkgs.python3 ];
            }
            ''
              mkdir -p "$out/bin" "$out/libexec"
              cp "${haloce-reference}/bin/haloce" "$out/bin/haloce"
              cp "${haloce-reference}/bin/haloce-unwrapped" "$out/bin/haloce-unwrapped"
              cp "${haloce-reference}/libexec/haloce-setupEnv.sh" "$out/libexec/haloce-setupEnv.sh"
              chmod +w "$out/bin/haloce" "$out/bin/haloce-unwrapped" "$out/libexec/haloce-setupEnv.sh"

              substituteInPlace "$out/bin/haloce" \
                --replace-fail "${haloce-reference}/bin/haloce-unwrapped" "$out/bin/haloce-unwrapped"
              substituteInPlace "$out/bin/haloce-unwrapped" \
                --replace-fail "${haloce-reference}/libexec/haloce-setupEnv.sh" "$out/libexec/haloce-setupEnv.sh"

              export HALOCE_TRACE_RUNNER="${halo-trace-run}/bin/halo-trace-run"
              export HALOCE_TRACE_BASH="${pkgs.bash}/bin/bash"
              export HALOCE_TRACE_SETUP="$out/libexec/haloce-setupEnv.sh"
              python3 - <<'PY'
import os
import re
from pathlib import Path

setup = Path(os.environ["HALOCE_TRACE_SETUP"])
trace_runner = os.environ["HALOCE_TRACE_RUNNER"]
trace_bash = os.environ["HALOCE_TRACE_BASH"]
text = setup.read_text()
replacement = (
    f'    "{trace_runner}" --out "''${{HALOCE_TRACE_OUT:?}}" '
    f'--test-id "''${{HALOCE_TRACE_TEST_ID:?}}" --arch auto -- '
    f'"{trace_bash}" ' + r'\1 "$executable" "$@" &'
)
text, count = re.subn(
    r'^    (/.*/bin/wine) "\$executable" "\$@" &$',
    replacement,
    text,
    count=1,
    flags=re.MULTILINE,
)
if count != 1:
    raise SystemExit(f"expected to patch one Wine launch line, patched {count}")
setup.write_text(text)
	PY
            '';

          haloce-windows-vm-bundle = pkgs.writeShellApplication {
            name = "haloce-windows-vm-bundle";
            runtimeInputs = [
              haloce-tools
              pkgs.jq
            ];
            text = ''
              out_dir="''${HALOCE_WINDOWS_VM_OUT:-build/windows-vm}"
              halo_runtime="${haloce-reference}/basePackage/drive_c/Program Files (x86)/Microsoft Games/Halo Custom Edition"
              exec haloce-catalog generate-windows-vm \
                --out-dir "$out_dir" \
                --dynamorio-root "${dynamorio-windows}" \
                --trace-client-dll "${halo-trace-client-win32}/bin/halo_trace.dll" \
                --halo-runtime-root "$halo_runtime" \
                --virtio-tools-root "${pkgs.virtio-win}" \
                --spice-tools-root "${pkgs.win-spice}" \
                --install-image-index "1" \
                --ovmf-code "${pkgs.OVMF.fd}/FV/OVMF_CODE.fd" \
                --ovmf-vars-template "${pkgs.OVMF.fd}/FV/OVMF_VARS.fd" \
                --xorriso "${pkgs.xorriso}/bin/xorriso" \
                "$@"
            '';
          };
        in
        {
          _module.args.pkgs = pkgs;

          packages = {
            inherit haloce-tools;
            inherit
              ghidra-headless
              wincr-trace-run
              wincr-trace-run-i386-late
              wincr-trace-run-dr8-i386-late
              halo-trace-client
              halo-trace-client32
              halo-trace-client32-dr8
              halo-trace-client64
              halo-trace-client-win32
              halo-trace-run
              halo-trace-run-i386-late
              halo-trace-run-dr8-i386-late
              halo-trace-wine-probe
              halo-trace-wine-probe-i386-late
              halo-trace-wine-probe-dr8-i386-late
              halo-trace-win32-smoke
              halo-trace-win32-smoke-root
              wincr-3d-reference-game
              wincr-3d-reference-observe
              wincr-3d-reference-root
              haloce-reference-analyze
              haloce-reference-provenance
              haloce-reference-traced
              haloce-windows-vm-bundle
              haloce-reference
              haloce-reference-root
              ;
            dynamorio = dynamorio-combined;
            dynamorio-linux-8_0_0 = dynamorio8-linux;
            dynamorio-windows = dynamorio-windows;
            wincr-tools = haloce-tools;
            default = haloce-tools;
          };

          apps = {
            default = {
              type = "app";
              program = "${haloce-tools}/bin/wincr";
            };

            wincr = {
              type = "app";
              program = "${haloce-tools}/bin/wincr";
            };

            haloce-catalog = {
              type = "app";
              program = "${haloce-tools}/bin/haloce-catalog";
            };

            haloce-reference-root = {
              type = "app";
              program = "${haloce-reference-root}/bin/haloce-reference-root";
            };

            haloce-reference-provenance = {
              type = "app";
              program = "${haloce-reference-provenance}/bin/haloce-reference-provenance";
            };

            haloce-reference-analyze = {
              type = "app";
              program = "${haloce-reference-analyze}/bin/haloce-reference-analyze";
            };

            haloce-reference-traced = {
              type = "app";
              program = "${haloce-reference-traced}/bin/haloce";
            };

            haloce-windows-vm-bundle = {
              type = "app";
              program = "${haloce-windows-vm-bundle}/bin/haloce-windows-vm-bundle";
            };

            ghidra-headless = {
              type = "app";
              program = "${ghidra-headless}/bin/analyzeHeadless";
            };

            halo-trace-run = {
              type = "app";
              program = "${halo-trace-run}/bin/halo-trace-run";
            };

            wincr-trace-run = {
              type = "app";
              program = "${wincr-trace-run}/bin/wincr-trace-run";
            };

            halo-trace-run-i386-late = {
              type = "app";
              program = "${halo-trace-run-i386-late}/bin/halo-trace-run-i386-late";
            };

            halo-trace-run-dr8-i386-late = {
              type = "app";
              program = "${halo-trace-run-dr8-i386-late}/bin/halo-trace-run-dr8-i386-late";
            };

            wincr-trace-run-i386-late = {
              type = "app";
              program = "${wincr-trace-run-i386-late}/bin/wincr-trace-run-i386-late";
            };

            wincr-trace-run-dr8-i386-late = {
              type = "app";
              program = "${wincr-trace-run-dr8-i386-late}/bin/wincr-trace-run-dr8-i386-late";
            };

            halo-trace-wine-probe = {
              type = "app";
              program = "${halo-trace-wine-probe}/bin/halo-trace-wine-probe";
            };

            halo-trace-wine-probe-i386-late = {
              type = "app";
              program = "${halo-trace-wine-probe-i386-late}/bin/halo-trace-wine-probe-i386-late";
            };

            halo-trace-wine-probe-dr8-i386-late = {
              type = "app";
              program = "${halo-trace-wine-probe-dr8-i386-late}/bin/halo-trace-wine-probe-dr8-i386-late";
            };

            halo-trace-win32-smoke-root = {
              type = "app";
              program = "${halo-trace-win32-smoke-root}/bin/halo-trace-win32-smoke-root";
            };

            wincr-3d-reference-root = {
              type = "app";
              program = "${wincr-3d-reference-root}/bin/wincr-3d-reference-root";
            };

            wincr-3d-reference-observe = {
              type = "app";
              program = "${wincr-3d-reference-observe}/bin/wincr-3d-reference-observe";
            };
          };

          checks = {
            inherit
              haloce-tools
              halo-trace-client
              halo-trace-client32
              halo-trace-client32-dr8
              halo-trace-client64
              halo-trace-client-win32
              halo-trace-run
              halo-trace-run-i386-late
              halo-trace-run-dr8-i386-late
              wincr-trace-run
              wincr-trace-run-i386-late
              wincr-trace-run-dr8-i386-late
              halo-trace-win32-smoke
              wincr-3d-reference-game
              haloce-windows-vm-bundle
              ;
          };

          devShells.default = pkgs.mkShell {
            packages = [
              pkgs.binutils
              pkgs.gdb
              ghidra-headless
              pkgs.ghidra
              pkgs.llvm
              python
              dynamorio-combined
              dynamorio8-linux
              halo-trace-client
              halo-trace-client32-dr8
              halo-trace-client-win32
              halo-trace-run
              halo-trace-run-i386-late
              halo-trace-run-dr8-i386-late
              wincr-trace-run
              wincr-trace-run-i386-late
              wincr-trace-run-dr8-i386-late
              halo-trace-wine-probe-i386-late
              halo-trace-wine-probe-dr8-i386-late
              halo-trace-win32-smoke
              halo-trace-win32-smoke-root
              wincr-3d-reference-game
              wincr-3d-reference-observe
              wincr-3d-reference-root
              haloce-windows-vm-bundle
              dynamorio-windows
              pkgs.frida-tools
              pkgs.libvirt
              pkgs.openssh
              pkgs.qemu_full
              pkgs.radare2
              pkgs.rizin
              pkgs.socat
              pkgs.sshpass
              pkgs.virt-manager
              pkgs.virt-viewer
              pkgs.winePackages.stable
              pkgs.wineWow64Packages.stable
              pkgs.xvfb
              pkgs.xorriso
              pkgs.jq
              pkgs.sqlite
            ];

            shellHook = ''
              export DYNAMORIO_HOME=${dynamorio-combined}
              export HALOCE_GHIDRA_HEADLESS="${pkgs.ghidra}/lib/ghidra/support/analyzeHeadless"
              export HALOCE_NIX_HALOCE_SOURCE_INFO='${nix-haloce-source-info-json}'
              export PYTHONPATH="$PWD/src''${PYTHONPATH:+:$PYTHONPATH}"
            '';
          };

          devShells.reference = pkgs.mkShell {
            packages = [
              haloce-reference-root
              haloce-tools
              pkgs.xvfb
            ];

            shellHook = ''
              export HALOCE_INSTALL_ROOT="${haloce-reference}/basePackage"
              export HALOCE_REFERENCE_PACKAGE="${haloce-reference}"
              export HALOCE_NIX_HALOCE_SOURCE_INFO='${nix-haloce-source-info-json}'
              export PYTHONPATH="$PWD/src''${PYTHONPATH:+:$PYTHONPATH}"
            '';
          };

          devShells.test = pkgs.mkShell {
            packages = [
              python
              pkgs.jq
              pkgs.sqlite
              pkgs.sshpass
            ];

            shellHook = ''
              export PYTHONPATH="$PWD/src''${PYTHONPATH:+:$PYTHONPATH}"
            '';
          };
        };
    };
}
