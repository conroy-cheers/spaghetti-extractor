{
  description = "Windows clean-room catalog, coverage, and oracle-spec toolkit";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    nixpkgs_24_11.url = "github:NixOS/nixpkgs/nixos-24.11";
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
      nixpkgs_24_11,
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
          pkgsGcc13 = import nixpkgs_24_11 {
            inherit system;
          };
          mingw32 = pkgs.pkgsCross.mingw32;
          mingwW64 = pkgs.pkgsCross.mingwW64;
          mingwW64Pthreads = mingwW64.windows.pthreads.overrideAttrs (old: {
            meta = (old.meta or { }) // {
              platforms = (old.meta.platforms or [ ]) ++ [ system ];
            };
          });
          mingw32Oniguruma = mingw32.oniguruma.overrideAttrs (old: {
            meta = (old.meta or { }) // {
              platforms = (old.meta.platforms or [ ]) ++ [ "i686-windows" ];
            };
          });
          stageAJqCommonCflags = "-g0 -fno-asynchronous-unwind-tables -fno-ident -fno-inline -fno-inline-functions -fno-inline-small-functions -fno-ipa-cp -fno-ipa-sra -fno-ipa-icf";
          stageAJqOriginalCflags = "-O2 -fno-align-functions -fno-align-labels -fno-align-loops -fno-align-jumps ${stageAJqCommonCflags}";
          stageAJqCandidateCflags = "-O2 -falign-functions=32 -falign-labels=16 -falign-loops=16 -falign-jumps=16 ${stageAJqCommonCflags}";
          mkStageAJq =
            label: cflags:
            (mingw32.jq.override {
              oniguruma = mingw32Oniguruma;
            }).overrideAttrs
              (old: {
                pname = "stage-a-jq-${label}";
                doCheck = false;
                doInstallCheck = false;
                dontStrip = true;
                outputs = [ "out" ];
                buildInputs = (old.buildInputs or [ ]) ++ [ mingw32.windows.pthreads ];
                configureFlags = [
                  "--prefix=${builtins.placeholder "out"}"
                  "--bindir=${builtins.placeholder "out"}/bin"
                  "--sbindir=${builtins.placeholder "out"}/bin"
                  "--datadir=${builtins.placeholder "out"}/share"
                  "--mandir=${builtins.placeholder "out"}/share/man"
                ];
                CFLAGS = cflags;
                LDFLAGS = "-Wl,-Map,jq-${label}.map";
                postFixup = "";
                postInstall =
                  (old.postInstall or "")
                  + ''
                    map_path="$(find . -name 'jq-${label}.map' -print -quit)"
                    if [ -z "$map_path" ]; then
                      echo "missing jq-${label}.map" >&2
                      exit 1
                    fi
                    mkdir -p "$out/share/wincr/stage-a-jq-fixtures/${label}"
                    cp "$map_path" "$out/share/wincr/stage-a-jq-fixtures/${label}/jq.map"
                    cp "$out/bin/jq.exe" "$out/share/wincr/stage-a-jq-fixtures/${label}/jq.exe"
                  '';
                meta = (old.meta or { }) // {
                  platforms = (old.meta.platforms or [ ]) ++ [ "i686-windows" ];
                };
              });

          python = pkgs.python3.withPackages (
            ps: with ps; [
              capstone
              keystone-engine
              lief
              pefile
              pytest
              unicorn
              z3-solver
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
              z3-solver
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

          stageBSkeletonSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./src/haloce_catalog/__init__.py
              ./src/haloce_catalog/pe.py
              ./src/haloce_catalog/presets
              ./src/haloce_catalog/roles.py
              ./src/haloce_catalog/stage_binary.py
              ./src/haloce_catalog/stage_b_skeleton.py
              ./src/haloce_catalog/target.py
              ./src/haloce_catalog/util.py
            ];
          };

          stageBSkeletonPython = pkgs.python3.withPackages (
            ps: with ps; [
              capstone
              pefile
            ]
          );

          stageBProvenanceSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./src/haloce_catalog/__init__.py
              ./src/haloce_catalog/stage_b_provenance.py
              ./src/haloce_catalog/util.py
            ];
          };

          stageBFunctionalSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./src/haloce_catalog/__init__.py
              ./src/haloce_catalog/stage_b_functional.py
              ./src/haloce_catalog/util.py
            ];
          };

          stage-b-skeleton-tools = pkgs.writeShellApplication {
            name = "stage-b-skeleton-wincr";
            text = ''
              if [ "$#" -lt 1 ]; then
                printf 'usage: stage-b-skeleton-wincr <stage-b-generate-skeleton|stage-b-generate-link-roots> [args]\n' >&2
                exit 2
              fi
              command="$1"
              shift
              case "$command" in
                stage-b-generate-skeleton)
                  export PYTHONPATH="${stageBSkeletonSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
                  exec ${stageBSkeletonPython}/bin/python3 - "$@" <<'PY'
              import argparse
              import sys
              from pathlib import Path

              from haloce_catalog.stage_b_skeleton import stage_b_generate_skeleton

              parser = argparse.ArgumentParser(prog="stage-b-skeleton-wincr stage-b-generate-skeleton")
              parser.add_argument("--original", type=Path, required=True)
              parser.add_argument("--linker-map", type=Path)
              parser.add_argument("--reference-contract", type=Path)
              parser.add_argument("--coverage-reference-contract", type=Path)
              parser.add_argument("--target-name", required=True)
              parser.add_argument("--source-language", choices=["c", "rust"], default="c")
              parser.add_argument("--decompiler-export", type=Path)
              parser.add_argument("--function-name", dest="function_names", action="append", default=[])
              parser.add_argument("--implementation-mode", choices=["scaffold", "decompiled-c"], default="scaffold")
              parser.add_argument("--runtime-entry-policy", choices=["bridge", "mingw-crt"], default="bridge")
              parser.add_argument("--out-dir", type=Path, required=True)
              args = parser.parse_args(sys.argv[1:])

              stage_b_generate_skeleton(
                  original=args.original,
                  linker_map=args.linker_map,
                  reference_contract=args.reference_contract,
                  coverage_reference_contract=args.coverage_reference_contract,
                  target_name=args.target_name,
                  source_language=args.source_language,
                  decompiler_export=args.decompiler_export,
                  function_names=args.function_names,
                  implementation_mode=args.implementation_mode,
                  runtime_entry_policy=args.runtime_entry_policy,
                  out_dir=args.out_dir,
              )
              PY
                  ;;
                stage-b-generate-link-roots)
                  export PYTHONPATH="${stageBSkeletonSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
                  exec ${stageBSkeletonPython}/bin/python3 - "$@" <<'PY'
              import argparse
              import json
              import sys
              from pathlib import Path

              from haloce_catalog.stage_b_skeleton import stage_b_generate_link_roots

              parser = argparse.ArgumentParser(prog="stage-b-skeleton-wincr stage-b-generate-link-roots")
              parser.add_argument("--original", type=Path, required=True)
              parser.add_argument("--linker-map-original", type=Path)
              parser.add_argument("--reference-contract", type=Path)
              parser.add_argument("--skeleton-functions", type=Path)
              parser.add_argument("--object", type=Path, required=True)
              parser.add_argument("--nm", default="llvm-nm")
              parser.add_argument("--out", type=Path, required=True)
              args = parser.parse_args(sys.argv[1:])

              result = stage_b_generate_link_roots(
                  original=args.original,
                  linker_map_original=args.linker_map_original,
                  reference_contract=args.reference_contract,
                  skeleton_functions=args.skeleton_functions,
                  object_file=args.object,
                  nm=args.nm,
                  out=args.out,
              )
              json.dump(result, sys.stdout, indent=2, sort_keys=True)
              sys.stdout.write("\n")
              PY
                  ;;
                *)
                  printf 'stage-b-skeleton-wincr only supports stage-b-generate-skeleton and stage-b-generate-link-roots, got: %s\n' "$command" >&2
                  exit 2
                  ;;
              esac
            '';
          };

          stage-b-provenance-tools = pkgs.writeShellApplication {
            name = "stage-b-provenance-wincr";
            text = ''
              if [ "$#" -lt 1 ]; then
                printf 'usage: stage-b-provenance-wincr <stage-b-generate-candidate-provenance> [args]\n' >&2
                exit 2
              fi
              command="$1"
              shift
              case "$command" in
                stage-b-generate-candidate-provenance)
                  export PYTHONPATH="${stageBProvenanceSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
                  exec ${pkgs.python3}/bin/python3 - "$@" <<'PY'
              import argparse
              import json
              import sys
              from pathlib import Path

              from haloce_catalog.stage_b_provenance import stage_b_generate_candidate_provenance

              parser = argparse.ArgumentParser(
                  prog="stage-b-provenance-wincr stage-b-generate-candidate-provenance"
              )
              parser.add_argument("--target-name", required=True)
              parser.add_argument("--skeleton-manifest", type=Path, required=True)
              parser.add_argument("--candidate", type=Path, required=True)
              parser.add_argument("--functional-report", type=Path)
              parser.add_argument("--build-target", required=True)
              parser.add_argument("--build-compiler", required=True)
              parser.add_argument("--build-output")
              parser.add_argument("--build-report", type=Path)
              parser.add_argument("--fixed-up-source", dest="fixed_up_sources", action="append", type=Path, default=[])
              parser.add_argument("--out", type=Path, required=True)
              args = parser.parse_args(sys.argv[1:])

              result = stage_b_generate_candidate_provenance(
                  target_name=args.target_name,
                  skeleton_manifest=args.skeleton_manifest,
                  candidate=args.candidate,
                  functional_report=args.functional_report,
                  build_target=args.build_target,
                  build_compiler=args.build_compiler,
                  build_output=args.build_output,
                  build_report=args.build_report,
                  fixed_up_sources=args.fixed_up_sources,
                  out=args.out,
              )
              json.dump(result, sys.stdout, indent=2, sort_keys=True)
              sys.stdout.write("\n")
              PY
                  ;;
                *)
                  printf 'stage-b-provenance-wincr only supports stage-b-generate-candidate-provenance, got: %s\n' "$command" >&2
                  exit 2
                  ;;
              esac
            '';
          };

          stage-b-functional-tools = pkgs.writeShellApplication {
            name = "stage-b-functional-wincr";
            text = ''
              if [ "$#" -lt 1 ]; then
                printf 'usage: stage-b-functional-wincr <stage-b-materialize-upstream-suite|stage-b-run-functional-suite> [args]\n' >&2
                exit 2
              fi
              command="$1"
              shift
              case "$command" in
                stage-b-materialize-upstream-suite)
                  export PYTHONPATH="${stageBFunctionalSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
                  exec ${pkgs.python3}/bin/python3 - "$@" <<'PY'
              import argparse
              import json
              import sys
              from pathlib import Path

              from haloce_catalog.stage_b_functional import stage_b_materialize_upstream_suite

              parser = argparse.ArgumentParser(
                  prog="stage-b-functional-wincr stage-b-materialize-upstream-suite"
              )
              parser.add_argument("--target-name", required=True)
              parser.add_argument("--suite-source", type=Path, required=True)
              parser.add_argument("--source-revision", required=True)
              parser.add_argument("--cases", type=Path, required=True)
              parser.add_argument("--suite-scope", default="full", choices=["full", "subset"])
              parser.add_argument("--out", type=Path, required=True)
              args = parser.parse_args(sys.argv[1:])

              result = stage_b_materialize_upstream_suite(
                  target_name=args.target_name,
                  suite_source=args.suite_source,
                  source_revision=args.source_revision,
                  cases=args.cases,
                  suite_scope=args.suite_scope,
                  out=args.out,
              )
              json.dump(result, sys.stdout, indent=2, sort_keys=True)
              sys.stdout.write("\n")
              PY
                  ;;
                stage-b-run-functional-suite)
                  export PYTHONPATH="${stageBFunctionalSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
                  exec ${pkgs.python3}/bin/python3 - "$@" <<'PY'
              import argparse
              import json
              import sys
              from pathlib import Path

              from haloce_catalog.stage_b_functional import stage_b_run_functional_suite

              def json_string_list(value: str, option_name: str) -> tuple[str, ...]:
                  try:
                      parsed = json.loads(value)
                  except json.JSONDecodeError as exc:
                      raise SystemExit(f"{option_name} must be valid JSON: {exc}") from exc
                  if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
                      raise SystemExit(f"{option_name} must be a JSON array of strings")
                  return tuple(parsed)

              parser = argparse.ArgumentParser(
                  prog="stage-b-functional-wincr stage-b-run-functional-suite"
              )
              parser.add_argument("--suite", type=Path, required=True)
              parser.add_argument("--candidate-command-json", required=True)
              parser.add_argument("--candidate-binary", type=Path)
              parser.add_argument("--timeout-seconds", type=float, default=30.0)
              parser.add_argument("--strip-stderr-line-regex", action="append", default=[])
              parser.add_argument("--out", type=Path, required=True)
              args = parser.parse_args(sys.argv[1:])

              result = stage_b_run_functional_suite(
                  suite=args.suite,
                  candidate_command=json_string_list(args.candidate_command_json, "--candidate-command-json"),
                  candidate_binary=args.candidate_binary,
                  timeout_seconds=args.timeout_seconds,
                  strip_stderr_line_regexes=tuple(args.strip_stderr_line_regex),
                  out=args.out,
              )
              json.dump(result, sys.stdout, indent=2, sort_keys=True)
              sys.stdout.write("\n")
              raise SystemExit(0 if result.get("status") == "pass" else 1)
              PY
                  ;;
                *)
                  printf 'stage-b-functional-wincr only supports stage-b-materialize-upstream-suite and stage-b-run-functional-suite, got: %s\n' "$command" >&2
                  exit 2
                  ;;
              esac
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

          stage-a-fixtures = pkgs.pkgsCross.mingw32.stdenv.mkDerivation {
            pname = "stage-a-fixtures";
            version = "0.1.0";
            src = ./tools/stage-a-fixtures;

            dontConfigure = true;
            nativeBuildInputs = [
              pkgs.python3
            ];

            buildPhase = ''
              runHook preBuild
              common_flags=(
                -g0
                -fno-asynchronous-unwind-tables
                -fno-exceptions
                -fno-ident
                -nostdlib
                -Wl,--exclude-all-symbols
                -Wl,--subsystem,console
                -Wl,-e,_mainCRTStartup
                -Wl,--image-base,0x400000
                -Wl,--section-alignment,0x1000
                -Wl,--file-alignment,0x200
              )
              compile_flags=(
                -g0
                -fno-asynchronous-unwind-tables
                -fno-exceptions
                -fno-ident
              )
              gcc15_bin="${pkgs.pkgsCross.mingw32.stdenv.cc}/bin"
              gcc13="${pkgsGcc13.pkgsCross.mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc"
              gcc13_bin="${pkgsGcc13.pkgsCross.mingw32.stdenv.cc}/bin"
              $CC -O0 "''${common_flags[@]}" -o stage-a-original.exe stage_a_equivalence.S -lkernel32
              $CC -O2 "''${common_flags[@]}" -DSTAGE_A_VARIANT_B -o stage-a-candidate.exe stage_a_equivalence.S -lkernel32
              $CC -Og "''${common_flags[@]}" -o stage-a-original-og.exe stage_a_equivalence.S -lkernel32
              $CC -Os "''${common_flags[@]}" -DSTAGE_A_VARIANT_B -o stage-a-candidate-os.exe stage_a_equivalence.S -lkernel32
              $CC -O2 "''${common_flags[@]}" -DSTAGE_A_MUTATION -o stage-a-mutated.exe stage_a_equivalence.S -lkernel32
              "$gcc13" -c -O0 "''${compile_flags[@]}" -DSTAGE_A_NO_EXTERNAL -o stage-a-gcc13-original.o stage_a_equivalence.S
              "$gcc13" -c -Og "''${compile_flags[@]}" -DSTAGE_A_NO_EXTERNAL -o stage-a-gcc13-original-og.o stage_a_equivalence.S
              $CC -c -O2 "''${compile_flags[@]}" -DSTAGE_A_VARIANT_B -DSTAGE_A_NO_EXTERNAL -o stage-a-gcc15-candidate.o stage_a_equivalence.S
              $CC -c -Os "''${compile_flags[@]}" -DSTAGE_A_VARIANT_B -DSTAGE_A_NO_EXTERNAL -o stage-a-gcc15-candidate-os.o stage_a_equivalence.S
              "$gcc13_bin/i686-w64-mingw32-objcopy" -O binary -j .text stage-a-gcc13-original.o stage-a-gcc13-original.text
              "$gcc13_bin/i686-w64-mingw32-objcopy" -O binary -j .text stage-a-gcc13-original-og.o stage-a-gcc13-original-og.text
              "$gcc15_bin/i686-w64-mingw32-objcopy" -O binary -j .text stage-a-gcc15-candidate.o stage-a-gcc15-candidate.text
              "$gcc15_bin/i686-w64-mingw32-objcopy" -O binary -j .text stage-a-gcc15-candidate-os.o stage-a-gcc15-candidate-os.text
              python3 pe32_from_text.py --text stage-a-gcc13-original.text --out stage-a-gcc13-original.exe
              python3 pe32_from_text.py --text stage-a-gcc13-original-og.text --out stage-a-gcc13-original-og.exe
              python3 pe32_from_text.py --text stage-a-gcc15-candidate.text --out stage-a-gcc15-candidate.exe
              python3 pe32_from_text.py --text stage-a-gcc15-candidate-os.text --out stage-a-gcc15-candidate-os.exe
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall
              fixture_dir="$out/share/wincr/stage-a-fixtures/symbolic-equivalence"
              mkdir -p "$fixture_dir"
              cp stage-a-original.exe stage-a-candidate.exe stage-a-original-og.exe stage-a-candidate-os.exe \
                stage-a-mutated.exe stage-a-gcc13-original.exe stage-a-gcc13-original-og.exe \
                stage-a-gcc15-candidate.exe stage-a-gcc15-candidate-os.exe "$fixture_dir/"
              cat > "$fixture_dir/block-map.json" <<'JSON'
              {
                "blocks": [
                  {
                    "id": "entry",
                    "kind": "code",
                    "reachable": true,
                    "original": { "rva": "0x1000", "size": 8 },
                    "candidate": { "rva": "0x1000", "size": 10 }
                  },
                  {
                    "id": "memory",
                    "kind": "code",
                    "reachable": true,
                    "root": { "kind": "fixture_function", "checked": true },
                    "original": { "rva": "0x1010", "size": 8 },
                    "candidate": { "rva": "0x1010", "size": 9 }
                  },
                  {
                    "id": "zero",
                    "kind": "code",
                    "reachable": true,
                    "root": { "kind": "fixture_function", "checked": true },
                    "original": { "rva": "0x1020", "size": 3 },
                    "candidate": { "rva": "0x1020", "size": 3 }
                  },
                  {
                    "id": "external",
                    "kind": "code",
                    "reachable": true,
                    "root": { "kind": "fixture_function", "checked": true },
                    "original": { "rva": "0x1030", "size": 9 },
                    "candidate": { "rva": "0x1030", "size": 9 },
                    "external_calls": [
                      {
                        "dll": "kernel32.dll",
                        "symbol": "GetTickCount",
                        "args": []
                      }
                    ]
                  },
                  {
                    "id": "branch-entry",
                    "kind": "code",
                    "reachable": true,
                    "root": { "kind": "fixture_function", "checked": true },
                    "original": { "rva": "0x1040", "size": 5 },
                    "candidate": { "rva": "0x1040", "size": 5 }
                  },
                  {
                    "id": "branch-fallthrough",
                    "kind": "code",
                    "reachable": true,
                    "original": { "rva": "0x1045", "size": 3 },
                    "candidate": { "rva": "0x1045", "size": 3 }
                  },
                  {
                    "id": "branch-taken",
                    "kind": "code",
                    "reachable": true,
                    "invariant": { "checked": true, "constraints": [ { "reg": "eax", "equals": 7 } ] },
                    "original": { "rva": "0x1048", "size": 6 },
                    "candidate": { "rva": "0x1048", "size": 6 }
                  }
                ],
                "waivers": [
                  {
                    "id": "original-entry-padding",
                    "binary": "original",
                    "rva": "0x1008",
                    "size": "0x8",
                    "reason": "post-ret alignment padding emitted by the fixture build"
                  },
                  {
                    "id": "candidate-entry-padding",
                    "binary": "candidate",
                    "rva": "0x100a",
                    "size": "0x6",
                    "reason": "post-ret alignment padding emitted by the fixture build"
                  },
                  {
                    "id": "original-memory-padding",
                    "binary": "original",
                    "rva": "0x1018",
                    "size": "0x8",
                    "reason": "post-ret alignment padding emitted by the fixture build"
                  },
                  {
                    "id": "candidate-memory-padding",
                    "binary": "candidate",
                    "rva": "0x1019",
                    "size": "0x7",
                    "reason": "post-ret alignment padding emitted by the fixture build"
                  },
                  {
                    "id": "zero-padding",
                    "binary": "both",
                    "rva": "0x1023",
                    "size": "0xd",
                    "reason": "post-ret alignment padding emitted by the fixture build"
                  },
                  {
                    "id": "external-padding",
                    "binary": "both",
                    "rva": "0x1039",
                    "size": "0x7",
                    "reason": "post-ret alignment padding emitted by the fixture build"
                  },
                  {
                    "id": "branch-tail-padding",
                    "binary": "both",
                    "rva": "0x104e",
                    "size": "0x2",
                    "reason": "post-ret alignment padding emitted by the fixture build"
                  }
                ]
              }
              JSON
              cat > "$fixture_dir/block-map-core.json" <<'JSON'
              {
                "blocks": [
                  {
                    "id": "entry",
                    "kind": "code",
                    "reachable": true,
                    "original": { "rva": "0x1000", "size": 8 },
                    "candidate": { "rva": "0x1000", "size": 10 }
                  },
                  {
                    "id": "memory",
                    "kind": "code",
                    "reachable": true,
                    "root": { "kind": "fixture_function", "checked": true },
                    "original": { "rva": "0x1010", "size": 8 },
                    "candidate": { "rva": "0x1010", "size": 9 }
                  },
                  {
                    "id": "zero",
                    "kind": "code",
                    "reachable": true,
                    "root": { "kind": "fixture_function", "checked": true },
                    "original": { "rva": "0x1020", "size": 3 },
                    "candidate": { "rva": "0x1020", "size": 3 }
                  },
                  {
                    "id": "branch-entry",
                    "kind": "code",
                    "reachable": true,
                    "root": { "kind": "fixture_function", "checked": true },
                    "original": { "rva": "0x1030", "size": 5 },
                    "candidate": { "rva": "0x1030", "size": 5 }
                  },
                  {
                    "id": "branch-fallthrough",
                    "kind": "code",
                    "reachable": true,
                    "original": { "rva": "0x1035", "size": 3 },
                    "candidate": { "rva": "0x1035", "size": 3 }
                  },
                  {
                    "id": "branch-taken",
                    "kind": "code",
                    "reachable": true,
                    "invariant": { "checked": true, "constraints": [ { "reg": "eax", "equals": 7 } ] },
                    "original": { "rva": "0x1038", "size": 6 },
                    "candidate": { "rva": "0x1038", "size": 6 }
                  }
                ],
                "waivers": [
                  {
                    "id": "original-entry-padding",
                    "binary": "original",
                    "rva": "0x1008",
                    "size": "0x8",
                    "reason": "post-ret alignment padding emitted by the fixture build"
                  },
                  {
                    "id": "candidate-entry-padding",
                    "binary": "candidate",
                    "rva": "0x100a",
                    "size": "0x6",
                    "reason": "post-ret alignment padding emitted by the fixture build"
                  },
                  {
                    "id": "original-memory-padding",
                    "binary": "original",
                    "rva": "0x1018",
                    "size": "0x8",
                    "reason": "post-ret alignment padding emitted by the fixture build"
                  },
                  {
                    "id": "candidate-memory-padding",
                    "binary": "candidate",
                    "rva": "0x1019",
                    "size": "0x7",
                    "reason": "post-ret alignment padding emitted by the fixture build"
                  },
                  {
                    "id": "zero-padding",
                    "binary": "both",
                    "rva": "0x1023",
                    "size": "0xd",
                    "reason": "post-ret alignment padding emitted by the fixture build"
                  },
                  {
                    "id": "branch-tail-padding",
                    "binary": "both",
                    "rva": "0x103e",
                    "size": "0x2",
                    "reason": "post-ret alignment padding emitted by the fixture build"
                  }
                ]
              }
              JSON
              cat > "$fixture_dir/block-map-mutated.json" <<'JSON'
              {
                "blocks": [
                  {
                    "id": "entry",
                    "kind": "code",
                    "reachable": true,
                    "original": { "rva": "0x1000", "size": 8 },
                    "candidate": { "rva": "0x1000", "size": 8 }
                  },
                  {
                    "id": "memory",
                    "kind": "code",
                    "reachable": true,
                    "root": { "kind": "fixture_function", "checked": true },
                    "original": { "rva": "0x1010", "size": 8 },
                    "candidate": { "rva": "0x1010", "size": 8 }
                  },
                  {
                    "id": "zero",
                    "kind": "code",
                    "reachable": true,
                    "root": { "kind": "fixture_function", "checked": true },
                    "original": { "rva": "0x1020", "size": 3 },
                    "candidate": { "rva": "0x1020", "size": 6 }
                  },
                  {
                    "id": "external",
                    "kind": "code",
                    "reachable": true,
                    "root": { "kind": "fixture_function", "checked": true },
                    "original": { "rva": "0x1030", "size": 9 },
                    "candidate": { "rva": "0x1030", "size": 9 },
                    "external_calls": [
                      {
                        "dll": "kernel32.dll",
                        "symbol": "GetTickCount",
                        "args": []
                      }
                    ]
                  },
                  {
                    "id": "branch-entry",
                    "kind": "code",
                    "reachable": true,
                    "root": { "kind": "fixture_function", "checked": true },
                    "original": { "rva": "0x1040", "size": 5 },
                    "candidate": { "rva": "0x1040", "size": 5 }
                  },
                  {
                    "id": "branch-fallthrough",
                    "kind": "code",
                    "reachable": true,
                    "original": { "rva": "0x1045", "size": 3 },
                    "candidate": { "rva": "0x1045", "size": 3 }
                  },
                  {
                    "id": "branch-taken",
                    "kind": "code",
                    "reachable": true,
                    "original": { "rva": "0x1048", "size": 6 },
                    "candidate": { "rva": "0x1048", "size": 6 }
                  }
                ],
                "waivers": [
                  {
                    "id": "entry-padding",
                    "binary": "both",
                    "rva": "0x1008",
                    "size": "0x8",
                    "reason": "post-ret alignment padding emitted by the fixture build"
                  },
                  {
                    "id": "memory-padding",
                    "binary": "both",
                    "rva": "0x1018",
                    "size": "0x8",
                    "reason": "post-ret alignment padding emitted by the fixture build"
                  },
                  {
                    "id": "original-zero-padding",
                    "binary": "original",
                    "rva": "0x1023",
                    "size": "0xd",
                    "reason": "post-ret alignment padding emitted by the fixture build"
                  },
                  {
                    "id": "candidate-zero-padding",
                    "binary": "candidate",
                    "rva": "0x1026",
                    "size": "0xa",
                    "reason": "post-ret alignment padding emitted by the fixture build"
                  },
                  {
                    "id": "external-padding",
                    "binary": "both",
                    "rva": "0x1039",
                    "size": "0x7",
                    "reason": "post-ret alignment padding emitted by the fixture build"
                  },
                  {
                    "id": "branch-tail-padding",
                    "binary": "both",
                    "rva": "0x104e",
                    "size": "0x2",
                    "reason": "post-ret alignment padding emitted by the fixture build"
                  }
                ]
              }
              JSON
              cat > "$fixture_dir/stage-a-fixture-lemmas.lean" <<'LEAN'
              namespace StageAFixture

              theorem fixtureSupplementChecked : True := True.intro

              end StageAFixture
              LEAN
              cat > "$fixture_dir/suite.json" <<'JSON'
              {
                "model": "x86-pe32-env-v1",
                "cases": [
                  {
                    "id": "gcc-o0-vs-gcc-o2-symbolic-equivalence",
                    "original": "stage-a-original.exe",
                    "candidate": "stage-a-candidate.exe",
                    "mapping": "block-map.json",
                    "lean_inputs": ["stage-a-fixture-lemmas.lean"],
                    "expect": "pass"
                  },
                  {
                    "id": "gcc-og-vs-gcc-os-symbolic-equivalence",
                    "original": "stage-a-original-og.exe",
                    "candidate": "stage-a-candidate-os.exe",
                    "mapping": "block-map.json",
                    "lean_inputs": ["stage-a-fixture-lemmas.lean"],
                    "expect": "pass"
                  },
                  {
                    "id": "gcc13-o0-vs-gcc15-o2-symbolic-equivalence",
                    "original": "stage-a-gcc13-original.exe",
                    "candidate": "stage-a-gcc15-candidate.exe",
                    "mapping": "block-map-core.json",
                    "lean_inputs": ["stage-a-fixture-lemmas.lean"],
                    "expect": "pass"
                  },
                  {
                    "id": "gcc13-og-vs-gcc15-os-symbolic-equivalence",
                    "original": "stage-a-gcc13-original-og.exe",
                    "candidate": "stage-a-gcc15-candidate-os.exe",
                    "mapping": "block-map-core.json",
                    "lean_inputs": ["stage-a-fixture-lemmas.lean"],
                    "expect": "pass"
                  },
                  {
                    "id": "gcc-o0-vs-mutated-candidate",
                    "original": "stage-a-original.exe",
                    "candidate": "stage-a-mutated.exe",
                    "mapping": "block-map-mutated.json",
                    "lean_inputs": ["stage-a-fixture-lemmas.lean"],
                    "expect": "fail"
                  }
                ]
              }
              JSON
              cat > "$fixture_dir/build-metadata.json" <<JSON
              {
                "format": "stage-a-fixture-build-metadata-v1",
                "source": "stage_a_equivalence.S",
                "compiler": "$($CC -dumpmachine)",
                "compiler_version": "$($CC -dumpfullversion -dumpversion)",
                "alternate_compiler": "$("$gcc13" -dumpmachine)",
                "alternate_compiler_version": "$("$gcc13" -dumpfullversion -dumpversion)",
                "cases": [
                  {"id": "gcc-o0-vs-gcc-o2-symbolic-equivalence", "original_flags": "-O0", "candidate_flags": "-O2 -DSTAGE_A_VARIANT_B"},
                  {"id": "gcc-og-vs-gcc-os-symbolic-equivalence", "original_flags": "-Og", "candidate_flags": "-Os -DSTAGE_A_VARIANT_B"},
                  {"id": "gcc13-o0-vs-gcc15-o2-symbolic-equivalence", "normalized_pe_layout": true, "original_compiler": "gcc13", "candidate_compiler": "gcc15", "original_flags": "-O0 -DSTAGE_A_NO_EXTERNAL", "candidate_flags": "-O2 -DSTAGE_A_VARIANT_B -DSTAGE_A_NO_EXTERNAL"},
                  {"id": "gcc13-og-vs-gcc15-os-symbolic-equivalence", "normalized_pe_layout": true, "original_compiler": "gcc13", "candidate_compiler": "gcc15", "original_flags": "-Og -DSTAGE_A_NO_EXTERNAL", "candidate_flags": "-Os -DSTAGE_A_VARIANT_B -DSTAGE_A_NO_EXTERNAL"},
                  {"id": "gcc-o0-vs-mutated-candidate", "original_flags": "-O0", "candidate_flags": "-O2 -DSTAGE_A_MUTATION"}
                ]
              }
              JSON
              runHook postInstall
            '';
          };

          stage-a-fixtures-root = pkgs.writeShellApplication {
            name = "stage-a-fixtures-root";
            text = ''
              printf '%s\n' "${stage-a-fixtures}"
            '';
          };

          stage-a-fixtures-check = pkgs.runCommand "stage-a-fixtures-check"
            {
              nativeBuildInputs = [
                haloce-tools
                pkgs.lean4
              ];
            }
            ''
              fixture_dir="${stage-a-fixtures}/share/wincr/stage-a-fixtures/symbolic-equivalence"
              wincr stage-a-validate-suite \
                --suite "$fixture_dir/suite.json" \
                --model x86-pe32-env-v1 \
                --out "$TMPDIR/stage-a-suite"
              mkdir -p "$out"
              cp -R "$TMPDIR/stage-a-suite/." "$out/"
            '';

          stage-a-jq-original = mkStageAJq "original" stageAJqOriginalCflags;
          stage-a-jq-candidate = mkStageAJq "candidate" stageAJqCandidateCflags;

          stage-a-jq-fixtures = pkgs.runCommand "stage-a-jq-fixtures"
            {
              nativeBuildInputs = [
                pkgs.jq
              ];
            }
            ''
              fixture_dir="$out/share/wincr/stage-a-fixtures/jq-o2-alignment"
              mkdir -p "$fixture_dir"
              cp "${stage-a-jq-original}/share/wincr/stage-a-jq-fixtures/original/jq.exe" "$fixture_dir/jq-original.exe"
              cp "${stage-a-jq-candidate}/share/wincr/stage-a-jq-fixtures/candidate/jq.exe" "$fixture_dir/jq-candidate.exe"
              cp "${stage-a-jq-original}/share/wincr/stage-a-jq-fixtures/original/jq.map" "$fixture_dir/jq-original.map"
              cp "${stage-a-jq-candidate}/share/wincr/stage-a-jq-fixtures/candidate/jq.map" "$fixture_dir/jq-candidate.map"
              cp -L "${stage-a-jq-original}"/bin/*.dll "$fixture_dir/"
              jq -n \
                --arg original_flags "${stageAJqOriginalCflags}" \
                --arg candidate_flags "${stageAJqCandidateCflags}" \
                --arg compiler "$(${mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc -dumpmachine)" \
                --arg compiler_version "$(${mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc -dumpfullversion -dumpversion)" \
                '{
                  format: "stage-a-jq-fixture-build-metadata-v1",
                  source: "jq-1.8.1 from nixpkgs",
                  target: "i686-w64-mingw32",
                  original: { file: "jq-original.exe", linker_map: "jq-original.map", flags: $original_flags },
                  candidate: { file: "jq-candidate.exe", linker_map: "jq-candidate.map", flags: $candidate_flags },
                  compiler: { target: $compiler, version: $compiler_version }
                }' > "$fixture_dir/build-metadata.json"
            '';

          stage-a-jq-fixtures-root = pkgs.writeShellApplication {
            name = "stage-a-jq-fixtures-root";
            text = ''
              printf '%s\n' "${stage-a-jq-fixtures}"
            '';
          };

          stage-b-smoke-check = pkgs.runCommand "stage-b-smoke-check"
            {
              nativeBuildInputs = [
                stage-b-functional-tools
                pkgs.jq
              ];
            }
            ''
              work="$TMPDIR/stage-b-smoke"
              mkdir -p "$work"
              printf 'stage-b smoke suite\n' > "$work/upstream-suite-source.txt"
              cat > "$work/cases.json" <<'JSON'
              {
                "format": "stage-b-upstream-suite-cases-v1",
                "cases": [
                  {
                    "id": "stage-b-smoke-echo",
                    "args": [],
                    "stdin": "smoke\n",
                    "timeout_seconds": 5,
                    "expected_returncode": 0,
                    "expected_stdout": "smoke\n",
                    "expected_stderr": ""
                  }
                ]
              }
              JSON
              stage-b-functional-wincr stage-b-materialize-upstream-suite \
                --target-name jq \
                --suite-source "$work/upstream-suite-source.txt" \
                --source-revision stage-b-smoke \
                --cases "$work/cases.json" \
                --suite-scope subset \
                --out "$work/materialized-suite" \
                > "$work/materialized-suite.stdout"
              cat_cmd="$(jq -cn --arg cat "${pkgs.coreutils}/bin/cat" '[$cat]')"
              stage-b-functional-wincr stage-b-run-functional-suite \
                --suite "$work/materialized-suite/functional-suite.json" \
                --candidate-command-json "$cat_cmd" \
                --out "$work/functional" \
                > "$work/functional.stdout"
              jq -e '
                .format == "stage-b-functional-report-v1"
                and .status == "pass"
                and .counts == {"cases":1,"passed":1,"failed":0}
                and .suite_id == "jq-upstream-integration-tests"
                and .coverage.suite_scope == "subset"
                and .coverage.source_revision == "stage-b-smoke"
                and .cases[0].status == "pass"
              ' "$work/functional/functional-report.json" >/dev/null
              mkdir -p "$out"
              cp "$work/materialized-suite/functional-suite.json" \
                "$work/functional/functional-report.json" \
                "$work/materialized-suite.stdout" \
                "$work/functional.stdout" \
                "$out/"
            '';

          stage-b-jq-decompiler-export = pkgs.runCommand "stage-b-jq-decompiler-export"
            {
              nativeBuildInputs = [
                pkgs.jq
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/wincr/stage-a-fixtures/jq-o2-alignment"
              export HOME="$TMPDIR/home"
              export XDG_CONFIG_HOME="$TMPDIR/xdg-config"
              export XDG_CACHE_HOME="$TMPDIR/xdg-cache"
              mkdir -p "$out" "$HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$TMPDIR/ghidra-projects"
              original="$fixture_dir/jq-original.exe"
              original_sha256="$(sha256sum "$original" | cut -d' ' -f1)"
              export_path="$out/jq.ghidra.json"
              stdout_path="$out/analyzeHeadless.stdout"
              stderr_path="$out/analyzeHeadless.stderr"
              project="stage-b-decompiler-export-jq-$(printf '%s' "$original_sha256" | cut -c1-12)"
              command_json="$(jq -cn \
                --arg analyze "${ghidra-headless}/bin/analyzeHeadless" \
                --arg project_dir "$TMPDIR/ghidra-projects" \
                --arg project "$project" \
                --arg original "$original" \
                --arg script_path "${./tools/ghidra}" \
                --arg script "HaloCatalogExport.java" \
                --arg export_path "$export_path" \
                --arg original_sha256 "$original_sha256" \
                '[$analyze,$project_dir,$project,"-import",$original,"-scriptPath",$script_path,"-postScript",$script,$export_path,$original_sha256,"-deleteProject"]')"
              set +e
              ${pkgs.coreutils}/bin/timeout --kill-after=10s 240s \
                ${ghidra-headless}/bin/analyzeHeadless \
                "$TMPDIR/ghidra-projects" \
                "$project" \
                -import "$original" \
                -scriptPath "${./tools/ghidra}" \
                -postScript HaloCatalogExport.java "$export_path" "$original_sha256" \
                -deleteProject \
                > "$stdout_path" \
                2> "$stderr_path"
              code=$?
              set -e
              printf '%s\n' "$code" > "$out/analyzeHeadless.returncode"
              if test "$code" -eq 0; then
                status=pass
                blocker=""
              else
                status=incomplete
                blocker="Ghidra decompiler export command failed"
              fi
              export_sha256="$(sha256sum "$export_path" | cut -d' ' -f1)"
              jq -n \
                --arg status "$status" \
                --arg blocker "$blocker" \
                --arg target_name jq \
                --arg original "$original" \
                --arg original_sha256 "$original_sha256" \
                --arg command_json "$command_json" \
                --arg script "${./tools/ghidra}/HaloCatalogExport.java" \
                --arg export_path "$export_path" \
                --arg export_sha256 "$export_sha256" \
                --arg stdout "$stdout_path" \
                --arg stderr "$stderr_path" \
                --slurpfile payload "$export_path" \
                '
                def completeness($p):
                  ($p.functions // [] | map(select(type == "object"))) as $functions
                  | (reduce $functions[] as $row ({};
                      ($row.name // "") as $name
                      | if $name == "" then . else .[$name] = ((.[$name] // 0) + 1) end
                    )) as $name_counts
                  | [($name_counts | to_entries[] | select(.value > 1) | .key)] as $duplicate_names
                  | (reduce $functions[] as $row ({decompiler_functions:0,decompiler_successes:0,decompiler_code_functions:0,status_counts:{}};
                      if ($row.decompiler | type) == "object" then
                        ($row.decompiler.c // $row.decompiler.code // $row.decompiler.decompiled_c // "") as $code
                        | ($row.decompiler.status // (if ($code | length) > 0 then "success" else "not_available" end)) as $decompiler_status
                        | .decompiler_functions += 1
                        | .status_counts[$decompiler_status] = ((.status_counts[$decompiler_status] // 0) + 1)
                        | if $decompiler_status == "success" then .decompiler_successes += 1 else . end
                        | if ($code | gsub("\\s";"") | length) > 0 then .decompiler_code_functions += 1 else . end
                      else . end
                    )) as $counts
                  | [
                      (if ($functions | length) == 0 then "missing_functions" else empty end),
                      (if $counts.decompiler_functions != ($functions | length) then "missing_decompiler_exports" else empty end),
                      (if $counts.decompiler_successes != ($functions | length) then "incomplete_decompiler_successes" else empty end),
                      (if $counts.decompiler_code_functions != ($functions | length) then "missing_decompiler_code" else empty end),
                      (if ($duplicate_names | length) > 0 then "duplicate_decompiler_function_names" else empty end)
                    ] as $blockers
                  | {
                      format: "stage-b-decompiler-export-completeness-v1",
                      status: (if ($blockers | length) == 0 then "complete" else "incomplete" end),
                      functions: ($functions | length),
                      decompiler_functions: $counts.decompiler_functions,
                      decompiler_successes: $counts.decompiler_successes,
                      decompiler_code_functions: $counts.decompiler_code_functions,
                      decompiler_status_counts: $counts.status_counts,
                      duplicate_function_names: $duplicate_names,
                      blockers: $blockers
                    };
                ($payload[0] // {}) as $p
                | {
                    format: "stage-b-decompiler-export-v1",
                    target_name: $target_name,
                    status: $status,
                    original: {path: $original, sha256: $original_sha256},
                    tool: {
                      name: "ghidra-analyzeHeadless",
                      command: ($command_json | fromjson),
                      script: $script,
                      returncode: ($status == "pass" | if . then 0 else 1 end)
                    },
                    outputs: {
                      export: $export_path,
                      stdout: $stdout,
                      stderr: $stderr,
                      report: "stage-b-decompiler-export.json"
                    },
                    decompiler_export: {
                      path: $export_path,
                      sha256: $export_sha256,
                      kind: ($p | type),
                      schema_version: $p.schema_version,
                      program_name: $p.program_name,
                      binary_sha256: $p.binary_sha256,
                      completeness: completeness($p)
                    },
                    blocker: $blocker
                  }
                ' > "$out/stage-b-decompiler-export.json"
              test "$code" -eq 0
              jq -e '
                .format == "stage-b-decompiler-export-v1"
                and .status == "pass"
                and .target_name == "jq"
                and .decompiler_export.completeness.status == "complete"
                and .decompiler_export.completeness.functions > 0
                and .decompiler_export.completeness.functions == .decompiler_export.completeness.decompiler_code_functions
                and (.decompiler_export.completeness.blockers | length) == 0
              ' "$out/stage-b-decompiler-export.json" >/dev/null
            '';

          stage-b-jq-libjq-decompiler-export = pkgs.runCommand "stage-b-jq-libjq-decompiler-export"
            {
              nativeBuildInputs = [
                pkgs.jq
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/wincr/stage-a-fixtures/jq-o2-alignment"
              export HOME="$TMPDIR/home"
              export XDG_CONFIG_HOME="$TMPDIR/xdg-config"
              export XDG_CACHE_HOME="$TMPDIR/xdg-cache"
              mkdir -p "$out" "$HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$TMPDIR/ghidra-projects"
              original="$fixture_dir/libjq-1.dll"
              original_sha256="$(sha256sum "$original" | cut -d' ' -f1)"
              export_path="$out/jq-libjq-1.ghidra.json"
              stdout_path="$out/analyzeHeadless.stdout"
              stderr_path="$out/analyzeHeadless.stderr"
              project="stage-b-decompiler-export-jq-libjq-1-$(printf '%s' "$original_sha256" | cut -c1-12)"
              command_json="$(jq -cn \
                --arg analyze "${ghidra-headless}/bin/analyzeHeadless" \
                --arg project_dir "$TMPDIR/ghidra-projects" \
                --arg project "$project" \
                --arg original "$original" \
                --arg script_path "${./tools/ghidra}" \
                --arg script "HaloCatalogExport.java" \
                --arg export_path "$export_path" \
                --arg original_sha256 "$original_sha256" \
                '[$analyze,$project_dir,$project,"-import",$original,"-scriptPath",$script_path,"-postScript",$script,$export_path,$original_sha256,"-deleteProject"]')"
              set +e
              ${pkgs.coreutils}/bin/timeout --kill-after=10s 600s \
                ${ghidra-headless}/bin/analyzeHeadless \
                "$TMPDIR/ghidra-projects" \
                "$project" \
                -import "$original" \
                -scriptPath "${./tools/ghidra}" \
                -postScript HaloCatalogExport.java "$export_path" "$original_sha256" \
                -deleteProject \
                > "$stdout_path" \
                2> "$stderr_path"
              code=$?
              set -e
              printf '%s\n' "$code" > "$out/analyzeHeadless.returncode"
              if test "$code" -eq 0; then
                status=pass
                blocker=""
              else
                status=incomplete
                blocker="Ghidra decompiler export command failed"
              fi
              export_sha256="$(sha256sum "$export_path" | cut -d' ' -f1)"
              jq -n \
                --arg status "$status" \
                --arg blocker "$blocker" \
                --arg target_name jq-libjq-1 \
                --arg original "$original" \
                --arg original_sha256 "$original_sha256" \
                --arg command_json "$command_json" \
                --arg script "${./tools/ghidra}/HaloCatalogExport.java" \
                --arg export_path "$export_path" \
                --arg export_sha256 "$export_sha256" \
                --arg stdout "$stdout_path" \
                --arg stderr "$stderr_path" \
                --slurpfile payload "$export_path" \
                '
                def function_rva($row): ($row.rva_start // $row.rva // null);
                def completeness($p):
                  ($p.functions // [] | map(select(type == "object"))) as $functions
                  | (reduce $functions[] as $row ({};
                      ($row.name // "") as $name
                      | if $name == "" then . else .[$name] = ((.[$name] // 0) + 1) end
                    )) as $name_counts
                  | [($name_counts | to_entries[] | select(.value > 1) | .key)] as $duplicate_names
                  | [
                      $duplicate_names[] as $name
                      | ([$functions[] | select((.name // "") == $name) | function_rva(.)]) as $rvas
                      | if (($rvas | all(. != null)) and (($rvas | unique | length) == ($rvas | length))) then empty else $name end
                    ] as $ambiguous_duplicate_names
                  | (reduce $functions[] as $row ({decompiler_functions:0,decompiler_successes:0,decompiler_code_functions:0,status_counts:{}};
                      if ($row.decompiler | type) == "object" then
                        ($row.decompiler.c // $row.decompiler.code // $row.decompiler.decompiled_c // "") as $code
                        | ($row.decompiler.status // (if ($code | length) > 0 then "success" else "not_available" end)) as $decompiler_status
                        | .decompiler_functions += 1
                        | .status_counts[$decompiler_status] = ((.status_counts[$decompiler_status] // 0) + 1)
                        | if $decompiler_status == "success" then .decompiler_successes += 1 else . end
                        | if ($code | gsub("\\s";"") | length) > 0 then .decompiler_code_functions += 1 else . end
                      else . end
                    )) as $counts
                  | [
                      (if ($functions | length) == 0 then "missing_functions" else empty end),
                      (if $counts.decompiler_functions != ($functions | length) then "missing_decompiler_exports" else empty end),
                      (if $counts.decompiler_successes != ($functions | length) then "incomplete_decompiler_successes" else empty end),
                      (if $counts.decompiler_code_functions != ($functions | length) then "missing_decompiler_code" else empty end),
                      (if ($ambiguous_duplicate_names | length) > 0 then "ambiguous_duplicate_decompiler_function_names" else empty end)
                    ] as $blockers
                  | {
                      format: "stage-b-decompiler-export-completeness-v1",
                      status: (if ($blockers | length) == 0 then "complete" else "incomplete" end),
                      functions: ($functions | length),
                      decompiler_functions: $counts.decompiler_functions,
                      decompiler_successes: $counts.decompiler_successes,
                      decompiler_code_functions: $counts.decompiler_code_functions,
                      decompiler_status_counts: $counts.status_counts,
                      duplicate_function_names: $duplicate_names,
                      ambiguous_duplicate_function_names: $ambiguous_duplicate_names,
                      name_disambiguation: {
                        status: (if ($ambiguous_duplicate_names | length) > 0 then "ambiguous" elif ($duplicate_names | length) > 0 then "required" else "not_required" end),
                        strategy: (if ($duplicate_names | length) > 0 then "append_rva_to_duplicate_decompiler_name" else "none" end)
                      },
                      blockers: $blockers
                    };
                ($payload[0] // {}) as $p
                | {
                    format: "stage-b-decompiler-export-v1",
                    target_name: $target_name,
                    status: $status,
                    original: {path: $original, sha256: $original_sha256},
                    tool: {
                      name: "ghidra-analyzeHeadless",
                      command: ($command_json | fromjson),
                      script: $script,
                      returncode: ($status == "pass" | if . then 0 else 1 end)
                    },
                    outputs: {
                      export: $export_path,
                      stdout: $stdout,
                      stderr: $stderr,
                      report: "stage-b-decompiler-export.json"
                    },
                    decompiler_export: {
                      path: $export_path,
                      sha256: $export_sha256,
                      kind: ($p | type),
                      schema_version: $p.schema_version,
                      program_name: $p.program_name,
                      binary_sha256: $p.binary_sha256,
                      completeness: completeness($p)
                    },
                    blocker: $blocker
                  }
                ' > "$out/stage-b-decompiler-export.json"
              test "$code" -eq 0
              jq -e '
                .format == "stage-b-decompiler-export-v1"
                and .status == "pass"
                and .target_name == "jq-libjq-1"
                and .decompiler_export.completeness.status == "complete"
                and .decompiler_export.completeness.functions > 0
                and .decompiler_export.completeness.functions == .decompiler_export.completeness.decompiler_code_functions
                and (.decompiler_export.completeness.blockers | length) == 0
              ' "$out/stage-b-decompiler-export.json" >/dev/null
            '';

          stage-b-jq-libjq-decompiled-c-skeleton = pkgs.runCommand "stage-b-jq-libjq-decompiled-c-skeleton"
            {
              nativeBuildInputs = [
                stage-b-skeleton-tools
                mingw32.stdenv.cc
                pkgs.jq
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/wincr/stage-a-fixtures/jq-o2-alignment"
              root="$out/share/wincr/stage-b/jq/target-closure-decompiled-c/jq-libjq-1"
              skeleton_dir="$root/decompiled-c-skeleton"
              compile_dir="$root/compile-diagnostic"
              mkdir -p "$compile_dir"
              stage-b-skeleton-wincr stage-b-generate-skeleton \
                --original "$fixture_dir/libjq-1.dll" \
                --decompiler-export "${stage-b-jq-libjq-decompiler-export}/jq-libjq-1.ghidra.json" \
                --target-name jq-libjq-1 \
                --source-language c \
                --implementation-mode decompiled-c \
                --runtime-entry-policy mingw-crt \
                --out-dir "$skeleton_dir" \
                > "$compile_dir/generate-skeleton.stdout"
              jq -e '
                .format == "stage-b-skeleton-v1"
                and .target_name == "jq-libjq-1"
                and .implementation_mode == "decompiled-c"
                and .runtime_entry_policy == "mingw-crt"
                and .implementation_recovery.status == "complete"
                and .implementation_recovery.source_implements_behavior == true
                and .implementation_recovery.generated_source_kind == "decompiler_recovered_behavior"
                and .implementation_recovery.decompiler_coverage.status == "complete"
                and .source_policy.upstream_source_read == false
                and .source_policy.manual_behavioral_fixups == false
              ' "$skeleton_dir/manifest.json" >/dev/null

              set +e
              i686-w64-mingw32-cc -std=gnu99 \
                -Wno-int-conversion \
                -Wno-incompatible-pointer-types \
                -Wno-builtin-declaration-mismatch \
                -fno-builtin \
                -ffunction-sections \
                -fdata-sections \
                -c "$skeleton_dir/src/jq-libjq-1_stage_b_skeleton.c" \
                -o "$compile_dir/jq-libjq-1_stage_b_skeleton.o" \
                > "$compile_dir/stdout.txt" \
                2> "$compile_dir/stderr.txt"
              compile_code=$?
              set -e
              printf '%s\n' "$compile_code" > "$compile_dir/returncode.txt"
              grep -E '(^|: )error: ' "$compile_dir/stderr.txt" > "$compile_dir/compiler-errors.txt" || true
              grep -E '(^|: )warning: ' "$compile_dir/stderr.txt" > "$compile_dir/compiler-warnings.txt" || true
              {
                sed -n '1,140p' "$compile_dir/compiler-errors.txt"
                sed -n '1,60p' "$compile_dir/compiler-warnings.txt"
              } > "$compile_dir/compiler-diagnostics.txt"
              diagnostic_count="$(wc -l < "$compile_dir/compiler-diagnostics.txt" | tr -d ' ')"
              error_count="$(wc -l < "$compile_dir/compiler-errors.txt" | tr -d ' ')"
              warning_count="$(wc -l < "$compile_dir/compiler-warnings.txt" | tr -d ' ')"
              jq -n \
                --arg status "$(if test "$compile_code" -eq 0; then printf pass; else printf incomplete; fi)" \
                --arg returncode "$compile_code" \
                --arg object "$compile_dir/jq-libjq-1_stage_b_skeleton.o" \
                --arg stdout "$compile_dir/stdout.txt" \
                --arg stderr "$compile_dir/stderr.txt" \
                --arg diagnostics "$compile_dir/compiler-diagnostics.txt" \
                --arg diagnostic_count "$diagnostic_count" \
                --arg errors "$compile_dir/compiler-errors.txt" \
                --arg error_count "$error_count" \
                --arg warnings "$compile_dir/compiler-warnings.txt" \
                --arg warning_count "$warning_count" \
                --arg source "$skeleton_dir/src/jq-libjq-1_stage_b_skeleton.c" \
                --slurpfile manifest "$skeleton_dir/manifest.json" \
                '{
                  format: "stage-b-decompiled-c-compile-diagnostic-v1",
                  target_name: "jq-libjq-1",
                  status: $status,
                  returncode: ($returncode | tonumber),
                  compiler_flags: ["-std=gnu99", "-Wno-int-conversion", "-Wno-incompatible-pointer-types", "-Wno-builtin-declaration-mismatch", "-fno-builtin", "-ffunction-sections", "-fdata-sections", "-c"],
                  source: $source,
                  object: $object,
                  stdout: $stdout,
                  stderr: $stderr,
                  diagnostics: $diagnostics,
                  diagnostic_count: ($diagnostic_count | tonumber),
                  compiler_errors: $errors,
                  error_count: ($error_count | tonumber),
                  compiler_warnings: $warnings,
                  warning_count: ($warning_count | tonumber),
                  skeleton: {
                    manifest: $manifest[0],
                    source_implements_behavior: $manifest[0].implementation_recovery.source_implements_behavior,
                    function_count: $manifest[0].counts.functions,
                    instruction_count: $manifest[0].counts.instructions
                  },
                  blocker: (if $status == "pass" then "" else "raw Ghidra C for the generated libjq closure needs compile/structure fixups before it can replace the scaffold DLL" end)
                }' > "$compile_dir/report.json"
            '';

          stage-b-jq-decompiled-c-skeleton = pkgs.runCommand "stage-b-jq-decompiled-c-skeleton"
            {
              nativeBuildInputs = [
                stage-b-skeleton-tools
                mingw32.stdenv.cc
                pkgs.llvm
                pkgs.jq
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/wincr/stage-a-fixtures/jq-o2-alignment"
              skeleton_dir="$out/share/wincr/stage-b/jq/decompiled-c-skeleton"
              compile_dir="$out/share/wincr/stage-b/jq/decompiled-c-compile-diagnostic"
              mkdir -p "$compile_dir"
              stage-b-skeleton-wincr stage-b-generate-skeleton \
                --original "$fixture_dir/jq-original.exe" \
                --decompiler-export "${stage-b-jq-decompiler-export}/jq.ghidra.json" \
                --reference-contract "${stage-a-jq-fixtures-check}/generated/jq-reference-contract.json" \
                --target-name jq \
                --source-language c \
                --implementation-mode decompiled-c \
                --runtime-entry-policy mingw-crt \
                --out-dir "$skeleton_dir"
              set +e
              i686-w64-mingw32-cc -std=gnu99 \
                -Wno-int-conversion \
                -Wno-incompatible-pointer-types \
                -Wno-builtin-declaration-mismatch \
                -fno-builtin \
                -ffunction-sections \
                -fdata-sections \
                -c "$skeleton_dir/src/jq_stage_b_skeleton.c" \
                -o "$compile_dir/jq_stage_b_skeleton.o" \
                > "$compile_dir/stdout.txt" \
                2> "$compile_dir/stderr.txt"
              compile_code=$?
              set -e
              printf '%s\n' "$compile_code" > "$compile_dir/returncode.txt"
              grep -E '(^|: )error: ' "$compile_dir/stderr.txt" > "$compile_dir/compiler-errors.txt" || true
              grep -E '(^|: )warning: ' "$compile_dir/stderr.txt" > "$compile_dir/compiler-warnings.txt" || true
              {
                sed -n '1,140p' "$compile_dir/compiler-errors.txt"
                sed -n '1,60p' "$compile_dir/compiler-warnings.txt"
              } > "$compile_dir/compiler-diagnostics.txt"
              diagnostic_count="$(wc -l < "$compile_dir/compiler-diagnostics.txt" | tr -d ' ')"
              error_count="$(wc -l < "$compile_dir/compiler-errors.txt" | tr -d ' ')"
              warning_count="$(wc -l < "$compile_dir/compiler-warnings.txt" | tr -d ' ')"
              if test "$compile_code" -eq 0; then
                compile_status="pass"
                compile_blocker=""
              else
                compile_status="incomplete"
                compile_blocker="raw Ghidra C did not compile to an object file before it can be linked as a Stage B candidate"
              fi
              jq -e '
                .format == "stage-b-skeleton-v1"
                and .target_name == "jq"
                and .implementation_mode == "decompiled-c"
                and .implementation_recovery.status == "incomplete"
                and .implementation_recovery.source_implements_behavior == false
                and .implementation_recovery.generated_source_kind == "decompiler_recovered_partial"
                and .reverse_engineering.function_source == "stage_a_reference_contract"
                and .implementation_recovery.functions == .reference_contract_function_coverage.counts.contract_functions
                and .implementation_recovery.decompiler_code_functions < .implementation_recovery.functions
                and .implementation_recovery.decompiler_coverage.status == "incomplete"
                and (.implementation_recovery.blockers | index("missing_decompiler_exports"))
                and (.implementation_recovery.blockers | index("missing_decompiler_code"))
                and .reference_contract_function_coverage.status == "complete"
                and .reference_contract_function_coverage.counts.contract_functions == 168
                and .reference_contract_function_coverage.counts.missing == 0
              ' "$skeleton_dir/manifest.json" >/dev/null
              jq -n \
                --arg status "$compile_status" \
                --arg returncode "$compile_code" \
                --arg object "$compile_dir/jq_stage_b_skeleton.o" \
                --arg stdout "$compile_dir/stdout.txt" \
                --arg stderr "$compile_dir/stderr.txt" \
                --arg diagnostics "$compile_dir/compiler-diagnostics.txt" \
                --arg diagnostic_count "$diagnostic_count" \
                --arg errors "$compile_dir/compiler-errors.txt" \
                --arg error_count "$error_count" \
                --arg warnings "$compile_dir/compiler-warnings.txt" \
                --arg warning_count "$warning_count" \
                --arg blocker "$compile_blocker" \
                '{
                  format: "stage-b-decompiled-c-compile-diagnostic-v1",
                  status: $status,
                  returncode: ($returncode | tonumber),
                  compiler_flags: ["-std=gnu99", "-Wno-int-conversion", "-Wno-incompatible-pointer-types", "-Wno-builtin-declaration-mismatch", "-fno-builtin", "-ffunction-sections", "-fdata-sections", "-c"],
                  blocker: $blocker,
                  object: $object,
                  stdout: $stdout,
                  stderr: $stderr,
                  diagnostics: $diagnostics,
                  diagnostic_count: ($diagnostic_count | tonumber),
                  compiler_errors: $errors,
                  error_count: ($error_count | tonumber),
                  compiler_warnings: $warnings,
                  warning_count: ($warning_count | tonumber)
                }' > "$compile_dir/report.json"
              test "$compile_code" -eq 0
              test -s "$compile_dir/jq_stage_b_skeleton.o"
              stage-b-skeleton-wincr stage-b-generate-link-roots \
                --original "$fixture_dir/jq-original.exe" \
                --reference-contract "${stage-a-jq-fixtures-check}/generated/jq-reference-contract.json" \
                --skeleton-functions "$skeleton_dir/functions.json" \
                --object "$compile_dir/jq_stage_b_skeleton.o" \
                --out "$compile_dir/link-roots" \
                > "$compile_dir/link-roots.stdout"
              link_root_flags=()
              while IFS= read -r flag; do
                if test -n "$flag"; then
                  link_root_flags+=("$flag")
                fi
              done < "$compile_dir/link-roots/link-root-flags.txt"
              import_thunk_root_flags=()
              while IFS= read -r flag; do
                if test -n "$flag"; then
                  import_thunk_root_flags+=("$flag")
                fi
              done < "$compile_dir/link-roots/import-thunk-root-flags.txt"
              budgeted_link_root_flags=()
              while IFS= read -r flag; do
                if test -n "$flag"; then
                  budgeted_link_root_flags+=("$flag")
                fi
              done < "$compile_dir/link-roots/budgeted-link-root-flags.txt"
              set +e
              i686-w64-mingw32-cc -municode \
                "$compile_dir/jq_stage_b_skeleton.o" \
                "''${import_thunk_root_flags[@]}" \
                "''${link_root_flags[@]}" \
                -L${stage-a-jq-original}/lib \
                -ljq \
                -L${mingw32Oniguruma.lib}/lib \
                -lonig \
                -L${mingw32.windows.mcfgthreads}/lib \
                -Wl,--gc-sections \
                -Wl,--section-start,.data=0x40d000 \
                -Wl,--section-start,.rdata=0x40e000 \
                -Wl,--section-start,.bss=0x410000 \
                -Wl,--section-start,.edata=0x411000 \
                -Wl,--section-start,.idata=0x412000 \
                -Wl,--section-start,.tls=0x413000 \
                -Wl,--section-start,.reloc=0x414000 \
                -Wl,-Map,"$compile_dir/jq_stage_b_skeleton.rooted.link.map" \
                -o "$compile_dir/jq_stage_b_skeleton.rooted.exe" \
                > "$compile_dir/rooted-link.stdout.txt" \
                2> "$compile_dir/rooted-link.stderr.txt"
              rooted_link_code=$?
              set -e
              printf '%s\n' "$rooted_link_code" > "$compile_dir/rooted-link-returncode.txt"
              set +e
              i686-w64-mingw32-cc -municode \
                "$compile_dir/jq_stage_b_skeleton.o" \
                "''${import_thunk_root_flags[@]}" \
                "''${budgeted_link_root_flags[@]}" \
                -L${stage-a-jq-original}/lib \
                -ljq \
                -L${mingw32Oniguruma.lib}/lib \
                -lonig \
                -L${mingw32.windows.mcfgthreads}/lib \
                -Wl,--gc-sections \
                -Wl,--section-start,.data=0x40d000 \
                -Wl,--section-start,.rdata=0x40e000 \
                -Wl,--section-start,.bss=0x410000 \
                -Wl,--section-start,.edata=0x411000 \
                -Wl,--section-start,.idata=0x412000 \
                -Wl,--section-start,.tls=0x413000 \
                -Wl,--section-start,.reloc=0x414000 \
                -Wl,-Map,"$compile_dir/jq_stage_b_skeleton.link.map" \
                -o "$compile_dir/jq_stage_b_skeleton.exe" \
                > "$compile_dir/link.stdout.txt" \
                2> "$compile_dir/link.stderr.txt"
              link_code=$?
              set -e
              printf '%s\n' "$link_code" > "$compile_dir/link-returncode.txt"
              set +e
              i686-w64-mingw32-cc -municode \
                "$compile_dir/jq_stage_b_skeleton.o" \
                "''${import_thunk_root_flags[@]}" \
                "''${budgeted_link_root_flags[@]}" \
                -L${mingw32Oniguruma.lib}/lib \
                -lonig \
                -L${mingw32.windows.mcfgthreads}/lib \
                -Wl,--gc-sections \
                -Wl,--section-start,.data=0x40d000 \
                -Wl,--section-start,.rdata=0x40e000 \
                -Wl,--section-start,.bss=0x410000 \
                -Wl,--section-start,.edata=0x411000 \
                -Wl,--section-start,.idata=0x412000 \
                -Wl,--section-start,.tls=0x413000 \
                -Wl,--section-start,.reloc=0x414000 \
                -Wl,-Map,"$compile_dir/jq_stage_b_skeleton.standalone.link.map" \
                -o "$compile_dir/jq_stage_b_skeleton.standalone.exe" \
                > "$compile_dir/standalone-link.stdout.txt" \
                2> "$compile_dir/standalone-link.stderr.txt"
              standalone_link_code=$?
              set -e
              printf '%s\n' "$standalone_link_code" > "$compile_dir/standalone-link-returncode.txt"
              grep 'undefined reference' "$compile_dir/standalone-link.stderr.txt" \
                | sort -u \
                > "$compile_dir/standalone-link-undefined-references.txt" || true
              standalone_unresolved_count="$(wc -l < "$compile_dir/standalone-link-undefined-references.txt" | tr -d ' ')"
              if test "$link_code" -eq 0; then
                link_status="pass"
                link_blocker=""
              else
                link_status="incomplete"
                link_blocker="generated jq decompiled-C object still needs link-time fixed-up data/import/runtime definitions before it can become a Stage B candidate"
              fi
              unresolved_count="$(grep -c 'undefined reference' "$compile_dir/link.stderr.txt" || true)"
              jq -n \
                --arg status "$link_status" \
                --arg returncode "$link_code" \
                --arg unresolved_count "$unresolved_count" \
                --arg exe "$compile_dir/jq_stage_b_skeleton.exe" \
                --arg map "$compile_dir/jq_stage_b_skeleton.link.map" \
                --arg rooted_status "$(if test "$rooted_link_code" -eq 0; then printf pass; else printf incomplete; fi)" \
                --arg rooted_returncode "$rooted_link_code" \
                --arg rooted_exe "$compile_dir/jq_stage_b_skeleton.rooted.exe" \
                --arg rooted_map "$compile_dir/jq_stage_b_skeleton.rooted.link.map" \
                --arg rooted_stdout "$compile_dir/rooted-link.stdout.txt" \
                --arg rooted_stderr "$compile_dir/rooted-link.stderr.txt" \
                --arg standalone_status "$(if test "$standalone_link_code" -eq 0; then printf pass; else printf incomplete; fi)" \
                --arg standalone_returncode "$standalone_link_code" \
                --arg standalone_unresolved_count "$standalone_unresolved_count" \
                --arg standalone_exe "$compile_dir/jq_stage_b_skeleton.standalone.exe" \
                --arg standalone_map "$compile_dir/jq_stage_b_skeleton.standalone.link.map" \
                --arg standalone_stdout "$compile_dir/standalone-link.stdout.txt" \
                --arg standalone_stderr "$compile_dir/standalone-link.stderr.txt" \
                --rawfile standalone_undefined "$compile_dir/standalone-link-undefined-references.txt" \
                --arg link_roots "$compile_dir/link-roots/link-roots.json" \
                --slurpfile link_root_flags "$compile_dir/link-roots/link-roots.json" \
                --arg stdout "$compile_dir/link.stdout.txt" \
                --arg stderr "$compile_dir/link.stderr.txt" \
                --arg blocker "$link_blocker" \
                '{
                  format: "stage-b-decompiled-c-link-diagnostic-v1",
                  status: $status,
                  returncode: ($returncode | tonumber),
                  unresolved_reference_lines: ($unresolved_count | tonumber),
                  linker_flags: (
                    ["-municode"]
                    + (($link_root_flags[0].import_thunk_linker_flags // []) | map(tostring))
                    + (($link_root_flags[0].budgeted_linker_flags // []) | map(tostring))
                    + ["-L${stage-a-jq-original}/lib", "-ljq", "-L${mingw32Oniguruma.lib}/lib", "-lonig", "-L${mingw32.windows.mcfgthreads}/lib", "-Wl,--gc-sections", "-Wl,--section-start,.data=0x40d000", "-Wl,--section-start,.rdata=0x40e000", "-Wl,--section-start,.bss=0x410000", "-Wl,--section-start,.edata=0x411000", "-Wl,--section-start,.idata=0x412000", "-Wl,--section-start,.tls=0x413000", "-Wl,--section-start,.reloc=0x414000", "-Wl,-Map,jq_stage_b_skeleton.link.map"]
                  ),
                  rooted_link_diagnostic: {
                    status: $rooted_status,
                    returncode: ($rooted_returncode | tonumber),
                    linker_flags: (
                      ["-municode"]
                      + (($link_root_flags[0].import_thunk_linker_flags // []) | map(tostring))
                      + (($link_root_flags[0].linker_flags // []) | map(tostring))
                      + ["-L${stage-a-jq-original}/lib", "-ljq", "-L${mingw32Oniguruma.lib}/lib", "-lonig", "-L${mingw32.windows.mcfgthreads}/lib", "-Wl,--gc-sections", "-Wl,--section-start,.data=0x40d000", "-Wl,--section-start,.rdata=0x40e000", "-Wl,--section-start,.bss=0x410000", "-Wl,--section-start,.edata=0x411000", "-Wl,--section-start,.idata=0x412000", "-Wl,--section-start,.tls=0x413000", "-Wl,--section-start,.reloc=0x414000", "-Wl,-Map,jq_stage_b_skeleton.rooted.link.map"]
                    ),
                    executable: $rooted_exe,
                    linker_map: $rooted_map,
                    stdout: $rooted_stdout,
                    stderr: $rooted_stderr
                  },
                  standalone_link_diagnostic: {
                    status: $standalone_status,
                    returncode: ($standalone_returncode | tonumber),
                    unresolved_reference_lines: ($standalone_unresolved_count | tonumber),
                    linker_flags: (
                      ["-municode"]
                      + (($link_root_flags[0].import_thunk_linker_flags // []) | map(tostring))
                      + (($link_root_flags[0].budgeted_linker_flags // []) | map(tostring))
                      + ["-L${mingw32Oniguruma.lib}/lib", "-lonig", "-L${mingw32.windows.mcfgthreads}/lib", "-Wl,--gc-sections", "-Wl,--section-start,.data=0x40d000", "-Wl,--section-start,.rdata=0x40e000", "-Wl,--section-start,.bss=0x410000", "-Wl,--section-start,.edata=0x411000", "-Wl,--section-start,.idata=0x412000", "-Wl,--section-start,.tls=0x413000", "-Wl,--section-start,.reloc=0x414000", "-Wl,-Map,jq_stage_b_skeleton.standalone.link.map"]
                    ),
                    executable: $standalone_exe,
                    linker_map: $standalone_map,
                    stdout: $standalone_stdout,
                    stderr: $standalone_stderr,
                    undefined_reference_samples: ($standalone_undefined | split("\n") | map(select(length > 0))[:100])
                  },
                  generated_import_libraries: [],
                  link_roots_report: $link_roots,
                  blocker: $blocker,
                  executable: $exe,
                  linker_map: $map,
                  stdout: $stdout,
                  stderr: $stderr
                }' > "$compile_dir/link-report.json"
              test "$link_code" -eq 0
              test -s "$compile_dir/jq_stage_b_skeleton.exe"
            '';

          stage-b-jq-program-slice-skeleton = pkgs.runCommand "stage-b-jq-program-slice-skeleton"
            {
              nativeBuildInputs = [
                stage-b-skeleton-tools
                mingw32.stdenv.cc
                pkgs.jq
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/wincr/stage-a-fixtures/jq-o2-alignment"
              skeleton_dir="$out/share/wincr/stage-b/jq/program-slice-skeleton"
              compile_dir="$out/share/wincr/stage-b/jq/program-slice-compile-diagnostic"
              mkdir -p "$compile_dir"
              stage-b-skeleton-wincr stage-b-generate-skeleton \
                --original "$fixture_dir/jq-original.exe" \
                --decompiler-export "${stage-b-jq-decompiler-export}/jq.ghidra.json" \
                --target-name jq \
                --source-language c \
                --implementation-mode decompiled-c \
                --function-name isoption \
                --function-name jv_is_valid \
                --function-name die \
                --function-name usage \
                --function-name priv_fwrite \
                --function-name isoptish \
                --function-name process \
                --function-name umain \
                --function-name _wmain \
                --out-dir "$skeleton_dir"
              i686-w64-mingw32-cc -std=gnu99 \
                -w \
                -Wno-int-conversion \
                -Wno-incompatible-pointer-types \
                -fsyntax-only "$skeleton_dir/src/jq_stage_b_skeleton.c" \
                > "$compile_dir/stdout.txt" \
                2> "$compile_dir/stderr.txt"
              printf '0\n' > "$compile_dir/returncode.txt"
              jq -e '
                .format == "stage-b-skeleton-v1"
                and .target_name == "jq"
                and .implementation_mode == "decompiled-c"
                and .reverse_engineering.function_filter.mode == "function_names"
                and .reverse_engineering.function_filter.included == [
                  "isoption",
                  "jv_is_valid",
                  "die",
                  "usage",
                  "priv_fwrite",
                  "isoptish",
                  "process",
                  "umain",
                  "_wmain"
                ]
                and .counts.functions == 9
                and .implementation_recovery.status == "complete"
                and .implementation_recovery.source_implements_behavior == true
                and .implementation_recovery.functions == 9
                and .implementation_recovery.decompiler_code_functions == 9
                and (.implementation_recovery.blockers | length) == 0
              ' "$skeleton_dir/manifest.json" >/dev/null
              jq -n \
                --arg stderr "$compile_dir/stderr.txt" \
                --arg manifest "$skeleton_dir/manifest.json" \
                '{
                  format: "stage-b-jq-program-slice-compile-diagnostic-v1",
                  status: "pass",
                  returncode: 0,
                  manifest: $manifest,
                  compiler_flags: ["-std=gnu99", "-Wno-int-conversion", "-Wno-incompatible-pointer-types", "-fsyntax-only"],
                  blocker: "",
                  stderr: $stderr
                }' > "$compile_dir/report.json"
            '';

          stage-a-jq-fixtures-check = pkgs.runCommand "stage-a-jq-fixtures-check"
            {
              nativeBuildInputs = [
                haloce-tools
                pkgs.jq
                pkgs.lean4
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/wincr/stage-a-fixtures/jq-o2-alignment"
              work="$TMPDIR/stage-a-jq"
              mkdir -p "$work"
              wincr stage-a-generate-map \
                --original "$fixture_dir/jq-original.exe" \
                --candidate "$fixture_dir/jq-candidate.exe" \
                --linker-map-original "$fixture_dir/jq-original.map" \
                --linker-map-candidate "$fixture_dir/jq-candidate.map" \
                --original-flags "${stageAJqOriginalCflags}" \
                --candidate-flags "${stageAJqCandidateCflags}" \
                --out "$work/jq-block-map.json" \
                --layout-contract-out "$work/jq-layout-contract.json" \
                --quiet
              cat > "$work/suite.json" <<JSON
              {
                "model": "x86-pe32-env-v1",
                "cases": [
                  {
                    "id": "jq-o2-alignment-windows-x86",
                    "original": "$fixture_dir/jq-original.exe",
                    "candidate": "$fixture_dir/jq-candidate.exe",
                    "mapping": "$work/jq-block-map.json",
                    "layout_contract": "$work/jq-layout-contract.json",
                    "expect": "pass"
                  }
                ]
              }
              JSON
                            wincr stage-a-validate-suite \
                              --suite "$work/suite.json" \
                              --model x86-pe32-env-v1 \
                              --out "$TMPDIR/stage-a-jq-suite"
                            mkdir -p "$out/generated" "$out/report"
                            cp "$work/jq-block-map.json" \
                              "$work/jq-layout-contract.json" \
                              "$work/suite.json" \
                              "$out/generated/"
                            cp -R "$TMPDIR/stage-a-jq-suite/." "$out/report/"
                            wincr stage-a-export-reference-contract \
                              --original "$fixture_dir/jq-original.exe" \
                              --candidate "$fixture_dir/jq-candidate.exe" \
                              --mapping "$out/generated/jq-block-map.json" \
                              --validation-report "$out/report/cases/jq-o2-alignment-windows-x86" \
                              --layout-contract "$out/generated/jq-layout-contract.json" \
                              --sidecar-dir "$out/generated" \
                              --unit-contract-dir "$out/generated" \
                              --out "$out/generated/jq-reference-contract.json" \
                              --quiet
                            jq -e '
                              .format == "stage-a-reference-contract-v1"
                              and .status == "pass"
                              and all(.families[].status; . != "represented")
                              and .constraints.executable_byte_coverage.status == "satisfied"
                              and .constraints.proof_obligation_inventory.status == "satisfied"
                            ' "$out/generated/jq-reference-contract.json" >/dev/null
                            wincr stage-a-smoke-contract \
                              --reference-contract "$out/generated/jq-reference-contract.json" \
                              --out "$out/generated/jq-reference-contract-smoke.json"
                            jq -e '
                              .format == "stage-a-contract-smoke-v1"
                              and .status == "pass"
                              and .counts.issues == 0
                            ' "$out/generated/jq-reference-contract-smoke.json" >/dev/null
                            if wincr stage-a-semantic-coverage \
                              --reference-contract "$out/generated/jq-reference-contract.json" \
                              --out "$out/generated/jq-semantic-coverage.json" \
                              --quiet
                            then
                              semantic_coverage_status=pass
                            else
                              semantic_coverage_status=incomplete
                            fi
                            jq -e '
                              .format == "stage-a-semantic-coverage-v1"
                              and (.status == "pass" or .status == "incomplete")
                            ' "$out/generated/jq-semantic-coverage.json" >/dev/null
                            printf '%s\n' "$semantic_coverage_status" > "$out/generated/jq-semantic-coverage.status"
                          '';

          stage-b-jq-skeleton = pkgs.runCommand "stage-b-jq-skeleton"
            {
              nativeBuildInputs = [
                stage-b-skeleton-tools
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/wincr/stage-a-fixtures/jq-o2-alignment"
              skeleton_dir="$out/share/wincr/stage-b/jq/skeleton"
              stage-b-skeleton-wincr stage-b-generate-skeleton \
                --original "$fixture_dir/jq-original.exe" \
                --linker-map "$fixture_dir/jq-original.map" \
                --target-name jq \
                --source-language c \
                --out-dir "$skeleton_dir"
            '';

          stage-b-jq-skeleton-root = pkgs.writeShellApplication {
            name = "stage-b-jq-skeleton-root";
            text = ''
              printf '%s\n' "${stage-b-jq-skeleton}"
            '';
          };

          stage-b-jq-skeleton-check = pkgs.runCommand "stage-b-jq-skeleton-check"
            {
              nativeBuildInputs = [
                pkgs.jq
              ];
            }
            ''
              skeleton_dir="${stage-b-jq-skeleton}/share/wincr/stage-b/jq/skeleton"
              jq -e '
                .format == "stage-b-skeleton-v1"
                and .status == "generated"
                and .target_name == "jq"
                and .proof_rule == "reproducible_stage_b_skeleton_reimplementation_v1"
                and .source_policy.upstream_source_read == false
                and .implementation_mode == "scaffold"
                and .implementation_recovery.generated_source_kind == "scaffold"
                and .implementation_recovery.source_implements_behavior == false
                and .completion.stage_a_validated == false
              ' "$skeleton_dir/manifest.json" >/dev/null
              mkdir -p "$out"
              cp "$skeleton_dir/manifest.json" "$skeleton_dir/functions.json" "$out/"
            '';

          stage-b-jq-skeleton-candidate = pkgs.runCommand "stage-b-jq-skeleton-candidate"
            {
              nativeBuildInputs = [
                stage-b-provenance-tools
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/wincr/stage-a-fixtures/jq-o2-alignment"
              skeleton_dir="${stage-b-jq-decompiled-c-skeleton}/share/wincr/stage-b/jq/decompiled-c-skeleton"
              diagnostic_dir="${stage-b-jq-decompiled-c-skeleton}/share/wincr/stage-b/jq/decompiled-c-compile-diagnostic"
              out_dir="$out/share/wincr/stage-b/jq/candidate"
              mkdir -p "$out_dir"
              cp "$diagnostic_dir/jq_stage_b_skeleton.exe" "$out_dir/jq-stage-b-skeleton-candidate.exe"
              cp "$diagnostic_dir/jq_stage_b_skeleton.link.map" "$out_dir/jq-stage-b-skeleton-candidate.map"
              cp "$fixture_dir"/*.dll "$out_dir/"
              cp "$diagnostic_dir/report.json" "$out_dir/decompiled-c-compile-report.json"
              cp "$diagnostic_dir/link-report.json" "$out_dir/decompiled-c-link-report.json"
              cp "$diagnostic_dir/link-roots/link-roots.json" "$out_dir/decompiled-c-link-roots.json"
              cp "$skeleton_dir/manifest.json" "$out_dir/skeleton-manifest.json"
              mkdir -p "$out_dir/src"
              cp "$skeleton_dir/src/jq_stage_b_skeleton.c" "$out_dir/src/"
              stage-b-provenance-wincr stage-b-generate-candidate-provenance \
                --target-name jq \
                --skeleton-manifest "$out_dir/skeleton-manifest.json" \
                --candidate "$out_dir/jq-stage-b-skeleton-candidate.exe" \
                --build-target i686-w64-mingw32 \
                --build-compiler i686-w64-mingw32-cc \
                --build-output jq-stage-b-skeleton-candidate.exe \
                --build-report "$out_dir/decompiled-c-link-report.json" \
                --out "$out_dir" \
                > "$out_dir/candidate-provenance.stdout"
            '';

          stage-b-jq-skeleton-candidate-check = pkgs.runCommand "stage-b-jq-skeleton-candidate-check"
            {
              nativeBuildInputs = [
                haloce-tools
                pkgs.jq
                pkgs.lean4
                stage-b-skeleton-tools
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/wincr/stage-a-fixtures/jq-o2-alignment"
              candidate_dir="${stage-b-jq-skeleton-candidate}/share/wincr/stage-b/jq/candidate"
              work="$TMPDIR/stage-b-jq-candidate"
              mkdir -p "$work"
              test -s "${stage-b-smoke-check}/functional-report.json"
              stage-b-skeleton-wincr stage-b-generate-skeleton \
                --original "$candidate_dir/jq-stage-b-skeleton-candidate.exe" \
                --linker-map "$candidate_dir/jq-stage-b-skeleton-candidate.map" \
                --target-name jq-candidate-smoke \
                --source-language c \
                --out-dir "$work/parse"
              functional_report=""
              functional_code=125
              mkdir -p "$work/materialized-suite" "$work/smoke-suite" "$work/functional" "$work/smoke"
              jq -n \
                --arg candidate "$candidate_dir/jq-stage-b-skeleton-candidate.exe" \
                '{
                  format: "stage-b-runtime-smoke-v1",
                  status: "skipped",
                  returncode: 125,
                  runner: "not_run",
                  candidate: {path: $candidate},
                  original_runtime_observations: false,
                  blockers: [
                    "runtime smoke is deferred until Stage A reference-contract validation is clean"
                  ]
                }' > "$work/smoke/report.json"
              printf 'skipped: Stage A reference-contract gate incomplete before runtime smoke\n' > "$work/materialized-suite.stdout"
              printf 'skipped: Stage A reference-contract gate incomplete before runtime smoke\n' > "$work/smoke-suite.stdout"
              printf 'skipped: Stage A reference-contract gate incomplete before runtime smoke\n' > "$work/full-suite.stdout"
              printf 'skipped: Stage A reference-contract gate incomplete before runtime smoke\n' > "$work/functional.stdout"
              wincr stage-b-generate-candidate-provenance \
                --target-name jq \
                --skeleton-manifest "$candidate_dir/skeleton-manifest.json" \
                --candidate "$candidate_dir/jq-stage-b-skeleton-candidate.exe" \
                --build-target i686-w64-mingw32 \
                --build-compiler i686-w64-mingw32-cc \
                --build-output jq-stage-b-skeleton-candidate.exe \
                --build-report "$candidate_dir/decompiled-c-link-report.json" \
                --out "$work/provenance" \
                > "$work/provenance.stdout"
              claimed_provenance="$work/provenance/candidate-provenance.json"
              set +e
              wincr stage-b-validate-candidate \
                --candidate "$candidate_dir/jq-stage-b-skeleton-candidate.exe" \
                --linker-map-candidate "$candidate_dir/jq-stage-b-skeleton-candidate.map" \
                --skeleton-manifest "$candidate_dir/skeleton-manifest.json" \
                --candidate-provenance "$claimed_provenance" \
                --reference-contract "${stage-a-jq-fixtures-check}/generated/jq-reference-contract.json" \
                --target-name jq \
                --out "$work/validate" \
                > "$work/validate.stdout"
              code=$?
              set -e
              if [ "$code" -eq 0 ]; then
                jq -e '
                  .status == "pass"
                  and .provenance_status == "pass"
                  and .functional.status == "pass"
                  and .stage_a.gate.status == "pass"
                  and .stage_a.gate.eligible == true
                  and .stage_a.gate.ran == true
                  and .stage_a.gate.behavioral_mismatch_blocks_stage_a == false
                ' "$work/validate/stage-b.json" >/dev/null
              else
                jq -e '
                  .status == "incomplete"
                  and .provenance_status == "incomplete"
                  and ([.issues[].category] | index("upstream_source_dependency"))
                  and ([.issues[].category] | index("reference_build_input_linkage"))
                  and ([.issues[].category] | index("target_library_linkage"))
                  and ([.issues[].category] | index("target_import_closure_incomplete"))
                  and ([.issues[].category] | index("standalone_build_incomplete"))
                  and .candidate.build.report.source_dependency_policy.status == "violated"
                  and .candidate.build.report.target_import_closure.status == "incomplete"
                  and .candidate.build.report.target_import_closure.dll_count == 1
                  and .candidate.build.report.target_import_closure.dlls[0].dll == "libjq-1.dll"
                  and .candidate.build.report.standalone_link_diagnostic.repair_plan.status == "blocked_on_target_import_closure"
                  and .candidate.build.report.standalone_link_diagnostic.target_import_symbol_count > 0
                  and ([.candidate.build.report.source_dependency_policy.violations[].kind] | index("reference_target_artifact"))
                  and ([.candidate.build.report.source_dependency_policy.violations[].kind] | index("target_library_linkage"))
                  and .functional == null
                  and .functional_report == null
                  and .functional_diagnostics.status == "not_provided"
                  and ([.issues[].category] | index("missing_functional_tests"))
                  and ([.issues[].category] | index("functional_tests_not_passing"))
                  and ([.issues[].category] | index("missing_functional_test_suites"))
                  and ([.issues[].category] | index("missing_required_functional_suite"))
                  and ([.issues[].category] | index("functional_test_failure") | not)
                  and ([.issues[].category] | index("functional_test_report_failed") | not)
                  and ([.issues[].category] | index("functional_test_report_incomplete_coverage_scope") | not)
                  and ([.issues[].category] | index("functional_test_report_wrong_suite_id") | not)
                  and ([.issues[].category] | index("functional_test_report_wrong_source_kind") | not)
                  and ([.issues[].category] | index("functional_test_report_wrong_materializer") | not)
                  and ([.issues[].category] | index("functional_binary_command_not_bound") | not)
                  and ([.issues[].category] | index("functional_test_report_original_baseline_failed") | not)
                  and .reference_contract_coverage.provided == true
                  and .reference_contract_coverage.status == "incomplete"
                  and .stage_a.gate.status == "blocked"
                  and .stage_a.gate.eligible == false
                  and .stage_a.gate.ran == false
                  and .stage_a.gate.reason == "pre_stage_a_requirements_incomplete"
                  and .stage_a.gate.behavioral_mismatch_blocks_stage_a == false
                  and .stage_a.gate.behavioral_blocking_issue_categories == []
                  and .stage_a.gate.iteration_policy == "stage_a_contract_first"
                  and .stage_a.gate.runtime_validation_policy == "candidate_only_after_stage_a_pass"
                  and ([.stage_a.gate.non_blocking_issue_categories[]] | index("missing_functional_tests"))
                ' "$work/validate/stage-b.json" >/dev/null
              fi
              mkdir -p "$out"
              cp "$candidate_dir/jq-stage-b-skeleton-candidate.exe" \
                "$candidate_dir/jq-stage-b-skeleton-candidate.map" \
                "$claimed_provenance" \
                "${stage-a-jq-fixtures-check}/generated/jq-reference-contract.json" \
                "$work/validate/stage-b.json" \
                "$out/"
              cp "$work/materialized-suite.stdout" \
                "$work/smoke-suite.stdout" \
                "$work/full-suite.stdout" \
                "$work/functional.stdout" \
                "$work/provenance.stdout" \
                "$work/validate.stdout" \
                "$out/"
              cp "$candidate_dir/decompiled-c-compile-report.json" \
                "$candidate_dir/decompiled-c-link-report.json" \
                "$candidate_dir/decompiled-c-link-roots.json" \
                "$out/"
              cp -R "$work/materialized-suite" "$out/materialized-suite"
              cp -R "$work/smoke-suite" "$out/smoke-suite"
              cp -R "$work/functional" "$out/functional"
              cp -R "$work/provenance" "$out/provenance"
              cp -R "$work/validate" "$out/validate"
              cp -R "$work/smoke" "$out/smoke"
              printf '%s\n' "$functional_code" > "$out/functional.returncode"
            '';

          stage-b-jq-target-closure-skeleton = pkgs.runCommand "stage-b-jq-target-closure-skeleton"
            {
              nativeBuildInputs = [
                haloce-tools
                stage-b-skeleton-tools
                pkgs.jq
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/wincr/stage-a-fixtures/jq-o2-alignment"
              report="${stage-b-jq-skeleton-candidate-check}/stage-b.json"
              closure_dir="$out/share/wincr/stage-b/jq/target-closure-skeletons"
              mkdir -p "$closure_dir"

              jq -e '
                .candidate.build.report.target_import_closure.status == "incomplete"
                and (.candidate.build.report.target_import_closure.dll_count >= 1)
              ' "$report" >/dev/null

              jq -r '.candidate.build.report.target_import_closure.dlls[].dll' "$report" \
                > "$closure_dir/target-dlls.txt"
              while IFS= read -r dll; do
                test -n "$dll"
                original="$fixture_dir/$dll"
                test -s "$original"
                target_name="jq-''${dll%.dll}"
                skeleton_dir="$closure_dir/$target_name"
                stage-b-skeleton-wincr stage-b-generate-skeleton \
                  --original "$original" \
                  --target-name "$target_name" \
                  --source-language c \
                  --out-dir "$skeleton_dir"
                jq -e '
                  .format == "stage-b-skeleton-v1"
                  and .status == "generated"
                  and .source_policy.upstream_source_read == false
                  and .reverse_engineering.function_source == "pe_exports_or_entrypoint_sections"
                  and .counts.functions > 1
                  and .implementation_recovery.generated_source_kind == "scaffold"
                  and .completion.stage_a_validated == false
                ' "$skeleton_dir/manifest.json" >/dev/null
                jq -r --arg dll "$dll" '
                  .candidate.build.report.target_import_closure.dlls[]
                  | select(.dll == $dll)
                  | .symbols[].symbol
                ' "$report" | sort -u > "$skeleton_dir/requested-symbols.txt"
                jq -r '.functions[] | .name, (.aliases[]?)' "$skeleton_dir/functions.json" \
                  | sort -u > "$skeleton_dir/generated-symbols.txt"
                missing=0
                while IFS= read -r symbol; do
                  if ! grep -Fx -- "$symbol" "$skeleton_dir/generated-symbols.txt" >/dev/null; then
                    printf '%s\n' "$symbol" >> "$skeleton_dir/missing-requested-symbols.txt"
                    missing=1
                  fi
                done < "$skeleton_dir/requested-symbols.txt"
                test "$missing" -eq 0
                printf '%s/manifest.json\n' "$skeleton_dir" >> "$closure_dir/manifest-paths.txt"
              done < "$closure_dir/target-dlls.txt"

              jq -n \
                --slurpfile report "$report" \
                --rawfile dlls "$closure_dir/target-dlls.txt" \
                --rawfile manifests "$closure_dir/manifest-paths.txt" \
                '{
                  format: "stage-b-target-closure-skeletons-v1",
                  target_name: "jq",
                  status: "generated",
                  source_policy: {
                    upstream_source_read: false,
                    allowed_inputs: ["stage-b-candidate-report", "target-owned-pe-dll", "pe-export-table", "capstone-disassembly"]
                  },
                  target_import_closure: $report[0].candidate.build.report.target_import_closure,
                  target_dlls: ($dlls | split("\n") | map(select(length > 0))),
                  skeleton_manifests: ($manifests | split("\n") | map(select(length > 0)))
                }' > "$closure_dir/target-closure-skeletons.json"
              wincr stage-b-generate-candidate-provenance \
                --target-name jq \
                --skeleton-manifest "${stage-b-jq-decompiled-c-skeleton}/share/wincr/stage-b/jq/decompiled-c-skeleton/manifest.json" \
                --candidate "${stage-b-jq-skeleton-candidate}/share/wincr/stage-b/jq/candidate/jq-stage-b-skeleton-candidate.exe" \
                --build-target i686-w64-mingw32 \
                --build-compiler i686-w64-mingw32-cc \
                --build-output jq-stage-b-skeleton-candidate.exe \
                --build-report "${stage-b-jq-skeleton-candidate-check}/decompiled-c-link-report.json" \
                --target-closure-manifest "$closure_dir/target-closure-skeletons.json" \
                --out "$closure_dir/closure-aware-provenance" \
                > "$closure_dir/closure-aware-provenance.stdout"
              jq -e '
                .format == "stage-b-candidate-provenance-v1"
                and .build.report.target_import_closure.status == "satisfied"
                and .build.report.target_import_closure.generated_closure.status == "satisfied"
                and .build.report.target_import_closure.generated_closure.counts.missing_symbols == 0
                and .build.report.standalone_link_diagnostic.repair_plan.status == "target_import_closure_not_linked"
                and .build.report.source_dependency_policy.status == "violated"
              ' "$closure_dir/closure-aware-provenance/candidate-provenance.json" >/dev/null
              cp "$report" "$closure_dir/jq-stage-b-report.json"
            '';

          stage-b-jq-generated-closure-candidate = pkgs.runCommand "stage-b-jq-generated-closure-candidate"
            {
              nativeBuildInputs = [
                haloce-tools
                stage-b-provenance-tools
                stage-b-skeleton-tools
                mingw32.stdenv.cc
                pkgs.gawk
                pkgs.jq
                pkgs.llvm
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/wincr/stage-a-fixtures/jq-o2-alignment"
              skeleton_dir="${stage-b-jq-decompiled-c-skeleton}/share/wincr/stage-b/jq/decompiled-c-skeleton"
              diagnostic_dir="${stage-b-jq-decompiled-c-skeleton}/share/wincr/stage-b/jq/decompiled-c-compile-diagnostic"
              libjq_skeleton_dir="${stage-b-jq-libjq-decompiled-c-skeleton}/share/wincr/stage-b/jq/target-closure-decompiled-c/jq-libjq-1/decompiled-c-skeleton"
              libjq_compile_dir="${stage-b-jq-libjq-decompiled-c-skeleton}/share/wincr/stage-b/jq/target-closure-decompiled-c/jq-libjq-1/compile-diagnostic"
              closure_root="${stage-b-jq-target-closure-skeleton}/share/wincr/stage-b/jq/target-closure-skeletons"
              closure_dir="$closure_root/jq-libjq-1"
              target_closure_manifest="$closure_root/target-closure-skeletons.json"
              work="$TMPDIR/stage-b-jq-generated-closure-candidate"
              out_dir="$out/share/wincr/stage-b/jq/generated-closure-candidate"
              mkdir -p "$work" "$out_dir"

              jq -e '
                .format == "stage-b-target-closure-skeletons-v1"
                and .target_name == "jq"
                and .status == "generated"
                and (.target_dlls == ["libjq-1.dll"])
              ' "$target_closure_manifest" >/dev/null
              test -s "$closure_dir/requested-symbols.txt"
              test -s "$libjq_skeleton_dir/src/jq-libjq-1_stage_b_skeleton.c"
              jq -e '
                .format == "stage-b-decompiled-c-compile-diagnostic-v1"
                and .target_name == "jq-libjq-1"
                and .status == "pass"
                and .error_count == 0
                and .skeleton.source_implements_behavior == true
              ' "$libjq_compile_dir/report.json" >/dev/null

              {
                printf '%s\n' 'LIBRARY libjq-1.dll' 'EXPORTS'
                sed 's/^/  /' "$closure_dir/requested-symbols.txt"
              } > "$work/libjq-1.def"
              sort -u "$closure_dir/requested-symbols.txt" > "$work/libjq-1-requested-symbols.sorted"
              jq -r '.functions[] | .name, (.aliases[]?)' "$libjq_skeleton_dir/functions.json" \
                | sort -u \
                > "$work/libjq-1-decompiled-symbols.sorted"
              comm -23 "$work/libjq-1-requested-symbols.sorted" "$work/libjq-1-decompiled-symbols.sorted" \
                > "$work/libjq-1-missing-requested-symbols.txt"
              missing_requested_count="$(wc -l < "$work/libjq-1-missing-requested-symbols.txt" | tr -d ' ')"
              awk '
                BEGIN { print "#include <stdint.h>" }
                /^[A-Za-z_][A-Za-z0-9_]*$/ {
                  printf "uintptr_t %s(void) { return 0; }\n", $1
                }
              ' "$work/libjq-1-missing-requested-symbols.txt" > "$work/libjq-1-export-wrappers.c"

              printf '%s\n' 'building generated Stage B libjq-1.dll from decompiled target-closure source'
              set +e
              i686-w64-mingw32-cc -std=gnu99 \
                -w \
                -Wno-int-conversion \
                -Wno-incompatible-pointer-types \
                -Wno-builtin-declaration-mismatch \
                -fno-builtin \
                -shared \
                "$libjq_skeleton_dir/src/jq-libjq-1_stage_b_skeleton.c" \
                "$work/libjq-1-export-wrappers.c" \
                "$work/libjq-1.def" \
                -L${mingw32Oniguruma.lib}/lib \
                -lonig \
                -L${mingw32.windows.pthreads}/lib \
                -lwinpthread \
                -lkernel32 \
                -lshlwapi \
                -Wl,--out-implib,"$work/libstage_b_target_closure_libjq_1.dll.a" \
                -Wl,-Map,"$work/libjq-1.generated-closure.link.map" \
                -o "$work/libjq-1.dll" \
                > "$work/libjq-1-link.stdout.txt" \
                2> "$work/libjq-1-link.stderr.txt"
              libjq_link_code=$?
              set -e
              printf '%s\n' "$libjq_link_code" > "$work/libjq-1-link.returncode"
              if test "$libjq_link_code" -ne 0; then
                grep -E '(^|: )(error:|undefined reference|multiple definition|cannot find|ld returned|ld:)' "$work/libjq-1-link.stderr.txt" \
                  | sed -n '1,200p' >&2 || true
                sed -n '1,80p' "$work/libjq-1-link.stderr.txt" >&2
                exit 1
              fi
              test -s "$work/libjq-1.dll"
              test -s "$work/libstage_b_target_closure_libjq_1.dll.a"

              import_thunk_root_flags=()
              while IFS= read -r flag; do
                if test -n "$flag"; then
                  import_thunk_root_flags+=("$flag")
                fi
              done < "$diagnostic_dir/link-roots/import-thunk-root-flags.txt"
              link_root_flags=()
              while IFS= read -r flag; do
                if test -n "$flag"; then
                  link_root_flags+=("$flag")
                fi
              done < "$diagnostic_dir/link-roots/link-root-flags.txt"
              budgeted_runtime_crt_root_flags=()
              while IFS= read -r flag; do
                if test -n "$flag"; then
                  budgeted_runtime_crt_root_flags+=("$flag")
                fi
              done < "$diagnostic_dir/link-roots/budgeted-runtime-crt-root-flags.txt"
              budgeted_link_root_flags=()
              while IFS= read -r flag; do
                if test -n "$flag"; then
                  budgeted_link_root_flags+=("$flag")
                fi
              done < "$diagnostic_dir/link-roots/budgeted-link-root-flags.txt"

              strict_layout_flags=(
                -Wl,--section-start,.data=0x40d000
                -Wl,--section-start,.rdata=0x40e000
                -Wl,--section-start,.bss=0x410000
                -Wl,--section-start,.edata=0x411000
                -Wl,--section-start,.idata=0x412000
                -Wl,--section-start,.tls=0x413000
                -Wl,--section-start,.reloc=0x414000
              )
              diagnostic_layout_flags=()

              printf '%s\n' 'linking jq Stage B candidate against generated target-closure import library with strict Stage A layout'
              set +e
              i686-w64-mingw32-cc -municode \
                "$diagnostic_dir/jq_stage_b_skeleton.o" \
                "''${import_thunk_root_flags[@]}" \
                "''${link_root_flags[@]}" \
                "''${budgeted_runtime_crt_root_flags[@]}" \
                -L"$work" \
                -l:libstage_b_target_closure_libjq_1.dll.a \
                -L${mingw32Oniguruma.lib}/lib \
                -lonig \
                -L${mingw32.windows.mcfgthreads}/lib \
                -Wl,--gc-sections \
                "''${strict_layout_flags[@]}" \
                -Wl,-Map,"$work/jq_stage_b_skeleton.generated-closure.strict.link.map" \
                -o "$work/jq_stage_b_skeleton.generated-closure.strict.exe" \
                > "$work/generated-closure-strict-link.stdout.txt" \
                2> "$work/generated-closure-strict-link.stderr.txt"
              strict_generated_link_code=$?
              set -e
              printf '%s\n' "$strict_generated_link_code" > "$work/generated-closure-strict-link.returncode"
              grep 'undefined reference' "$work/generated-closure-strict-link.stderr.txt" \
                | sort -u \
                > "$work/generated-closure-strict-link-undefined-references.txt" || true
              strict_generated_unresolved_count="$(wc -l < "$work/generated-closure-strict-link-undefined-references.txt" | tr -d ' ')"

              if test "$strict_generated_link_code" -eq 0; then
                cp "$work/jq_stage_b_skeleton.generated-closure.strict.exe" "$work/jq_stage_b_skeleton.generated-closure.exe"
                cp "$work/jq_stage_b_skeleton.generated-closure.strict.link.map" "$work/jq_stage_b_skeleton.generated-closure.link.map"
                cp "$work/generated-closure-strict-link.stdout.txt" "$work/generated-closure-link.stdout.txt"
                cp "$work/generated-closure-strict-link.stderr.txt" "$work/generated-closure-link.stderr.txt"
                cp "$work/generated-closure-strict-link.returncode" "$work/generated-closure-link.returncode"
                cp "$work/generated-closure-strict-link-undefined-references.txt" "$work/generated-closure-link-undefined-references.txt"
                generated_link_code="$strict_generated_link_code"
                generated_unresolved_count="$strict_generated_unresolved_count"
                generated_link_status="pass"
                layout_policy="stage_a_strict"
                layout_fallback_used="false"
              else
                printf '%s\n' 'strict Stage A layout link failed; building diagnostic fallback candidate without fixed section RVAs' >&2
                sed -n '1,200p' "$work/generated-closure-strict-link.stderr.txt" >&2
                set +e
                i686-w64-mingw32-cc -municode \
                  "$diagnostic_dir/jq_stage_b_skeleton.o" \
                  "''${import_thunk_root_flags[@]}" \
                  "''${link_root_flags[@]}" \
                  "''${budgeted_runtime_crt_root_flags[@]}" \
                  -L"$work" \
                  -l:libstage_b_target_closure_libjq_1.dll.a \
                  -L${mingw32Oniguruma.lib}/lib \
                  -lonig \
                  -L${mingw32.windows.mcfgthreads}/lib \
                  -Wl,--gc-sections \
                  "''${diagnostic_layout_flags[@]}" \
                  -Wl,-Map,"$work/jq_stage_b_skeleton.generated-closure.link.map" \
                  -o "$work/jq_stage_b_skeleton.generated-closure.exe" \
                  > "$work/generated-closure-link.stdout.txt" \
                  2> "$work/generated-closure-link.stderr.txt"
                generated_link_code=$?
                set -e
                printf '%s\n' "$generated_link_code" > "$work/generated-closure-link.returncode"
                grep 'undefined reference' "$work/generated-closure-link.stderr.txt" \
                  | sort -u \
                  > "$work/generated-closure-link-undefined-references.txt" || true
                generated_unresolved_count="$(wc -l < "$work/generated-closure-link-undefined-references.txt" | tr -d ' ')"
                if test "$generated_link_code" -ne 0; then
                  sed -n '1,200p' "$work/generated-closure-link.stderr.txt" >&2
                  exit 1
                fi
                generated_link_status="incomplete"
                layout_policy="diagnostic_fallback"
                layout_fallback_used="true"
              fi
              test -s "$work/jq_stage_b_skeleton.generated-closure.exe"

              cp "$work/jq_stage_b_skeleton.generated-closure.exe" "$out_dir/jq-stage-b-generated-closure-candidate.exe"
              cp "$work/jq_stage_b_skeleton.generated-closure.link.map" "$out_dir/jq-stage-b-generated-closure-candidate.map"
              cp "$work/libjq-1.dll" "$out_dir/libjq-1.dll"
              cp "$work/libstage_b_target_closure_libjq_1.dll.a" "$out_dir/"
              cp "$work/libjq-1.def" "$out_dir/"
              cp "$work/libjq-1-export-wrappers.c" "$out_dir/"
              cp "$work/libjq-1-missing-requested-symbols.txt" "$out_dir/"
              cp "$work/libjq-1-decompiled-symbols.sorted" "$out_dir/"
              cp "$work/libjq-1.generated-closure.link.map" "$out_dir/"
              cp "$work/libjq-1-link.stdout.txt" "$work/libjq-1-link.stderr.txt" "$out_dir/"
              cp "$work/generated-closure-link.stdout.txt" "$work/generated-closure-link.stderr.txt" "$out_dir/"
              cp "$work/generated-closure-strict-link.stdout.txt" "$work/generated-closure-strict-link.stderr.txt" "$out_dir/"
              cp "$work/generated-closure-strict-link.returncode" "$out_dir/"
              cp "$diagnostic_dir/report.json" "$out_dir/decompiled-c-compile-report.json"
              cp "$diagnostic_dir/link-roots/link-roots.json" "$out_dir/decompiled-c-link-roots.json"
              cp "$skeleton_dir/manifest.json" "$out_dir/skeleton-manifest.json"
              cp "$libjq_skeleton_dir/manifest.json" "$out_dir/libjq-1-skeleton-manifest.json"
              mkdir -p "$out_dir/src"
              cp "$skeleton_dir/src/jq_stage_b_skeleton.c" "$out_dir/src/"
              cp "$libjq_skeleton_dir/src/jq-libjq-1_stage_b_skeleton.c" "$out_dir/src/"
              cp "$libjq_compile_dir/report.json" "$out_dir/libjq-1-decompiled-c-compile-report.json"
              for dll in "$fixture_dir"/*.dll "$fixture_dir"/*.DLL; do
                if test -e "$dll" && test "$(basename "$dll" | tr A-Z a-z)" != "libjq-1.dll"; then
                  cp "$dll" "$out_dir/"
                fi
              done

              jq -n \
                --arg status "$generated_link_status" \
                --arg returncode "$strict_generated_link_code" \
                --arg fallback_returncode "$generated_link_code" \
                --arg unresolved_count "$strict_generated_unresolved_count" \
                --arg fallback_unresolved_count "$generated_unresolved_count" \
                --arg layout_policy "$layout_policy" \
                --argjson layout_fallback_used "$layout_fallback_used" \
                --arg exe "$out_dir/jq-stage-b-generated-closure-candidate.exe" \
                --arg map "$out_dir/jq-stage-b-generated-closure-candidate.map" \
                --arg stdout "$out_dir/generated-closure-link.stdout.txt" \
                --arg stderr "$out_dir/generated-closure-link.stderr.txt" \
                --arg strict_stdout "$out_dir/generated-closure-strict-link.stdout.txt" \
                --arg strict_stderr "$out_dir/generated-closure-strict-link.stderr.txt" \
                --rawfile standalone_undefined "$work/generated-closure-strict-link-undefined-references.txt" \
                --rawfile fallback_undefined "$work/generated-closure-link-undefined-references.txt" \
                --arg import_lib "$out_dir/libstage_b_target_closure_libjq_1.dll.a" \
                --arg generated_dll "$out_dir/libjq-1.dll" \
                --arg def "$out_dir/libjq-1.def" \
                --arg wrappers "$out_dir/libjq-1-export-wrappers.c" \
                --arg missing_export_stubs "$out_dir/libjq-1-missing-requested-symbols.txt" \
                --arg missing_export_stub_count "$missing_requested_count" \
                --arg closure_manifest "$target_closure_manifest" \
                --arg closure_skeleton "$libjq_skeleton_dir/manifest.json" \
                --arg libjq_compile_report "$out_dir/libjq-1-decompiled-c-compile-report.json" \
                --arg link_roots "$out_dir/decompiled-c-link-roots.json" \
                --slurpfile link_root_flags "$diagnostic_dir/link-roots/link-roots.json" \
                '{
                  format: "stage-b-decompiled-c-link-diagnostic-v1",
                  status: $status,
                  layout_policy: $layout_policy,
                  stage_a_layout_eligible: ($layout_fallback_used | not),
                  returncode: ($returncode | tonumber),
                  unresolved_reference_lines: ($unresolved_count | tonumber),
                  linker_flags: (
                    ["-municode"]
                    + (($link_root_flags[0].import_thunk_linker_flags // []) | map(tostring))
                    + (($link_root_flags[0].linker_flags // []) | map(tostring))
                    + (($link_root_flags[0].budgeted_runtime_crt_linker_flags // []) | map(tostring))
                    + ["generated-target-closure/libstage_b_target_closure_libjq_1.dll.a", "-L${mingw32Oniguruma.lib}/lib", "-lonig", "-L${mingw32.windows.mcfgthreads}/lib", "-Wl,--gc-sections", "-Wl,--section-start,.data=0x40d000", "-Wl,--section-start,.rdata=0x40e000", "-Wl,--section-start,.bss=0x410000", "-Wl,--section-start,.edata=0x411000", "-Wl,--section-start,.idata=0x412000", "-Wl,--section-start,.tls=0x413000", "-Wl,--section-start,.reloc=0x414000", "-Wl,-Map,jq_stage_b_skeleton.generated-closure.link.map"]
                  ),
                  standalone_link_diagnostic: {
                    status: $status,
                    returncode: ($returncode | tonumber),
                    unresolved_reference_lines: ($unresolved_count | tonumber),
                    linker_flags: (
                      ["-municode"]
                      + (($link_root_flags[0].import_thunk_linker_flags // []) | map(tostring))
                      + (($link_root_flags[0].linker_flags // []) | map(tostring))
                      + (($link_root_flags[0].budgeted_runtime_crt_linker_flags // []) | map(tostring))
                      + ["generated-target-closure/libstage_b_target_closure_libjq_1.dll.a", "-L${mingw32Oniguruma.lib}/lib", "-lonig", "-L${mingw32.windows.mcfgthreads}/lib", "-Wl,--gc-sections", "-Wl,--section-start,.data=0x40d000", "-Wl,--section-start,.rdata=0x40e000", "-Wl,--section-start,.bss=0x410000", "-Wl,--section-start,.edata=0x411000", "-Wl,--section-start,.idata=0x412000", "-Wl,--section-start,.tls=0x413000", "-Wl,--section-start,.reloc=0x414000", "-Wl,-Map,jq_stage_b_skeleton.generated-closure.link.map"]
                    ),
                    executable: $exe,
                    linker_map: $map,
                    stdout: $stdout,
                    stderr: $stderr,
                    repair_plan: (
                      if $layout_fallback_used then
                        {
                          status: "strict_layout_link_failed",
                          next_action: "reduce or repair generated source/layout so the Stage A strict PE section RVAs link without the diagnostic fallback"
                        }
                      else
                        {status: "not_applicable"}
                      end
                    ),
                    undefined_reference_samples: ($standalone_undefined | split("\n") | map(select(length > 0))[:100])
                  },
                  strict_layout_link: {
                    status: (if ($returncode | tonumber) == 0 then "pass" else "incomplete" end),
                    returncode: ($returncode | tonumber),
                    stdout: $strict_stdout,
                    stderr: $strict_stderr,
                    undefined_reference_samples: ($standalone_undefined | split("\n") | map(select(length > 0))[:100])
                  },
                  diagnostic_layout_fallback: {
                    status: (if $layout_fallback_used then "used" else "not_applicable" end),
                    reason: (if $layout_fallback_used then "strict_stage_a_layout_link_failed" else "" end),
                    returncode: ($fallback_returncode | tonumber),
                    stdout: $stdout,
                    stderr: $stderr,
                    unresolved_reference_lines: ($fallback_unresolved_count | tonumber),
                    undefined_reference_samples: ($fallback_undefined | split("\n") | map(select(length > 0))[:100])
                  },
                  generated_target_closure: {
                    format: "stage-b-generated-target-closure-link-artifacts-v1",
                    target_closure_manifest: $closure_manifest,
                    skeleton_manifest: $closure_skeleton,
                    compile_report: $libjq_compile_report,
                    dll: $generated_dll,
                    import_library: $import_lib,
                    def: $def,
                    wrappers: $wrappers,
                    missing_export_stubs: {
                      status: (if ($missing_export_stub_count | tonumber) == 0 then "not_applicable" else "incomplete" end),
                      count: ($missing_export_stub_count | tonumber),
                      symbols_file: $missing_export_stubs
                    },
                    exports_source: "target-closure requested-symbols.txt",
                    source_policy: {
                      upstream_source_read: false,
                      manual_behavioral_fixups: false,
                      behavior_implemented: false,
                      recovered_source_kind: "decompiler_recovered_behavior",
                      behavior_blocker: (
                        if ($missing_export_stub_count | tonumber) == 0 then
                          "generated decompiler-recovered target closure has not passed Stage A or functional validation"
                        else
                          "missing target-import exports are represented by compile-only stubs"
                        end
                      )
                    }
                  },
                  generated_import_libraries: [$import_lib],
                  generated_target_dlls: [$generated_dll],
                  link_roots_report: $link_roots,
                  blocker: (
                    if $layout_fallback_used then
                      "strict Stage A PE section layout failed to link; diagnostic fallback binary is not eligible for final Stage A pass"
                    elif ($missing_export_stub_count | tonumber) == 0 then
                      ""
                    else
                      "generated target-closure DLL still has missing requested-export stubs"
                    end
                  ),
                  executable: $exe,
                  linker_map: $map,
                  stdout: $stdout,
                  stderr: $stderr
                }' > "$out_dir/decompiled-c-generated-closure-link-report.json"

              printf '%s\n' 'generating jq Stage B provenance for generated-closure candidate'
              wincr stage-b-generate-candidate-provenance \
                --target-name jq \
                --skeleton-manifest "$out_dir/skeleton-manifest.json" \
                --candidate "$out_dir/jq-stage-b-generated-closure-candidate.exe" \
                --build-target i686-w64-mingw32 \
                --build-compiler i686-w64-mingw32-cc \
                --build-output jq-stage-b-generated-closure-candidate.exe \
                --build-report "$out_dir/decompiled-c-generated-closure-link-report.json" \
                --target-closure-manifest "$target_closure_manifest" \
                --out "$out_dir/provenance" \
                > "$out_dir/candidate-provenance.stdout"
              cp "$out_dir/provenance/candidate-provenance.json" "$out_dir/candidate-provenance.json"

              smoke_dir="$out_dir/smoke"
              mkdir -p "$smoke_dir"
              printf '%s\n' 'smoke parsing generated-closure candidate PE and linker map'
              stage-b-skeleton-wincr stage-b-generate-skeleton \
                --original "$out_dir/jq-stage-b-generated-closure-candidate.exe" \
                --linker-map "$out_dir/jq-stage-b-generated-closure-candidate.map" \
                --target-name jq-generated-closure-candidate-smoke \
                --source-language c \
                --out-dir "$smoke_dir/parse"
              printf '%s\n' 'skipping generated-closure candidate runtime smoke until Stage A gate passes'
              printf '%s\n' 'skipped: Stage A reference-contract gate has not run in the candidate artifact derivation' \
                > "$smoke_dir/candidate-version.stdout"
              : > "$smoke_dir/candidate-version.stderr"
              smoke_code=125
              printf '%s\n' "$smoke_code" > "$smoke_dir/candidate-version.returncode"
              smoke_status="skipped"
              smoke_blocker="runtime smoke is deferred until stage-b-jq-generated-closure-candidate-check observes a passing Stage A reference-contract gate"
              jq -n \
                --arg status "$smoke_status" \
                --arg returncode "$smoke_code" \
                --arg stdout "$smoke_dir/candidate-version.stdout" \
                --arg stderr "$smoke_dir/candidate-version.stderr" \
                --arg blocker "$smoke_blocker" \
                '{
                  format: "stage-b-runtime-smoke-v1",
                  target_name: "jq",
                  status: $status,
                  returncode: ($returncode | tonumber),
                  command: ["jq-stage-b-generated-closure-candidate.exe", "--version"],
                  runner: "not_run",
                  stdout: $stdout,
                  stderr: $stderr,
                  blocker: $blocker
                }' > "$smoke_dir/report.json"

              printf '%s\n' 'asserting generated-closure candidate provenance stays strict and behavior-incomplete'
              jq -e '
                .format == "stage-b-candidate-provenance-v1"
                and .build.report.source_dependency_policy.status == "satisfied"
                and .build.report.target_import_closure.status == "satisfied"
                and .build.report.target_import_closure.generated_closure.status == "satisfied"
                and (
                  if .build.report.layout_policy == "diagnostic_fallback" then
                    .build.report.status == "incomplete"
                    and .build.report.stage_a_layout_eligible == false
                    and .build.report.strict_layout_link.status == "incomplete"
                    and .build.report.diagnostic_layout_fallback.status == "used"
                    and .build.report.standalone_link_diagnostic.status == "incomplete"
                    and .build.report.standalone_link_diagnostic.repair_plan.status == "strict_layout_link_failed"
                  else
                    .build.report.layout_policy == "stage_a_strict"
                    and .build.report.status == "pass"
                    and .build.report.stage_a_layout_eligible == true
                    and .build.report.standalone_link_diagnostic.status == "pass"
                    and .build.report.standalone_link_diagnostic.repair_plan.status == "not_applicable"
                    and .build.report.standalone_link_diagnostic.undefined_symbol_count == 0
                  end
                )
                and .build.report.generated_target_closure.source_policy.behavior_implemented == false
                and .functional_tests.status == "not_run"
              ' "$out_dir/candidate-provenance.json" >/dev/null || {
                cat "$out_dir/candidate-provenance.json" >&2
                exit 1
              }
            '';

          stage-b-jq-contract-iteration-check = pkgs.runCommand "stage-b-jq-contract-iteration-check"
            {
              nativeBuildInputs = [
                haloce-tools
                pkgs.jq
              ];
            }
            ''
              candidate_dir="${stage-b-jq-generated-closure-candidate}/share/wincr/stage-b/jq/generated-closure-candidate"
              closure_manifest="${stage-b-jq-target-closure-skeleton}/share/wincr/stage-b/jq/target-closure-skeletons/target-closure-skeletons.json"
              work="$TMPDIR/stage-b-jq-contract-iteration-check"
              mkdir -p "$work"
              test -s "$candidate_dir/smoke/report.json"
              jq -e '
                .format == "stage-b-runtime-smoke-v1"
                and .status == "skipped"
                and .runner == "not_run"
                and .returncode == 125
              ' "$candidate_dir/smoke/report.json" >/dev/null

              wincr stage-b-generate-candidate-provenance \
                --target-name jq \
                --skeleton-manifest "$candidate_dir/skeleton-manifest.json" \
                --candidate "$candidate_dir/jq-stage-b-generated-closure-candidate.exe" \
                --build-target i686-w64-mingw32 \
                --build-compiler i686-w64-mingw32-cc \
                --build-output jq-stage-b-generated-closure-candidate.exe \
                --build-report "$candidate_dir/decompiled-c-generated-closure-link-report.json" \
                --target-closure-manifest "$closure_manifest" \
                --out "$work/provenance" \
                > "$work/provenance.stdout"
              claimed_provenance="$work/provenance/candidate-provenance.json"

              set +e
              wincr stage-b-validate-candidate \
                --candidate "$candidate_dir/jq-stage-b-generated-closure-candidate.exe" \
                --linker-map-candidate "$candidate_dir/jq-stage-b-generated-closure-candidate.map" \
                --skeleton-manifest "$candidate_dir/skeleton-manifest.json" \
                --candidate-provenance "$claimed_provenance" \
                --reference-contract "${stage-a-jq-fixtures-check}/generated/jq-reference-contract.json" \
                --target-name jq \
                --out "$work/validate" \
                > "$work/validate.stdout"
              validate_code=$?
              wincr stage-b-explain-delta \
                --reference-contract "${stage-a-jq-fixtures-check}/generated/jq-reference-contract.json" \
                --candidate "$candidate_dir/jq-stage-b-generated-closure-candidate.exe" \
                --linker-map-candidate "$candidate_dir/jq-stage-b-generated-closure-candidate.map" \
                --skeleton-manifest "$candidate_dir/skeleton-manifest.json" \
                --candidate-module "name=libjq-1.dll,candidate=$candidate_dir/libjq-1.dll,linker_map=$candidate_dir/libjq-1.generated-closure.link.map,skeleton_manifest=$candidate_dir/libjq-1-skeleton-manifest.json" \
                --out "$work/delta" \
                > "$work/delta.stdout"
              delta_code=$?
              set -e

              validate_status="$(jq -r '.status' "$work/validate/stage-b.json")"
              case "$validate_status" in
                pass) test "$validate_code" -eq 0 ;;
                incomplete) test "$validate_code" -ne 0 ;;
                *) printf 'unexpected Stage B validation status: %s\n' "$validate_status" >&2; exit 1 ;;
              esac
              delta_status="$(jq -r '.status' "$work/delta/stage-b-delta.json")"
              case "$delta_status" in
                pass) test "$delta_code" -eq 0 ;;
                incomplete) test "$delta_code" -ne 0 ;;
                *) printf 'unexpected Stage B delta status: %s\n' "$delta_status" >&2; exit 1 ;;
              esac

              jq -e '
                .format == "stage-b-validation-v1"
                and (.status == "pass" or .status == "incomplete")
                and .reference_contract_coverage.provided == true
                and .stage_a.gate.ran == true
                and .stage_a.gate.iteration_policy == "stage_a_contract_first"
                and .stage_a.gate.runtime_validation_policy == "candidate_only_after_stage_a_pass"
                and .functional == null
                and .functional_report == null
                and .functional_diagnostics.status == "not_provided"
              ' "$work/validate/stage-b.json" >/dev/null
              jq -e '
                .format == "stage-b-delta-explanation-v1"
                and (.status == "pass" or .status == "incomplete")
                and .functional_report == null
                and .functional_diagnostics.status == "not_provided"
                and (
                  .status == "pass"
                  or (
                    ((.counts.by_evidence_source["stage-a-contract-candidate-validation"] // 0) > 0)
                    and .repair_items[0].evidence.source == "stage-a-contract-candidate-validation"
                    and (
                      .repair_items[0].evidence
                      | has("coverage_gap")
                        or has("missing_function_detail")
                        or has("section_delta")
                        or has("entrypoint_delta")
                        or has("header_delta")
                        or has("import_delta")
                        or has("family")
                    )
                  )
                )
              ' "$work/delta/stage-b-delta.json" >/dev/null

              mkdir -p "$out"
              cp "$candidate_dir/jq-stage-b-generated-closure-candidate.exe" "$out/"
              cp "$candidate_dir/jq-stage-b-generated-closure-candidate.map" "$out/"
              cp "$candidate_dir/decompiled-c-generated-closure-link-report.json" "$out/"
              cp "$candidate_dir/decompiled-c-link-roots.json" "$out/"
              cp -R "$candidate_dir/src" "$out/src"
              cp "$claimed_provenance" "$out/candidate-provenance.json"
              cp "$work/validate/stage-b.json" "$out/stage-b.json"
              cp "$work/delta/stage-b-delta.json" "$out/stage-b-delta.json"
              cp "$work/provenance.stdout" "$work/validate.stdout" "$work/delta.stdout" "$out/"
              cp -R "$work/provenance" "$out/provenance"
              cp -R "$work/validate" "$out/validate"
              cp -R "$work/delta" "$out/delta"
            '';

          stage-b-jq-generated-closure-candidate-check = pkgs.runCommand "stage-b-jq-generated-closure-candidate-check"
            {
              nativeBuildInputs = [
                haloce-tools
                pkgs.jq
                pkgs.wineWow64Packages.stable
                pkgs.xvfb-run
                stage-b-functional-tools
              ];
            }
            ''
              candidate_dir="${stage-b-jq-generated-closure-candidate}/share/wincr/stage-b/jq/generated-closure-candidate"
              closure_manifest="${stage-b-jq-target-closure-skeleton}/share/wincr/stage-b/jq/target-closure-skeletons/target-closure-skeletons.json"
              work="$TMPDIR/stage-b-jq-generated-closure-candidate-check"
              mkdir -p "$work"
              test -s "${stage-b-smoke-check}/functional-report.json"
              test -s "$candidate_dir/smoke/report.json"
              test -s "$candidate_dir/src/jq_stage_b_skeleton.c"
              test -s "$candidate_dir/src/jq-libjq-1_stage_b_skeleton.c"
              jq -e '
                .format == "stage-b-runtime-smoke-v1"
                and .status == "skipped"
                and .runner == "not_run"
                and .returncode == 125
              ' "$candidate_dir/smoke/report.json" >/dev/null

              wincr stage-b-generate-candidate-provenance \
                --target-name jq \
                --skeleton-manifest "$candidate_dir/skeleton-manifest.json" \
                --candidate "$candidate_dir/jq-stage-b-generated-closure-candidate.exe" \
                --build-target i686-w64-mingw32 \
                --build-compiler i686-w64-mingw32-cc \
                --build-output jq-stage-b-generated-closure-candidate.exe \
                --build-report "$candidate_dir/decompiled-c-generated-closure-link-report.json" \
                --target-closure-manifest "$closure_manifest" \
                --out "$work/provenance" \
                > "$work/provenance.stdout"
              claimed_provenance="$work/provenance/candidate-provenance.json"

              set +e
              wincr stage-b-validate-candidate \
                --candidate "$candidate_dir/jq-stage-b-generated-closure-candidate.exe" \
                --linker-map-candidate "$candidate_dir/jq-stage-b-generated-closure-candidate.map" \
                --skeleton-manifest "$candidate_dir/skeleton-manifest.json" \
                --candidate-provenance "$claimed_provenance" \
                --reference-contract "${stage-a-jq-fixtures-check}/generated/jq-reference-contract.json" \
                --target-name jq \
                --out "$work/validate" \
                > "$work/validate.stdout"
              validate_code=$?
              wincr stage-b-explain-delta \
                --reference-contract "${stage-a-jq-fixtures-check}/generated/jq-reference-contract.json" \
                --candidate "$candidate_dir/jq-stage-b-generated-closure-candidate.exe" \
                --linker-map-candidate "$candidate_dir/jq-stage-b-generated-closure-candidate.map" \
                --skeleton-manifest "$candidate_dir/skeleton-manifest.json" \
                --candidate-module "name=libjq-1.dll,candidate=$candidate_dir/libjq-1.dll,linker_map=$candidate_dir/libjq-1.generated-closure.link.map,skeleton_manifest=$candidate_dir/libjq-1-skeleton-manifest.json" \
                --out "$work/delta" \
                > "$work/delta.stdout"
              delta_code=$?
              set -e

              functional_report=""
              functional_code=125
              jq -n \
                --arg candidate "$candidate_dir/jq-stage-b-generated-closure-candidate.exe" \
                '{
                  format: "stage-b-candidate-crash-v1",
                  source: "contract-first-static-gate",
                  target_name: "jq",
                  original_runtime_observations: false,
                  candidate: {path: $candidate},
                  functional_report: null,
                  diagnostic_functional_report: null,
                  case_id: "",
                  status: "not_detected",
                  crash_kind: "",
                  access: "",
                  fault_address: null,
                  instruction_address: null,
                  thread: "",
                  stderr_artifact: null,
                  diagnostic_stderr_artifact: null,
                  stderr_preview: "",
                  stderr_crash_excerpt: "",
                  backtrace: [],
                  loaded_modules: [],
                  seh_exception: null,
                  repair_hints: [
                    "runtime smoke skipped because Stage A reference-contract validation is not yet clean"
                  ]
                }' > "$work/candidate-crash.json"
              printf 'skipped: Stage A reference-contract gate incomplete before runtime smoke\n' > "$work/materialized-suite.stdout"
              printf 'skipped: Stage A reference-contract gate incomplete before runtime smoke\n' > "$work/smoke-suite.stdout"
              printf 'skipped: Stage A reference-contract gate incomplete before runtime smoke\n' > "$work/full-suite.stdout"
              printf 'skipped: Stage A reference-contract gate incomplete before runtime smoke\n' > "$work/functional.stdout"
              printf 'skipped: Stage A reference-contract gate incomplete before runtime smoke\n' > "$work/candidate-crash.stdout"
              mkdir -p "$work/materialized-suite" "$work/smoke-suite" "$work/functional"

              if jq -e '
                .stage_a.gate.ran == true
                and .stage_a.gate.status == "pass"
                and .stage_a.verdict == "pass"
              ' "$work/validate/stage-b.json" >/dev/null; then
                tar -C "$work" -xf "${pkgs.jq.src}" jq-1.8.1/tests
              (
                cd "$work/jq-1.8.1"
                find tests -type f -print0 | sort -z | xargs -0 sha256sum
              ) > "$work/upstream-suite-source.txt"
              cat > "$work/cases.json" <<'JSON'
              {
                "format": "stage-b-upstream-suite-cases-v1",
                "cases": [
                  {
                    "id": "jq-upstream-run-tests-generated-closure",
                    "args": ["-L", "tests/modules", "--run-tests", "tests/jq.test"],
                    "stdin": "",
                    "cwd": "__JQ_TEST_ROOT__",
                    "expected_returncode": 0,
                    "expected_stdout_policy": "any",
                    "expected_stderr_policy": "any",
                    "timeout_seconds": 120,
                    "candidate_timeout_seconds": 120
                  }
                ]
              }
              JSON
              substituteInPlace "$work/cases.json" \
                --replace-fail "__JQ_TEST_ROOT__" "$work/jq-1.8.1"
              stage-b-functional-wincr stage-b-materialize-upstream-suite \
                --target-name jq \
                --suite-source "$work/upstream-suite-source.txt" \
                --source-revision jq-1.8.1 \
                --cases "$work/cases.json" \
                --suite-scope full \
                --out "$work/materialized-suite" \
                > "$work/materialized-suite.stdout"
              cp "$work/materialized-suite.stdout" "$work/full-suite.stdout"
              cat > "$work/smoke-cases.json" <<'JSON'
              {
                "format": "stage-b-upstream-suite-cases-v1",
                "cases": [
                  {
                    "id": "jq-smoke-version-generated-closure",
                    "args": ["--version"],
                    "stdin": "",
                    "expected_returncode": 0,
                    "expected_stdout": "jq-1.8.1\r\n",
                    "expected_stderr": "",
                    "timeout_seconds": 30,
                    "candidate_timeout_seconds": 30
                  },
                  {
                    "id": "jq-smoke-null-generated-closure",
                    "args": ["-n", "null"],
                    "stdin": "",
                    "expected_returncode": 0,
                    "expected_stdout": "null\r\n",
                    "expected_stderr": "",
                    "timeout_seconds": 30,
                    "candidate_timeout_seconds": 30
                  }
                ]
              }
              JSON
              stage-b-functional-wincr stage-b-materialize-upstream-suite \
                --target-name jq \
                --suite-source "$work/upstream-suite-source.txt" \
                --source-revision jq-1.8.1-smoke \
                --cases "$work/smoke-cases.json" \
                --suite-scope subset \
                --out "$work/smoke-suite" \
                > "$work/smoke-suite.stdout"

              export HOME="$work/home"
              export XDG_CACHE_HOME="$work/xdg-cache"
              export XDG_CONFIG_HOME="$work/xdg-config"
              export XDG_DATA_HOME="$work/xdg-data"
              export WINEPREFIX="$work/wineprefix"
              export WINEDEBUG=-all
              export WINEDLLOVERRIDES=mscoree,mshtml,winedbg.exe=
              export MESA_VK_IGNORE_CONFORMANCE_WARNING=1
              mkdir -p "$HOME" "$XDG_CACHE_HOME/fontconfig" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME"
              cat > "$work/run-jq-generated-closure-under-wine" <<EOF
              #!${pkgs.runtimeShell}
              set -eu
              pe="\$1"
              shift
              runroot="\$(mktemp -d "\''${TMPDIR:-/tmp}/stage-b-jq-generated-closure-under-wine.XXXXXX")"
              cleanup() {
                ${pkgs.coreutils}/bin/timeout --kill-after=5s 30s \
                  ${pkgs.wineWow64Packages.stable}/bin/wineserver -k >/dev/null 2>&1 || true
                rm -rf "\$runroot"
              }
              trap cleanup EXIT
              trap 'exit 143' INT TERM
              mkdir -p "\$runroot/bin"
              exe_name="\$(basename "\$pe")"
              pe_dir="\$(dirname "\$pe")"
              cp "\$pe" "\$runroot/bin/\$exe_name"
              for dll in "\$pe_dir"/*.dll "\$pe_dir"/*.DLL; do
                if test -e "\$dll"; then
                  cp "\$dll" "\$runroot/bin/"
                fi
              done
              chmod +x "\$runroot/bin/\$exe_name"
              set +e
              ${pkgs.xvfb-run}/bin/xvfb-run -a \
                ${pkgs.wineWow64Packages.stable}/bin/wine "\$runroot/bin/\$exe_name" "\$@"
              code=\$?
              set -e
              exit "\$code"
              EOF
              chmod +x "$work/run-jq-generated-closure-under-wine"
              candidate_cmd="$(jq -cn \
                --arg runner "$work/run-jq-generated-closure-under-wine" \
                --arg exe "$candidate_dir/jq-stage-b-generated-closure-candidate.exe" \
                '[$runner,$exe]')"

              set +e
              stage-b-functional-wincr stage-b-run-functional-suite \
                --suite "$work/smoke-suite/functional-suite.json" \
                --candidate-command-json "$candidate_cmd" \
                --candidate-binary "$candidate_dir/jq-stage-b-generated-closure-candidate.exe" \
                --strip-stderr-line-regex '^wine: created the configuration directory ' \
                --strip-stderr-line-regex '^XIO:  fatal IO error [0-9]+ .* on X server ":[0-9]+"$' \
                --strip-stderr-line-regex '^      after [0-9]+ requests .* with [0-9]+ events remaining\.$' \
                --strip-stderr-line-regex '^X connection to :[0-9]+ broken \(explicit kill or server shutdown\)\.$' \
                --out "$work/functional" \
                > "$work/functional.stdout"
              smoke_functional_code=$?
              set -e
              if [ "$smoke_functional_code" -eq 0 ]; then
                failed_suite="$work/materialized-suite/functional-suite.json"
                set +e
                stage-b-functional-wincr stage-b-run-functional-suite \
                  --suite "$work/materialized-suite/functional-suite.json" \
                  --candidate-command-json "$candidate_cmd" \
                  --candidate-binary "$candidate_dir/jq-stage-b-generated-closure-candidate.exe" \
                  --strip-stderr-line-regex '^wine: created the configuration directory ' \
                  --strip-stderr-line-regex '^XIO:  fatal IO error [0-9]+ .* on X server ":[0-9]+"$' \
                  --strip-stderr-line-regex '^      after [0-9]+ requests .* with [0-9]+ events remaining\.$' \
                  --strip-stderr-line-regex '^X connection to :[0-9]+ broken \(explicit kill or server shutdown\)\.$' \
                  --out "$work/functional" \
                  > "$work/functional.stdout"
                functional_code=$?
                set -e
              else
                failed_suite="$work/smoke-suite/functional-suite.json"
                printf 'skipped: jq generated-closure smoke check failed before the full upstream integration suite\n' \
                  > "$work/full-suite.stdout"
                functional_code="$smoke_functional_code"
              fi
              functional_report="$work/functional/functional-report.json"
              diagnostic_functional_report=""
              if [ "$functional_code" -ne 0 ]; then
                old_winedebug="$WINEDEBUG"
                export WINEDEBUG=+seh
                set +e
                stage-b-functional-wincr stage-b-run-functional-suite \
                  --suite "$failed_suite" \
                  --candidate-command-json "$candidate_cmd" \
                  --candidate-binary "$candidate_dir/jq-stage-b-generated-closure-candidate.exe" \
                  --strip-stderr-line-regex '^wine: created the configuration directory ' \
                  --strip-stderr-line-regex '^XIO:  fatal IO error [0-9]+ .* on X server ":[0-9]+"$' \
                  --strip-stderr-line-regex '^      after [0-9]+ requests .* with [0-9]+ events remaining\.$' \
                  --strip-stderr-line-regex '^X connection to :[0-9]+ broken \(explicit kill or server shutdown\)\.$' \
                  --out "$work/functional-seh" \
                  > "$work/functional-seh.stdout"
                seh_functional_code=$?
                set -e
                export WINEDEBUG="$old_winedebug"
                printf '%s\n' "$seh_functional_code" > "$work/functional-seh.returncode"
                if test -s "$work/functional-seh/functional-report.json"; then
                  diagnostic_functional_report="$work/functional-seh/functional-report.json"
                fi
              fi
              if test -n "$diagnostic_functional_report"; then
                diagnostic_args=(--diagnostic-functional-report "$diagnostic_functional_report")
              else
                diagnostic_args=()
              fi
              wincr stage-b-extract-candidate-crash \
                --functional-report "$functional_report" \
                "''${diagnostic_args[@]}" \
                --candidate "$candidate_dir/jq-stage-b-generated-closure-candidate.exe" \
                --target-name jq \
                --out "$work" \
                > "$work/candidate-crash.stdout"

              wincr stage-b-generate-candidate-provenance \
                --target-name jq \
                --skeleton-manifest "$candidate_dir/skeleton-manifest.json" \
                --candidate "$candidate_dir/jq-stage-b-generated-closure-candidate.exe" \
                --functional-report "$functional_report" \
                --build-target i686-w64-mingw32 \
                --build-compiler i686-w64-mingw32-cc \
                --build-output jq-stage-b-generated-closure-candidate.exe \
                --build-report "$candidate_dir/decompiled-c-generated-closure-link-report.json" \
                --target-closure-manifest "$closure_manifest" \
                --out "$work/provenance" \
                > "$work/provenance.stdout"
              claimed_provenance="$work/provenance/candidate-provenance.json"

              set +e
              wincr stage-b-validate-candidate \
                --candidate "$candidate_dir/jq-stage-b-generated-closure-candidate.exe" \
                --linker-map-candidate "$candidate_dir/jq-stage-b-generated-closure-candidate.map" \
                --skeleton-manifest "$candidate_dir/skeleton-manifest.json" \
                --candidate-provenance "$claimed_provenance" \
                --functional-report "$functional_report" \
                --reference-contract "${stage-a-jq-fixtures-check}/generated/jq-reference-contract.json" \
                --target-name jq \
                --out "$work/validate" \
                > "$work/validate.stdout"
              validate_code=$?
              wincr stage-b-explain-delta \
                --reference-contract "${stage-a-jq-fixtures-check}/generated/jq-reference-contract.json" \
                --candidate "$candidate_dir/jq-stage-b-generated-closure-candidate.exe" \
                --linker-map-candidate "$candidate_dir/jq-stage-b-generated-closure-candidate.map" \
                --skeleton-manifest "$candidate_dir/skeleton-manifest.json" \
                --candidate-module "name=libjq-1.dll,candidate=$candidate_dir/libjq-1.dll,linker_map=$candidate_dir/libjq-1.generated-closure.link.map,skeleton_manifest=$candidate_dir/libjq-1-skeleton-manifest.json" \
                --functional-report "$functional_report" \
                --candidate-crash-report "$work/candidate-crash.json" \
                --out "$work/delta" \
                > "$work/delta.stdout"
              delta_code=$?
              fi
              set -e
              test "$validate_code" -ne 0
              test "$delta_code" -ne 0
              jq -e '
                .status == "incomplete"
                and .candidate.build.report.source_dependency_policy.status == "satisfied"
                and .candidate.build.report.target_import_closure.status == "satisfied"
                and (
                  if .candidate.build.report.layout_policy == "diagnostic_fallback" then
                    .candidate.build.report.stage_a_layout_eligible == false
                    and .candidate.build.report.strict_layout_link.status == "incomplete"
                    and .candidate.build.report.diagnostic_layout_fallback.status == "used"
                    and .candidate.build.report.standalone_link_diagnostic.status == "incomplete"
                    and .candidate.build.report.standalone_link_diagnostic.repair_plan.status == "strict_layout_link_failed"
                    and ([.issues[].category] | index("standalone_build_incomplete"))
                  else
                    .candidate.build.report.layout_policy == "stage_a_strict"
                    and .candidate.build.report.stage_a_layout_eligible == true
                    and .candidate.build.report.standalone_link_diagnostic.status == "pass"
                    and ([.issues[].category] | index("standalone_build_incomplete") | not)
                  end
                )
                and ([.issues[].category] | index("target_library_linkage") | not)
                and ([.issues[].category] | index("target_import_closure_incomplete") | not)
                and .reference_contract_coverage.provided == true
                and .stage_a.gate.ran == true
                and (
                  if .functional == null then
                    .functional_report == null
                    and .functional_diagnostics.status == "not_provided"
                    and .stage_a.gate.status != "pass"
                  else
                    .functional.oracle.original_runtime_observations == false
                    and (.functional.commands | has("original") | not)
                    and (.functional.binary_bindings | has("original") | not)
                  end
                )
              ' "$work/validate/stage-b.json" >/dev/null
              jq -e '
                .format == "stage-b-delta-explanation-v1"
                and .status == "incomplete"
                and .counts.repair_items > 0
                and (.candidate_modules | length) == 1
                and (
                  if .candidate_crash_report == null then
                    .functional_report == null
                    and .functional_diagnostics.status == "not_provided"
                    and ([.repair_items[].violated_contract_family] | index("candidate_crash") | not)
                  else
                    (
                      if (.candidate_crash_report.status // "not_detected") == "detected" then
                        ([.repair_items[].violated_contract_family] | index("candidate_crash"))
                        and (.candidate_crash_report.has_seh_exception == true)
                        and (
                          ([.repair_items[].likely_repair_class] | index("candidate_crash_register_context"))
                          or ([.repair_items[].likely_repair_class] | index("candidate_crash_fault_address_context"))
                          or ([.repair_items[].likely_repair_class] | index("runtime_crt_tls_callback_context"))
                        )
                        and (
                          ([.repair_items[].likely_repair_class] | index("stack_probe_or_frame_layout"))
                          or ([.repair_items[].likely_repair_class] | index("stack_scratch_buffer_or_out_param"))
                          or ([.repair_items[].likely_repair_class] | index("runtime_crt_stack_bridge"))
                          or ([.repair_items[].likely_repair_class] | index("candidate_crash_fault_address_context"))
                        )
                      else
                        ([.repair_items[].violated_contract_family] | index("candidate_crash") | not)
                        and (
                          if (.functional_diagnostics.status // "") == "fail" then
                            ([.repair_items[].violated_contract_family] | index("functional_expected_output"))
                          else
                            true
                          end
                        )
                      end
                    )
                  end
                )
              ' "$work/delta/stage-b-delta.json" >/dev/null

              mkdir -p "$out"
              cp "$candidate_dir/jq-stage-b-generated-closure-candidate.exe" "$out/"
              cp "$candidate_dir/jq-stage-b-generated-closure-candidate.map" "$out/"
              cp "$candidate_dir/libjq-1.dll" "$out/"
              cp "$candidate_dir/decompiled-c-generated-closure-link-report.json" "$out/"
              cp "$candidate_dir/decompiled-c-link-roots.json" "$out/"
              cp -R "$candidate_dir/src" "$out/src"
              cp "$candidate_dir/candidate-provenance.json" "$out/initial-candidate-provenance.json"
              cp "$claimed_provenance" "$out/candidate-provenance.json"
              if test -n "$functional_report"; then
                cp "$functional_report" "$out/functional-report.json"
              fi
              cp "$work/validate/stage-b.json" "$out/stage-b.json"
              cp "$work/delta/stage-b-delta.json" "$out/stage-b-delta.json"
              cp "$work/candidate-crash.json" "$out/candidate-crash.json"
              cp "$work/materialized-suite.stdout" \
                "$work/smoke-suite.stdout" \
                "$work/full-suite.stdout" \
                "$work/functional.stdout" \
                "$work/provenance.stdout" \
                "$work/validate.stdout" \
                "$work/delta.stdout" \
                "$out/"
              cp -R "$work/materialized-suite" "$out/materialized-suite"
              cp -R "$work/smoke-suite" "$out/smoke-suite"
              cp -R "$work/functional" "$out/functional"
              cp -R "$work/provenance" "$out/provenance"
              cp -R "$work/validate" "$out/validate"
              cp -R "$work/delta" "$out/delta"
              cp -R "$candidate_dir/smoke" "$out/smoke"
              printf '%s\n' "$functional_code" > "$out/functional.returncode"
              printf '%s\n' "$validate_code" > "$out/validate.returncode"
              printf '%s\n' "$delta_code" > "$out/delta.returncode"
            '';

          stage-b-ripgrep-toolchain-diagnostic = pkgs.runCommand "stage-b-ripgrep-toolchain-diagnostic"
            {
              nativeBuildInputs = [
                pkgs.jq
              ];
            }
            ''
              out_dir="$out/share/wincr/stage-b/ripgrep"
              mkdir -p "$out_dir"
              jq -n \
                --arg model "x86-pe32-env-v1" \
                --arg attr "pkgs.pkgsCross.mingw32.ripgrep" \
                --arg required_target "i686-pc-windows-gnu" \
                '{
                  format: "stage-b-ripgrep-i686-toolchain-diagnostic-v1",
                  status: "blocked_i686",
                  model: $model,
                  required_target: $required_target,
                  nix_attr: $attr,
                  blocker: "current Nix cross Rust toolchain fails while linking i686-pc-windows-gnu std with unresolved _Unwind_* symbols before ripgrep builds",
                  next_action: "use the x86_64 PE32+ ripgrep Stage B path for current skeleton work, or fix the i686 Windows Rust cross toolchain before adding a PE32 ripgrep validation check"
                }' > "$out_dir/status.json"
            '';

          stage-b-ripgrep-toolchain-diagnostic-root = pkgs.writeShellApplication {
            name = "stage-b-ripgrep-toolchain-diagnostic-root";
            text = ''
              printf '%s\n' "${stage-b-ripgrep-toolchain-diagnostic}"
            '';
          };

          stage-b-ripgrep-x64-original = (mingwW64.ripgrep.override { withPCRE2 = false; }).overrideAttrs (old: {
            pname = "stage-b-ripgrep-x64-original";
            doCheck = false;
            doInstallCheck = false;
            installCheckPhase = "";
            postFixup = "";
            postInstall =
              (old.postInstall or "")
              + ''
                mkdir -p "$out/share/wincr/stage-b/ripgrep/original"
                cp "$out/bin/rg.exe" "$out/share/wincr/stage-b/ripgrep/original/rg.exe"
              '';
          });

          stage-b-ripgrep-reference-contract = pkgs.runCommand "stage-b-ripgrep-reference-contract"
            {
              nativeBuildInputs = [
                haloce-tools
                pkgs.jq
              ];
            }
            ''
              original="${stage-b-ripgrep-x64-original}/share/wincr/stage-b/ripgrep/original/rg.exe"
              out_dir="$out/share/wincr/stage-b/ripgrep/reference-contract"
              mkdir -p "$out_dir"
              set +e
              wincr stage-a-export-reference-contract \
                --original "$original" \
                --model x86_64-pe32plus-env-v1 \
                --out "$out_dir/ripgrep-reference-contract.json" \
                > "$out_dir/export.stdout"
              code=$?
              set -e
              test "$code" -ne 0
              jq -e '
                .format == "stage-a-reference-contract-v1"
                and .model == "x86_64-pe32plus-env-v1"
                and .status == "incomplete"
                and .candidate == null
                and .constraints.pe_sections_imports_relocations_image_base.status == "derived"
                and .constraints.validation_report_artifact_binding.status == "not_provided"
                and .constraints.proof_obligation_inventory.status == "not_provided"
                and .original.machine == "x86_64"
                and .original.bitness == 64
              ' "$out_dir/ripgrep-reference-contract.json" >/dev/null
            '';

          stage-b-ripgrep-integration-harness = ((mingwW64.ripgrep.override { withPCRE2 = false; }).overrideAttrs (old: {
            pname = "stage-b-ripgrep-integration-harness";
            doCheck = false;
            doInstallCheck = false;
            postFixup = "";
            cargoBuildFlags = (old.cargoBuildFlags or [ ]) ++ [
              "--test"
              "integration"
            ];
            installPhase = ''
              runHook preInstall
              test_bin="$(find target/x86_64-pc-windows-gnu/release/deps -maxdepth 1 -type f -name 'integration-*.exe' -print -quit)"
              if [ -z "$test_bin" ]; then
                echo "missing Windows ripgrep integration test binary" >&2
                find target -maxdepth 5 -type f -name 'integration*' -print >&2 || true
                exit 1
              fi
              mkdir -p "$out/bin" "$out/share/wincr/stage-b/ripgrep/upstream-integration"
              cp "$test_bin" "$out/bin/ripgrep-integration.exe"
              (
                find tests -type f -print0 | sort -z | xargs -0 sha256sum
                sha256sum Cargo.toml Cargo.lock
              ) > "$out/share/wincr/stage-b/ripgrep/upstream-integration/source-manifest.sha256"
              cp tests/tests.rs tests/macros.rs tests/util.rs "$out/share/wincr/stage-b/ripgrep/upstream-integration/"
              runHook postInstall
            '';
          }));

          stage-b-ripgrep-skeleton = pkgs.runCommand "stage-b-ripgrep-skeleton"
            {
              nativeBuildInputs = [
                stage-b-skeleton-tools
              ];
            }
            ''
              skeleton_dir="$out/share/wincr/stage-b/ripgrep/skeleton"
              stage-b-skeleton-wincr stage-b-generate-skeleton \
                --original "${stage-b-ripgrep-x64-original}/share/wincr/stage-b/ripgrep/original/rg.exe" \
                --target-name ripgrep \
                --source-language rust \
                --out-dir "$skeleton_dir"
            '';

          stage-b-ripgrep-skeleton-root = pkgs.writeShellApplication {
            name = "stage-b-ripgrep-skeleton-root";
            text = ''
              printf '%s\n' "${stage-b-ripgrep-skeleton}"
            '';
          };

          stage-b-ripgrep-skeleton-check = pkgs.runCommand "stage-b-ripgrep-skeleton-check"
            {
              nativeBuildInputs = [
                pkgs.jq
              ];
            }
            ''
              skeleton_dir="${stage-b-ripgrep-skeleton}/share/wincr/stage-b/ripgrep/skeleton"
              jq -e '
                .format == "stage-b-skeleton-v1"
                and .status == "generated"
                and .target_name == "ripgrep"
                and .original.machine == "x86_64"
                and .original.bitness == 64
                and (.source_policy.allowed_inputs | index("pe32plus-original"))
                and .implementation_mode == "scaffold"
                and .implementation_recovery.generated_source_kind == "scaffold"
                and .implementation_recovery.source_implements_behavior == false
                and .completion.stage_a_validated == false
              ' "$skeleton_dir/manifest.json" >/dev/null
              mkdir -p "$out"
              cp "$skeleton_dir/manifest.json" "$skeleton_dir/functions.json" "$out/"
            '';

          stage-b-ripgrep-skeleton-candidate = pkgs.runCommand "stage-b-ripgrep-skeleton-candidate"
            {
              nativeBuildInputs = [
                stage-b-provenance-tools
                mingwW64.rustc
                mingwW64.stdenv.cc
              ];
            }
            ''
              skeleton_dir="${stage-b-ripgrep-skeleton}/share/wincr/stage-b/ripgrep/skeleton"
              source="$skeleton_dir/src/ripgrep_stage_b_skeleton.rs"
              out_dir="$out/share/wincr/stage-b/ripgrep/candidate"
              mkdir -p "$out_dir"
              rustc --target x86_64-pc-windows-gnu -C panic=abort \
                -L native=${mingwW64Pthreads}/lib \
                -o "$out_dir/rg-stage-b-skeleton-candidate.exe" "$source"
              printf 'stage-b skeleton candidate map is unavailable until final Stage A validation is attempted\n' \
                > "$out_dir/rg-stage-b-skeleton-candidate.map"
              cp "$skeleton_dir/manifest.json" "$out_dir/skeleton-manifest.json"
              stage-b-provenance-wincr stage-b-generate-candidate-provenance \
                --target-name ripgrep \
                --skeleton-manifest "$out_dir/skeleton-manifest.json" \
                --candidate "$out_dir/rg-stage-b-skeleton-candidate.exe" \
                --build-target x86_64-pc-windows-gnu \
                --build-compiler rustc \
                --build-output rg-stage-b-skeleton-candidate.exe \
                --out "$out_dir" \
                > "$out_dir/candidate-provenance.stdout"
            '';

          stage-b-ripgrep-skeleton-candidate-check = pkgs.runCommand "stage-b-ripgrep-skeleton-candidate-check"
            {
              nativeBuildInputs = [
                haloce-tools
                pkgs.jq
                pkgs.lean4
                stage-b-skeleton-tools
              ];
            }
            ''
              original_dir="${stage-b-ripgrep-x64-original}/share/wincr/stage-b/ripgrep/original"
              candidate_dir="${stage-b-ripgrep-skeleton-candidate}/share/wincr/stage-b/ripgrep/candidate"
              work="$TMPDIR/stage-b-ripgrep-candidate"
              mkdir -p "$work"
              test -s "${stage-b-smoke-check}/functional-report.json"
              printf 'stage-b pre-validation placeholder\n' > "$work/original-placeholder.map"
              stage-b-skeleton-wincr stage-b-generate-skeleton \
                --original "$candidate_dir/rg-stage-b-skeleton-candidate.exe" \
                --target-name ripgrep-candidate-smoke \
                --source-language rust \
                --out-dir "$work/parse"
              functional_report=""
              functional_code=125
              mkdir -p "$work/materialized-suite" "$work/smoke-suite" "$work/smoke-functional" "$work/functional"
              jq -n \
                --arg candidate "$candidate_dir/rg-stage-b-skeleton-candidate.exe" \
                '{
                  format: "stage-b-runtime-smoke-v1",
                  status: "skipped",
                  returncode: 125,
                  runner: "not_run",
                  candidate: {path: $candidate},
                  original_runtime_observations: false,
                  blockers: [
                    "runtime smoke is deferred until Stage A reference-contract validation is clean"
                  ]
                }' > "$work/smoke-functional/report.json"
              printf 'skipped: Stage A reference-contract gate incomplete before runtime smoke\n' > "$work/materialized-suite.stdout"
              printf 'skipped: Stage A reference-contract gate incomplete before runtime smoke\n' > "$work/smoke-suite.stdout"
              printf 'skipped: Stage A reference-contract gate incomplete before runtime smoke\n' > "$work/smoke-functional.stdout"
              printf 'skipped: Stage A reference-contract gate incomplete before runtime smoke\n' > "$work/full-suite.stdout"
              printf 'skipped: Stage A reference-contract gate incomplete before runtime smoke\n' > "$work/functional.stdout"
              wincr stage-b-generate-candidate-provenance \
                --target-name ripgrep \
                --skeleton-manifest "$candidate_dir/skeleton-manifest.json" \
                --candidate "$candidate_dir/rg-stage-b-skeleton-candidate.exe" \
                --build-target x86_64-pc-windows-gnu \
                --build-compiler rustc \
                --build-output rg-stage-b-skeleton-candidate.exe \
                --out "$work/provenance" \
                > "$work/provenance.stdout"
              claimed_provenance="$work/provenance/candidate-provenance.json"
              set +e
              wincr stage-b-validate-candidate \
                --candidate "$candidate_dir/rg-stage-b-skeleton-candidate.exe" \
                --linker-map-candidate "$candidate_dir/rg-stage-b-skeleton-candidate.map" \
                --skeleton-manifest "$candidate_dir/skeleton-manifest.json" \
                --candidate-provenance "$claimed_provenance" \
                --reference-contract "${stage-b-ripgrep-reference-contract}/share/wincr/stage-b/ripgrep/reference-contract/ripgrep-reference-contract.json" \
                --target-name ripgrep \
                --model x86_64-pe32plus-env-v1 \
                --out "$work/validate" \
                > "$work/validate.stdout"
              code=$?
              wincr stage-b-explain-delta \
                --reference-contract "${stage-b-ripgrep-reference-contract}/share/wincr/stage-b/ripgrep/reference-contract/ripgrep-reference-contract.json" \
                --candidate "$candidate_dir/rg-stage-b-skeleton-candidate.exe" \
                --linker-map-candidate "$candidate_dir/rg-stage-b-skeleton-candidate.map" \
                --skeleton-manifest "$candidate_dir/skeleton-manifest.json" \
                --model x86_64-pe32plus-env-v1 \
                --out "$work/delta" \
                > "$work/delta.stdout"
              delta_code=$?
              set -e
              test "$code" -ne 0
              test "$delta_code" -ne 0
              jq -e '
                .status == "incomplete"
                and .provenance_status == "incomplete"
                and .functional == null
                and .functional_report == null
                and .functional_diagnostics.status == "not_provided"
                and ([.issues[].category] | index("missing_functional_tests"))
                and ([.issues[].category] | index("functional_tests_not_passing"))
                and ([.issues[].category] | index("missing_functional_test_suites"))
                and ([.issues[].category] | index("missing_required_functional_suite"))
                and ([.issues[].category] | index("functional_test_failure") | not)
                and ([.issues[].category] | index("functional_test_report_failed") | not)
                and ([.issues[].category] | index("functional_test_report_incomplete_coverage_scope") | not)
                and ([.issues[].category] | index("functional_test_report_wrong_suite_id") | not)
                and ([.issues[].category] | index("functional_test_report_wrong_source_kind") | not)
                and ([.issues[].category] | index("functional_test_report_wrong_materializer") | not)
                and ([.issues[].category] | index("functional_binary_command_not_bound") | not)
                and ([.issues[].category] | index("functional_test_report_original_baseline_failed") | not)
                and .stage_a.gate.status == "incomplete"
                and .stage_a.gate.reason == "stage_a_validation_incomplete"
                and .stage_a.gate.eligible == true
                and .stage_a.gate.ran == true
                and .stage_a.gate.behavioral_mismatch_blocks_stage_a == false
                and .stage_a.gate.behavioral_blocking_issue_categories == []
                and .stage_a.gate.iteration_policy == "stage_a_contract_first"
                and .stage_a.gate.runtime_validation_policy == "candidate_only_after_stage_a_pass"
                and ([.stage_a.gate.non_blocking_issue_categories[]] | index("missing_functional_tests"))
                and .reference_contract_coverage.provided == true
                and .reference_contract_coverage.status == "incomplete"
                and .reference_contract_coverage.contract_status == "incomplete"
                and ([.reference_contract_coverage.families[] | select(.family == "pe_sections_imports_relocations_image_base").status][0] == "incomplete")
                and ([.reference_contract_coverage.families[] | select(.family == "pe_sections_imports_relocations_image_base").stage_b_status][0] == "represented")
                and ([.reference_contract_coverage.families[] | select(.family == "validation_report_artifact_binding").status][0] == "incomplete")
              ' "$work/validate/stage-b.json" >/dev/null
              jq -e '
                .format == "stage-b-delta-explanation-v1"
                and .status == "incomplete"
                and .functional_report == null
                and .functional_diagnostics.status == "not_provided"
                and .counts.repair_items > 0
                and ([.repair_items[].violated_contract_family] | index("functional_expected_output") | not)
              ' "$work/delta/stage-b-delta.json" >/dev/null
              mkdir -p "$out"
              cp "$candidate_dir/rg-stage-b-skeleton-candidate.exe" \
                "$candidate_dir/rg-stage-b-skeleton-candidate.map" \
                "$claimed_provenance" \
                "$work/validate/stage-b.json" \
                "$work/delta/stage-b-delta.json" \
                "$out/"
              cp "$work/materialized-suite.stdout" \
                "$work/functional.stdout" \
                "$work/provenance.stdout" \
                "$work/validate.stdout" \
                "$work/delta.stdout" \
                "$work/smoke-suite.stdout" \
                "$work/smoke-functional.stdout" \
                "$work/full-suite.stdout" \
                "$out/"
              cp -R "$work/materialized-suite" "$out/materialized-suite"
              cp -R "$work/functional" "$out/functional"
              cp -R "$work/provenance" "$out/provenance"
              cp -R "$work/validate" "$out/validate"
              cp -R "$work/delta" "$out/delta"
              cp -R "$work/smoke-suite" "$out/smoke-suite"
              cp -R "$work/smoke-functional" "$out/smoke-functional"
              printf '%s\n' "$functional_code" > "$out/functional.returncode"
              printf '%s\n' "$delta_code" > "$out/delta.returncode"
            '';

          stage-b-functional-runner-check = pkgs.runCommand "stage-b-functional-runner-check"
            {
              nativeBuildInputs = [
                stage-b-functional-tools
                pkgs.jq
                pkgs.python3
              ];
            }
            ''
              work="$TMPDIR/stage-b-functional"
              mkdir -p "$work"
              cat > "$work/candidate.py" <<'PY'
              import sys
              print("argv=" + ",".join(sys.argv[1:]))
              print("stdin=" + sys.stdin.read())
              PY
              printf '%s\n' 'jq upstream integration suite runner fixture' > "$work/upstream-suite-source.txt"
              cat > "$work/cases.json" <<'JSON'
              {
                "format": "stage-b-upstream-suite-cases-v1",
                "cases": [
                  {
                    "id": "stdin-argv",
                    "args": ["-n", "."],
                    "stdin": "{\"a\":1}",
                    "expected_returncode": 0,
                    "expected_stdout": "argv=-n,.\nstdin={\"a\":1}\n",
                    "expected_stderr": ""
                  }
                ]
              }
              JSON
              stage-b-functional-wincr stage-b-materialize-upstream-suite \
                --target-name jq \
                --suite-source "$work/upstream-suite-source.txt" \
                --source-revision fixture \
                --cases "$work/cases.json" \
                --out "$work/materialized-suite" \
                > "$work/materialized-suite.stdout"
              candidate_cmd="$(jq -cn --arg python "${pkgs.python3}/bin/python3" --arg script "$work/candidate.py" '[$python,$script]')"
              stage-b-functional-wincr stage-b-run-functional-suite \
                --suite "$work/materialized-suite/functional-suite.json" \
                --candidate-command-json "$candidate_cmd" \
                --candidate-binary "$work/candidate.py" \
                --out "$work/report"
              jq -e \
                --arg candidate_hash "$(sha256sum "$work/candidate.py" | cut -d' ' -f1)" \
                --arg source_hash "$(sha256sum "$work/upstream-suite-source.txt" | cut -d' ' -f1)" \
                '
                .format == "stage-b-functional-report-v1"
                and .runner.name == "stage-b-run-functional-suite"
                and .status == "pass"
                and .target_name == "jq"
                and (.suite_sha256 | type == "string" and length == 64)
                and (.suite_case_manifest_sha256 | type == "string" and length == 64)
                and .suite_id == "jq-upstream-integration-tests"
                and .suite_kind == "upstream_integration"
                and .upstream_suite == true
                and .coverage.suite_sha256 == .suite_sha256
                and .coverage.suite_case_manifest_sha256 == .suite_case_manifest_sha256
                and .coverage.suite_scope == "full"
                and .coverage.source_kind == "upstream_integration_suite"
                and .coverage.source_sha256 == ($source_hash)
                and .coverage.source_revision == "fixture"
                and .coverage.materialized_by == "stage-b-materialize-upstream-suite"
                and .coverage.required_suite_ids == ["jq-upstream-integration-tests"]
                and .coverage.case_ids == ["stdin-argv"]
                and (.coverage.case_ids_sha256 | type == "string" and length == 64)
                and .binary_bindings.candidate.sha256 == ($candidate_hash)
                and .binary_bindings.candidate.command_contains_path == true
                and .oracle.original_runtime_observations == false
                and (.commands | has("original") | not)
                and (.binary_bindings | has("original") | not)
                and (.case_manifest | length == 1)
                and .case_manifest[0].id == "stdin-argv"
                and (.case_manifest[0].env_sha256 | type == "string" and length == 64)
                and .counts == {"cases":1,"passed":1,"failed":0}
              ' "$work/report/functional-report.json" >/dev/null
              jq -e \
                --arg source_hash "$(sha256sum "$work/upstream-suite-source.txt" | cut -d' ' -f1)" \
                '
                .format == "stage-b-functional-suite-v1"
                and .materializer.name == "stage-b-materialize-upstream-suite"
                and .materializer.source_sha256 == ($source_hash)
                and .coverage.source_sha256 == ($source_hash)
              ' "$work/materialized-suite/functional-suite.json" >/dev/null
              mkdir -p "$out"
              cp "$work/report/functional-report.json" "$out/"
            '';

          stage-b-readiness-audit-check = pkgs.runCommand "stage-b-readiness-audit-check"
            {
              nativeBuildInputs = [
                haloce-tools
                pkgs.jq
              ];
            }
            ''
              work="$TMPDIR/stage-b-readiness"
              mkdir -p "$work"
              set +e
              wincr stage-b-audit-readiness \
                --report "jq=${stage-b-jq-contract-iteration-check}/stage-b.json" \
                --report "ripgrep=${stage-b-ripgrep-skeleton-candidate-check}/stage-b.json" \
                --out "$work/audit" \
                > "$work/audit.stdout"
              code=$?
              set -e
              test "$code" -ne 0
              jq -e '
                .format == "stage-b-readiness-audit-v1"
                and .status == "incomplete"
                and .counts == {"targets":2,"ready":0,"incomplete":2}
                and .targets.jq.status == "incomplete"
                and .targets.ripgrep.status == "incomplete"
                and ([.targets.jq.requirements[] | select(.id == "generated_skeleton_source_root").status][0] == "satisfied")
                and ([.targets.ripgrep.requirements[] | select(.id == "generated_skeleton_source_root").status][0] == "satisfied")
                and ([.targets.jq.requirements[] | select(.id == "generated_behavior_source").status][0] == "incomplete")
                and ([.targets.ripgrep.requirements[] | select(.id == "generated_behavior_source").status][0] == "incomplete")
                and ([.targets.jq.requirements[] | select(.id == "same_architecture_same_os").status][0] == "satisfied")
                and ([.targets.ripgrep.requirements[] | select(.id == "same_architecture_same_os").status][0] == "satisfied")
                and ([.targets.jq.requirements[] | select(.id == "functional_binary_bindings").status][0] == "incomplete")
                and ([.targets.ripgrep.requirements[] | select(.id == "functional_binary_bindings").status][0] == "incomplete")
                and ([.targets.jq.requirements[] | select(.id == "canonical_upstream_functional_suite").status][0] == "incomplete")
                and ([.targets.jq.requirements[] | select(.id == "canonical_upstream_functional_suite").evidence.status][0] == null)
                and ([.targets.jq.requirements[] | select(.id == "no_upstream_source_dependency").status][0] == "satisfied")
                and ([.targets.jq.requirements[] | select(.id == "no_upstream_source_dependency").evidence.status][0] == "satisfied")
                and ([.targets.jq.requirements[] | select(.id == "no_upstream_source_dependency").evidence.target_import_closure.status][0] == "satisfied")
                and ([.targets.jq.requirements[] | select(.id == "stage_a_final_pass").status][0] == "incomplete")
                and ([.targets.jq.requirements[] | select(.id == "stage_a_final_pass").evidence.gate.reason][0] == "stage_a_validation_incomplete")
                and ([.targets.jq.requirements[] | select(.id == "stage_a_final_pass").evidence.gate.behavioral_mismatch_blocks_stage_a][0] == false)
                and ([.targets.jq.requirements[] | select(.id == "stage_a_final_pass").evidence.gate.iteration_policy][0] == "stage_a_contract_first")
                and ([.targets.jq.requirements[] | select(.id == "stage_a_final_pass").evidence.gate.runtime_validation_policy][0] == "candidate_only_after_stage_a_pass")
                and ([.targets.jq.requirements[] | select(.id == "stage_a_final_pass").evidence.gate.ran][0] == true)
                and ([.targets.jq.requirements[] | select(.id == "stage_a_reference_contract_coverage").status][0] == "incomplete")
                and ([.targets.jq.requirements[] | select(.id == "stage_a_reference_contract_coverage").evidence.provided][0] == true)
                and ([.targets.jq.requirements[] | select(.id == "stage_a_reference_contract_coverage").evidence.family_statuses.validation_report_artifact_binding][0] == "satisfied")
                and ([.targets.ripgrep.requirements[] | select(.id == "canonical_upstream_functional_suite").status][0] == "incomplete")
                and ([.targets.ripgrep.requirements[] | select(.id == "stage_a_final_pass").status][0] == "incomplete")
                and ([.targets.ripgrep.requirements[] | select(.id == "stage_a_final_pass").evidence.gate.reason][0] == "stage_a_validation_incomplete")
                and ([.targets.ripgrep.requirements[] | select(.id == "stage_a_final_pass").evidence.gate.behavioral_mismatch_blocks_stage_a][0] == false)
                and ([.targets.ripgrep.requirements[] | select(.id == "stage_a_final_pass").evidence.gate.iteration_policy][0] == "stage_a_contract_first")
                and ([.targets.ripgrep.requirements[] | select(.id == "stage_a_final_pass").evidence.gate.runtime_validation_policy][0] == "candidate_only_after_stage_a_pass")
                and ([.targets.ripgrep.requirements[] | select(.id == "stage_a_final_pass").evidence.gate.ran][0] == true)
                and ([.targets.ripgrep.requirements[] | select(.id == "stage_a_reference_contract_coverage").status][0] == "incomplete")
                and ([.targets.ripgrep.requirements[] | select(.id == "stage_a_reference_contract_coverage").evidence.provided][0] == true)
                and ([.targets.ripgrep.requirements[] | select(.id == "stage_a_reference_contract_coverage").evidence.family_statuses.pe_sections_imports_relocations_image_base][0] == "incomplete")
                and ([.targets.ripgrep.requirements[] | select(.id == "stage_a_reference_contract_coverage").evidence.stage_b_statuses.pe_sections_imports_relocations_image_base][0] == "represented")
                and ([.targets.ripgrep.requirements[] | select(.id == "stage_a_reference_contract_coverage").evidence.family_statuses.validation_report_artifact_binding][0] == "incomplete")
              ' "$work/audit/stage-b-readiness.json" >/dev/null
              mkdir -p "$out"
              cp "$work/audit/stage-b-readiness.json" "$work/audit.stdout" "$out/"
            '';

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
                ${dynamorio-windows}/ext/lib32/release/drwrap.lib \
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
                echo "usage: halo-trace-run --out trace.jsonl --test-id TEST [--arch auto|32|64] [--block-state-trace] [--block-state-max-records N] -- app [args...]" >&2
              }

              out=""
              test_id=""
              arch="auto"
              semantic_profile=0
              semantic_max_records=128
              block_state_trace=0
              block_state_max_records=8192
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
                  --block-state-trace)
                    block_state_trace=1
                    shift
                    ;;
                  --block-state-max-records)
                    block_state_max_records="''${2:-8192}"
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
              case "$block_state_trace" in
                1|true|yes|on) client_args+=(-block_state_trace -block_state_max_records "$block_state_max_records") ;;
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
                echo "usage: halo-trace-run-i386-late --out trace.jsonl --test-id TEST [--follow-children] [--block-state-trace] [--block-state-max-records N] -- app [args...]" >&2
              }

              out=""
              test_id=""
              follow_children="''${HALOCE_TRACE_FOLLOW_CHILDREN:-0}"
              semantic_profile=0
              semantic_max_records=128
              block_state_trace=0
              block_state_max_records=8192
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
                  --block-state-trace)
                    block_state_trace=1
                    shift
                    ;;
                  --block-state-max-records)
                    block_state_max_records="''${2:-8192}"
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
              case "$block_state_trace" in
                1|true|yes|on) client_args+=(-block_state_trace -block_state_max_records "$block_state_max_records") ;;
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
                echo "usage: halo-trace-run-dr8-i386-late --out trace.jsonl --test-id TEST [--block-state-trace] [--block-state-max-records N] -- app [args...]" >&2
              }

              out=""
              test_id=""
              semantic_profile=0
              semantic_max_records=128
              block_state_trace=0
              block_state_max_records=8192
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
                  --block-state-trace)
                    block_state_trace=1
                    shift
                    ;;
                  --block-state-max-records)
                    block_state_max_records="''${2:-8192}"
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
              case "$block_state_trace" in
                1|true|yes|on) client_args+=(-block_state_trace -block_state_max_records "$block_state_max_records") ;;
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
              block_state_trace="''${WINCR_3D_REFERENCE_BLOCK_STATE_TRACE:-1}"
              block_state_max_records="''${WINCR_3D_REFERENCE_BLOCK_STATE_MAX_RECORDS:-250000}"
              block_state_scope="''${WINCR_3D_REFERENCE_BLOCK_STATE_SCOPE:-representative}"
              trace_timeout_seconds="''${WINCR_3D_REFERENCE_TRACE_TIMEOUT_SECONDS:-120}"
              block_state_trace_args=()
              coverage_trace_args=()
              case "$block_state_trace" in
                1|true|TRUE|yes|YES|on|ON)
                  block_state_trace_args=(--block-state-trace --block-state-max-records "$block_state_max_records")
                  case "$block_state_scope" in
                    all|ALL)
                      coverage_trace_args=("''${block_state_trace_args[@]}")
                      trace_timeout_seconds="''${WINCR_3D_REFERENCE_BLOCK_STATE_TIMEOUT_SECONDS:-240}"
                      ;;
                    representative|REPRESENTATIVE|first|FIRST|"")
                      ;;
                    *)
                      echo "unsupported WINCR_3D_REFERENCE_BLOCK_STATE_SCOPE: $block_state_scope" >&2
                      exit 2
                      ;;
                  esac
                  ;;
              esac

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
                  --timeout-seconds "$trace_timeout_seconds" \
                  --fail-on-timeout \
                  --semantic-profile \
                  --semantic-max-records 256 \
                  "''${block_state_trace_args[@]}" \
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
                  --timeout-seconds "$trace_timeout_seconds" \
                  --fail-on-timeout \
                  "''${coverage_trace_args[@]}" \
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
                  --timeout-seconds "$trace_timeout_seconds" \
                  --fail-on-timeout \
                  "''${coverage_trace_args[@]}" \
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
                  --timeout-seconds "$trace_timeout_seconds" \
                  --fail-on-timeout \
                  "''${coverage_trace_args[@]}" \
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
                  --timeout-seconds "$trace_timeout_seconds" \
                  --fail-on-timeout \
                  "''${coverage_trace_args[@]}" \
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
                  --timeout-seconds "$trace_timeout_seconds" \
                  --fail-on-timeout \
                  "''${coverage_trace_args[@]}" \
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
                  --timeout-seconds "$trace_timeout_seconds" \
                  --fail-on-timeout \
                  "''${coverage_trace_args[@]}" \
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
                  --timeout-seconds "$trace_timeout_seconds" \
                  --fail-on-timeout \
                  "''${coverage_trace_args[@]}" \
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
                  --timeout-seconds "$trace_timeout_seconds" \
                  --fail-on-timeout \
                  "''${coverage_trace_args[@]}" \
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
                  --timeout-seconds "$trace_timeout_seconds" \
                  --fail-on-timeout \
                  "''${coverage_trace_args[@]}" \
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
                  --timeout-seconds "$trace_timeout_seconds" \
                  --fail-on-timeout \
                  "''${coverage_trace_args[@]}" \
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
                    --timeout-seconds "$trace_timeout_seconds" \
                    --fail-on-timeout \
                    "''${coverage_trace_args[@]}" \
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
                  --timeout-seconds "$trace_timeout_seconds" \
                  --fail-on-timeout \
                  "''${coverage_trace_args[@]}" \
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
                  --timeout-seconds "$trace_timeout_seconds" \
                  --fail-on-timeout \
                  "''${coverage_trace_args[@]}" \
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
                  --timeout-seconds "$trace_timeout_seconds" \
                  --fail-on-timeout \
                  "''${coverage_trace_args[@]}" \
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

                wincr validate-dirty-corpus \
                  --corpus-dir "$private_artifact_dir" \
                  --report-json "$report_dir/dirty-corpus-validation.json" \
                  --report-md "$report_dir/dirty-corpus-validation.md" \
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
              stage-a-fixtures
              stage-a-fixtures-check
              stage-a-fixtures-root
              stage-a-jq-fixtures
              stage-a-jq-fixtures-check
              stage-a-jq-fixtures-root
              stage-b-jq-decompiler-export
              stage-b-jq-libjq-decompiler-export
              stage-b-jq-libjq-decompiled-c-skeleton
              stage-b-jq-decompiled-c-skeleton
              stage-b-jq-program-slice-skeleton
              stage-b-jq-skeleton
              stage-b-jq-skeleton-check
              stage-b-jq-skeleton-candidate
              stage-b-jq-skeleton-candidate-check
              stage-b-jq-target-closure-skeleton
              stage-b-jq-generated-closure-candidate
              stage-b-jq-contract-iteration-check
              stage-b-jq-generated-closure-candidate-check
              stage-b-jq-skeleton-root
              stage-b-ripgrep-toolchain-diagnostic
              stage-b-ripgrep-toolchain-diagnostic-root
              stage-b-ripgrep-x64-original
              stage-b-ripgrep-reference-contract
              stage-b-ripgrep-integration-harness
              stage-b-ripgrep-skeleton
              stage-b-ripgrep-skeleton-check
              stage-b-ripgrep-skeleton-candidate
              stage-b-ripgrep-skeleton-candidate-check
              stage-b-ripgrep-skeleton-root
              stage-b-skeleton-tools
              stage-b-provenance-tools
              stage-b-functional-tools
              stage-b-smoke-check
              stage-b-functional-runner-check
              stage-b-readiness-audit-check
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

            stage-a-fixtures-root = {
              type = "app";
              program = "${stage-a-fixtures-root}/bin/stage-a-fixtures-root";
            };

            stage-a-jq-fixtures-root = {
              type = "app";
              program = "${stage-a-jq-fixtures-root}/bin/stage-a-jq-fixtures-root";
            };

            stage-b-jq-skeleton-root = {
              type = "app";
              program = "${stage-b-jq-skeleton-root}/bin/stage-b-jq-skeleton-root";
            };

            stage-b-ripgrep-toolchain-diagnostic-root = {
              type = "app";
              program = "${stage-b-ripgrep-toolchain-diagnostic-root}/bin/stage-b-ripgrep-toolchain-diagnostic-root";
            };

            stage-b-ripgrep-skeleton-root = {
              type = "app";
              program = "${stage-b-ripgrep-skeleton-root}/bin/stage-b-ripgrep-skeleton-root";
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
              stage-a-fixtures
              stage-a-fixtures-check
              stage-a-jq-fixtures
              stage-a-jq-fixtures-check
              stage-b-jq-decompiler-export
              stage-b-jq-libjq-decompiler-export
              stage-b-jq-libjq-decompiled-c-skeleton
              stage-b-jq-decompiled-c-skeleton
              stage-b-jq-program-slice-skeleton
              stage-b-jq-skeleton
              stage-b-jq-skeleton-check
              stage-b-jq-skeleton-candidate
              stage-b-jq-skeleton-candidate-check
              stage-b-jq-target-closure-skeleton
              stage-b-jq-generated-closure-candidate
              stage-b-jq-contract-iteration-check
              stage-b-jq-generated-closure-candidate-check
              stage-b-ripgrep-integration-harness
              stage-b-ripgrep-reference-contract
              stage-b-ripgrep-skeleton
              stage-b-ripgrep-skeleton-check
              stage-b-ripgrep-skeleton-candidate
              stage-b-ripgrep-skeleton-candidate-check
              stage-b-smoke-check
              stage-b-functional-runner-check
              stage-b-readiness-audit-check
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
              pkgs.cargo
              pkgs.lean4
              python
              pkgs.rustc
              pkgs.rustfmt
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
              stage-a-fixtures
              stage-a-fixtures-root
              stage-a-jq-fixtures
              stage-a-jq-fixtures-root
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
              pkgs.z3
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
              pkgs.cargo
              pkgs.jq
              pkgs.lean4
              pkgs.rustc
              pkgs.rustfmt
              stage-a-fixtures
              stage-a-fixtures-root
              stage-a-jq-fixtures
              stage-a-jq-fixtures-root
              pkgs.sqlite
              pkgs.sshpass
              pkgs.z3
            ];

            shellHook = ''
              export PYTHONPATH="$PWD/src''${PYTHONPATH:+:$PYTHONPATH}"
            '';
          };
        };
    };
}
