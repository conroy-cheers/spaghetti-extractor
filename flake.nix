{
  description = "jq Stage A/B Windows PE reimplementation tooling";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          mingw32 = pkgs.pkgsCross.mingw32;
          mingw32Oniguruma = mingw32.oniguruma.overrideAttrs (old: {
            meta = (old.meta or { }) // {
              platforms = (old.meta.platforms or [ ]) ++ [ "i686-windows" ];
            };
          });
          pythonEnv = pkgs.python3.withPackages (
            ps: with ps; [
              capstone
              pefile
              z3-solver
            ]
          );
          wincr-tools = pkgs.python3Packages.buildPythonApplication {
            pname = "wincr-tools";
            version = "0.1.0";
            src = ./.;
            pyproject = true;

            build-system = with pkgs.python3Packages; [
              setuptools
            ];

            dependencies = with pkgs.python3Packages; [
              capstone
              pefile
              z3-solver
            ];

            doCheck = false;
            pythonImportsCheck = [ "wincr" ];
          };
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
          stage-a-jq-original = mkStageAJq "original" stageAJqOriginalCflags;
          stage-a-jq-candidate = mkStageAJq "candidate" stageAJqCandidateCflags;
          stage-a-fixtures = mingw32.stdenv.mkDerivation {
            pname = "stage-a-fixtures";
            version = "0.1.0";
            src = ./tools/stage-a-fixtures;

            dontConfigure = true;
            nativeBuildInputs = [ pkgs.python3 ];

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
              $CC -O0 "''${common_flags[@]}" -DSTAGE_A_NO_EXTERNAL -DSTAGE_A_NO_BRANCH -o stage-a-original.exe stage_a_equivalence.S
              $CC -O2 "''${common_flags[@]}" -DSTAGE_A_NO_EXTERNAL -DSTAGE_A_NO_BRANCH -DSTAGE_A_VARIANT_B -o stage-a-candidate.exe stage_a_equivalence.S
              $CC -O2 "''${common_flags[@]}" -DSTAGE_A_NO_EXTERNAL -DSTAGE_A_NO_BRANCH -DSTAGE_A_MUTATION -o stage-a-mutated.exe stage_a_equivalence.S
              $CC -O0 "''${common_flags[@]}" -o stage-a-calls-original.exe stage_a_calls.S -lkernel32
              $CC -O2 "''${common_flags[@]}" -DSTAGE_A_VARIANT_B -o stage-a-calls-candidate.exe stage_a_calls.S -lkernel32
              python3 - stage-a-original.exe stage-a-candidate.exe stage-a-mutated.exe <<'PY'
              import pathlib
              import struct
              import sys

              for name in sys.argv[1:]:
                  path = pathlib.Path(name)
                  data = bytearray(path.read_bytes())
                  pe_offset = struct.unpack_from("<I", data, 0x3c)[0]
                  import_directory = pe_offset + 24 + 104
                  data[import_directory : import_directory + 8] = b"\0" * 8
                  path.write_bytes(data)
              PY
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall
              fixture_dir="$out/share/wincr/stage-a-fixtures/symbolic-equivalence"
              mkdir -p "$fixture_dir"
              cp stage-a-original.exe stage-a-candidate.exe stage-a-mutated.exe \
                stage-a-calls-original.exe stage-a-calls-candidate.exe "$fixture_dir/"
              cat > "$fixture_dir/block-map.json" <<'JSON'
              {
                "blocks": [
                  { "id": "entry", "kind": "code", "reachable": true, "root": { "kind": "fixture_function", "checked": true }, "original": { "rva": "0x1000", "size": 8 }, "candidate": { "rva": "0x1000", "size": 10 } },
                  { "id": "memory", "kind": "code", "reachable": true, "root": { "kind": "fixture_function", "checked": true }, "original": { "rva": "0x1010", "size": 8 }, "candidate": { "rva": "0x1010", "size": 9 } },
                  { "id": "zero", "kind": "code", "reachable": true, "root": { "kind": "fixture_function", "checked": true }, "original": { "rva": "0x1020", "size": 3 }, "candidate": { "rva": "0x1020", "size": 3 } }
                ],
                "waivers": [
                  { "id": "original-entry-padding", "binary": "original", "rva": "0x1008", "size": "0x8", "reason": "post-ret alignment padding emitted by the fixture build" },
                  { "id": "candidate-entry-padding", "binary": "candidate", "rva": "0x100a", "size": "0x6", "reason": "post-ret alignment padding emitted by the fixture build" },
                  { "id": "original-memory-padding", "binary": "original", "rva": "0x1018", "size": "0x8", "reason": "post-ret alignment padding emitted by the fixture build" },
                  { "id": "candidate-memory-padding", "binary": "candidate", "rva": "0x1019", "size": "0x7", "reason": "post-ret alignment padding emitted by the fixture build" },
                  { "id": "zero-padding", "binary": "both", "rva": "0x1023", "size": "0xd", "reason": "post-ret alignment padding emitted by the fixture build" }
                ]
              }
              JSON
              cat > "$fixture_dir/block-map-mutated.json" <<'JSON'
              {
                "blocks": [
                  { "id": "entry", "kind": "code", "reachable": true, "root": { "kind": "fixture_function", "checked": true }, "original": { "rva": "0x1000", "size": 8 }, "candidate": { "rva": "0x1000", "size": 8 } },
                  { "id": "memory", "kind": "code", "reachable": true, "root": { "kind": "fixture_function", "checked": true }, "original": { "rva": "0x1010", "size": 8 }, "candidate": { "rva": "0x1010", "size": 8 } },
                  { "id": "zero", "kind": "code", "reachable": true, "root": { "kind": "fixture_function", "checked": true }, "original": { "rva": "0x1020", "size": 3 }, "candidate": { "rva": "0x1020", "size": 6 } }
                ],
                "waivers": [
                  { "id": "entry-padding", "binary": "both", "rva": "0x1008", "size": "0x8", "reason": "post-ret alignment padding emitted by the fixture build" },
                  { "id": "memory-padding", "binary": "both", "rva": "0x1018", "size": "0x8", "reason": "post-ret alignment padding emitted by the fixture build" },
                  { "id": "original-zero-padding", "binary": "original", "rva": "0x1023", "size": "0xd", "reason": "post-ret alignment padding emitted by the fixture build" },
                  { "id": "candidate-zero-padding", "binary": "candidate", "rva": "0x1026", "size": "0xa", "reason": "post-ret alignment padding emitted by the fixture build" }
                ]
              }
              JSON
              cat > "$fixture_dir/block-map-calls.json" <<'JSON'
              {
                "blocks": [
                  { "id": "import-call", "kind": "code", "reachable": true, "root": { "kind": "fixture_function", "checked": true }, "original": { "rva": "0x1000", "size": 6 }, "candidate": { "rva": "0x1000", "size": 6 } },
                  { "id": "import-continuation", "kind": "code", "reachable": true, "original": { "rva": "0x1006", "size": 1 }, "candidate": { "rva": "0x1006", "size": 1 } },
                  { "id": "internal-caller", "kind": "code", "reachable": true, "root": { "kind": "fixture_function", "checked": true }, "original": { "rva": "0x1010", "size": 5 }, "candidate": { "rva": "0x1010", "size": 5 } },
                  { "id": "internal-continuation", "kind": "code", "reachable": true, "original": { "rva": "0x1015", "size": 1 }, "candidate": { "rva": "0x1015", "size": 1 } },
                  { "id": "internal-callee", "kind": "code", "reachable": true, "original": { "rva": "0x1020", "size": 3 }, "candidate": { "rva": "0x1020", "size": 3 } }
                ],
                "waivers": [
                  { "id": "import-call-padding", "binary": "both", "rva": "0x1007", "size": "0x9", "reason": "post-return alignment padding emitted by the fixture build" },
                  { "id": "internal-caller-padding", "binary": "both", "rva": "0x1016", "size": "0xa", "reason": "post-return alignment padding emitted by the fixture build" },
                  { "id": "internal-callee-padding", "binary": "both", "rva": "0x1023", "size": "0xd", "reason": "post-return alignment padding emitted by the fixture build" }
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
                  { "id": "gcc-o0-vs-gcc-o2-symbolic-equivalence", "original": "stage-a-original.exe", "candidate": "stage-a-candidate.exe", "mapping": "block-map.json", "lean_inputs": [ "stage-a-fixture-lemmas.lean" ], "expect": "pass" },
                  { "id": "gcc-o0-vs-mutated-candidate", "original": "stage-a-original.exe", "candidate": "stage-a-mutated.exe", "mapping": "block-map-mutated.json", "lean_inputs": [ "stage-a-fixture-lemmas.lean" ], "expect": "fail" },
                  { "id": "mingw-import-relocation-call-composition", "original": "stage-a-calls-original.exe", "candidate": "stage-a-calls-candidate.exe", "mapping": "block-map-calls.json", "expect": "pass" }
                ]
              }
              JSON
              runHook postInstall
            '';
          };
          stage-a-fixtures-check = pkgs.runCommand "stage-a-fixtures-check"
            {
              nativeBuildInputs = [
                wincr-tools
                pkgs.lean4
              ];
            }
            ''
              fixture_dir="${stage-a-fixtures}/share/wincr/stage-a-fixtures/symbolic-equivalence"
              wincr stage-a-validate-suite \
                --suite "$fixture_dir/suite.json" \
                --model x86-pe32-env-v1 \
                --out "$TMPDIR/stage-a-suite"
              wincr stage-a-check-proof \
                --report "$TMPDIR/stage-a-suite/cases/gcc-o0-vs-gcc-o2-symbolic-equivalence" \
                --out "$TMPDIR/stage-a-suite/formal-proof-check.json"
              wincr stage-a-check-proof \
                --report "$TMPDIR/stage-a-suite/cases/mingw-import-relocation-call-composition" \
                --out "$TMPDIR/stage-a-suite/formal-proof-check-calls.json"
              mkdir -p "$out"
              cp -R "$TMPDIR/stage-a-suite/." "$out/"
            '';
          stage-a-fixtures-root = pkgs.writeShellApplication {
            name = "stage-a-fixtures-root";
            text = ''
              printf '%s\n' "${stage-a-fixtures}"
            '';
          };
          stage-a-jq-fixtures = pkgs.runCommand "stage-a-jq-fixtures"
            {
              nativeBuildInputs = [ pkgs.jq ];
            }
            ''
              fixture_dir="$out/share/wincr/stage-a-fixtures/jq-o2-alignment"
              mkdir -p "$fixture_dir"
              cp "${stage-a-jq-original}/share/wincr/stage-a-jq-fixtures/original/jq.exe" "$fixture_dir/jq-original.exe"
              cp "${stage-a-jq-candidate}/share/wincr/stage-a-jq-fixtures/candidate/jq.exe" "$fixture_dir/jq-candidate.exe"
              cp "${stage-a-jq-original}/share/wincr/stage-a-jq-fixtures/original/jq.map" "$fixture_dir/jq-original.map"
              cp "${stage-a-jq-candidate}/share/wincr/stage-a-jq-fixtures/candidate/jq.map" "$fixture_dir/jq-candidate.map"
              for path in "${stage-a-jq-original}"/bin/*.dll "${stage-a-jq-candidate}"/bin/*.dll; do
                [ -e "$path" ] || continue
                name="$(basename "$path")"
                if [ ! -e "$fixture_dir/$name" ]; then
                  cp -L "$path" "$fixture_dir/"
                  chmod u+w "$fixture_dir/$name"
                fi
              done
              jq -n \
                --arg original_flags "${stageAJqOriginalCflags}" \
                --arg candidate_flags "${stageAJqCandidateCflags}" \
                --arg compiler "$(${mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc -dumpmachine)" \
                --arg compiler_version "$(${mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc -dumpfullversion -dumpversion)" \
                '{
                  format: "stage-a-jq-fixture-build-metadata-v1",
                  source: "jq from nixpkgs",
                  target: "i686-w64-mingw32",
                  original: { file: "jq-original.exe", linker_map: "jq-original.map", flags: $original_flags },
                  candidate: { file: "jq-candidate.exe", linker_map: "jq-candidate.map", flags: $candidate_flags },
                  compiler: { target: $compiler, version: $compiler_version }
                }' > "$fixture_dir/build-metadata.json"
            '';
          stage-a-jq-fixtures-check = pkgs.runCommand "stage-a-jq-fixtures-check"
            {
              nativeBuildInputs = [
                wincr-tools
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
                > "$work/generate-map.stdout"
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
                    "expect": "incomplete"
                  }
                ]
              }
              JSON
              wincr stage-a-validate-suite \
                --suite "$work/suite.json" \
                --model x86-pe32-env-v1 \
                --out "$work/suite"
              jq -e '.status == "pass" and .counts.passed == .counts.cases and .cases[0].actual_verdict == "incomplete"' "$work/suite/suite.json" >/dev/null
              mkdir -p "$out/generated" "$out/report"
              cp "$work/jq-block-map.json" "$work/jq-layout-contract.json" "$work/suite.json" "$out/report/"
              cp -R "$work/suite/." "$out/report/suite"
              jq '.proof.lean.failed_formal_pass_attempt.formal_proof.diagnostics' \
                "$out/report/suite/cases/jq-o2-alignment-windows-x86/verdict.json" \
                > "$out/generated/jq-formal-gaps.json"
              if wincr stage-a-export-reference-contract \
                  --original "$fixture_dir/jq-original.exe" \
                  --candidate "$fixture_dir/jq-candidate.exe" \
                  --mapping "$out/report/jq-block-map.json" \
                  --validation-report "$out/report/suite/cases/jq-o2-alignment-windows-x86" \
                  --layout-contract "$out/report/jq-layout-contract.json" \
                  --sidecar-dir "$out/generated" \
                  --unit-contract-dir "$out/generated" \
                  --out "$out/generated/jq-reference-contract.json" \
                  > "$work/reference-contract.stdout"; then
                echo "jq reference contract unexpectedly claimed formal completion" >&2
                exit 1
              fi
              jq -e '.status == "incomplete"' "$out/generated/jq-reference-contract.json" >/dev/null
              wincr stage-a-smoke-contract \
                --reference-contract "$out/generated/jq-reference-contract.json" \
                --out "$out/generated/contract-smoke.json" \
                > "$work/smoke.stdout"
              jq -e '.status == "pass"' "$out/generated/contract-smoke.json" >/dev/null
            '';
          stage-a-jq-fixtures-root = pkgs.writeShellApplication {
            name = "stage-a-jq-fixtures-root";
            text = ''
              printf '%s\n' "${stage-a-jq-fixtures}"
            '';
          };
          stage-b-jq-skeleton = pkgs.runCommand "stage-b-jq-skeleton"
            {
              nativeBuildInputs = [ wincr-tools ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/wincr/stage-a-fixtures/jq-o2-alignment"
              work="$TMPDIR/stage-b-jq-skeleton"
              mkdir -p "$work"
              wincr stage-b-generate-skeleton \
                --original "$fixture_dir/jq-original.exe" \
                --reference-contract "${stage-a-jq-fixtures-check}/generated/jq-reference-contract.json" \
                --target-name jq \
                --source-language c \
                --implementation-mode contract-guided-c \
                --out-dir "$work/skeleton" \
                > "$work/skeleton.stdout"
              out_dir="$out/share/wincr/stage-b/jq/skeleton"
              mkdir -p "$out_dir"
              cp -R "$work/skeleton/." "$out_dir/"
            '';
          stage-b-jq-skeleton-root = pkgs.writeShellApplication {
            name = "stage-b-jq-skeleton-root";
            text = ''
              printf '%s\n' "${stage-b-jq-skeleton}/share/wincr/stage-b/jq/skeleton"
            '';
          };
        in
        {
          default = wincr-tools;
          inherit
            wincr-tools
            stage-a-fixtures
            stage-a-fixtures-check
            stage-a-fixtures-root
            stage-a-jq-fixtures
            stage-a-jq-fixtures-check
            stage-a-jq-fixtures-root
            stage-b-jq-skeleton
            stage-b-jq-skeleton-root
            ;
        }
      );

      apps = forAllSystems (
        system:
        let
          packages = self.packages.${system};
        in
        {
          default = {
            type = "app";
            program = "${packages.wincr-tools}/bin/wincr";
          };
          wincr = {
            type = "app";
            program = "${packages.wincr-tools}/bin/wincr";
          };
          wincr-slice = {
            type = "app";
            program = "${packages.wincr-tools}/bin/wincr-slice";
          };
          stage-a-fixtures-root = {
            type = "app";
            program = "${packages.stage-a-fixtures-root}/bin/stage-a-fixtures-root";
          };
          stage-a-jq-fixtures-root = {
            type = "app";
            program = "${packages.stage-a-jq-fixtures-root}/bin/stage-a-jq-fixtures-root";
          };
          stage-b-jq-skeleton-root = {
            type = "app";
            program = "${packages.stage-b-jq-skeleton-root}/bin/stage-b-jq-skeleton-root";
          };
        }
      );

      checks = forAllSystems (
        system:
        let
          packages = self.packages.${system};
        in
        {
          inherit (packages)
            wincr-tools
            stage-a-fixtures-check
            stage-a-jq-fixtures-check
            stage-b-jq-skeleton
            ;
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          packages = self.packages.${system};
          pythonEnv = pkgs.python3.withPackages (
            ps: with ps; [
              capstone
              pefile
              pytest
              z3-solver
            ]
          );
        in
        {
          default = pkgs.mkShell {
            packages = [
              pythonEnv
              packages.wincr-tools
              pkgs.jq
              pkgs.lean4
              pkgs.nix
              pkgs.pkgsCross.mingw32.stdenv.cc
              pkgs.llvm
            ];
            shellHook = ''
              export PYTHONPATH="$PWD/src''${PYTHONPATH:+:$PYTHONPATH}"
            '';
          };
        }
      );
    };
}
