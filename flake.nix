{
  description = "Spaghetti Extractor binary reimplementation and equivalence-proof tooling";

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
          spaghettiExtractorSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./pyproject.toml
              ./src
              ./nix/stage-a-lean-graph.nix
              ./profiles
            ];
          };
          spaghetti-extractor = pkgs.python3Packages.buildPythonApplication {
            pname = "spaghetti-extractor";
            version = "0.1.0";
            src = spaghettiExtractorSource;
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
            pythonImportsCheck = [ "spaghetti_extractor" ];
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
                    mkdir -p "$out/share/spaghetti-extractor/stage-a-jq-fixtures/${label}"
                    cp "$map_path" "$out/share/spaghetti-extractor/stage-a-jq-fixtures/${label}/jq.map"
                    cp "$out/bin/jq.exe" "$out/share/spaghetti-extractor/stage-a-jq-fixtures/${label}/jq.exe"
                  '';
                meta = (old.meta or { }) // {
                  platforms = (old.meta.platforms or [ ]) ++ [ "i686-windows" ];
                };
              });
          stage-a-jq-original = mkStageAJq "original" stageAJqOriginalCflags;
          stage-a-jq-candidate = mkStageAJq "candidate" stageAJqCandidateCflags;
          stage-a-fixtures = mingw32.stdenv.mkDerivation {
            pname = "stage-a-fixtures";
            version = "0.2.0";
            src = ./tools/stage-a-fixtures;

            dontConfigure = true;

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
              $CC -O0 "''${common_flags[@]}" -o stage-a-loop-original.exe stage_a_loop.S
              $CC -O2 "''${common_flags[@]}" -o stage-a-loop-candidate.exe stage_a_loop.S
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall
              fixture_dir="$out/share/spaghetti-extractor/stage-a-fixtures/relational-v3"
              mkdir -p "$fixture_dir"
              cp stage-a-loop-original.exe stage-a-loop-candidate.exe "$fixture_dir/"
              cat > "$fixture_dir/block-map-loop.json" <<'JSON'
              {
                "blocks": [
                  {
                    "id": "entry-loop",
                    "kind": "code",
                    "reachable": true,
                    "root": { "kind": "pe_entrypoint", "checked": true },
                    "original": { "rva": "0x1000", "size": 2 },
                    "candidate": { "rva": "0x1000", "size": 2 },
                    "source": {
                      "kind": "fixture",
                      "function": "entry_loop",
                      "function_block_index": 0
                    }
                  }
                ],
                "waivers": [
                  { "id": "loop-linker-padding", "binary": "both", "rva": "0x1002", "size": 2, "reason": "verified post-jump NOP alignment emitted by the PE linker" }
                ]
              }
              JSON
              cat > "$fixture_dir/layout-contract.json" <<'JSON'
              {
                "format": "stage-a-layout-contract-v1",
                "required_facts": [
                  "matching_architecture",
                  "matching_section_rvas",
                  "matching_section_permissions",
                  "matching_imports",
                  "all_executable_bytes_classified",
                  "matching_normalized_executable_section_spans"
                ],
                "facts": {
                  "matching_architecture": true,
                  "matching_section_rvas": true,
                  "matching_section_permissions": true,
                  "matching_imports": true,
                  "all_executable_bytes_classified": true,
                  "matching_normalized_executable_section_spans": true
                }
              }
              JSON
              runHook postInstall
            '';
          };
          stage-a-fixtures-check = pkgs.runCommand "stage-a-fixtures-check"
            {
              nativeBuildInputs = [
                spaghetti-extractor
                pkgs.jq
                pkgs.lean4
              ];
            }
            ''
              fixture_dir="${stage-a-fixtures}/share/spaghetti-extractor/stage-a-fixtures/relational-v3"
              work="$TMPDIR/stage-a-v3"
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$TMPDIR/stage-a-relational-cache"
              mkdir -p "$work"
              spaghetti-extractor stage-a-generate-relation-contract \
                --original "$fixture_dir/stage-a-loop-original.exe" \
                --candidate "$fixture_dir/stage-a-loop-candidate.exe" \
                --mapping "$fixture_dir/block-map-loop.json" \
                --out "$work/relation-contract.json"
              spaghetti-extractor stage-a-prove \
                --original "$fixture_dir/stage-a-loop-original.exe" \
                --candidate "$fixture_dir/stage-a-loop-candidate.exe" \
                --relation-contract "$work/relation-contract.json" \
                --out "$work/proof"
              spaghetti-extractor stage-a-check-proof \
                --report "$work/proof" \
                --out "$work/proof-check.json"
              spaghetti-extractor stage-a-export-reference-contract \
                --original "$fixture_dir/stage-a-loop-original.exe" \
                --candidate "$fixture_dir/stage-a-loop-candidate.exe" \
                --mapping "$fixture_dir/block-map-loop.json" \
                --validation-report "$work/proof" \
                --layout-contract "$fixture_dir/layout-contract.json" \
                --sidecar-dir "$work/contract" \
                --unit-contract-dir "$work/contract" \
                --out "$work/contract/reference-contract.json"
              jq -e '
                .constraints.validation_report_artifact_binding.status == "satisfied" and
                .constraints.proof_obligation_inventory.status == "satisfied"
              ' "$work/contract/reference-contract.json" >/dev/null
              spaghetti-extractor stage-a-smoke-contract \
                --reference-contract "$work/contract/reference-contract.json" \
                --out "$work/contract-smoke.json"
              jq -e '.status == "pass"' "$work/contract-smoke.json" >/dev/null
              mkdir -p "$out"
              cp -R "$work/." "$out/"
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
              fixture_dir="$out/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment"
              mkdir -p "$fixture_dir"
              cp "${stage-a-jq-original}/share/spaghetti-extractor/stage-a-jq-fixtures/original/jq.exe" "$fixture_dir/jq-original.exe"
              cp "${stage-a-jq-candidate}/share/spaghetti-extractor/stage-a-jq-fixtures/candidate/jq.exe" "$fixture_dir/jq-candidate.exe"
              cp "${stage-a-jq-original}/share/spaghetti-extractor/stage-a-jq-fixtures/original/jq.map" "$fixture_dir/jq-original.map"
              cp "${stage-a-jq-candidate}/share/spaghetti-extractor/stage-a-jq-fixtures/candidate/jq.map" "$fixture_dir/jq-candidate.map"
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
          stage-a-jq-prepared-proof = pkgs.runCommand "stage-a-jq-prepared-proof"
            {
              nativeBuildInputs = [
                spaghetti-extractor
                pkgs.jq
                pkgs.lean4
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment"
              work="$TMPDIR/stage-a-jq"
              mkdir -p "$work"
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-relational-kernel-cache}"
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_JOBS=16
              spaghetti-extractor stage-a-generate-map \
                --original "$fixture_dir/jq-original.exe" \
                --candidate "$fixture_dir/jq-candidate.exe" \
                --linker-map-original "$fixture_dir/jq-original.map" \
                --linker-map-candidate "$fixture_dir/jq-candidate.map" \
                --original-flags "${stageAJqOriginalCflags}" \
                --candidate-flags "${stageAJqCandidateCflags}" \
                --out "$work/jq-block-map.json" \
                --layout-contract-out "$work/jq-layout-contract.json" \
                > "$work/generate-map.stdout"
              spaghetti-extractor stage-a-generate-relation-contract \
                --original "$fixture_dir/jq-original.exe" \
                --candidate "$fixture_dir/jq-candidate.exe" \
                --mapping "$work/jq-block-map.json" \
                --external-profile "${./profiles/pe32-kernel32-lockstep-v1.json}" \
                --external-profile "${./profiles/pe32-msvcrt-lockstep-v1.json}" \
                --out "$work/jq-relation-contract.json" \
                > "$work/generate-relation.stdout"
              SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$work/relational-cache" \
                spaghetti-extractor stage-a-prepare-relational \
                  --original "$fixture_dir/jq-original.exe" \
                  --candidate "$fixture_dir/jq-candidate.exe" \
                  --relation-contract "$work/jq-relation-contract.json" \
                  --out "$work/relational-v3" \
                  > "$work/relational-v3.stdout"
              mkdir -p "$out/report"
              cp "$work/jq-block-map.json" "$work/jq-layout-contract.json" \
                "$work/jq-relation-contract.json" "$out/report/"
              cp -R "$work/relational-v3" "$out/report/relational-v3"
            '';
          stage-a-jq-reference-contract = pkgs.runCommand "stage-a-jq-reference-contract"
            {
              nativeBuildInputs = [
                spaghetti-extractor
                pkgs.jq
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment"
              prepared="${stage-a-jq-prepared-proof}/report"
              work="$TMPDIR/stage-a-jq-reference"
              mkdir -p "$work" "$out/generated"
              cp "$prepared/relational-v3/semantic-gaps.json" \
                "$out/generated/jq-formal-gaps.json"
              if spaghetti-extractor stage-a-export-reference-contract \
                  --original "$fixture_dir/jq-original.exe" \
                  --candidate "$fixture_dir/jq-candidate.exe" \
                  --mapping "$prepared/jq-block-map.json" \
                  --validation-report "$prepared/relational-v3" \
                  --layout-contract "$prepared/jq-layout-contract.json" \
                  --sidecar-dir "$out/generated" \
                  --unit-contract-dir "$out/generated" \
                  --out "$out/generated/jq-reference-contract.json" \
                  > "$work/reference-contract.stdout"; then
                echo "jq reference contract unexpectedly claimed formal completion" >&2
                exit 1
              fi
              jq -e '.status == "incomplete"' \
                "$out/generated/jq-reference-contract.json" >/dev/null
              spaghetti-extractor stage-a-smoke-contract \
                --reference-contract "$out/generated/jq-reference-contract.json" \
                --out "$out/generated/contract-smoke.json" \
                > "$work/smoke.stdout"
              jq -e '.status == "pass"' \
                "$out/generated/contract-smoke.json" >/dev/null
            '';
          stage-a-jq-fixtures-check = pkgs.runCommand "stage-a-jq-fixtures-check"
            {
              nativeBuildInputs = [ pkgs.jq ];
            }
            ''
              prepared="${stage-a-jq-prepared-proof}/report"
              generated="${stage-a-jq-reference-contract}/generated"
              jq -e '
                .status == "prepared" and
                .acceptance.status == "incomplete" and
                .acceptance.theorem == null and
                .composition_progress.status == "incomplete" and
                .composition_progress.counts.rooted_reachable_nodes > 0 and
                .composition_progress.counts.rooted_reachable_feasible_edges > 0 and
                .composition_progress.counts.rooted_external_refinement_candidates > 0 and
                .composition_progress.counts.rooted_refined_segments > 0 and
                .composition_progress.counts.rooted_refined_segments <
                  .composition_progress.counts.rooted_reachable_feasible_edges and
                .composition_progress.counts.unsupported_instructions == 0
              ' "$prepared/relational-v3/prepared-proof.json" >/dev/null
              jq -e '
                (.machine_import_call_contracts | any(
                  .import.dll == "kernel32.dll" and
                  .import.symbol == "TlsGetValue" and
                  .world_effect == "tlsState")) and
                (.machine_import_call_contracts | any(
                  .import.dll == "msvcrt.dll" and
                  .import.symbol == "free" and
                  .world_effect == "dynamicRangeRelease")) and
                (.machine_import_call_contracts | any(
                  .import.dll == "msvcrt.dll" and
                  .import.symbol == "atexit" and
                  .world_effect == "callbackRegistration")) and
                (.machine_import_call_contracts | any(
                  .import.dll == "msvcrt.dll" and
                  .import.symbol == "exit" and
                  .disposition == "protocol"))
              ' "$prepared/relational-v3/relation-contract.json" >/dev/null
              jq -e '.format == "stage-a-interface-manifest-v1"' \
                "$prepared/relational-v3/stage-a-interface-manifest.json" >/dev/null
              jq -e '.status == "supported" and .counts.issues == 0' \
                "$prepared/relational-v3/semantic-gaps.json" >/dev/null
              jq -e '.status == "incomplete"' \
                "$generated/jq-reference-contract.json" >/dev/null
              jq -e '.status == "pass"' \
                "$generated/contract-smoke.json" >/dev/null
              mkdir -p "$out"
              ln -s "$prepared" "$out/report"
              ln -s "$generated" "$out/generated"
            '';
          relationalLeanSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = ./src/spaghetti_extractor/lean/StageA;
          };
          stage-a-relational-kernel-cache = pkgs.runCommand
            "stage-a-relational-kernel-cache"
            {
              nativeBuildInputs = [
                pkgs.lean4
              ];
            }
            ''
              work="$TMPDIR/relational-kernel"
              mkdir -p "$out/StageA" "$work"
              cp -R ${relationalLeanSource}/src/spaghetti_extractor/lean/StageA \
                "$work/StageA"
              chmod -R u+w "$work/StageA"
              cd "$work"
              export LEAN_PATH=.
              for module in \
                Formal \
                RelationalDecode \
                RelationalMachine \
                Relational \
                RelationalInvariant \
                RelationalExecution \
                RelationalImage \
                RelationalSegment \
                RelationalComposition \
                RelationalEnvironment \
                RelationalCallbacks \
                RelationalCertificates \
                RelationalStaticTree
              do
                lean -o "StageA/$module.olean" "StageA/$module.lean"
              done
              cp StageA/*.lean StageA/*.olean "$out/StageA/"
              printf '%s\n' \
                'format=stage-a-relational-precompiled-kernel-v1' \
                "lean=$(lean --version | head -n 1)" \
                > "$out/kernel-build.txt"
            '';
          mkStageARelationalTest = name: module: testFiles:
            let
              usesLean =
                builtins.elem name [ "state" "lean" "pipeline" ]
                || pkgs.lib.hasPrefix "state-" name
                || pkgs.lib.hasPrefix "lean-" name
                || pkgs.lib.hasPrefix "pipeline-" name
                || pkgs.lib.hasPrefix "contract" name
                || pkgs.lib.hasPrefix "acceptance" name;
              testSource = pkgs.lib.fileset.toSource {
                root = ./.;
                fileset = pkgs.lib.fileset.unions (
                  [
                    ./tests/stage_a_relational_support.py
                  ]
                  ++ testFiles
                  ++ pkgs.lib.optionals usesLean
                    [ ./src/spaghetti_extractor/lean/StageA ]
                  ++ pkgs.lib.optionals (pkgs.lib.hasPrefix "contract" name)
                    [ ./nix/stage-a-lean-graph.nix ]
                );
              };
            in
            pkgs.runCommand "stage-a-relational-tests-${name}"
              {
                nativeBuildInputs = [
                  spaghetti-extractor
                  pythonEnv
                  pkgs.lean4
                ];
              }
              ''
                export HOME="$TMPDIR/home"
                export XDG_CACHE_HOME="$TMPDIR/xdg-cache"
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$TMPDIR/relational-cache"
                ${pkgs.lib.optionalString usesLean ''
                  export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-relational-kernel-cache}"
                ''}
                export PYTHONPATH="${spaghetti-extractor}/${pkgs.python3.sitePackages}:${pythonEnv}/${pkgs.python3.sitePackages}:${testSource}:${testSource}/tests"
                mkdir -p "$HOME" "$XDG_CACHE_HOME" "$SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE"
                cd "$TMPDIR"
                python -m unittest -v ${module}
                mkdir -p "$out/${name}"
                printf '%s\n' '${module}' > "$out/${name}/test-module.txt"
              '';
          mkStageARelationalTestSuite = name: module: className: testFile:
            let
              testMethods = builtins.filter (method: method != null) (
                map
                  (line:
                    let
                      matched = builtins.match
                        "^    def (test_[A-Za-z0-9_]+)\\(self.*$" line;
                    in
                    if matched == null then null else builtins.head matched)
                  (pkgs.lib.splitString "\n" (builtins.readFile testFile))
              );
              cases = builtins.listToAttrs (
                map
                  (method:
                    let caseName = pkgs.lib.removePrefix "test_" method;
                    in {
                      name = caseName;
                      value = mkStageARelationalTest
                        "${name}-${caseName}"
                        "${module}.${className}.${method}"
                        [ testFile ];
                    })
                  testMethods
              );
            in
            {
              inherit cases;
              aggregate = pkgs.symlinkJoin {
                name = "stage-a-relational-tests-${name}";
                paths = builtins.attrValues cases;
              };
            };
          stage-a-relational-tests-schema = mkStageARelationalTest
            "schema"
            "tests.test_relational_schema tests.test_contract_tools.ContractToolTests.test_cli_exposes_one_stage_a_authority_and_candidate_only_stage_b_tools"
            [
              ./tests/test_relational_schema.py
              ./tests/test_contract_tools.py
              ./tests/contract_fixtures.py
              ./tests/pe_fixtures.py
            ];
          stageARelationalContractSuite = mkStageARelationalTestSuite
            "contract" "tests.test_stage_a_relational_contract"
            "StageARelationalContractTests" ./tests/test_stage_a_relational_contract.py;
          stageARelationalStateSuite = mkStageARelationalTestSuite
            "state" "tests.test_stage_a_relational_state"
            "StageARelationalStateTests" ./tests/test_stage_a_relational_state.py;
          stageARelationalPipelineSuite = mkStageARelationalTestSuite
            "pipeline" "tests.test_stage_a_relational_pipeline"
            "StageARelationalPipelineTests" ./tests/test_stage_a_relational_pipeline.py;
          stageARelationalLeanSuite = mkStageARelationalTestSuite
            "lean" "tests.test_stage_a_relational_lean"
            "StageARelationalLeanTests" ./tests/test_stage_a_relational_lean.py;
          stageARelationalAcceptanceSuite = mkStageARelationalTestSuite
            "acceptance" "tests.test_stage_a_relational_acceptance"
            "StageARelationalAcceptanceTests" ./tests/test_stage_a_relational_acceptance.py;
          stage-a-relational-tests-contract = stageARelationalContractSuite.aggregate;
          stage-a-relational-tests-state = stageARelationalStateSuite.aggregate;
          stage-a-relational-tests-pipeline = stageARelationalPipelineSuite.aggregate;
          stage-a-relational-tests-lean = stageARelationalLeanSuite.aggregate;
          stage-a-relational-tests-acceptance = stageARelationalAcceptanceSuite.aggregate;
          stage-a-relational-tests-acceptance-nested-external =
            stageARelationalAcceptanceSuite.cases.nested_external_call_preserves_internal_runtime_frame_end_to_end;
          stage-a-relational-tests-acceptance-direct-stack-read =
            stageARelationalAcceptanceSuite.cases.direct_paired_stack_read_loop_closes_whole_program_theorem;
          stage-a-relational-tests-acceptance-representative =
            stageARelationalAcceptanceSuite.cases.representative_control_slice_closes_whole_program_theorem;
          stage-a-relational-tests-acceptance-terminal-return =
            stageARelationalAcceptanceSuite.cases.top_level_return_checks_terminal_invariant_end_to_end;
          stage-a-relational-tests-acceptance-external-loop =
            stageARelationalAcceptanceSuite.cases.external_call_loop_checks_paired_environment_end_to_end;
          stage-a-relational-tests-acceptance-input-flag-guard =
            stageARelationalAcceptanceSuite.cases.input_flag_guard_closes_only_for_the_same_checked_flag;
          stage-a-relational-tests-acceptance-exact-pure-guard =
            stageARelationalAcceptanceSuite.cases.exact_pure_guard_uses_derived_register_exactness;
          stage-a-relational-tests-acceptance-immutable-image-word =
            stageARelationalAcceptanceSuite.cases.immutable_image_word_load_closes_register_transfer;
          stage-a-relational-tests-acceptance-direct-call-stack-writes =
            stageARelationalAcceptanceSuite.cases.direct_call_with_prepared_stack_word_checks_whole_program_theorem;
          stage-a-relational-tests = pkgs.symlinkJoin {
            name = "stage-a-relational-tests";
            paths = [
              stage-a-relational-tests-schema
              stage-a-relational-tests-contract
              stage-a-relational-tests-state
              stage-a-relational-tests-pipeline
              stage-a-relational-tests-lean
              stage-a-relational-tests-acceptance
            ];
          };
          stage-a-jq-fixtures-root = pkgs.writeShellApplication {
            name = "stage-a-jq-fixtures-root";
            text = ''
              printf '%s\n' "${stage-a-jq-fixtures}"
            '';
          };
          stage-b-jq-skeleton = pkgs.runCommand "stage-b-jq-skeleton"
            {
              nativeBuildInputs = [ spaghetti-extractor ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment"
              work="$TMPDIR/stage-b-jq-skeleton"
              mkdir -p "$work"
              spaghetti-extractor stage-b-generate-skeleton \
                --original "$fixture_dir/jq-original.exe" \
                --reference-contract "${stage-a-jq-fixtures-check}/generated/jq-reference-contract.json" \
                --target-name jq \
                --source-language c \
                --implementation-mode contract-guided-c \
                --out-dir "$work/skeleton" \
                > "$work/skeleton.stdout"
              out_dir="$out/share/spaghetti-extractor/stage-b/jq/skeleton"
              mkdir -p "$out_dir"
              cp -R "$work/skeleton/." "$out_dir/"
            '';
          stage-b-jq-skeleton-root = pkgs.writeShellApplication {
            name = "stage-b-jq-skeleton-root";
            text = ''
              printf '%s\n' "${stage-b-jq-skeleton}/share/spaghetti-extractor/stage-b/jq/skeleton"
            '';
          };
        in
        {
          default = spaghetti-extractor;
          inherit
            spaghetti-extractor
            stage-a-fixtures
            stage-a-fixtures-check
            stage-a-fixtures-root
            stage-a-jq-fixtures
            stage-a-jq-prepared-proof
            stage-a-jq-reference-contract
            stage-a-jq-fixtures-check
            stage-a-jq-fixtures-root
            stage-a-relational-kernel-cache
            stage-a-relational-tests
            stage-a-relational-tests-schema
            stage-a-relational-tests-contract
            stage-a-relational-tests-state
            stage-a-relational-tests-pipeline
            stage-a-relational-tests-lean
            stage-a-relational-tests-acceptance
            stage-a-relational-tests-acceptance-nested-external
            stage-a-relational-tests-acceptance-direct-stack-read
            stage-a-relational-tests-acceptance-representative
            stage-a-relational-tests-acceptance-terminal-return
            stage-a-relational-tests-acceptance-external-loop
            stage-a-relational-tests-acceptance-input-flag-guard
            stage-a-relational-tests-acceptance-exact-pure-guard
            stage-a-relational-tests-acceptance-immutable-image-word
            stage-a-relational-tests-acceptance-direct-call-stack-writes
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
            program = "${packages.spaghetti-extractor}/bin/spaghetti-extractor";
          };
          spaghetti-extractor = {
            type = "app";
            program = "${packages.spaghetti-extractor}/bin/spaghetti-extractor";
          };
          spaghetti-extractor-slice = {
            type = "app";
            program = "${packages.spaghetti-extractor}/bin/spaghetti-extractor-slice";
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
            spaghetti-extractor
            stage-a-fixtures-check
            stage-a-jq-fixtures-check
            stage-a-relational-tests
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
              packages.spaghetti-extractor
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
