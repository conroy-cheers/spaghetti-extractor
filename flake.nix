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
              unicorn
              z3-solver
            ]
          );
          bochs-conformance = pkgs.callPackage ./nix/bochs-conformance.nix {
            instrumentationSrc = ./tools/bochs-conformance;
          };
          spaghettiExtractorCoreSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./pyproject.toml
              ./src
              ./nix/stage-a-lean-graph.nix
            ];
          };
          spaghetti-extractor-core = pkgs.python3Packages.buildPythonApplication {
            pname = "spaghetti-extractor";
            version = "0.1.0";
            src = spaghettiExtractorCoreSource;
            pyproject = true;

            postPatch = ''
              sed -i '/share\/spaghetti-extractor\/profiles/d' pyproject.toml
            '';

            build-system = with pkgs.python3Packages; [
              setuptools
            ];

            dependencies = with pkgs.python3Packages; [
              capstone
              pefile
              unicorn
              z3-solver
            ];

            doCheck = false;
            pythonImportsCheck = [ "spaghetti_extractor" ];
          };
          spaghetti-extractor-profiles = pkgs.runCommand
            "spaghetti-extractor-profiles"
            { }
            ''
              mkdir -p "$out/share/spaghetti-extractor/profiles"
              cp ${./profiles}/*.json "$out/share/spaghetti-extractor/profiles/"
            '';
          spaghetti-extractor = pkgs.symlinkJoin {
            name = "spaghetti-extractor-0.1.0";
            paths = [
              spaghetti-extractor-core
              spaghetti-extractor-profiles
            ];
            meta.mainProgram = "spaghetti-extractor";
          };
          relationalAnalysisKernelModules = [
            "Formal"
            "ISAQualification"
            "RelationalDecode"
            "RelationalLoader"
            "RelationalMachine"
            "Relational"
            "RelationalPEExecution"
            "RelationalISAQualification"
          ];
          spaghettiExtractorAnalysisPythonFiles = [
            ./src/spaghetti_extractor/__init__.py
            ./src/spaghetti_extractor/contract_tools.py
            ./src/spaghetti_extractor/pe.py
            ./src/spaghetti_extractor/stage_binary.py
            ./src/spaghetti_extractor/util.py
            ./src/spaghetti_extractor/relational/__init__.py
            ./src/spaghetti_extractor/relational/analysis.py
            ./src/spaghetti_extractor/relational/analysis_artifact.py
            ./src/spaghetti_extractor/relational/analysis_cli.py
            ./src/spaghetti_extractor/relational/artifacts.py
            ./src/spaghetti_extractor/relational/binary_inventory.py
            ./src/spaghetti_extractor/relational/callsite_preservation.py
            ./src/spaghetti_extractor/relational/contract.py
            ./src/spaghetti_extractor/relational/diagnostics.py
            ./src/spaghetti_extractor/relational/extraction.py
            ./src/spaghetti_extractor/relational/interfaces.py
            ./src/spaghetti_extractor/relational/ir.py
            ./src/spaghetti_extractor/relational/isa_requirements.py
            ./src/spaghetti_extractor/relational/mapping.py
            ./src/spaghetti_extractor/relational/model.py
            ./src/spaghetti_extractor/relational/pair_normalization.py
            ./src/spaghetti_extractor/relational/pair_normalization_artifact.py
            ./src/spaghetti_extractor/relational/phases.py
            ./src/spaghetti_extractor/relational/pipeline.py
            ./src/spaghetti_extractor/relational/preflight.py
            ./src/spaghetti_extractor/relational/region_facts.py
            ./src/spaghetti_extractor/relational/region_facts_artifact.py
            ./src/spaghetti_extractor/relational/region_facts_cli.py
            ./src/spaghetti_extractor/relational/schema.py
            ./src/spaghetti_extractor/relational/side_extraction.py
            ./src/spaghetti_extractor/relational/side_extraction_artifact.py
            ./src/spaghetti_extractor/relational/side_isa_artifact.py
            ./src/spaghetti_extractor/relational/verdict.py
            ./src/spaghetti_extractor/relational/analyses/__init__.py
            ./src/spaghetti_extractor/relational/analyses/callsite.py
            ./src/spaghetti_extractor/relational/analyses/control.py
            ./src/spaghetti_extractor/relational/analyses/external.py
            ./src/spaghetti_extractor/relational/analyses/invariants.py
            ./src/spaghetti_extractor/relational/analyses/memory.py
            ./src/spaghetti_extractor/relational/analyses/registers.py
            ./src/spaghetti_extractor/relational/analyses/segments.py
            ./src/spaghetti_extractor/relational/analyses/stack.py
            ./src/spaghetti_extractor/relational/lean/__init__.py
            ./src/spaghetti_extractor/relational/lean/analysis_source.py
            ./src/spaghetti_extractor/relational/lean/common.py
            ./src/spaghetti_extractor/relational/lean/compiler.py
            ./src/spaghetti_extractor/relational/lean/expressions.py
          ];
          spaghettiExtractorAnalysisSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              (pkgs.lib.fileset.unions spaghettiExtractorAnalysisPythonFiles)
              (pkgs.lib.fileset.unions (
                map
                  (module: ./src/spaghetti_extractor/lean/StageA + "/${module}.lean")
                  relationalAnalysisKernelModules
              ))
            ];
          };
          spaghetti-extractor-analysis = pkgs.writeShellApplication {
            name = "spaghetti-extractor-analysis";
            runtimeInputs = [ pythonEnv ];
            text = ''
              export PYTHONPATH="${spaghettiExtractorAnalysisSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
              exec python -m spaghetti_extractor.relational.analysis_cli "$@"
            '';
          };
          spaghettiExtractorRegionFactsPythonFiles = [
            ./src/spaghetti_extractor/__init__.py
            ./src/spaghetti_extractor/contract_tools.py
            ./src/spaghetti_extractor/pe.py
            ./src/spaghetti_extractor/stage_binary.py
            ./src/spaghetti_extractor/util.py
            ./src/spaghetti_extractor/relational/__init__.py
            ./src/spaghetti_extractor/relational/artifacts.py
            ./src/spaghetti_extractor/relational/callsite_preservation.py
            ./src/spaghetti_extractor/relational/contract.py
            ./src/spaghetti_extractor/relational/diagnostics.py
            ./src/spaghetti_extractor/relational/extraction.py
            ./src/spaghetti_extractor/relational/model.py
            ./src/spaghetti_extractor/relational/pair_normalization.py
            ./src/spaghetti_extractor/relational/pair_normalization_artifact.py
            ./src/spaghetti_extractor/relational/preflight.py
            ./src/spaghetti_extractor/relational/region_facts.py
            ./src/spaghetti_extractor/relational/region_facts_artifact.py
            ./src/spaghetti_extractor/relational/region_facts_cli.py
            ./src/spaghetti_extractor/relational/schema.py
            ./src/spaghetti_extractor/relational/side_extraction_artifact.py
            ./src/spaghetti_extractor/relational/analyses/__init__.py
            ./src/spaghetti_extractor/relational/analyses/callsite.py
            ./src/spaghetti_extractor/relational/analyses/control.py
            ./src/spaghetti_extractor/relational/analyses/external.py
            ./src/spaghetti_extractor/relational/analyses/invariants.py
            ./src/spaghetti_extractor/relational/analyses/memory.py
            ./src/spaghetti_extractor/relational/analyses/registers.py
            ./src/spaghetti_extractor/relational/analyses/segments.py
            ./src/spaghetti_extractor/relational/analyses/stack.py
            ./src/spaghetti_extractor/relational/lean/__init__.py
            ./src/spaghetti_extractor/relational/lean/analysis_source.py
            ./src/spaghetti_extractor/relational/lean/common.py
            ./src/spaghetti_extractor/relational/lean/compiler.py
            ./src/spaghetti_extractor/relational/lean/expressions.py
          ];
          spaghettiExtractorRegionFactsSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              (pkgs.lib.fileset.unions spaghettiExtractorRegionFactsPythonFiles)
              (pkgs.lib.fileset.unions (
                map
                  (module: ./src/spaghetti_extractor/lean/StageA + "/${module}.lean")
                  relationalAnalysisKernelModules
              ))
            ];
          };
          spaghetti-extractor-region-facts = pkgs.writeShellApplication {
            name = "spaghetti-extractor-region-facts";
            runtimeInputs = [ pythonEnv pkgs.lean4 ];
            text = ''
              export PYTHONPATH="${spaghettiExtractorRegionFactsSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
              exec python -m spaghetti_extractor.relational.region_facts_cli "$@"
            '';
          };
          spaghettiExtractorMappingPythonFiles = [
            ./src/spaghetti_extractor/__init__.py
            ./src/spaghetti_extractor/contract_tools.py
            ./src/spaghetti_extractor/pe.py
            ./src/spaghetti_extractor/stage_binary.py
            ./src/spaghetti_extractor/util.py
            ./src/spaghetti_extractor/relational/__init__.py
            ./src/spaghetti_extractor/relational/artifacts.py
            ./src/spaghetti_extractor/relational/contract.py
            ./src/spaghetti_extractor/relational/mapping.py
            ./src/spaghetti_extractor/relational/mapping_cli.py
            ./src/spaghetti_extractor/relational/model.py
            ./src/spaghetti_extractor/relational/schema.py
          ];
          spaghettiExtractorMappingSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions spaghettiExtractorMappingPythonFiles;
          };
          spaghetti-extractor-mapping = pkgs.writeShellApplication {
            name = "spaghetti-extractor-mapping";
            runtimeInputs = [ pythonEnv ];
            text = ''
              export PYTHONPATH="${spaghettiExtractorMappingSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
              exec python -m spaghetti_extractor.relational.mapping_cli "$@"
            '';
          };
          spaghettiExtractorSidePythonFiles = [
            ./src/spaghetti_extractor/__init__.py
            ./src/spaghetti_extractor/contract_tools.py
            ./src/spaghetti_extractor/pe.py
            ./src/spaghetti_extractor/stage_binary.py
            ./src/spaghetti_extractor/util.py
            ./src/spaghetti_extractor/relational/__init__.py
            ./src/spaghetti_extractor/relational/artifacts.py
            ./src/spaghetti_extractor/relational/binary_inventory.py
            ./src/spaghetti_extractor/relational/contract.py
            ./src/spaghetti_extractor/relational/extraction.py
            ./src/spaghetti_extractor/relational/isa_requirements.py
            ./src/spaghetti_extractor/relational/model.py
            ./src/spaghetti_extractor/relational/preflight.py
            ./src/spaghetti_extractor/relational/schema.py
            ./src/spaghetti_extractor/relational/side_cli.py
            ./src/spaghetti_extractor/relational/side_extraction.py
            ./src/spaghetti_extractor/relational/side_extraction_artifact.py
            ./src/spaghetti_extractor/relational/side_isa_artifact.py
            ./src/spaghetti_extractor/relational/analyses/__init__.py
            ./src/spaghetti_extractor/relational/analyses/external.py
            ./src/spaghetti_extractor/relational/lean/__init__.py
            ./src/spaghetti_extractor/relational/lean/analysis_source.py
            ./src/spaghetti_extractor/relational/lean/common.py
            ./src/spaghetti_extractor/relational/lean/compiler.py
            ./src/spaghetti_extractor/relational/lean/expressions.py
          ];
          spaghettiExtractorSideSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              (pkgs.lib.fileset.unions spaghettiExtractorSidePythonFiles)
              (pkgs.lib.fileset.unions (
                map
                  (module: ./src/spaghetti_extractor/lean/StageA + "/${module}.lean")
                  relationalAnalysisKernelModules
              ))
            ];
          };
          spaghetti-extractor-side = pkgs.writeShellApplication {
            name = "spaghetti-extractor-side";
            runtimeInputs = [ pythonEnv ];
            text = ''
              export PYTHONPATH="${spaghettiExtractorSideSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
              exec python -m spaghetti_extractor.relational.side_cli "$@"
            '';
          };
          spaghettiExtractorNormalizationPythonFiles = [
            ./src/spaghetti_extractor/__init__.py
            ./src/spaghetti_extractor/pe.py
            ./src/spaghetti_extractor/stage_binary.py
            ./src/spaghetti_extractor/util.py
            ./src/spaghetti_extractor/relational/__init__.py
            ./src/spaghetti_extractor/relational/artifacts.py
            ./src/spaghetti_extractor/relational/contract.py
            ./src/spaghetti_extractor/relational/extraction.py
            ./src/spaghetti_extractor/relational/model.py
            ./src/spaghetti_extractor/relational/pair_normalization.py
            ./src/spaghetti_extractor/relational/pair_normalization_artifact.py
            ./src/spaghetti_extractor/relational/pair_normalization_cli.py
            ./src/spaghetti_extractor/relational/preflight.py
            ./src/spaghetti_extractor/relational/schema.py
            ./src/spaghetti_extractor/relational/side_extraction_artifact.py
            ./src/spaghetti_extractor/relational/analyses/__init__.py
            ./src/spaghetti_extractor/relational/analyses/external.py
            ./src/spaghetti_extractor/relational/lean/__init__.py
            ./src/spaghetti_extractor/relational/lean/analysis_source.py
            ./src/spaghetti_extractor/relational/lean/common.py
            ./src/spaghetti_extractor/relational/lean/compiler.py
            ./src/spaghetti_extractor/relational/lean/expressions.py
          ];
          spaghettiExtractorNormalizationSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              (pkgs.lib.fileset.unions spaghettiExtractorNormalizationPythonFiles)
              (pkgs.lib.fileset.unions (
                map
                  (module: ./src/spaghetti_extractor/lean/StageA + "/${module}.lean")
                  relationalAnalysisKernelModules
              ))
            ];
          };
          spaghetti-extractor-normalize = pkgs.writeShellApplication {
            name = "spaghetti-extractor-normalize";
            runtimeInputs = [ pythonEnv ];
            text = ''
              export PYTHONPATH="${spaghettiExtractorNormalizationSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
              exec python -m spaghetti_extractor.relational.pair_normalization_cli "$@"
            '';
          };
          stage-a-analysis-source-boundary-check = pkgs.runCommand
            "stage-a-analysis-source-boundary-check"
            { }
            ''
              source="${spaghettiExtractorAnalysisSource}/src/spaghetti_extractor"
              test -f "$source/relational/analysis_cli.py"
              test -f "$source/relational/binary_inventory.py"
              test -f "$source/relational/lean/analysis_source.py"
              test -f "$source/relational/lean/compiler.py"
              test ! -e "$source/cli.py"
              test ! -e "$source/stage_b.py"
              test ! -e "$source/relational/build.py"
              test ! -e "$source/relational/executor.py"
              test ! -e "$source/relational/proof_diagnostics.py"
              test ! -e "$source/relational/lean/acceptance.py"
              test ! -e "$source/relational/lean/generation.py"
              test ! -e "$source/relational/lean/segments.py"
              test "$(find "$source/lean/StageA" -type f -name '*.lean' | wc -l)" -eq 8
              side="${spaghettiExtractorSideSource}/src/spaghetti_extractor"
              test -f "$side/relational/side_extraction.py"
              test -f "$side/relational/binary_inventory.py"
              test -f "$side/relational/side_cli.py"
              test ! -e "$side/relational/analysis_cli.py"
              test ! -e "$side/relational/analysis.py"
              test ! -e "$side/relational/analysis_artifact.py"
              test ! -e "$side/relational/pipeline.py"
              test ! -e "$side/relational/phases.py"
              test ! -e "$side/relational/mapping.py"
              test ! -e "$side/relational/verdict.py"
              ${spaghetti-extractor-side}/bin/spaghetti-extractor-side --help >/dev/null
              mapping="${spaghettiExtractorMappingSource}/src/spaghetti_extractor"
              test -f "$mapping/relational/mapping.py"
              test -f "$mapping/relational/mapping_cli.py"
              test ! -e "$mapping/relational/analysis.py"
              test ! -e "$mapping/relational/analysis_cli.py"
              test ! -e "$mapping/relational/extraction.py"
              test ! -e "$mapping/relational/pipeline.py"
              ${spaghetti-extractor-mapping}/bin/spaghetti-extractor-mapping --help >/dev/null
              normalization="${spaghettiExtractorNormalizationSource}/src/spaghetti_extractor"
              test -f "$normalization/relational/pair_normalization.py"
              test -f "$normalization/relational/pair_normalization_artifact.py"
              test ! -e "$normalization/relational/analysis.py"
              test ! -e "$normalization/relational/analysis_artifact.py"
              test ! -e "$normalization/relational/analysis_cli.py"
              test ! -e "$normalization/relational/pipeline.py"
              test ! -e "$normalization/relational/phases.py"
              test ! -e "$normalization/relational/verdict.py"
              ${spaghetti-extractor-normalize}/bin/spaghetti-extractor-normalize --help >/dev/null
              region_facts="${spaghettiExtractorRegionFactsSource}/src/spaghetti_extractor"
              test -f "$region_facts/relational/region_facts.py"
              test -f "$region_facts/relational/region_facts_artifact.py"
              test -f "$region_facts/relational/region_facts_cli.py"
              test ! -e "$region_facts/relational/pipeline.py"
              test ! -e "$region_facts/relational/analysis.py"
              test ! -e "$region_facts/relational/analysis_artifact.py"
              test ! -e "$region_facts/relational/build.py"
              test ! -e "$region_facts/relational/lean/generation.py"
              ${spaghetti-extractor-region-facts}/bin/spaghetti-extractor-region-facts --help >/dev/null
              touch "$out"
            '';
          singlestep-80386-conformance =
            pkgs.callPackage ./nix/singlestep-80386-conformance.nix {
              inherit spaghetti-extractor;
            };
          stageABochs80386ShardIndices = pkgs.lib.range 0 15;
          stageABochs80386Opcodes = [
            "6601"
            "6605"
            "6629"
            "6631"
            "6639"
            "6685"
            "6689"
            "668B"
            "66B8"
          ];
          stageABochs80386Shards = pkgs.lib.concatMap
            (opcode:
              map
                (shardIndex:
                  let
                    imported =
                      singlestep-80386-conformance.importDerivations.${opcode}.${toString shardIndex};
                    shardName = "${pkgs.lib.toLower opcode}-${toString shardIndex}-of-16";
                  in
                  pkgs.runCommand "stage-a-bochs-80386-${shardName}"
                    {
                      nativeBuildInputs = [
                        bochs-conformance
                        pkgs.jq
                        pkgs.lean4
                        spaghetti-extractor
                      ];
                      preferLocalBuild = false;
                      allowSubstitutes = true;
                    }
                    ''
                      shard_out="$out/${opcode}/shard-${toString shardIndex}-of-16"
                      mkdir -p "$shard_out"
                      export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-isa-kernel-cache}"
                      spaghetti-extractor stage-a-check-isa-conformance \
                        --corpus ${imported}/corpus.json \
                        --backend bochs \
                        --bochs-runner ${bochs-conformance}/bin/spaghetti-bochs-conformance-runner \
                        --out "$shard_out/report.json" \
                        > "$shard_out/check.stdout"
                      jq -e \
                        '.status == "pass"
                         and .qualification == "qualified"
                         and .counts.cases > 0
                         and .counts.matched == .counts.cases
                         and .counts.mismatched == 0
                         and .counts.unsupported == 0
                         and .counts.errors == 0
                         and .proof_authority == false
                        and .closes_stage_a_proof == false' \
                        "$shard_out/check.stdout" > /dev/null
                      spaghetti-extractor stage-a-check-isa-conformance \
                        --corpus ${imported}/corpus.json \
                        --backend unicorn \
                        --out "$shard_out/unicorn-report.json" \
                        > "$shard_out/unicorn-check.stdout"
                      jq -e \
                        '.status == "pass"
                         and .qualification == "qualified"
                         and .counts.cases > 0
                         and .counts.matched == .counts.cases
                         and .counts.mismatched == 0
                         and .counts.unsupported == 0
                         and .counts.errors == 0
                         and .proof_authority == false
                         and .closes_stage_a_proof == false' \
                        "$shard_out/unicorn-check.stdout" > /dev/null
                      spaghetti-extractor stage-a-check-isa-conformance \
                        --corpus ${imported}/corpus.json \
                        --backend lean \
                        --out "$shard_out/lean-report.json" \
                        --forms-out "$shard_out/lean-forms.json" \
                        > "$shard_out/lean-check.stdout"
                      jq -e \
                        '.status == "pass"
                         and .qualification == "qualified"
                         and .counts.cases > 0
                         and .counts.matched == .counts.cases
                         and .counts.mismatched == 0
                         and .counts.unsupported == 0
                         and .counts.errors == 0
                         and .proof_authority == false
                         and .closes_stage_a_proof == false' \
                        "$shard_out/lean-check.stdout" > /dev/null
                      corpus_sha256="$(sha256sum ${imported}/corpus.json | cut -d ' ' -f 1)"
                      report_sha256="$(sha256sum "$shard_out/report.json" | cut -d ' ' -f 1)"
                      unicorn_report_sha256="$(sha256sum "$shard_out/unicorn-report.json" | cut -d ' ' -f 1)"
                      lean_report_sha256="$(sha256sum "$shard_out/lean-report.json" | cut -d ' ' -f 1)"
                      lean_forms_sha256="$(sha256sum "$shard_out/lean-forms.json" | cut -d ' ' -f 1)"
                      import_manifest_sha256="$(sha256sum ${imported}/manifest.json | cut -d ' ' -f 1)"
                      runner_sha256="$(sha256sum ${bochs-conformance}/bin/spaghetti-bochs-conformance-runner | cut -d ' ' -f 1)"
                      guest_sha256="$(sha256sum ${bochs-conformance}/libexec/spaghetti-extractor/bochs-conformance/guest.img | cut -d ' ' -f 1)"
                      bochs_sha256="$(sha256sum ${bochs-conformance}/libexec/spaghetti-extractor/bochs-conformance/bochs-raw | cut -d ' ' -f 1)"
                      jq -n \
                        --arg opcode ${pkgs.lib.escapeShellArg opcode} \
                        --argjson shard_index ${toString shardIndex} \
                        --argjson shard_count 16 \
                        --arg bochs_store_path ${pkgs.lib.escapeShellArg (toString bochs-conformance)} \
                        --arg corpus_store_path ${pkgs.lib.escapeShellArg (toString imported)} \
                        --arg corpus_sha256 "$corpus_sha256" \
                        --arg report_sha256 "$report_sha256" \
                        --arg unicorn_report_sha256 "$unicorn_report_sha256" \
                        --arg lean_report_sha256 "$lean_report_sha256" \
                        --arg lean_forms_sha256 "$lean_forms_sha256" \
                        --arg import_manifest_sha256 "$import_manifest_sha256" \
                        --arg runner_sha256 "$runner_sha256" \
                        --arg guest_sha256 "$guest_sha256" \
                        --arg bochs_sha256 "$bochs_sha256" \
                        --slurpfile package_metadata ${bochs-conformance}/share/spaghetti-extractor/bochs-conformance/package-metadata.json \
                        '{
                          format: "stage-a-bochs-conformance-execution-v1",
                          source: {
                            opcode: $opcode,
                            shard_index: $shard_index,
                            shard_count: $shard_count,
                            corpus_store_path: $corpus_store_path,
                            corpus_sha256: $corpus_sha256,
                            import_manifest_sha256: $import_manifest_sha256
                          },
                          backend: {
                            store_path: $bochs_store_path,
                            runner_sha256: $runner_sha256,
                            guest_sha256: $guest_sha256,
                            bochs_binary_sha256: $bochs_sha256,
                            package: $package_metadata[0]
                          },
                          report: {
                            path: "report.json",
                            sha256: $report_sha256
                          },
                          unicorn_report: {
                            path: "unicorn-report.json",
                            sha256: $unicorn_report_sha256
                          },
                          lean_report: {
                            path: "lean-report.json",
                            sha256: $lean_report_sha256
                          },
                          lean_forms: {
                            path: "lean-forms.json",
                            sha256: $lean_forms_sha256
                          },
                          trust: {
                            role: "isa_conformance_evidence_only",
                            proof_authority: false,
                            closes_stage_a_proof: false
                          }
                        }' > "$shard_out/execution-manifest.json"
                      ln -s ${imported}/manifest.json "$shard_out/import-manifest.json"
                      ln -s ${imported}/corpus.json "$shard_out/corpus.json"
                    '')
                stageABochs80386ShardIndices)
            stageABochs80386Opcodes;
          stageABochs80386EvidenceIndex = pkgs.lib.concatMap
            (opcode:
              map
                (shardIndex: {
                  inherit opcode;
                  shard_index = shardIndex;
                  shard_count = 16;
                  path = "${opcode}/shard-${toString shardIndex}-of-16/execution-manifest.json";
                })
                stageABochs80386ShardIndices)
            stageABochs80386Opcodes;
          stage-a-isa-conformance-bochs-80386 = pkgs.runCommand
            "stage-a-isa-conformance-bochs-80386"
            { }
            ''
              mkdir -p "$out"
              ${pkgs.lib.concatMapStringsSep "\n"
                (opcode:
                  pkgs.lib.concatMapStringsSep "\n"
                    (shardIndex:
                      let
                        shard = builtins.elemAt stageABochs80386Shards (
                          (pkgs.lib.lists.findFirstIndex
                            (value: value == opcode) 0 stageABochs80386Opcodes)
                          * builtins.length stageABochs80386ShardIndices
                          + shardIndex
                        );
                        relative = "${opcode}/shard-${toString shardIndex}-of-16";
                      in ''
                        mkdir -p "$out/${opcode}"
                        ln -s "${shard}/${relative}" "$out/${relative}"
                      '')
                    stageABochs80386ShardIndices)
                stageABochs80386Opcodes}
              cat > "$out/index.json" <<'JSON'
              ${builtins.toJSON {
                format = "stage-a-isa-conformance-evidence-set-v1";
                suite = "SingleStepTests-80386-Bochs-Unicorn-Lean";
                shards = stageABochs80386EvidenceIndex;
                trust = {
                  role = "isa_conformance_evidence_only";
                  proof_authority = false;
                  closes_stage_a_proof = false;
                };
              }}
              JSON
            '';
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
          stageAGnuHelloCommonCflags = "-g0 -fno-asynchronous-unwind-tables -fno-ident -fno-inline -fno-inline-functions -fno-inline-small-functions -fno-ipa-cp -fno-ipa-sra -fno-ipa-icf";
          stageAGnuHelloOriginalCflags = "-O2 -fno-align-functions -fno-align-labels -fno-align-loops -fno-align-jumps ${stageAGnuHelloCommonCflags}";
          stageAGnuHelloCandidateCflags = "-O2 -falign-functions=32 -falign-labels=16 -falign-loops=16 -falign-jumps=16 ${stageAGnuHelloCommonCflags}";
          stageAGnuHelloLayoutLdflags = pkgs.lib.concatStringsSep " " [
            "-Wl,--section-start=.data=0x420000"
            "-Wl,--section-start=.rdata=0x421000"
            "-Wl,--section-start=.bss=0x430000"
            "-Wl,--section-start=.edata=0x431000"
            "-Wl,--section-start=.idata=0x432000"
            "-Wl,--section-start=.tls=0x433000"
            "-Wl,--section-start=.reloc=0x434000"
          ];
          mkStageAGnuHello =
            label: cflags:
            mingw32.hello.overrideAttrs (old: {
              pname = "stage-a-gnu-hello-${label}";
              doCheck = false;
              doInstallCheck = false;
              dontStrip = true;
              outputs = [ "out" ];
              env = (old.env or { }) // {
                CFLAGS = cflags;
                LDFLAGS = "${stageAGnuHelloLayoutLdflags} -Wl,-Map,hello-${label}.map";
              };
              postFixup = "";
              postInstall =
                (old.postInstall or "")
                + ''
                  map_path="$(find . -name 'hello-${label}.map' -print -quit)"
                  if [ -z "$map_path" ]; then
                    echo "missing hello-${label}.map" >&2
                    exit 1
                  fi
                  fixture_dir="$out/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/${label}"
                  mkdir -p "$fixture_dir"
                  cp "$map_path" "$fixture_dir/hello.map"
                  cp "$out/bin/hello.exe" "$fixture_dir/hello.exe"
                '';
              meta = (old.meta or { }) // {
                platforms = (old.meta.platforms or [ ]) ++ [ "i686-windows" ];
              };
            });
          stage-a-gnu-hello-original = mkStageAGnuHello "original" stageAGnuHelloOriginalCflags;
          stage-a-gnu-hello-candidate = mkStageAGnuHello "candidate" stageAGnuHelloCandidateCflags;
          stageAMinimalHelloCommonCflags = "-g0 -fno-asynchronous-unwind-tables -fno-ident";
          stageAMinimalHelloOriginalCflags = "-O2 -fno-align-functions -fno-align-labels -fno-align-loops -fno-align-jumps ${stageAMinimalHelloCommonCflags}";
          stageAMinimalHelloCandidateCflags = "-O2 -falign-functions=32 -falign-labels=16 -falign-loops=16 -falign-jumps=16 ${stageAMinimalHelloCommonCflags}";
          stageAMinimalHelloLayoutLdflags = stageAGnuHelloLayoutLdflags;
          mkStageAMinimalHello =
            label: cflags:
            mingw32.stdenv.mkDerivation {
              pname = "stage-a-minimal-hello-${label}";
              version = "1";
              src = ./tools/stage-a-fixtures;
              dontConfigure = true;
              dontStrip = true;

              buildPhase = ''
                runHook preBuild
                $CC ${cflags} ${stageAMinimalHelloLayoutLdflags} \
                  -Wl,-Map,hello-${label}.map \
                  -o hello.exe stage_a_hello.c
                runHook postBuild
              '';

              installPhase = ''
                runHook preInstall
                fixture_dir="$out/share/spaghetti-extractor/stage-a-minimal-hello-fixtures/${label}"
                mkdir -p "$fixture_dir"
                cp hello.exe "$fixture_dir/hello.exe"
                cp "hello-${label}.map" "$fixture_dir/hello.map"
                runHook postInstall
              '';
            };
          stage-a-minimal-hello-original =
            mkStageAMinimalHello "original" stageAMinimalHelloOriginalCflags;
          stage-a-minimal-hello-candidate =
            mkStageAMinimalHello "candidate" stageAMinimalHelloCandidateCflags;
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
              jq -e '
                .format == "stage-a-relational-proof-check-v1" and
                .status == "pass" and
                .claim_scope.kind == "whole_program_observational_equivalence" and
                .claim_scope.whole_program_observational_equivalence == true and
                .lean_check.status == "checked" and
                .lean_check.theorem ==
                  "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent" and
                ([.checks[]] | all)
              ' "$work/proof-check.json" >/dev/null
              jq -e '
                .format == "stage-a-relational-verdict-v1" and
                .verdict == "pass" and
                .counts.failed == 0 and
                .counts.incomplete == 0 and
                .counts.incomplete_assumptions == 0
              ' "$work/proof/verdict.json" >/dev/null
              jq -e '
                .format == "stage-a-whole-program-acceptance-v1" and
                .status == "ready" and
                .theorem ==
                  "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent" and
                .required_theorem ==
                  "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent"
              ' "$work/proof/whole-program-acceptance.json" >/dev/null
              jq -e '
                .format == "stage-a-composition-progress-v1" and
                .status == "ready_for_lean" and
                .counts.roots == 1 and
                .counts.rooted_reachable_nodes == 1 and
                .counts.rooted_reachable_feasible_edges == 1 and
                .counts.rooted_refined_segments == 1 and
                .counts.rooted_segment_refinement_frontier_edges == 0 and
                .counts.rooted_decoded_control_frontier_nodes == 0 and
                .counts.unresolved_indirect_control_nodes == 0 and
                .counts.unsupported_instructions == 0 and
                .counts.acceptance_blockers == 0
              ' "$work/proof/composition-progress.json" >/dev/null
              jq -e '
                .format == "stage-a-lean-module-graph-v1" and
                .expected_final_theorem ==
                  "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent" and
                (.approved_axioms | sort) ==
                  (["propext", "Classical.choice", "Quot.sound"] | sort) and
                .acceptance.status == "ready" and
                .acceptance.theorem ==
                  "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent" and
                .acceptance.blockers == []
              ' "$work/proof/module-graph.json" >/dev/null
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
          stage-a-exit-fixtures = mingw32.stdenv.mkDerivation {
            pname = "stage-a-exit-fixtures";
            version = "1";
            src = ./tools/stage-a-fixtures;
            dontConfigure = true;
            dontStrip = true;

            buildPhase = ''
              runHook preBuild
              common_flags=(
                -x assembler-with-cpp
                -g0
                -nostdlib
                -Wl,--exclude-all-symbols
                -Wl,--subsystem,console
                -Wl,-e,_mainCRTStartup
                -Wl,--disable-dynamicbase
                -Wl,--image-base,0x400000
                -Wl,--section-alignment,0x1000
                -Wl,--file-alignment,0x400
              )
              $CC "''${common_flags[@]}" -Wl,-Map,exit-original.map \
                -o exit-original.exe stage_a_exit.S -lkernel32
              $CC -DSTAGE_A_CANDIDATE "''${common_flags[@]}" \
                -Wl,-Map,exit-candidate.map \
                -o exit-candidate.exe stage_a_exit.S -lkernel32
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall
              fixture_dir="$out/share/spaghetti-extractor/stage-a-fixtures/exit-distinct"
              mkdir -p "$fixture_dir"
              cp exit-original.exe exit-candidate.exe \
                exit-original.map exit-candidate.map "$fixture_dir/"
              runHook postInstall
            '';
          };
          stage-a-exit-static-map = pkgs.runCommand "stage-a-exit-static-map"
            {
              nativeBuildInputs = [ spaghetti-extractor-core ];
            }
            ''
              fixture_dir="${stage-a-exit-fixtures}/share/spaghetti-extractor/stage-a-fixtures/exit-distinct"
              mkdir -p "$out"
              spaghetti-extractor stage-a-generate-map \
                --original "$fixture_dir/exit-original.exe" \
                --candidate "$fixture_dir/exit-candidate.exe" \
                --linker-map-original "$fixture_dir/exit-original.map" \
                --linker-map-candidate "$fixture_dir/exit-candidate.map" \
                --original-flags "handwritten-mov-exit-42" \
                --candidate-flags "handwritten-xor-add-exit-42" \
                --out "$out/exit-block-map.json" \
                --layout-contract-out "$out/exit-layout-contract.json" \
                > "$out/generate-map.stdout"
            '';
          stage-a-exit-relation-contract = pkgs.runCommand "stage-a-exit-relation-contract"
            {
              nativeBuildInputs = [ spaghetti-extractor-core ];
            }
            ''
              fixture_dir="${stage-a-exit-fixtures}/share/spaghetti-extractor/stage-a-fixtures/exit-distinct"
              mkdir -p "$out"
              spaghetti-extractor stage-a-generate-relation-contract \
                --original "$fixture_dir/exit-original.exe" \
                --candidate "$fixture_dir/exit-candidate.exe" \
                --mapping "${stage-a-exit-static-map}/exit-block-map.json" \
                --external-profile "${./profiles/pe32-kernel32-console-lockstep-v1.json}" \
                --out "$out/exit-relation-contract.json" \
                > "$out/generate-relation.stdout"
            '';
          stage-a-exit-prepared-proof = pkgs.runCommand "stage-a-exit-prepared-proof"
            {
              nativeBuildInputs = [ spaghetti-extractor-core pkgs.lean4 ];
            }
            ''
              fixture_dir="${stage-a-exit-fixtures}/share/spaghetti-extractor/stage-a-fixtures/exit-distinct"
              work="$TMPDIR/stage-a-exit"
              mkdir -p "$work"
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-relational-kernel-cache}"
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_JOBS=4
              SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$work/cache" \
                spaghetti-extractor stage-a-prepare-relational \
                  --original "$fixture_dir/exit-original.exe" \
                  --candidate "$fixture_dir/exit-candidate.exe" \
                  --relation-contract "${stage-a-exit-relation-contract}/exit-relation-contract.json" \
                  --out "$work/relational-v3" \
                  > "$work/prepare.stdout"
              mkdir -p "$out/report"
              cp "${stage-a-exit-static-map}/exit-block-map.json" \
                "${stage-a-exit-static-map}/exit-layout-contract.json" \
                "${stage-a-exit-relation-contract}/exit-relation-contract.json" \
                "$out/report/"
              cp -R "$work/relational-v3" "$out/report/relational-v3"
              cp "$work/prepare.stdout" "$out/report/"
            '';
          stage-a-exit-evidence-bundle =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              prepared = stage-a-exit-prepared-proof + "/report/relational-v3";
              targetNodes = [ "relationalacceptance" ];
              targetBundle = true;
            };
          stage-a-exit-check = pkgs.runCommand "stage-a-exit-check"
            {
              nativeBuildInputs = [ pkgs.jq ];
            }
            ''
              prepared="${stage-a-exit-prepared-proof}/report/relational-v3"
              jq -e '
                .status == "prepared" and
                .original_sha256 != .candidate_sha256 and
                .expected_final_theorem ==
                  "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent" and
                .acceptance.status == "ready" and
                .acceptance.blockers == [] and
                .acceptance.launch_realizability.profile ==
                  "paired-preferred-base-import-stack-v1" and
                (.acceptance.launch_realizability.import_bindings | length) == 1 and
                .composition_progress.status == "ready_for_lean" and
                .composition_progress.counts.roots == 1 and
                .composition_progress.counts.rooted_reachable_nodes == 2 and
                .composition_progress.counts.rooted_reachable_feasible_edges == 1 and
                .composition_progress.counts.rooted_refined_segments == 1 and
                .composition_progress.counts.acceptance_blockers == 0 and
                .composition_progress.counts.unsupported_instructions == 0
              ' "$prepared/prepared-proof.json" >/dev/null
              jq -e '
                .format == "stage-a-lean-target-bundle-v1" and
                .lean_trust == 0 and
                ([.nodes[].id] | index("relationalacceptance")) != null
              ' "${stage-a-exit-evidence-bundle}/bundle.json" >/dev/null
              mkdir -p "$out"
              cp "$prepared/prepared-proof.json" "$out/"
              cp "${stage-a-exit-evidence-bundle}/bundle.json" \
                "$out/evidence-bundle.json"
            '';
          stage-a-winapi-hello-fixtures = mingw32.stdenv.mkDerivation {
            pname = "stage-a-winapi-hello-fixtures";
            version = "1";
            src = ./tools/stage-a-fixtures;
            dontConfigure = true;
            dontStrip = true;

            buildPhase = ''
              runHook preBuild
              common_flags=(
                -x assembler-with-cpp
                -g0
                -nostdlib
                -Wl,--exclude-all-symbols
                -Wl,--subsystem,console
                -Wl,-e,_mainCRTStartup
                -Wl,--disable-dynamicbase
                -Wl,--image-base,0x400000
                -Wl,--section-alignment,0x1000
                -Wl,--file-alignment,0x400
              )
              $CC "''${common_flags[@]}" -Wl,-Map,hello-original.map \
                -o hello-original.exe stage_a_winapi_hello.S -lkernel32
              $CC -DSTAGE_A_CANDIDATE "''${common_flags[@]}" \
                -Wl,-Map,hello-candidate.map \
                -o hello-candidate.exe stage_a_winapi_hello.S -lkernel32
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall
              fixture_dir="$out/share/spaghetti-extractor/stage-a-fixtures/winapi-hello"
              mkdir -p "$fixture_dir"
              cp hello-original.exe hello-candidate.exe \
                hello-original.map hello-candidate.map "$fixture_dir/"
              runHook postInstall
            '';
          };
          stage-a-winapi-hello-static-map =
            pkgs.runCommand "stage-a-winapi-hello-static-map"
              {
                nativeBuildInputs = [ spaghetti-extractor-core ];
              }
              ''
                fixture_dir="${stage-a-winapi-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/winapi-hello"
                mkdir -p "$out"
                spaghetti-extractor stage-a-generate-map \
                  --original "$fixture_dir/hello-original.exe" \
                  --candidate "$fixture_dir/hello-candidate.exe" \
                  --linker-map-original "$fixture_dir/hello-original.map" \
                  --linker-map-candidate "$fixture_dir/hello-candidate.map" \
                  --original-flags "handwritten-winapi-console" \
                  --candidate-flags "handwritten-winapi-console-reachable-nop" \
                  --out "$out/hello-block-map.json" \
                  --layout-contract-out "$out/hello-layout-contract.json" \
                  > "$out/generate-map.stdout"
              '';
          stage-a-winapi-hello-relation-contract =
            pkgs.runCommand "stage-a-winapi-hello-relation-contract"
              {
                nativeBuildInputs = [ spaghetti-extractor-core ];
              }
              ''
                fixture_dir="${stage-a-winapi-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/winapi-hello"
                mkdir -p "$out"
                spaghetti-extractor stage-a-generate-relation-contract \
                  --original "$fixture_dir/hello-original.exe" \
                  --candidate "$fixture_dir/hello-candidate.exe" \
                  --mapping "${stage-a-winapi-hello-static-map}/hello-block-map.json" \
                  --external-profile "${./profiles/pe32-kernel32-console-lockstep-v1.json}" \
                  --out "$out/hello-relation-contract.json" \
                  > "$out/generate-relation.stdout"
              '';
          stage-a-winapi-hello-prepared-proof =
            pkgs.runCommand "stage-a-winapi-hello-prepared-proof"
              {
                nativeBuildInputs = [ spaghetti-extractor-core pkgs.lean4 ];
              }
              ''
                fixture_dir="${stage-a-winapi-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/winapi-hello"
                work="$TMPDIR/stage-a-winapi-hello"
                mkdir -p "$work"
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-relational-kernel-cache}"
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_JOBS=8
                SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$work/cache" \
                  spaghetti-extractor stage-a-prepare-relational \
                    --original "$fixture_dir/hello-original.exe" \
                    --candidate "$fixture_dir/hello-candidate.exe" \
                    --relation-contract "${stage-a-winapi-hello-relation-contract}/hello-relation-contract.json" \
                    --out "$work/relational-v3" \
                    > "$work/prepare.stdout"
                mkdir -p "$out/report"
                cp "${stage-a-winapi-hello-static-map}/hello-block-map.json" \
                  "${stage-a-winapi-hello-static-map}/hello-layout-contract.json" \
                  "${stage-a-winapi-hello-relation-contract}/hello-relation-contract.json" \
                  "$out/report/"
                cp -R "$work/relational-v3" "$out/report/relational-v3"
                cp "$work/prepare.stdout" "$out/report/"
              '';
          stage-a-winapi-hello-proof-audit =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              prepared =
                stage-a-winapi-hello-prepared-proof + "/report/relational-v3";
            };
          stage-a-winapi-hello-check =
            pkgs.runCommand "stage-a-winapi-hello-check"
              {
                nativeBuildInputs = [ pkgs.jq ];
              }
              ''
                prepared="${stage-a-winapi-hello-prepared-proof}/report/relational-v3"
                jq -e '
                  .status == "prepared" and
                  .original_sha256 != .candidate_sha256 and
                  .expected_final_theorem ==
                    "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent" and
                  .acceptance.status == "ready" and
                  .acceptance.blockers == [] and
                  .acceptance.launch_realizability.profile ==
                    "paired-preferred-base-import-stack-v1" and
                  (.acceptance.launch_realizability.import_bindings | length) == 3 and
                  .composition_progress.status == "ready_for_lean" and
                  .composition_progress.counts.roots == 1 and
                  .composition_progress.counts.rooted_reachable_nodes == 11 and
                  .composition_progress.counts.rooted_reachable_feasible_edges == 8 and
                  .composition_progress.counts.rooted_refined_segments == 8 and
                  .composition_progress.counts.rooted_segment_refinement_frontier_edges == 0 and
                  .composition_progress.counts.rooted_decoded_control_frontier_nodes == 0 and
                  .composition_progress.counts.rooted_stack_invariant_frontier_nodes == 0 and
                  .composition_progress.counts.rooted_relational_call_frame_frontier_nodes == 0 and
                  .composition_progress.counts.unresolved_indirect_control_nodes == 0 and
                  .composition_progress.counts.unsupported_instructions == 0 and
                  .composition_progress.counts.acceptance_blockers == 0
                ' "$prepared/prepared-proof.json" >/dev/null
                jq -e '
                  .format == "stage-a-lean-module-graph-v1" and
                  ([.nodes[] |
                    select(
                      (.modules | length) == 1 and
                      (.modules[0] | startswith("RelationalLaunch")) and
                      (.modules[0] | contains("Leaf"))
                    )] | length) == 16 and
                  all(.nodes[] |
                    select(
                      (.modules | length) == 1 and
                      (.modules[0] | startswith("RelationalLaunch")) and
                      (.modules[0] | contains("Leaf"))
                    );
                    .resource_class == "high-memory" and
                    .estimated_memory_mb >= 4096
                  ) and
                  any(.nodes[];
                    .modules == ["RelationalLaunchRealizabilityCertificate"] and
                    .resource_class == "light"
                  ) and
                  any(.nodes[];
                    .modules == ["RelationalLaunchCheckCertificate"] and
                    (.dependencies | length) == 16
                  )
                ' "$prepared/module-graph.json" >/dev/null
                jq -e '
                  .format == "stage-a-relational-lean-audit-v1" and
                  .status == "checked" and
                  .theorem ==
                    "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent" and
                  .lean_trust == 0 and
                  .unexpected_axioms == []
                ' "${stage-a-winapi-hello-proof-audit}/audit.json" >/dev/null
                mkdir -p "$out"
                cp "$prepared/prepared-proof.json" "$out/"
                cp "${stage-a-winapi-hello-proof-audit}/audit.json" \
                  "$out/lean-audit.json"
                cp "${stage-a-winapi-hello-proof-audit}/node-provenance.json" \
                  "$out/lean-node-provenance.json"
              '';
          stage-a-exit-behavior-smoke =
            pkgs.runCommand "stage-a-exit-behavior-smoke"
              {
                nativeBuildInputs = [
                  pkgs.wineWow64Packages.stable
                  pkgs.xvfb-run
                ];
              }
              ''
                test -s "${stage-a-exit-check}/prepared-proof.json"
                fixture_dir="${stage-a-exit-fixtures}/share/spaghetti-extractor/stage-a-fixtures/exit-distinct"
                export HOME="$TMPDIR/home"
                export WINEPREFIX="$TMPDIR/wine"
                export WINEDEBUG=-all
                export WINEDLLOVERRIDES="mscoree,mshtml="
                mkdir -p "$HOME"
                set +e
                xvfb-run -a wine "$fixture_dir/exit-candidate.exe" \
                  > "$TMPDIR/stdout" 2> "$TMPDIR/stderr"
                status=$?
                set -e
                if [ "$status" -ne 42 ]; then
                  cat "$TMPDIR/stdout" >&2
                  cat "$TMPDIR/stderr" >&2
                  echo "candidate exit status was $status, expected 42" >&2
                  exit 1
                fi
                test ! -s "$TMPDIR/stdout"
                mkdir -p "$out"
                cp "$TMPDIR/stdout" "$TMPDIR/stderr" "$out/"
                printf '%s\n' "$status" > "$out/exit-status"
              '';
          stage-a-winapi-hello-behavior-smoke =
            pkgs.runCommand "stage-a-winapi-hello-behavior-smoke"
              {
                nativeBuildInputs = [
                  pkgs.wineWow64Packages.stable
                  pkgs.xvfb-run
                ];
              }
              ''
                test -s "${stage-a-winapi-hello-check}/prepared-proof.json"
                fixture_dir="${stage-a-winapi-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/winapi-hello"
                export HOME="$TMPDIR/home"
                export WINEPREFIX="$TMPDIR/wine"
                export WINEDEBUG=-all
                export WINEDLLOVERRIDES="mscoree,mshtml="
                mkdir -p "$HOME"
                xvfb-run -a wine "$fixture_dir/hello-candidate.exe" \
                  > "$TMPDIR/stdout" 2> "$TMPDIR/stderr"
                printf 'Hello, world!\r\n' > "$TMPDIR/expected"
                cmp "$TMPDIR/expected" "$TMPDIR/stdout"
                mkdir -p "$out"
                cp "$TMPDIR/stdout" "$TMPDIR/stderr" "$out/"
              '';
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
          stage-a-gnu-hello-fixtures = pkgs.runCommand "stage-a-gnu-hello-fixtures"
            {
              nativeBuildInputs = [ pkgs.jq ];
            }
            ''
              fixture_dir="$out/share/spaghetti-extractor/stage-a-fixtures/gnu-hello-o2-alignment"
              mkdir -p "$fixture_dir"
              cp "${stage-a-gnu-hello-original}/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/original/hello.exe" "$fixture_dir/hello-original.exe"
              cp "${stage-a-gnu-hello-candidate}/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/candidate/hello.exe" "$fixture_dir/hello-candidate.exe"
              cp "${stage-a-gnu-hello-original}/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/original/hello.map" "$fixture_dir/hello-original.map"
              cp "${stage-a-gnu-hello-candidate}/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/candidate/hello.map" "$fixture_dir/hello-candidate.map"
              jq -n \
                --arg original_flags "${stageAGnuHelloOriginalCflags}" \
                --arg candidate_flags "${stageAGnuHelloCandidateCflags}" \
                --arg linker_flags "${stageAGnuHelloLayoutLdflags}" \
                --arg compiler "$(${mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc -dumpmachine)" \
                --arg compiler_version "$(${mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc -dumpfullversion -dumpversion)" \
                '{
                  format: "stage-a-gnu-hello-fixture-build-metadata-v1",
                  source: "GNU hello from pinned nixpkgs",
                  target: "i686-w64-mingw32",
                  original: { file: "hello-original.exe", linker_map: "hello-original.map", flags: $original_flags },
                  candidate: { file: "hello-candidate.exe", linker_map: "hello-candidate.map", flags: $candidate_flags },
                  linker_flags: $linker_flags,
                  compiler: { target: $compiler, version: $compiler_version }
                }' > "$fixture_dir/build-metadata.json"
            '';
          mkStageAGnuHelloInventory = label: fixture:
            pkgs.runCommand "stage-a-gnu-hello-${label}-inventory"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-side
                  pkgs.jq
                ];
                preferLocalBuild = false;
                allowSubstitutes = true;
              }
              ''
                fixture_dir="${fixture}/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/${label}"
                mkdir -p "$out"
                spaghetti-extractor-side inventory-binary \
                  --binary "$fixture_dir/hello.exe" \
                  --linker-map "$fixture_dir/hello.map" \
                  --side "${label}" \
                  --out "$out/inventory.json" \
                  > "$out/inventory.stdout"
                jq -e '
                  .format == "stage-a-binary-cutpoint-inventory-v1" and
                  .status == "pass" and
                  .counts.issues == 0 and
                  .counts.regions > 0 and
                  .counts.extraction_regions >= .counts.regions
                ' "$out/inventory.json" >/dev/null
                spaghetti-extractor-side \
                  project-inventory-extraction-request \
                  --inventory "$out/inventory.json" \
                  --scope base \
                  --out "$out/request.json" \
                  > "$out/request.stdout"
                jq -e '
                  .format == "stage-a-relational-side-extraction-request-v1" and
                  .side == "${label}" and
                  (.regions | length) > 0
                ' "$out/request.json" >/dev/null
                spaghetti-extractor-side \
                  project-inventory-extraction-request \
                  --inventory "$out/inventory.json" \
                  --scope superset \
                  --out "$out/isa-request.json" \
                  > "$out/isa-request.stdout"
                jq -e \
                  --argjson base_count "$(jq '.regions | length' "$out/request.json")" '
                  .format == "stage-a-relational-side-extraction-request-v1" and
                  .side == "${label}" and
                  (.regions | length) >= $base_count
                ' "$out/isa-request.json" >/dev/null
              '';
          stage-a-gnu-hello-original-inventory =
            mkStageAGnuHelloInventory "original" stage-a-gnu-hello-original;
          stage-a-gnu-hello-candidate-inventory =
            mkStageAGnuHelloInventory "candidate" stage-a-gnu-hello-candidate;
          mkStageAGnuHelloSideExtraction = label: fixture: inventory:
            pkgs.runCommand "stage-a-gnu-hello-${label}-extraction"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-side
                  pkgs.lean4
                  pkgs.jq
                ];
                preferLocalBuild = false;
                allowSubstitutes = true;
              }
              ''
                fixture_dir="${fixture}/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/${label}"
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-relational-analysis-kernel-cache}"
                export SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_MEMORY_MB=8192
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_JOBS=8
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_BATCH=4
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$TMPDIR/relational-cache"
                mkdir -p "$out"
                spaghetti-extractor-side extract-side \
                  --binary "$fixture_dir/hello.exe" \
                  --request "${inventory}/request.json" \
                  --out "$out/extraction.json" \
                  > "$out/extraction.stdout"
                jq -e '
                  .format == "stage-a-relational-side-extraction-v1" and
                  .side == "${label}" and
                  (.regions | length) > 0
                ' "$out/extraction.json" >/dev/null
              '';
          stage-a-gnu-hello-original-extraction =
            mkStageAGnuHelloSideExtraction
              "original"
              stage-a-gnu-hello-original
              stage-a-gnu-hello-original-inventory;
          stage-a-gnu-hello-candidate-extraction =
            mkStageAGnuHelloSideExtraction
              "candidate"
              stage-a-gnu-hello-candidate
              stage-a-gnu-hello-candidate-inventory;
          mkStageAGnuHelloSideIsa = label: fixture: inventory:
            pkgs.runCommand "stage-a-gnu-hello-${label}-isa"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-side
                  pkgs.lean4
                  pkgs.jq
                ];
                preferLocalBuild = false;
                allowSubstitutes = true;
              }
              ''
                fixture_dir="${fixture}/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/${label}"
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-relational-analysis-kernel-cache}"
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$TMPDIR/relational-cache"
                mkdir -p "$out"
                spaghetti-extractor-side extract-side-isa \
                  --binary "$fixture_dir/hello.exe" \
                  --request "${inventory}/isa-request.json" \
                  --out "$out/isa.json" \
                  > "$out/isa.stdout"
                jq -e '
                  .format == "stage-a-relational-side-isa-v1" and
                  .side == "${label}" and
                  (.regions | length) > 0
                ' "$out/isa.json" >/dev/null
              '';
          stage-a-gnu-hello-original-isa =
            mkStageAGnuHelloSideIsa
              "original"
              stage-a-gnu-hello-original
              stage-a-gnu-hello-original-inventory;
          stage-a-gnu-hello-candidate-isa =
            mkStageAGnuHelloSideIsa
              "candidate"
              stage-a-gnu-hello-candidate
              stage-a-gnu-hello-candidate-inventory;
          stage-a-gnu-hello-static-map = pkgs.runCommand "stage-a-gnu-hello-static-map"
            {
              nativeBuildInputs = [ spaghetti-extractor-mapping ];
            }
            ''
              fixture_dir="${stage-a-gnu-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/gnu-hello-o2-alignment"
              mkdir -p "$out"
              spaghetti-extractor-mapping generate-map \
                --original "$fixture_dir/hello-original.exe" \
                --candidate "$fixture_dir/hello-candidate.exe" \
                --linker-map-original "$fixture_dir/hello-original.map" \
                --linker-map-candidate "$fixture_dir/hello-candidate.map" \
                --original-flags "${stageAGnuHelloOriginalCflags}" \
                --candidate-flags "${stageAGnuHelloCandidateCflags}" \
                --out "$out/hello-block-map.json" \
                --layout-contract-out "$out/hello-layout-contract.json" \
                > "$out/generate-map.stdout"
            '';
          stage-a-gnu-hello-relation-contract = pkgs.runCommand "stage-a-gnu-hello-relation-contract"
            {
              nativeBuildInputs = [ spaghetti-extractor-mapping ];
            }
            ''
              fixture_dir="${stage-a-gnu-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/gnu-hello-o2-alignment"
              mkdir -p "$out"
              spaghetti-extractor-mapping generate-relation-contract \
                --original "$fixture_dir/hello-original.exe" \
                --candidate "$fixture_dir/hello-candidate.exe" \
                --mapping "${stage-a-gnu-hello-static-map}/hello-block-map.json" \
                --external-profile "${./profiles/pe32-kernel32-lockstep-v1.json}" \
                --external-profile "${./profiles/pe32-msvcrt-lockstep-v1.json}" \
                --out "$out/hello-relation-contract.json" \
                > "$out/generate-relation.stdout"
            '';
          mkStageAGnuHelloSupplementRequest = label: fixture: inventory:
            pkgs.runCommand "stage-a-gnu-hello-${label}-supplement-request"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-side
                  pkgs.lean4
                  pkgs.jq
                ];
                preferLocalBuild = false;
                allowSubstitutes = true;
              }
              ''
                fixture_dir="${fixture}/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/${label}"
                mkdir -p "$out"
                spaghetti-extractor-side \
                  project-missing-side-extraction-request \
                  --binary "$fixture_dir/hello.exe" \
                  --side "${label}" \
                  --relation-contract "${stage-a-gnu-hello-relation-contract}/hello-relation-contract.json" \
                  --inventory "${inventory}/inventory.json" \
                  --out "$out/request.json" \
                  > "$out/request.stdout"
                jq -e '
                  .format == "stage-a-relational-side-extraction-request-v1" and
                  .side == "${label}"
                ' "$out/request.json" >/dev/null
              '';
          stage-a-gnu-hello-original-supplement-request =
            mkStageAGnuHelloSupplementRequest
              "original"
              stage-a-gnu-hello-original
              stage-a-gnu-hello-original-inventory;
          stage-a-gnu-hello-candidate-supplement-request =
            mkStageAGnuHelloSupplementRequest
              "candidate"
              stage-a-gnu-hello-candidate
              stage-a-gnu-hello-candidate-inventory;
          mkStageAGnuHelloSupplementExtraction = label: fixture: request:
            pkgs.runCommand "stage-a-gnu-hello-${label}-supplement-extraction"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-side
                  pkgs.lean4
                  pkgs.jq
                ];
                preferLocalBuild = false;
                allowSubstitutes = true;
              }
              ''
                fixture_dir="${fixture}/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/${label}"
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-relational-analysis-kernel-cache}"
                export SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_MEMORY_MB=8192
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_JOBS=2
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_BATCH=1
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$TMPDIR/relational-cache"
                mkdir -p "$out"
                spaghetti-extractor-side extract-side \
                  --binary "$fixture_dir/hello.exe" \
                  --request "${request}/request.json" \
                  --out "$out/extraction.json" \
                  > "$out/extraction.stdout"
                jq -e '
                  .format == "stage-a-relational-side-extraction-v1" and
                  .side == "${label}"
                ' "$out/extraction.json" >/dev/null
              '';
          stage-a-gnu-hello-original-supplement-extraction =
            mkStageAGnuHelloSupplementExtraction
              "original"
              stage-a-gnu-hello-original
              stage-a-gnu-hello-original-supplement-request;
          stage-a-gnu-hello-candidate-supplement-extraction =
            mkStageAGnuHelloSupplementExtraction
              "candidate"
              stage-a-gnu-hello-candidate
              stage-a-gnu-hello-candidate-supplement-request;
          mkStageAGnuHelloMergedExtraction =
            label: fixture: base: supplement:
            pkgs.runCommand "stage-a-gnu-hello-${label}-merged-extraction"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-side
                  pkgs.lean4
                  pkgs.jq
                ];
                preferLocalBuild = false;
                allowSubstitutes = true;
              }
              ''
                fixture_dir="${fixture}/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/${label}"
                mkdir -p "$out"
                spaghetti-extractor-side merge-side-extractions \
                  --binary "$fixture_dir/hello.exe" \
                  --side "${label}" \
                  --input "${base}/extraction.json" \
                  --input "${supplement}/extraction.json" \
                  --out "$out/extraction.json" \
                  > "$out/merge.stdout"
                jq -e '
                  .format == "stage-a-relational-side-extraction-v1" and
                  .side == "${label}" and
                  (.regions | length) > 0
                ' "$out/extraction.json" >/dev/null
              '';
          stage-a-gnu-hello-original-merged-extraction =
            mkStageAGnuHelloMergedExtraction
              "original"
              stage-a-gnu-hello-original
              stage-a-gnu-hello-original-extraction
              stage-a-gnu-hello-original-supplement-extraction;
          stage-a-gnu-hello-candidate-merged-extraction =
            mkStageAGnuHelloMergedExtraction
              "candidate"
              stage-a-gnu-hello-candidate
              stage-a-gnu-hello-candidate-extraction
              stage-a-gnu-hello-candidate-supplement-extraction;
          stage-a-gnu-hello-normalized-behaviors =
            pkgs.runCommand "stage-a-gnu-hello-normalized-behaviors"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-normalize
                  pkgs.lean4
                  pkgs.jq
                ];
                preferLocalBuild = false;
                allowSubstitutes = true;
              }
              ''
                fixture_dir="${stage-a-gnu-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/gnu-hello-o2-alignment"
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-relational-analysis-kernel-cache}"
                export SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_MEMORY_MB=8192
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_NORMALIZATION_JOBS=8
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_NORMALIZATION_BATCH=128
                mkdir -p "$out"
                spaghetti-extractor-normalize \
                  --original "$fixture_dir/hello-original.exe" \
                  --candidate "$fixture_dir/hello-candidate.exe" \
                  --relation-contract "${stage-a-gnu-hello-relation-contract}/hello-relation-contract.json" \
                  --original-extraction "${stage-a-gnu-hello-original-merged-extraction}/extraction.json" \
                  --candidate-extraction "${stage-a-gnu-hello-candidate-merged-extraction}/extraction.json" \
                  --out "$out/normalized-behaviors.json" \
                  > "$out/normalization.stdout"
                jq -e '
                  .format == "stage-a-relational-pair-normalization-v1" and
                  .status == "untrusted_proposal_requires_lean_normalization_replay" and
                  (.regions | length) > 0
                ' "$out/normalized-behaviors.json" >/dev/null
              '';
          stage-a-gnu-hello-region-facts =
            pkgs.runCommand "stage-a-gnu-hello-region-facts"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-region-facts
                  pkgs.jq
                ];
              }
              ''
                fixture_dir="${stage-a-gnu-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/gnu-hello-o2-alignment"
                mkdir -p "$out"
                if ! spaghetti-extractor-region-facts \
                  --original "$fixture_dir/hello-original.exe" \
                  --candidate "$fixture_dir/hello-candidate.exe" \
                  --relation-contract "${stage-a-gnu-hello-relation-contract}/hello-relation-contract.json" \
                  --original-extraction "${stage-a-gnu-hello-original-merged-extraction}/extraction.json" \
                  --candidate-extraction "${stage-a-gnu-hello-candidate-merged-extraction}/extraction.json" \
                  --normalized-behaviors "${stage-a-gnu-hello-normalized-behaviors}/normalized-behaviors.json" \
                  --out "$out/region-facts.json" \
                  > "$out/result.json"; then
                  cat "$out/result.json" >&2
                  exit 1
                fi
                jq -e '
                  .format == "stage-a-relational-region-facts-v1" and
                  .status == "untrusted_proposal_requires_global_analysis" and
                  (.region_count > 0)
                ' "$out/region-facts.json" >/dev/null
              '';
          stage-a-gnu-hello-analysis = pkgs.runCommand "stage-a-gnu-hello-analysis"
            {
              nativeBuildInputs = [
                spaghetti-extractor-analysis
                pkgs.lean4
                pkgs.jq
              ];
            }
            ''
              fixture_dir="${stage-a-gnu-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/gnu-hello-o2-alignment"
              work="$TMPDIR/stage-a-gnu-hello-analysis"
              mkdir -p "$work"
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-relational-analysis-kernel-cache}"
              export SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_MEMORY_MB=8192
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_JOBS=16
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_NORMALIZATION_JOBS=8
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_NORMALIZATION_BATCH=128
              set +e
              SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$work/relational-cache" \
                spaghetti-extractor-analysis analyze-relational \
                  --original "$fixture_dir/hello-original.exe" \
                  --candidate "$fixture_dir/hello-candidate.exe" \
                  --relation-contract "${stage-a-gnu-hello-relation-contract}/hello-relation-contract.json" \
                  --original-extraction "${stage-a-gnu-hello-original-merged-extraction}/extraction.json" \
                  --candidate-extraction "${stage-a-gnu-hello-candidate-merged-extraction}/extraction.json" \
                  --normalized-behaviors "${stage-a-gnu-hello-normalized-behaviors}/normalized-behaviors.json" \
                  --original-isa "${stage-a-gnu-hello-original-isa}/isa.json" \
                  --candidate-isa "${stage-a-gnu-hello-candidate-isa}/isa.json" \
                  --region-facts "${stage-a-gnu-hello-region-facts}/region-facts.json" \
                  --out "$work/analysis" \
                  > "$work/analysis.stdout" \
                  2> "$work/analysis.stderr"
              analysis_status=$?
              set -e
              if [ "$analysis_status" -ne 0 ]; then
                cat "$work/analysis.stderr" >&2
                cat "$work/analysis.stdout" >&2
                exit "$analysis_status"
              fi
              if ! spaghetti-extractor-analysis validate-analysis \
                --analysis "$work/analysis" \
                > "$work/analysis-validation.json"; then
                cat "$work/analysis-validation.json" >&2
                exit 1
              fi
              if ! jq -e '
                .format == "stage-a-relational-analysis-v1" and
                .status == "analyzed" and
                (.files | length) > 20
              ' "$work/analysis/relational-analysis-manifest.json" >/dev/null; then
                jq . "$work/analysis/relational-analysis-manifest.json" >&2
                exit 1
              fi
              if [ -e "$work/analysis/lean" ] || [ -e "$work/analysis/certificates" ]; then
                find "$work/analysis" -maxdepth 2 -type d -print >&2
                echo "analysis artifact contains downstream proof products" >&2
                exit 1
              fi
              mkdir -p "$out"
              cp -R "$work/analysis" "$out/analysis"
              cp "$work/analysis.stdout" "$work/analysis.stderr" \
                "$work/analysis-validation.json" "$out/"
            '';
          stage-a-gnu-hello-preflight = pkgs.runCommand "stage-a-gnu-hello-preflight"
            {
              nativeBuildInputs = [
                spaghetti-extractor-core
                pkgs.lean4
                pkgs.jq
              ];
            }
            ''
              work="$TMPDIR/stage-a-gnu-hello"
              mkdir -p "$work"
              set +e
              spaghetti-extractor stage-a-generate-relational \
                  --analysis "${stage-a-gnu-hello-analysis}/analysis" \
                  --out "$work/relational-v3" \
                  > "$work/relational-v3.stdout" \
                  2> "$work/relational-v3.stderr"
              prepare_status=$?
              set -e
              if [ "$prepare_status" -ne 0 ]; then
                cat "$work/relational-v3.stderr" >&2
                echo "GNU hello relational preparation failed" >&2
                exit 1
              fi
              if ! jq -e '
                .status == "supported" and
                (.issues | length) == 0
              ' "$work/relational-v3/semantic-gaps.json" >/dev/null; then
                jq . "$work/relational-v3/semantic-gaps.json" >&2
                echo "GNU hello semantic preflight assertion failed" >&2
                exit 1
              fi
              if ! jq -e '
                .status == "incomplete" and
                .theorem == null and
                (.blockers | length) > 0 and
                all(.blockers[]; (.code | type) == "string" and (.code | length) > 0)
              ' "$work/relational-v3/whole-program-acceptance.json" >/dev/null; then
                jq . "$work/relational-v3/whole-program-acceptance.json" >&2
                echo "GNU hello acceptance frontier assertion failed" >&2
                exit 1
              fi
              if ! jq -e '
                .status == "prepared" and
                .acceptance.status == "incomplete" and
                .expected_final_theorem == null and
                (.acceptance.blockers | length) > 0
              ' "$work/relational-v3/prepared-proof.json" >/dev/null; then
                jq . "$work/relational-v3/prepared-proof.json" >&2
                echo "GNU hello prepared-proof assertion failed" >&2
                exit 1
              fi
              mkdir -p "$out/report"
              cp "${stage-a-gnu-hello-static-map}/hello-block-map.json" \
                "${stage-a-gnu-hello-static-map}/hello-layout-contract.json" \
                "${stage-a-gnu-hello-relation-contract}/hello-relation-contract.json" \
                "$out/report/"
              cp -R "$work/relational-v3" "$out/report/relational-v3"
              cp "$work/relational-v3.stdout" "$work/relational-v3.stderr" "$out/report/"
            '';
          stage-a-gnu-hello-launch-proof =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              prepared = stage-a-gnu-hello-preflight + "/report/relational-v3";
              targetNodes = [ "relationallaunchrealizabilitycertificate" ];
              targetBundle = true;
            };
          stage-a-gnu-hello-check = pkgs.runCommand "stage-a-gnu-hello-check"
            {
              nativeBuildInputs = [ pkgs.jq ];
            }
            ''
              prepared="${stage-a-gnu-hello-preflight}/report/relational-v3"
              jq -e '
                .status == "prepared" and
                .acceptance.status == "incomplete" and
                .acceptance.theorem == null and
                .acceptance.launch_realizability.profile ==
                  "paired-preferred-base-import-stack-tls-static-v2" and
                .composition_progress.status == "incomplete" and
                .composition_progress.counts.unsupported_instructions == 0 and
                .composition_progress.counts.rooted_reachable_nodes > 1000 and
                .composition_progress.counts.rooted_reachable_feasible_edges > 1000 and
                .composition_progress.counts.rooted_refined_segments > 0 and
                .composition_progress.counts.rooted_refined_segments <
                  .composition_progress.counts.rooted_reachable_feasible_edges and
                .composition_progress.counts.acceptance_blockers > 0
              ' "$prepared/prepared-proof.json" >/dev/null
              jq -e '
                .format == "stage-a-lean-target-bundle-v1" and
                .lean_trust == 0 and
                ([.nodes[].id] |
                  index("relationallaunchrealizabilitycertificate")) != null
              ' "${stage-a-gnu-hello-launch-proof}/bundle.json" >/dev/null
              mkdir -p "$out"
              cp "$prepared/prepared-proof.json" "$prepared/semantic-gaps.json" "$out/"
              cp "${stage-a-gnu-hello-launch-proof}/bundle.json" \
                "$out/launch-proof-bundle.json"
            '';
          stage-a-minimal-hello-fixtures = pkgs.runCommand "stage-a-minimal-hello-fixtures"
            {
              nativeBuildInputs = [ pkgs.jq ];
            }
            ''
              fixture_dir="$out/share/spaghetti-extractor/stage-a-fixtures/minimal-hello-o2-alignment"
              mkdir -p "$fixture_dir"
              cp "${stage-a-minimal-hello-original}/share/spaghetti-extractor/stage-a-minimal-hello-fixtures/original/hello.exe" "$fixture_dir/hello-original.exe"
              cp "${stage-a-minimal-hello-candidate}/share/spaghetti-extractor/stage-a-minimal-hello-fixtures/candidate/hello.exe" "$fixture_dir/hello-candidate.exe"
              cp "${stage-a-minimal-hello-original}/share/spaghetti-extractor/stage-a-minimal-hello-fixtures/original/hello.map" "$fixture_dir/hello-original.map"
              cp "${stage-a-minimal-hello-candidate}/share/spaghetti-extractor/stage-a-minimal-hello-fixtures/candidate/hello.map" "$fixture_dir/hello-candidate.map"
              jq -n \
                --arg original_flags "${stageAMinimalHelloOriginalCflags}" \
                --arg candidate_flags "${stageAMinimalHelloCandidateCflags}" \
                --arg linker_flags "${stageAMinimalHelloLayoutLdflags}" \
                --arg compiler "$(${mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc -dumpmachine)" \
                --arg compiler_version "$(${mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc -dumpfullversion -dumpversion)" \
                '{
                  format: "stage-a-minimal-hello-fixture-build-metadata-v1",
                  source: "tools/stage-a-fixtures/stage_a_hello.c",
                  target: "i686-w64-mingw32",
                  original: { file: "hello-original.exe", linker_map: "hello-original.map", flags: $original_flags },
                  candidate: { file: "hello-candidate.exe", linker_map: "hello-candidate.map", flags: $candidate_flags },
                  linker_flags: $linker_flags,
                  compiler: { target: $compiler, version: $compiler_version }
                }' > "$fixture_dir/build-metadata.json"
            '';
          stage-a-minimal-hello-static-map = pkgs.runCommand "stage-a-minimal-hello-static-map"
            {
              nativeBuildInputs = [ spaghetti-extractor-core ];
            }
            ''
              fixture_dir="${stage-a-minimal-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/minimal-hello-o2-alignment"
              mkdir -p "$out"
              spaghetti-extractor stage-a-generate-map \
                --original "$fixture_dir/hello-original.exe" \
                --candidate "$fixture_dir/hello-candidate.exe" \
                --linker-map-original "$fixture_dir/hello-original.map" \
                --linker-map-candidate "$fixture_dir/hello-candidate.map" \
                --original-flags "${stageAMinimalHelloOriginalCflags}" \
                --candidate-flags "${stageAMinimalHelloCandidateCflags}" \
                --out "$out/hello-block-map.json" \
                --layout-contract-out "$out/hello-layout-contract.json" \
                > "$out/generate-map.stdout"
            '';
          stage-a-minimal-hello-relation-contract = pkgs.runCommand "stage-a-minimal-hello-relation-contract"
            {
              nativeBuildInputs = [ spaghetti-extractor-core ];
            }
            ''
              fixture_dir="${stage-a-minimal-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/minimal-hello-o2-alignment"
              mkdir -p "$out"
              spaghetti-extractor stage-a-generate-relation-contract \
                --original "$fixture_dir/hello-original.exe" \
                --candidate "$fixture_dir/hello-candidate.exe" \
                --mapping "${stage-a-minimal-hello-static-map}/hello-block-map.json" \
                --external-profile "${./profiles/pe32-kernel32-lockstep-v1.json}" \
                --external-profile "${./profiles/pe32-msvcrt-lockstep-v1.json}" \
                --out "$out/hello-relation-contract.json" \
                > "$out/generate-relation.stdout"
            '';
          stage-a-minimal-hello-prepared-proof = pkgs.runCommand "stage-a-minimal-hello-prepared-proof"
            {
              nativeBuildInputs = [
                spaghetti-extractor-core
                pkgs.lean4
              ];
            }
            ''
              fixture_dir="${stage-a-minimal-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/minimal-hello-o2-alignment"
              work="$TMPDIR/stage-a-minimal-hello"
              mkdir -p "$work"
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-relational-kernel-cache}"
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_JOBS=16
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_LAUNCH_CHECK_CHUNK=1024
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_STATIC_CODE_MAP_NIX_PACK_MODULES=4
              SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$work/relational-cache" \
                spaghetti-extractor stage-a-prepare-relational \
                  --original "$fixture_dir/hello-original.exe" \
                  --candidate "$fixture_dir/hello-candidate.exe" \
                  --relation-contract "${stage-a-minimal-hello-relation-contract}/hello-relation-contract.json" \
                  --out "$work/relational-v3" \
                  > "$work/relational-v3.stdout"
              mkdir -p "$out/report"
              cp "${stage-a-minimal-hello-static-map}/hello-block-map.json" \
                "${stage-a-minimal-hello-static-map}/hello-layout-contract.json" \
                "${stage-a-minimal-hello-relation-contract}/hello-relation-contract.json" \
                "$out/report/"
              cp -R "$work/relational-v3" "$out/report/relational-v3"
              cp "$work/relational-v3.stdout" "$out/report/"
            '';
          stage-a-minimal-hello-proof-smoke =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              prepared = stage-a-minimal-hello-prepared-proof + "/report/relational-v3";
              targetNodes = [ "relationalsegmentrefinementedge127" ];
              targetBundle = true;
            };
          stage-a-minimal-hello-launch-proof =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              prepared = stage-a-minimal-hello-prepared-proof + "/report/relational-v3";
              targetNodes = [ "relationallaunchrealizabilitycertificate" ];
              targetBundle = true;
            };
          stage-a-minimal-hello-segment-proofs =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              prepared = stage-a-minimal-hello-prepared-proof + "/report/relational-v3";
              targetNodes = [ "relationalsegmentrefinementcertificate" ];
              targetBundle = true;
            };
          stage-a-minimal-hello-evidence-bundle =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              prepared = stage-a-minimal-hello-prepared-proof + "/report/relational-v3";
              targetNodes = [ "relationalbundle" ];
              targetBundle = true;
            };
          stage-a-minimal-hello-check = pkgs.runCommand "stage-a-minimal-hello-check"
            {
              nativeBuildInputs = [ pkgs.jq ];
            }
            ''
              prepared="${stage-a-minimal-hello-prepared-proof}/report/relational-v3"
              jq -e '
                .status == "prepared" and
                .acceptance.status == "incomplete" and
                .acceptance.theorem == null and
                .composition_progress.status == "incomplete" and
                .composition_progress.counts.unsupported_instructions == 0 and
                .composition_progress.counts.rooted_reachable_nodes > 0 and
                .composition_progress.counts.rooted_reachable_feasible_edges > 0 and
                .composition_progress.counts.rooted_refined_segments > 0 and
                .composition_progress.counts.rooted_refined_segments <
                  .composition_progress.counts.rooted_reachable_feasible_edges
              ' "$prepared/prepared-proof.json" >/dev/null
              jq -e '.status == "supported" and (.issues | length) == 0' \
                "$prepared/semantic-gaps.json" >/dev/null
              jq -e '
                .format == "stage-a-lean-target-bundle-v1" and
                .lean_trust == 0 and
                ([.nodes[].id] | index("relationalsegmentrefinementedge127")) != null
              ' "${stage-a-minimal-hello-proof-smoke}/bundle.json" >/dev/null
              jq -e '
                .format == "stage-a-lean-target-bundle-v1" and
                .lean_trust == 0 and
                ([.nodes[].id] |
                  index("relationallaunchrealizabilitycertificate")) != null
              ' "${stage-a-minimal-hello-launch-proof}/bundle.json" >/dev/null
              mkdir -p "$out"
              cp "$prepared/prepared-proof.json" "$prepared/semantic-gaps.json" "$out/"
              cp "${stage-a-minimal-hello-proof-smoke}/bundle.json" "$out/proof-smoke-bundle.json"
              cp "${stage-a-minimal-hello-launch-proof}/bundle.json" "$out/launch-proof-bundle.json"
            '';
          stage-a-jq-static-map = pkgs.runCommand "stage-a-jq-static-map"
            {
              nativeBuildInputs = [
                spaghetti-extractor-core
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment"
              mkdir -p "$out"
              spaghetti-extractor stage-a-generate-map \
                --original "$fixture_dir/jq-original.exe" \
                --candidate "$fixture_dir/jq-candidate.exe" \
                --linker-map-original "$fixture_dir/jq-original.map" \
                --linker-map-candidate "$fixture_dir/jq-candidate.map" \
                --original-flags "${stageAJqOriginalCflags}" \
                --candidate-flags "${stageAJqCandidateCflags}" \
                --out "$out/jq-block-map.json" \
                --layout-contract-out "$out/jq-layout-contract.json" \
                > "$out/generate-map.stdout"
            '';
          stage-a-jq-relation-contract = pkgs.runCommand "stage-a-jq-relation-contract"
            {
              nativeBuildInputs = [
                spaghetti-extractor-core
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment"
              mkdir -p "$out"
              spaghetti-extractor stage-a-generate-relation-contract \
                --original "$fixture_dir/jq-original.exe" \
                --candidate "$fixture_dir/jq-candidate.exe" \
                --mapping "${stage-a-jq-static-map}/jq-block-map.json" \
                --external-profile "${./profiles/pe32-kernel32-lockstep-v1.json}" \
                --external-profile "${./profiles/pe32-msvcrt-lockstep-v1.json}" \
                --out "$out/jq-relation-contract.json" \
                > "$out/generate-relation.stdout"
            '';
          stage-a-jq-prepared-proof = pkgs.runCommand "stage-a-jq-prepared-proof"
            {
              nativeBuildInputs = [
                spaghetti-extractor-core
                pkgs.lean4
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment"
              work="$TMPDIR/stage-a-jq"
              mkdir -p "$work"
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-relational-kernel-cache}"
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_JOBS=16
              SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$work/relational-cache" \
                spaghetti-extractor stage-a-prepare-relational \
                  --original "$fixture_dir/jq-original.exe" \
                  --candidate "$fixture_dir/jq-candidate.exe" \
                  --relation-contract "${stage-a-jq-relation-contract}/jq-relation-contract.json" \
                  --out "$work/relational-v3" \
                  > "$work/relational-v3.stdout"
              mkdir -p "$out/report"
              cp "${stage-a-jq-static-map}/jq-block-map.json" \
                "${stage-a-jq-static-map}/jq-layout-contract.json" \
                "${stage-a-jq-relation-contract}/jq-relation-contract.json" \
                "$out/report/"
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
                .composition_progress.counts.unsupported_instructions == 0 and
                .composition_progress.reachability_assurance.status == "incomplete" and
                (.composition_progress.reachability_assurance.blocker_totals.coverage_bearing | not) and
                (.composition_progress.reachability_assurance.blocker_totals.comparable | not) and
                .composition_progress.reachability_assurance.conservative_potential_reachability.node_count ==
                  .composition_progress.counts.potential_reachable_nodes and
                .composition_progress.reachability_assurance.represented_rooted_reachability.node_count ==
                  .composition_progress.counts.rooted_reachable_nodes and
                .composition_progress.reachability_assurance.conservative_potential_reachability.node_count >
                  .composition_progress.reachability_assurance.represented_rooted_reachability.node_count
              ' "$prepared/relational-v3/prepared-proof.json" >/dev/null
              jq -e '
                (.launch.original_is_dll | not) and
                (.launch.candidate_is_dll | not) and
                .launch.original_exports == [] and
                .launch.candidate_exports == [] and
                (.launch.original_tls_callback_rvas | length) == 2 and
                (.launch.candidate_tls_callback_rvas | length) == 2 and
                (.launch.tls_callback_target_ids | length) == 2 and
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
          relationalAnalysisLeanSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions (
              map
                (module: ./src/spaghetti_extractor/lean/StageA + "/${module}.lean")
                relationalAnalysisKernelModules
            );
          };
          relationalKernelModules = [
            "Formal"
            "ISAQualification"
            "ISAConformance"
            "ISAConformanceRunner"
            "RelationalDecode"
            "RelationalLoader"
            "RelationalMachine"
            "RelationalPEExecution"
            "RelationalISAQualification"
            "Relational"
            "RelationalInvariant"
            "RelationalExactExpr"
            "RelationalExecution"
            "RelationalImage"
            "RelationalSegment"
            "RelationalComposition"
            "RelationalLinkedFrames"
            "RelationalEnvironment"
            "RelationalCallbacks"
            "RelationalCertificates"
            "RelationalPEWorldExecution"
            "RelationalStaticTree"
          ];
          isaKernelModules = [
            "Formal"
            "ISAQualification"
            "ISAConformance"
            "ISAConformanceRunner"
          ];
          stage-a-isa-kernel-cache =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              standaloneSourceRoot =
                relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
              standaloneModules = isaKernelModules;
              targetNodes = isaKernelModules;
              targetBundle = true;
            };
          stage-a-relational-analysis-kernel-cache =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              standaloneSourceRoot =
                relationalAnalysisLeanSource + "/src/spaghetti_extractor/lean/StageA";
              standaloneModules = relationalAnalysisKernelModules;
              targetNodes = relationalAnalysisKernelModules;
              targetBundle = true;
            };
          stage-a-relational-kernel-cache =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              standaloneSourceRoot =
                relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
              standaloneModules = relationalKernelModules;
              targetNodes = relationalKernelModules;
              targetBundle = true;
            };
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
          stage-a-relational-tests-build-graph = mkStageARelationalTest
            "build-graph"
            "tests.test_stage_a_build_graph"
            [
              ./tests/test_stage_a_build_graph.py
              ./flake.lock
            ];
          stage-a-relational-tests-static-word-relations = mkStageARelationalTest
            "acceptance-static-word-relations"
            "tests.test_stage_a_static_word_relations"
            [ ./tests/test_stage_a_static_word_relations.py ];
          stage-a-relational-tests-external-protocol = mkStageARelationalTest
            "external-protocol"
            "tests.test_stage_a_external_protocol"
            [
              ./tests/test_stage_a_external_protocol.py
              ./profiles/pe32-msvcrt-lockstep-v1.json
            ];
          stage-a-relational-tests-external-contract-selection =
            mkStageARelationalTest
              "external-contract-selection"
              "tests.test_stage_a_external_contract_selection"
              [ ./tests/test_stage_a_external_contract_selection.py ];
          stage-a-relational-tests-external-stateful-memory =
            mkStageARelationalTest
              "external-stateful-memory"
              "tests.test_stage_a_external_stateful_memory"
              [
                ./tests/test_stage_a_external_stateful_memory.py
                ./profiles/pe32-msvcrt-lockstep-v1.json
              ];
          stage-a-relational-tests-external-stateful-memory-kernel =
            mkStageARelationalTest
              "lean-external-stateful-memory"
              "tests.test_stage_a_external_stateful_memory_kernel"
              [ ./tests/test_stage_a_external_stateful_memory_kernel.py ];
          stage-a-relational-tests-reachable-acceptance =
            mkStageARelationalTest
              "reachable-acceptance"
              "tests.test_stage_a_reachable_acceptance"
              [ ./tests/test_stage_a_reachable_acceptance.py ];
          stage-a-relational-tests-pe-entry-surface =
            mkStageARelationalTest
              "pe-entry-surface"
              "tests.test_stage_a_pe_entry_surface"
              [
                ./tests/test_stage_a_pe_entry_surface.py
                ./tests/pe_fixtures.py
              ];
          stage-a-relational-tests-formal-pe-entry-surface =
            mkStageARelationalTest
              "lean-formal-pe-entry-surface"
              "tests.test_stage_a_formal_pe_entry_surface"
              [ ./tests/test_stage_a_formal_pe_entry_surface.py ];
          stage-a-relational-tests-proof-blocked =
            mkStageARelationalTest
              "lean-proof-blocked"
              "tests.test_stage_a_proof_blocked"
              [ ./tests/test_stage_a_proof_blocked.py ];
          stage-a-relational-tests-loader-image-diagnostics =
            mkStageARelationalTest
              "loader-image-diagnostics"
              "tests.test_stage_a_loader_image_diagnostics"
              [
                ./tests/test_stage_a_loader_image_diagnostics.py
                ./tests/pe_fixtures.py
              ];
          stage-a-relational-tests-loader-image-valid =
            mkStageARelationalTest
              "lean-loader-image-valid"
              "tests.test_stage_a_loader_image_valid"
              [ ./tests/test_stage_a_loader_image_valid.py ];
          stage-a-relational-tests-raw-eip-execution =
            mkStageARelationalTest
              "lean-raw-eip-execution"
              "tests.test_stage_a_raw_eip_execution"
              [
                ./tests/test_stage_a_raw_eip_execution.py
                ./tests/pe_fixtures.py
              ];
          stage-a-relational-tests-indirect-control = mkStageARelationalTest
            "indirect-control"
            "tests.test_stage_a_indirect_control tests.test_stage_a_initial_static_code_pointers"
            [
              ./tests/test_stage_a_indirect_control.py
              ./tests/test_stage_a_initial_static_code_pointers.py
            ];
          stage-a-relational-tests-control-provenance = mkStageARelationalTest
            "control-provenance"
            "tests.test_stage_a_control_provenance"
            [ ./tests/test_stage_a_control_provenance.py ];
          stage-a-relational-tests-isa-conformance = mkStageARelationalTest
            "isa-conformance"
            "tests.test_stage_a_isa_conformance"
            [ ./tests/test_stage_a_isa_conformance.py ];
          stage-a-relational-tests-isa-conformance-kernel =
            mkStageARelationalTest
              "lean-isa-conformance-kernel"
              "tests.test_stage_a_isa_conformance_kernel"
              [ ./tests/test_stage_a_isa_conformance_kernel.py ];
          stage-a-relational-tests-isa-conformance-lean =
            mkStageARelationalTest
              "lean-isa-conformance-runner"
              "tests.test_stage_a_isa_conformance_lean"
              [
                ./tests/test_stage_a_isa_conformance.py
                ./tests/test_stage_a_isa_conformance_lean.py
              ];
          stage-a-relational-tests-isa-conformance-unicorn =
            mkStageARelationalTest
              "isa-conformance-unicorn"
              "tests.test_stage_a_isa_conformance_unicorn"
              [ ./tests/test_stage_a_isa_conformance_unicorn.py ];
          stage-a-relational-tests-isa-conformance-bochs =
            mkStageARelationalTest
              "isa-conformance-bochs"
              "tests.test_stage_a_isa_conformance_bochs"
              [ ./tests/test_stage_a_isa_conformance_bochs.py ];
          stage-a-relational-tests-isa-conformance-differential =
            mkStageARelationalTest
              "lean-isa-conformance-differential"
              "tests.test_stage_a_isa_conformance_differential"
              [
                ./tests/test_stage_a_isa_conformance_differential.py
                ./tests/test_stage_a_isa_conformance_unicorn.py
              ];
          stage-a-relational-tests-isa-conformance-80386 =
            mkStageARelationalTest
              "isa-conformance-80386-import"
              "tests.test_stage_a_isa_conformance_80386"
              [ ./tests/test_stage_a_isa_conformance_80386.py ];
          stage-a-relational-tests-isa-conformance-80386-differential =
            mkStageARelationalTest
              "lean-isa-conformance-80386-differential"
              "tests.test_stage_a_isa_conformance_80386_differential"
              [
                ./tests/test_stage_a_isa_conformance_80386.py
                ./tests/test_stage_a_isa_conformance_80386_differential.py
              ];
          stage-a-relational-tests-bounded-table-call-generation =
            mkStageARelationalTest
              "bounded-table-call-generation"
              "tests.test_stage_a_bounded_table_call_generation"
              [ ./tests/test_stage_a_bounded_table_call_generation.py ];
          stage-a-relational-tests-bounded-table-call-kernel =
            mkStageARelationalTest
              "lean-bounded-table-call-kernel"
              "tests.test_stage_a_bounded_table_call_kernel"
              [ ./tests/test_stage_a_bounded_table_call_kernel.py ];
          stage-a-relational-tests-reverse-sentinel-scanner-integration =
            mkStageARelationalTest
              "lean-reverse-sentinel-scanner-integration"
              "tests.test_stage_a_reverse_sentinel_scanner_integration"
              [ ./tests/test_stage_a_reverse_sentinel_scanner_integration.py ];
          stage-a-relational-tests-callsite-preservation = mkStageARelationalTest
            "callsite-preservation"
            "tests.test_stage_a_callsite_preservation"
            [ ./tests/test_stage_a_callsite_preservation.py ];
          stage-a-relational-tests-callsite-summary-generation =
            mkStageARelationalTest
              "callsite-summary-generation"
              "tests.test_stage_a_callsite_summary_generation"
              [ ./tests/test_stage_a_callsite_summary_generation.py ];
          stage-a-relational-tests-call-return-summary =
            mkStageARelationalTest
              "call-return-summary"
              "tests.test_stage_a_call_return_summary"
              [ ./tests/test_stage_a_call_return_summary.py ];
          stage-a-relational-tests-callsite-preservation-schema =
            mkStageARelationalTest
              "callsite-preservation-schema"
              "tests.test_stage_a_callsite_preservation_schema"
              [ ./tests/test_stage_a_callsite_preservation_schema.py ];
          stage-a-relational-tests-register-analysis =
            mkStageARelationalTest
              "register-analysis"
              "tests.test_stage_a_register_analysis"
              [ ./tests/test_stage_a_register_analysis.py ];
          stage-a-relational-tests-lean-runtime-frame-import-environment =
            mkStageARelationalTest
              "lean-runtime-frame-import-environment"
              "tests.test_stage_a_runtime_frame_import_environment"
              [ ./tests/test_stage_a_runtime_frame_import_environment.py ];
          stage-a-relational-tests-acceptance-runtime-frame-import =
            mkStageARelationalTest
              "acceptance-runtime-frame-import"
              "tests.test_stage_a_runtime_frame_import_acceptance"
              [ ./tests/test_stage_a_runtime_frame_import_acceptance.py ];
          stage-a-relational-tests-acceptance-runtime-frame-register =
            mkStageARelationalTest
              "acceptance-runtime-frame-register"
              "tests.test_stage_a_runtime_frame_register_acceptance"
              [ ./tests/test_stage_a_runtime_frame_register_acceptance.py ];
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
          stageARelationalStaticWordSlotCertificateSuite =
            mkStageARelationalTestSuite
              "lean-static-word-slot-certificate"
              "tests.test_stage_a_relational_static_word_slot_certificate"
              "StageARelationalStaticWordSlotCertificateTests"
              ./tests/test_stage_a_relational_static_word_slot_certificate.py;
          stage-a-relational-tests-contract = stageARelationalContractSuite.aggregate;
          stage-a-relational-tests-state = stageARelationalStateSuite.aggregate;
          stage-a-relational-tests-pipeline = stageARelationalPipelineSuite.aggregate;
          stage-a-relational-tests-pipeline-cmov-general-composition =
            stageARelationalPipelineSuite.cases.cmov_expression_emits_general_compositional_components;
          stage-a-relational-tests-lean = stageARelationalLeanSuite.aggregate;
          stage-a-relational-tests-lean-return-slot-inventory =
            stageARelationalLeanSuite.cases.import_register_indirect_call_witness_is_checked_by_lean;
          stage-a-relational-tests-lean-dynamic-range-result =
            stageARelationalLeanSuite.cases.dynamic_range_result_relation_is_checked_by_lean;
          stage-a-relational-tests-lean-linked-frames =
            stageARelationalLeanSuite.cases.linked_runtime_frames_support_an_arbitrary_dormant_tail;
          stage-a-relational-tests-contract-machine-import =
            stageARelationalContractSuite.cases.machine_import_call_contract_validation_fails_closed;
          stage-a-relational-tests-acceptance = stageARelationalAcceptanceSuite.aggregate;
          stage-a-relational-tests-static-word-slot-certificate =
            stageARelationalStaticWordSlotCertificateSuite.aggregate;
          stage-a-relational-tests-acceptance-whole-program-kernel =
            stageARelationalAcceptanceSuite.cases.whole_program_equivalence_kernel_checks_without_sorry;
          stage-a-relational-tests-acceptance-instruction-adequacy =
            stageARelationalAcceptanceSuite.cases.instruction_semantics_adequacy_rejects_ambiguous_pe_fetch;
          stage-a-relational-tests-acceptance-instruction-adequacy-tamper =
            stageARelationalAcceptanceSuite.cases.instruction_adequacy_aggregate_rejects_tampered_region_span;
          stage-a-relational-tests-acceptance-instruction-adequacy-multi-chunk =
            stageARelationalAcceptanceSuite.cases.instruction_adequacy_aggregate_composes_multiple_chunks;
          stage-a-relational-tests-acceptance-entry-surface =
            stageARelationalAcceptanceSuite.cases.console_launch_rejects_dll_and_export_entry_surfaces;
          stage-a-relational-tests-acceptance-direct-loop =
            stageARelationalAcceptanceSuite.cases.direct_loop_emits_and_checks_closed_whole_program_theorem;
          stage-a-relational-tests-acceptance-canonical-region =
            stageARelationalAcceptanceSuite.cases.whole_program_theorem_rejects_noncanonical_reachable_region;
          stage-a-relational-tests-acceptance-executable-coverage =
            stageARelationalAcceptanceSuite.cases.whole_program_theorem_rejects_tampered_executable_partition;
          stage-a-relational-tests-acceptance-semantic-code-aliases =
            stageARelationalAcceptanceSuite.cases.whole_program_theorem_requires_semantic_code_alias_bridges;
          stage-a-relational-tests-acceptance-tls-launch =
            stageARelationalAcceptanceSuite.cases.tls_directory_is_parsed_and_rejected_by_console_launch_v1;
          stage-a-relational-tests-acceptance-tls-parsing =
            stageARelationalAcceptanceSuite.cases.formal_tls_directory_and_callback_parsing;
          stage-a-relational-tests-acceptance-tls-roots =
            stageARelationalAcceptanceSuite.cases.tls_callbacks_become_lean_checked_launch_roots;
          stage-a-relational-tests-acceptance-control-frontier =
            stageARelationalAcceptanceSuite.cases.control_frontier_does_not_hide_independent_reachable_branch;
          stage-a-relational-tests-acceptance-nested-external =
            stageARelationalAcceptanceSuite.cases.nested_external_call_preserves_internal_runtime_frame_end_to_end;
          stage-a-relational-tests-acceptance-protocol-callback =
            stageARelationalAcceptanceSuite.cases.protocol_call_and_callback_return_close_whole_program_theorem;
          stage-a-relational-tests-acceptance-import-register-return =
            stageARelationalAcceptanceSuite.cases.import_register_survives_checked_internal_call_and_return;
          stage-a-relational-tests-acceptance-direct-stack-read =
            stageARelationalAcceptanceSuite.cases.direct_paired_stack_read_loop_closes_whole_program_theorem;
          stage-a-relational-tests-acceptance-below-frame-stack-read =
            stageARelationalAcceptanceSuite.cases.below_frame_stack_read_closes_only_for_same_checked_location;
          stage-a-relational-tests-acceptance-below-frame-stack-guard =
            stageARelationalAcceptanceSuite.cases.below_frame_zero_guard_closes_only_for_same_checked_location;
          stage-a-relational-tests-acceptance-stack-base-related-word =
            stageARelationalAcceptanceSuite.cases.preserved_stack_base_becomes_related_word_at_successor;
          stage-a-relational-tests-state-dynamic-flow-call-boundary =
            stageARelationalStateSuite.cases.dynamic_range_flow_does_not_cross_call_frames;
          stage-a-relational-tests-acceptance-representative =
            stageARelationalAcceptanceSuite.cases.representative_control_slice_closes_whole_program_theorem;
          stage-a-relational-tests-acceptance-terminal-return =
            stageARelationalAcceptanceSuite.cases.top_level_return_checks_terminal_invariant_end_to_end;
          stage-a-relational-tests-acceptance-nonidentical-launch =
            stageARelationalAcceptanceSuite.cases.nonidentical_launch_uses_checked_memory_model;
          stage-a-relational-tests-acceptance-related-word-launch =
            stageARelationalAcceptanceSuite.cases.launch_realizability_accepts_related_word_self_registers;
          stage-a-relational-tests-acceptance-nonreturning-import-thunk =
            stageARelationalAcceptanceSuite.cases.nonreturning_import_thunk_terminates_whole_program_end_to_end;
          stage-a-relational-tests-acceptance-external-loop =
            stageARelationalAcceptanceSuite.cases.external_call_loop_checks_paired_environment_end_to_end;
          stage-a-relational-tests-acceptance-external-allocation =
            stageARelationalAcceptanceSuite.cases.external_allocation_and_dynamic_write_close_whole_program_theorem;
          stage-a-relational-tests-acceptance-input-flag-guard =
            stageARelationalAcceptanceSuite.cases.input_flag_guard_closes_only_for_the_same_checked_flag;
          stage-a-relational-tests-acceptance-exact-pure-guard =
            stageARelationalAcceptanceSuite.cases.exact_pure_guard_uses_derived_register_exactness;
          stage-a-relational-tests-acceptance-exact-to-related =
            stageARelationalAcceptanceSuite.cases.exact_register_output_weakens_to_related_successor;
          stage-a-relational-tests-acceptance-exact-register-transfer =
            stageARelationalAcceptanceSuite.cases.exact_register_transfer_and_cfg_edge_are_checked_by_lean;
          stage-a-relational-tests-acceptance-immutable-image-word =
            stageARelationalAcceptanceSuite.cases.immutable_image_word_load_closes_register_transfer;
          stage-a-relational-tests-acceptance-fixed-immutable-expression =
            stageARelationalAcceptanceSuite.cases.fixed_immutable_expression_chain_closes_whole_program_theorem;
          stage-a-relational-tests-acceptance-static-word-slot =
            stageARelationalAcceptanceSuite.cases.static_word_slot_load_closes_register_transfer;
          stage-a-relational-tests-acceptance-paired-static-word-guard =
            stageARelationalAcceptanceSuite.cases.paired_static_word_guard_closes_whole_program_theorem;
          stage-a-relational-tests-acceptance-immutable-pe-pointer-chain =
            stageARelationalAcceptanceSuite.cases.immutable_pe_pointer_chain_guard_closes_whole_program_theorem;
          stage-a-relational-tests-acceptance-immutable-pe-header =
            stageARelationalAcceptanceSuite.cases.immutable_mapped_pe_header_read8_closes_exact_guard;
          stage-a-relational-tests-acceptance-direct-call-stack-writes =
            stageARelationalAcceptanceSuite.cases.direct_call_with_prepared_stack_word_checks_whole_program_theorem;
          stage-a-relational-tests-acceptance-dynamic-spill =
            stageARelationalAcceptanceSuite.cases.dynamic_base_spill_with_field_write_is_checked_by_lean;
          stage-a-relational-tests-acceptance-direct-call-static-writes =
            stageARelationalAcceptanceSuite.cases.direct_call_with_prepared_static_word_checks_whole_program_theorem;
          stage-a-relational-tests = pkgs.symlinkJoin {
            name = "stage-a-relational-tests";
            paths = [
              stage-a-relational-tests-schema
              stage-a-relational-tests-build-graph
              stage-a-relational-tests-static-word-relations
              stage-a-relational-tests-external-protocol
              stage-a-relational-tests-external-contract-selection
              stage-a-relational-tests-external-stateful-memory
              stage-a-relational-tests-external-stateful-memory-kernel
              stage-a-relational-tests-reachable-acceptance
              stage-a-relational-tests-pe-entry-surface
              stage-a-relational-tests-formal-pe-entry-surface
              stage-a-relational-tests-proof-blocked
              stage-a-relational-tests-loader-image-diagnostics
              stage-a-relational-tests-loader-image-valid
              stage-a-relational-tests-raw-eip-execution
              stage-a-relational-tests-indirect-control
              stage-a-relational-tests-control-provenance
              stage-a-relational-tests-isa-conformance
              stage-a-relational-tests-isa-conformance-kernel
              stage-a-relational-tests-isa-conformance-lean
              stage-a-relational-tests-isa-conformance-unicorn
              stage-a-relational-tests-isa-conformance-bochs
              stage-a-relational-tests-isa-conformance-differential
              stage-a-relational-tests-isa-conformance-80386
              stage-a-relational-tests-isa-conformance-80386-differential
              stage-a-relational-tests-bounded-table-call-generation
              stage-a-relational-tests-bounded-table-call-kernel
              stage-a-relational-tests-callsite-preservation
              stage-a-relational-tests-callsite-summary-generation
              stage-a-relational-tests-call-return-summary
              stage-a-relational-tests-callsite-preservation-schema
              stage-a-relational-tests-register-analysis
              stage-a-relational-tests-lean-runtime-frame-import-environment
              stage-a-relational-tests-acceptance-runtime-frame-import
              stage-a-relational-tests-acceptance-runtime-frame-register
              stage-a-relational-tests-contract
              stage-a-relational-tests-state
              stage-a-relational-tests-pipeline
              stage-a-relational-tests-lean
              stage-a-relational-tests-acceptance
              stage-a-relational-tests-static-word-slot-certificate
            ];
          };
          stage-a-jq-fixtures-root = pkgs.writeShellApplication {
            name = "stage-a-jq-fixtures-root";
            text = ''
              printf '%s\n' "${stage-a-jq-fixtures}"
            '';
          };
          stage-a-gnu-hello-fixtures-root = pkgs.writeShellApplication {
            name = "stage-a-gnu-hello-fixtures-root";
            text = ''
              printf '%s\n' "${stage-a-gnu-hello-fixtures}"
            '';
          };
          stage-a-minimal-hello-fixtures-root = pkgs.writeShellApplication {
            name = "stage-a-minimal-hello-fixtures-root";
            text = ''
              printf '%s\n' "${stage-a-minimal-hello-fixtures}"
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
            bochs-conformance
            singlestep-80386-conformance
            spaghetti-extractor
            spaghetti-extractor-analysis
            spaghetti-extractor-mapping
            spaghetti-extractor-normalize
            spaghetti-extractor-region-facts
            spaghetti-extractor-side
            stage-a-analysis-source-boundary-check
            stage-a-isa-conformance-bochs-80386
            stage-a-isa-kernel-cache
            stage-a-fixtures
            stage-a-fixtures-check
            stage-a-fixtures-root
            stage-a-exit-fixtures
            stage-a-exit-static-map
            stage-a-exit-relation-contract
            stage-a-exit-prepared-proof
            stage-a-exit-evidence-bundle
            stage-a-exit-check
            stage-a-exit-behavior-smoke
            stage-a-winapi-hello-fixtures
            stage-a-winapi-hello-static-map
            stage-a-winapi-hello-relation-contract
            stage-a-winapi-hello-prepared-proof
            stage-a-winapi-hello-proof-audit
            stage-a-winapi-hello-check
            stage-a-winapi-hello-behavior-smoke
            stage-a-gnu-hello-fixtures
            stage-a-gnu-hello-original-inventory
            stage-a-gnu-hello-candidate-inventory
            stage-a-gnu-hello-original-extraction
            stage-a-gnu-hello-candidate-extraction
            stage-a-gnu-hello-original-isa
            stage-a-gnu-hello-candidate-isa
            stage-a-gnu-hello-original-supplement-request
            stage-a-gnu-hello-candidate-supplement-request
            stage-a-gnu-hello-original-supplement-extraction
            stage-a-gnu-hello-candidate-supplement-extraction
            stage-a-gnu-hello-original-merged-extraction
            stage-a-gnu-hello-candidate-merged-extraction
            stage-a-gnu-hello-normalized-behaviors
            stage-a-gnu-hello-static-map
            stage-a-gnu-hello-relation-contract
            stage-a-gnu-hello-region-facts
            stage-a-gnu-hello-analysis
            stage-a-gnu-hello-preflight
            stage-a-gnu-hello-launch-proof
            stage-a-gnu-hello-check
            stage-a-gnu-hello-fixtures-root
            stage-a-minimal-hello-fixtures
            stage-a-minimal-hello-static-map
            stage-a-minimal-hello-relation-contract
            stage-a-minimal-hello-prepared-proof
            stage-a-minimal-hello-proof-smoke
            stage-a-minimal-hello-launch-proof
            stage-a-minimal-hello-segment-proofs
            stage-a-minimal-hello-evidence-bundle
            stage-a-minimal-hello-check
            stage-a-minimal-hello-fixtures-root
            stage-a-jq-fixtures
            stage-a-jq-static-map
            stage-a-jq-relation-contract
            stage-a-jq-prepared-proof
            stage-a-jq-reference-contract
            stage-a-jq-fixtures-check
            stage-a-jq-fixtures-root
            stage-a-relational-analysis-kernel-cache
            stage-a-relational-kernel-cache
            stage-a-relational-tests
            stage-a-relational-tests-schema
            stage-a-relational-tests-build-graph
            stage-a-relational-tests-static-word-relations
            stage-a-relational-tests-external-protocol
            stage-a-relational-tests-external-contract-selection
            stage-a-relational-tests-external-stateful-memory
            stage-a-relational-tests-external-stateful-memory-kernel
            stage-a-relational-tests-reachable-acceptance
            stage-a-relational-tests-pe-entry-surface
            stage-a-relational-tests-formal-pe-entry-surface
            stage-a-relational-tests-proof-blocked
            stage-a-relational-tests-loader-image-diagnostics
            stage-a-relational-tests-loader-image-valid
            stage-a-relational-tests-raw-eip-execution
            stage-a-relational-tests-indirect-control
            stage-a-relational-tests-control-provenance
            stage-a-relational-tests-isa-conformance
            stage-a-relational-tests-isa-conformance-kernel
            stage-a-relational-tests-isa-conformance-lean
            stage-a-relational-tests-isa-conformance-unicorn
            stage-a-relational-tests-isa-conformance-bochs
            stage-a-relational-tests-isa-conformance-differential
            stage-a-relational-tests-isa-conformance-80386
            stage-a-relational-tests-isa-conformance-80386-differential
            stage-a-relational-tests-bounded-table-call-generation
            stage-a-relational-tests-bounded-table-call-kernel
            stage-a-relational-tests-reverse-sentinel-scanner-integration
            stage-a-relational-tests-callsite-preservation
            stage-a-relational-tests-callsite-summary-generation
            stage-a-relational-tests-call-return-summary
            stage-a-relational-tests-callsite-preservation-schema
            stage-a-relational-tests-register-analysis
            stage-a-relational-tests-lean-runtime-frame-import-environment
            stage-a-relational-tests-acceptance-runtime-frame-import
            stage-a-relational-tests-acceptance-runtime-frame-register
            stage-a-relational-tests-static-word-slot-certificate
            stage-a-relational-tests-contract
            stage-a-relational-tests-state
            stage-a-relational-tests-pipeline
            stage-a-relational-tests-pipeline-cmov-general-composition
            stage-a-relational-tests-lean
            stage-a-relational-tests-lean-return-slot-inventory
            stage-a-relational-tests-lean-dynamic-range-result
            stage-a-relational-tests-lean-linked-frames
            stage-a-relational-tests-contract-machine-import
            stage-a-relational-tests-acceptance
            stage-a-relational-tests-acceptance-whole-program-kernel
            stage-a-relational-tests-acceptance-instruction-adequacy
            stage-a-relational-tests-acceptance-instruction-adequacy-tamper
            stage-a-relational-tests-acceptance-instruction-adequacy-multi-chunk
            stage-a-relational-tests-acceptance-entry-surface
            stage-a-relational-tests-acceptance-direct-loop
            stage-a-relational-tests-acceptance-related-word-launch
            stage-a-relational-tests-acceptance-canonical-region
            stage-a-relational-tests-acceptance-executable-coverage
            stage-a-relational-tests-acceptance-semantic-code-aliases
            stage-a-relational-tests-acceptance-tls-launch
            stage-a-relational-tests-acceptance-tls-parsing
            stage-a-relational-tests-acceptance-tls-roots
            stage-a-relational-tests-acceptance-control-frontier
            stage-a-relational-tests-acceptance-nested-external
            stage-a-relational-tests-acceptance-protocol-callback
            stage-a-relational-tests-acceptance-import-register-return
            stage-a-relational-tests-acceptance-direct-stack-read
            stage-a-relational-tests-acceptance-below-frame-stack-read
            stage-a-relational-tests-acceptance-below-frame-stack-guard
            stage-a-relational-tests-acceptance-stack-base-related-word
            stage-a-relational-tests-state-dynamic-flow-call-boundary
            stage-a-relational-tests-acceptance-representative
            stage-a-relational-tests-acceptance-terminal-return
            stage-a-relational-tests-acceptance-nonidentical-launch
            stage-a-relational-tests-acceptance-nonreturning-import-thunk
            stage-a-relational-tests-acceptance-external-loop
            stage-a-relational-tests-acceptance-external-allocation
            stage-a-relational-tests-acceptance-input-flag-guard
            stage-a-relational-tests-acceptance-exact-pure-guard
            stage-a-relational-tests-acceptance-exact-to-related
            stage-a-relational-tests-acceptance-exact-register-transfer
              stage-a-relational-tests-acceptance-immutable-image-word
              stage-a-relational-tests-acceptance-fixed-immutable-expression
              stage-a-relational-tests-acceptance-static-word-slot
            stage-a-relational-tests-acceptance-paired-static-word-guard
            stage-a-relational-tests-acceptance-immutable-pe-pointer-chain
            stage-a-relational-tests-acceptance-immutable-pe-header
            stage-a-relational-tests-acceptance-direct-call-stack-writes
            stage-a-relational-tests-acceptance-dynamic-spill
            stage-a-relational-tests-acceptance-direct-call-static-writes
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
          stage-a-gnu-hello-fixtures-root = {
            type = "app";
            program = "${packages.stage-a-gnu-hello-fixtures-root}/bin/stage-a-gnu-hello-fixtures-root";
          };
          stage-a-minimal-hello-fixtures-root = {
            type = "app";
            program = "${packages.stage-a-minimal-hello-fixtures-root}/bin/stage-a-minimal-hello-fixtures-root";
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
            stage-a-isa-conformance-bochs-80386
            stage-a-fixtures-check
            stage-a-exit-check
            stage-a-exit-behavior-smoke
            stage-a-winapi-hello-check
            stage-a-winapi-hello-behavior-smoke
            stage-a-gnu-hello-preflight
            stage-a-gnu-hello-check
            stage-a-minimal-hello-check
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
              unicorn
              z3-solver
            ]
          );
        in
        {
          default = pkgs.mkShell {
            packages = [
              pythonEnv
              packages.bochs-conformance
              packages.spaghetti-extractor
              pkgs.jq
              pkgs.lean4
              pkgs.nix
              pkgs.pkgsCross.mingw32.stdenv.cc
              pkgs.llvm
              pkgs.xed
            ];
            shellHook = ''
              export PYTHONPATH="$PWD/src''${PYTHONPATH:+:$PYTHONPATH}"
            '';
          };
        }
      );
    };
}
