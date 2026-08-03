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
      lib = {
        mkStageALeanGraph = import ./nix/stage-a-lean-graph.nix;
        mkStageASourceEquivalence = import ./nix/stage-a-source-equivalence.nix;
        mkStageAISAQualificationGraph = import ./nix/stage-a-isa-qualification-graph.nix;
        mkStageARelationalAnalysisGraph = import ./nix/stage-a-relational-analysis-graph.nix;
        mkStageARoundtripCorpus = import ./nix/stage-a-roundtrip-corpus.nix;
        mkStageARoundtripSmoke = import ./nix/stage-a-roundtrip-smoke.nix;
        mkStageBComponentAnalysis = import ./nix/stage-b-component-analysis.nix;
        mkStageBLinkedLibraryAnalysis = import ./nix/stage-b-linked-libraries.nix;
        mkStageBSourceCallSubstitutions =
          import ./nix/stage-b-source-call-substitutions.nix;
        mkStageBUpstreamShellSuite = import ./nix/stage-b-upstream-shell-suite.nix;
      };

      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          vintagePkgs = import nixpkgs {
            inherit system;
            config.allowUnfreePredicate = package:
              pkgs.lib.hasPrefix "open-watcom-bin" (pkgs.lib.getName package);
          };
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
          mkPythonWorker =
            {
              name,
              source,
              module,
              runtimeInputs,
              preferLocalBuild ? null,
            }:
            let
              worker = pkgs.writeShellApplication {
                inherit name runtimeInputs;
                text = ''
                  export PYTHONPATH="${source}/src''${PYTHONPATH:+:$PYTHONPATH}"
                  exec python -m ${module} "$@"
                '';
              };
            in
            if preferLocalBuild == null then worker else worker.overrideAttrs { inherit preferLocalBuild; };
          bochs-conformance = pkgs.callPackage ./nix/bochs-conformance.nix {
            instrumentationSrc = ./tools/bochs-conformance;
          };
          xed-isa-catalog = pkgs.stdenv.mkDerivation {
            pname = "spaghetti-extractor-xed-isa-catalog";
            version = "1";
            src = ./tools/xed-isa-catalog;
            dontConfigure = true;
            dontFixup = true;

            buildPhase = ''
              runHook preBuild
              $CC -std=c11 -O2 -Wall -Wextra -Werror \
                -I${pkgs.xed}/include \
                main.c ${pkgs.xed}/lib/libxed.a \
                -o xed-isa-catalog
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall
              install -Dm755 xed-isa-catalog "$out/bin/xed-isa-catalog"
              install -Dm644 README.md \
                "$out/share/doc/spaghetti-extractor-xed-isa-catalog/README.md"
              runHook postInstall
            '';
          };
          stage-a-isa-xed-catalog = pkgs.runCommand
            "stage-a-isa-xed-catalog-pe32-i686-v1"
            {
              nativeBuildInputs = [
                pkgs.jq
                xed-isa-catalog
              ];
              preferLocalBuild = false;
              allowSubstitutes = true;
              __contentAddressed = true;
            }
            ''
              mkdir -p "$out"
              xed-isa-catalog > "$out/xed-inst-catalog.json"
              jq -e '
                .format == "spaghetti-extractor-xed-inst-catalog-v1"
                and .profile.id == "pe32-i686-v1"
                and .profile.chip == "PENTIUMPRO"
                and .profile.privilege == "ring3"
                and (.templates | length) > 1000
                and all(.templates[];
                  .cpl == 3
                  and (.iform | type == "string" and length > 0)
                  and (.isa_set | type == "string" and length > 0)
                  and (.operands | type == "array")
                )
              ' "$out/xed-inst-catalog.json" > /dev/null
              catalog_sha256="$(sha256sum "$out/xed-inst-catalog.json" | cut -d ' ' -f 1)"
              extractor_sha256="$(
                sha256sum ${xed-isa-catalog}/bin/xed-isa-catalog | cut -d ' ' -f 1
              )"
              xed_version="$(jq -r '.generator.xed_version' "$out/xed-inst-catalog.json")"
              template_count="$(jq '.templates | length' "$out/xed-inst-catalog.json")"
              jq -n \
                --arg catalog_sha256 "$catalog_sha256" \
                --arg extractor_sha256 "$extractor_sha256" \
                --arg extractor_store_path ${pkgs.lib.escapeShellArg (toString xed-isa-catalog)} \
                --arg xed_store_path ${pkgs.lib.escapeShellArg (toString pkgs.xed)} \
                --arg xed_version "$xed_version" \
                --argjson template_count "$template_count" \
                '{
                  format: "stage-a-isa-xed-catalog-manifest-v1",
                  profile: "pe32-i686-v1",
                  catalog: {
                    path: "xed-inst-catalog.json",
                    sha256: $catalog_sha256,
                    template_count: $template_count
                  },
                  extractor: {
                    store_path: $extractor_store_path,
                    sha256: $extractor_sha256
                  },
                  xed: {
                    store_path: $xed_store_path,
                    version: $xed_version
                  },
                  trust: {
                    role: "untrusted_isa_catalog_proposal",
                    proof_authority: false,
                    closes_stage_a_proof: false
                  }
                }' > "$out/manifest.json"
            '';
          spaghettiExtractorCoreSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./pyproject.toml
              ./src
              ./nix/stage-a-lean-graph.nix
              ./nix/stage-a-lean-compact.nix
              ./nix/stage-a-isa-conformance.nix
              ./nix/stage-a-isa-qualification-graph.nix
              ./nix/stage-a-register-dataflow-graph.nix
              ./nix/stage-a-relational-analysis-graph.nix
              ./nix/stage-b-native-object-graph.nix
              ./nix/stage-b-component-discovery.nix
              ./nix/stage-b-component-analysis.nix
              ./nix/stage-b-component-interfaces.nix
              ./nix/stage-b-component-selection.nix
              ./nix/stage-b-interpreter-package.nix
              ./nix/stage-b-linked-libraries.nix
              ./nix/stage-b-python-sources.nix
              ./nix/stage-b-reconstruction-workspace.nix
              ./nix/stage-b-semantic-components.nix
              ./nix/stage-b-semantic-component-workspaces.nix
              ./nix/stage-b-source-call-substitutions.nix
              ./nix/stage-b-upstream-shell-suite.nix
            ];
          };
          spaghettiExtractorRoundtripSource = pkgs.lib.fileset.toSource {
            root = ./.;
            # Corpus generation and static preflight do not consume Lean or
            # Nix evaluators. Keeping those sources out of this tool prevents
            # proof-only edits from regenerating binaries and analyses.
            fileset = pkgs.lib.fileset.difference ./src ./src/spaghetti_extractor/lean;
          };
          stageBStaticAnalysisPythonFiles = pkgs.lib.fileset.unions [
              ./src/spaghetti_extractor/__init__.py
              ./src/spaghetti_extractor/_contract_tools/abi.py
              ./src/spaghetti_extractor/_contract_tools/common.py
              ./src/spaghetti_extractor/_contract_tools/map_generation.py
              ./src/spaghetti_extractor/_contract_tools/reference_contract.py
              ./src/spaghetti_extractor/_contract_tools/symbolic_execution.py
              ./src/spaghetti_extractor/artifact_formats.py
              ./src/spaghetti_extractor/errors.py
              ./src/spaghetti_extractor/machine_import_profiles.py
              ./src/spaghetti_extractor/opaque_reconstruction.py
              ./src/spaghetti_extractor/pe.py
              ./src/spaghetti_extractor/reconstruction_control.py
              ./src/spaghetti_extractor/reconstruction_ir.py
              ./src/spaghetti_extractor/stage_b_state_machine.py
              ./src/spaghetti_extractor/stage_binary.py
              ./src/spaghetti_extractor/util.py
              ./src/spaghetti_extractor/relational/__init__.py
              ./src/spaghetti_extractor/relational/artifacts.py
              ./src/spaghetti_extractor/relational/binary_inventory.py
              ./src/spaghetti_extractor/relational/contract.py
              ./src/spaghetti_extractor/relational/model.py
              ./src/spaghetti_extractor/relational/reference_contract.py
              ./src/spaghetti_extractor/relational/schema.py
              ./src/spaghetti_extractor/relational/semantic_cutpoints.py
              ./src/spaghetti_extractor/relational/side_extraction_artifact.py
              ./src/spaghetti_extractor/relational/x87_profile.py
              ./src/spaghetti_extractor/roundtrip_fuzz/__init__.py
              ./src/spaghetti_extractor/roundtrip_fuzz/image_contract.py
            ];
          stageBStaticAnalysisPythonSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = stageBStaticAnalysisPythonFiles;
          };
          stageBPlanningPythonSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              stageBStaticAnalysisPythonFiles
              ./src/spaghetti_extractor/reconstruction_composition.py
              ./src/spaghetti_extractor/reconstruction_contract_analysis.py
              ./src/spaghetti_extractor/reconstruction_validation.py
              ./src/spaghetti_extractor/reconstruction_workspace.py
              ./src/spaghetti_extractor/region_replacement.py
            ];
          };
          stageBComponentDiscoveryPythonSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./src/spaghetti_extractor/__init__.py
              ./src/spaghetti_extractor/component_discovery.py
            ];
          };
          stageBComponentSelectionPythonSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./src/spaghetti_extractor/__init__.py
              ./src/spaghetti_extractor/artifact_formats.py
              ./src/spaghetti_extractor/component_selection.py
              ./src/spaghetti_extractor/util.py
            ];
          };
          stageBSemanticComponentPythonSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./src/spaghetti_extractor/__init__.py
              ./src/spaghetti_extractor/artifact_formats.py
              ./src/spaghetti_extractor/linked_library_contracts.py
              ./src/spaghetti_extractor/semantic_components.py
              ./src/spaghetti_extractor/util.py
            ];
          };
          stageBComponentInterfacePythonSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./src/spaghetti_extractor/__init__.py
              ./src/spaghetti_extractor/artifact_formats.py
              ./src/spaghetti_extractor/component_interface.py
              ./src/spaghetti_extractor/util.py
            ];
          };
          stageBPythonSources =
            import ./nix/stage-b-python-sources.nix { inherit pkgs; };
          stageBInterpreterPythonSource = stageBPythonSources.interpreter;
          stageBComponentWorkspacePythonSource = stageBPythonSources.workspace;
          stageBLinkedLibraryPythonSource = stageBPythonSources.linkedLibraries;
          stageBSourceCallSubstitutionPythonSource =
            stageBPythonSources.sourceCallSubstitutions;
          spaghetti-extractor-roundtrip = mkPythonWorker {
            name = "spaghetti-extractor";
            source = spaghettiExtractorRoundtripSource;
            module = "spaghetti_extractor";
            runtimeInputs = [ pythonEnv ];
            preferLocalBuild = false;
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
          spaghetti-extractor-profiles = pkgs.runCommand "spaghetti-extractor-profiles" { } ''
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
          relationalLeanModuleDirectory = ./src/spaghetti_extractor/lean/StageA;
          relationalLeanModuleEntries = builtins.readDir relationalLeanModuleDirectory;
          relationalLeanModules = map (file: pkgs.lib.removeSuffix ".lean" file) (
            builtins.filter (
              file: relationalLeanModuleEntries.${file} == "regular" && pkgs.lib.hasSuffix ".lean" file
            ) (builtins.attrNames relationalLeanModuleEntries)
          );
          relationalLeanImports =
            module:
            pkgs.lib.unique (
              pkgs.lib.filter (dependency: dependency != null) (
                map
                  (
                    line:
                    let
                      matched = builtins.match "^import StageA\\.([A-Za-z0-9_]+)$" line;
                    in
                    if matched == null then null else builtins.head matched
                  )
                  (pkgs.lib.splitString "\n" (builtins.readFile (relationalLeanModuleDirectory + "/${module}.lean")))
              )
            );
          relationalLeanModuleClosure =
            roots:
            pkgs.lib.sort builtins.lessThan (
              map (entry: entry.key) (
                builtins.genericClosure {
                  startSet = map (module: { key = module; }) roots;
                  operator = entry: map (dependency: { key = dependency; }) (relationalLeanImports entry.key);
                }
              )
            );
          relationalRoundtripRequiredModules = [
            "RelationalEngine"
            "RelationalDefinedness"
            "RelationalIdentity"
            "RelationalInterpreter"
            "RelationalInterpreterKernel"
            "RelationalInterpreterTransfer"
            "RelationalInterpreterX87"
            "RelationalPEBytePacks"
            "RelationalSymbolicSoundness"
            "RelationalLockstepEnvironment"
            "RelationalOpaqueLockstepEnvironment"
            "RelationalStaticMachineImportContracts"
          ];
          relationalAcceptanceKernelRoots = [
            "RelationalPEWorldExecution"
            "RelationalStaticTree"
          ];
          relationalAcceptanceKernelModules = relationalLeanModuleClosure relationalAcceptanceKernelRoots;
          relationalRoundtripKernelRoots = relationalRoundtripRequiredModules;
          relationalRoundtripKernelModules = relationalLeanModuleClosure relationalRoundtripKernelRoots;
          relationalInterpreterNativeKernelRoots = [
            "RelationalInterpreterWholeProgramAcceptance"
          ];
          relationalInterpreterNativeKernelModules = relationalLeanModuleClosure relationalInterpreterNativeKernelRoots;
          relationalProgramLookupNativeKernelRoots = [
            "RelationalInterpreterKernelProgramLookupFrameExecutor"
          ];
          relationalProgramLookupNativeKernelModules = relationalLeanModuleClosure relationalProgramLookupNativeKernelRoots;
          relationalProgramLookupOperationKernelRoots = [
            "RelationalInterpreterKernelProgramLookupOperation"
          ];
          relationalProgramLookupOperationKernelModules = relationalLeanModuleClosure relationalProgramLookupOperationKernelRoots;
          relationalRunIterationKernelRoots = [
            "RelationalInterpreterKernelRunIteration"
          ];
          relationalRunIterationKernelModules =
            relationalLeanModuleClosure relationalRunIterationKernelRoots;
          relationalOperationStateRouteKernelRoots = [
            "RelationalInterpreterKernelOperationStateRouteChecker"
          ];
          relationalOperationStateRouteKernelModules =
            relationalLeanModuleClosure relationalOperationStateRouteKernelRoots;
          relationalOperationRankedStateRouteKernelRoots = [
            "RelationalInterpreterKernelOperationRankedStateRoute"
          ];
          relationalOperationRankedStateRouteKernelModules =
            relationalLeanModuleClosure
              relationalOperationRankedStateRouteKernelRoots;
          relationalOperationRouteInvariantKernelRoots = [
            "RelationalInterpreterKernelOperationRouteInvariant"
          ];
          relationalOperationRouteInvariantKernelModules =
            relationalLeanModuleClosure
              relationalOperationRouteInvariantKernelRoots;
          relationalOperationPredicateRouteKernelRoots = [
            "RelationalInterpreterKernelOperationPredicateRoute"
          ];
          relationalOperationPredicateRouteKernelModules =
            relationalLeanModuleClosure
              relationalOperationPredicateRouteKernelRoots;
          relationalOperationEffectCheckerKernelRoots = [
            "RelationalInterpreterKernelOperationEffectChecker"
          ];
          relationalOperationEffectCheckerKernelModules =
            relationalLeanModuleClosure
              relationalOperationEffectCheckerKernelRoots;
          relationalOperationMemoryRouteKernelRoots = [
            "RelationalInterpreterKernelOperationMemoryRoute"
          ];
          relationalOperationMemoryRouteKernelModules =
            relationalLeanModuleClosure
              relationalOperationMemoryRouteKernelRoots;
          relationalCdeclStaticPreservationKernelRoots = [
            "RelationalInterpreterKernelCdeclEpilogueStaticPreservation"
          ];
          relationalCdeclStaticPreservationKernelModules =
            relationalLeanModuleClosure
              relationalCdeclStaticPreservationKernelRoots;
          relationalInterpreterKernelEngineCopyRoots = [
            "RelationalInterpreterKernelEngineCopy"
          ];
          relationalInterpreterKernelEngineCopyModules =
            relationalLeanModuleClosure
              relationalInterpreterKernelEngineCopyRoots;
          relationalOperationStateBoundaryKernelRoots = [
            "RelationalInterpreterKernelOperationStateBoundaryChecker"
          ];
          relationalOperationStateBoundaryKernelModules =
            relationalLeanModuleClosure
              relationalOperationStateBoundaryKernelRoots;
          relationalOperationStateRouteRunAdapterKernelRoots = [
            "RelationalInterpreterKernelOperationStateRouteRunAdapter"
          ];
          relationalOperationStateRouteRunAdapterKernelModules =
            relationalLeanModuleClosure
              relationalOperationStateRouteRunAdapterKernelRoots;
          relationalOperationStepRouteAdapterKernelRoots = [
            "RelationalInterpreterKernelOperationStepRouteAdapter"
          ];
          relationalOperationStepRouteAdapterKernelModules =
            relationalLeanModuleClosure
              relationalOperationStepRouteAdapterKernelRoots;
          relationalRoundtripKernelResources = {
            RelationalEngine = {
              resource_class = "medium";
              estimated_memory_mb = 2048;
            };
            RelationalIdentity = {
              resource_class = "medium";
              estimated_memory_mb = 3072;
            };
            RelationalInterpreter = {
              resource_class = "medium";
              estimated_memory_mb = 3072;
            };
            RelationalInterpreterTransfer = {
              resource_class = "high-memory";
              estimated_memory_mb = 8192;
            };
            RelationalInterpreterX87 = {
              resource_class = "high-memory";
              estimated_memory_mb = 8192;
            };
            RelationalPEBytePacks = {
              resource_class = "medium";
              estimated_memory_mb = 2048;
            };
            RelationalInterpreterKernel = {
              resource_class = "high-memory";
              estimated_memory_mb = 12288;
            };
            RelationalInterpreterKernelLookupNative = {
              resource_class = "medium";
              estimated_memory_mb = 4096;
            };
            RelationalInterpreterKernelProgramLookupOperation = {
              resource_class = "medium";
              estimated_memory_mb = 2048;
            };
            RelationalInterpreterWholeProgramAcceptance = {
              resource_class = "medium";
              estimated_memory_mb = 4096;
            };
            RelationalSymbolicSoundness = {
              resource_class = "high-memory";
              estimated_memory_mb = 12288;
            };
            RelationalLockstepEnvironment = {
              resource_class = "medium";
              estimated_memory_mb = 3072;
            };
            RelationalOpaqueLockstepEnvironment = {
              resource_class = "high-memory";
              estimated_memory_mb = 6144;
            };
            # The normalization names are reserved for the forthcoming checked
            # lowering kernels. Prefix discovery adds them to the same graph as
            # soon as their staged Lean sources exist.
            RelationalInterpreterNormalization = {
              resource_class = "high-memory";
              estimated_memory_mb = 12288;
            };
            RelationalInterpreterDefinedness = {
              resource_class = "high-memory";
              estimated_memory_mb = 8192;
            };
            RelationalDefinedness = {
              resource_class = "high-memory";
              estimated_memory_mb = 8192;
            };
            RelationalNormalization = {
              resource_class = "high-memory";
              estimated_memory_mb = 12288;
            };
          };
          relationalAnalysisKernelModules = relationalLeanModuleClosure [
            "X87"
            "RelationalX87"
            "Formal"
            "RelationalX87Decode"
            "ISAQualification"
            "RelationalDecode"
            "RelationalSemanticsChecker"
            "RelationalCheckedArtifacts"
            "RelationalLoader"
            "RelationalFiniteIndex"
            "RelationalMachine"
            "Relational"
            "RelationalEngine"
            "RelationalX87Machine"
            "RelationalPEExecution"
            "RelationalISAQualification"
          ];
          spaghettiExtractorAnalysisPythonFiles = [
            ./src/spaghetti_extractor/__init__.py
            ./src/spaghetti_extractor/artifact_formats.py
            ./src/spaghetti_extractor/_contract_tools/common.py
            ./src/spaghetti_extractor/_contract_tools/map_generation.py
            ./src/spaghetti_extractor/errors.py
            ./src/spaghetti_extractor/isa_semantic_forms.py
            ./src/spaghetti_extractor/pe.py
            ./src/spaghetti_extractor/stage_binary.py
            ./src/spaghetti_extractor/util.py
            ./src/spaghetti_extractor/relational/__init__.py
            ./src/spaghetti_extractor/relational/analysis.py
            ./src/spaghetti_extractor/relational/analysis_artifact.py
            ./src/spaghetti_extractor/relational/analysis_reference.py
            ./src/spaghetti_extractor/relational/assembly.py
            ./src/spaghetti_extractor/relational/assembly_cli.py
            ./src/spaghetti_extractor/relational/artifacts.py
            ./src/spaghetti_extractor/relational/binary_inventory.py
            ./src/spaghetti_extractor/relational/callsite_preservation.py
            ./src/spaghetti_extractor/relational/composition_products.py
            ./src/spaghetti_extractor/relational/composition_products_artifact.py
            ./src/spaghetti_extractor/relational/composition_products_cli.py
            ./src/spaghetti_extractor/relational/composition_products_format.py
            ./src/spaghetti_extractor/relational/contract.py
            ./src/spaghetti_extractor/relational/semantic_cutpoints.py
            ./src/spaghetti_extractor/relational/diagnostics.py
            ./src/spaghetti_extractor/relational/extraction.py
            ./src/spaghetti_extractor/relational/interfaces.py
            ./src/spaghetti_extractor/relational/ir.py
            ./src/spaghetti_extractor/relational/isa_requirements.py
            ./src/spaghetti_extractor/relational/mapping.py
            ./src/spaghetti_extractor/relational/memory_products.py
            ./src/spaghetti_extractor/relational/memory_products_artifact.py
            ./src/spaghetti_extractor/relational/memory_products_cli.py
            ./src/spaghetti_extractor/relational/memory_products_format.py
            ./src/spaghetti_extractor/relational/model.py
            ./src/spaghetti_extractor/relational/pair_normalization.py
            ./src/spaghetti_extractor/relational/pair_normalization_artifact.py
            ./src/spaghetti_extractor/relational/phases.py
            ./src/spaghetti_extractor/relational/pipeline.py
            ./src/spaghetti_extractor/relational/preflight.py
            ./src/spaghetti_extractor/relational/x87_profile.py
            ./src/spaghetti_extractor/relational/proposal_artifact.py
            ./src/spaghetti_extractor/relational/proposal_cli.py
            ./src/spaghetti_extractor/relational/region_facts.py
            ./src/spaghetti_extractor/relational/region_facts_artifact.py
            ./src/spaghetti_extractor/relational/region_facts_cli.py
            ./src/spaghetti_extractor/relational/report.py
            ./src/spaghetti_extractor/relational/report_schema.py
            ./src/spaghetti_extractor/relational/runtime_frame_artifact.py
            ./src/spaghetti_extractor/relational/register_dataflow_artifact.py
            ./src/spaghetti_extractor/relational/register_dataflow_aggregate.py
            ./src/spaghetti_extractor/relational/register_dataflow_formats.py
            ./src/spaghetti_extractor/relational/register_dataflow_seed.py
            ./src/spaghetti_extractor/relational/register_dataflow_solution.py
            ./src/spaghetti_extractor/relational/register_dataflow_solver.py
            ./src/spaghetti_extractor/relational/register_dataflow_summary_format.py
            ./src/spaghetti_extractor/relational/register_replay.py
            ./src/spaghetti_extractor/relational/register_replay_artifact.py
            ./src/spaghetti_extractor/relational/register_replay_cli.py
            ./src/spaghetti_extractor/relational/register_replay_format.py
            ./src/spaghetti_extractor/relational/register_transfer_core.py
            ./src/spaghetti_extractor/relational/register_transfer_ir.py
            ./src/spaghetti_extractor/relational/schema.py
            ./src/spaghetti_extractor/relational/semantic_products.py
            ./src/spaghetti_extractor/relational/semantic_products_artifact.py
            ./src/spaghetti_extractor/relational/semantic_products_cli.py
            ./src/spaghetti_extractor/relational/semantic_products_format.py
            ./src/spaghetti_extractor/relational/side_extraction.py
            ./src/spaghetti_extractor/relational/side_extraction_artifact.py
            ./src/spaghetti_extractor/relational/side_isa_artifact.py
            ./src/spaghetti_extractor/relational/worker_diagnostics.py
            ./src/spaghetti_extractor/relational/analyses/__init__.py
            ./src/spaghetti_extractor/relational/analyses/affine_linked_control.py
            ./src/spaghetti_extractor/relational/analyses/callsite.py
            ./src/spaghetti_extractor/relational/analyses/control.py
            ./src/spaghetti_extractor/relational/analyses/dataflow.py
            ./src/spaghetti_extractor/relational/analyses/external.py
            ./src/spaghetti_extractor/relational/analyses/fixedpoint.py
            ./src/spaghetti_extractor/relational/analyses/frames.py
            ./src/spaghetti_extractor/relational/analyses/invariants.py
            ./src/spaghetti_extractor/relational/analyses/memory.py
            ./src/spaghetti_extractor/relational/analyses/predicates.py
            ./src/spaghetti_extractor/relational/analyses/region_local.py
            ./src/spaghetti_extractor/relational/analyses/registers.py
            ./src/spaghetti_extractor/relational/analyses/register_static.py
            ./src/spaghetti_extractor/relational/analyses/register_lattice.py
            ./src/spaghetti_extractor/relational/analyses/semantic_control.py
            ./src/spaghetti_extractor/relational/analyses/segments.py
            ./src/spaghetti_extractor/relational/analyses/stack.py
            ./src/spaghetti_extractor/relational/analyses/x87.py
            ./src/spaghetti_extractor/relational/lean/__init__.py
            ./src/spaghetti_extractor/relational/lean/analysis_source.py
            ./src/spaghetti_extractor/relational/lean/common.py
            ./src/spaghetti_extractor/relational/lean/compiler.py
            ./src/spaghetti_extractor/relational/lean/expressions.py
          ];
          spaghettiExtractorProposalPythonFiles = pkgs.lib.subtractLists [
            ./src/spaghetti_extractor/relational/analysis.py
            ./src/spaghetti_extractor/relational/analysis_reference.py
            ./src/spaghetti_extractor/relational/assembly.py
            ./src/spaghetti_extractor/relational/assembly_cli.py
            ./src/spaghetti_extractor/relational/composition_products.py
            ./src/spaghetti_extractor/relational/composition_products_artifact.py
            ./src/spaghetti_extractor/relational/composition_products_cli.py
            ./src/spaghetti_extractor/relational/composition_products_format.py
            ./src/spaghetti_extractor/relational/analyses/invariants.py
            ./src/spaghetti_extractor/relational/memory_products.py
            ./src/spaghetti_extractor/relational/memory_products_artifact.py
            ./src/spaghetti_extractor/relational/memory_products_cli.py
            ./src/spaghetti_extractor/relational/memory_products_format.py
            ./src/spaghetti_extractor/relational/register_dataflow_aggregate.py
            ./src/spaghetti_extractor/relational/register_dataflow_packs.py
            ./src/spaghetti_extractor/relational/register_dataflow_solution.py
            ./src/spaghetti_extractor/relational/register_dataflow_solver.py
            ./src/spaghetti_extractor/relational/register_dataflow_summary_format.py
            ./src/spaghetti_extractor/relational/register_replay.py
            ./src/spaghetti_extractor/relational/register_replay_artifact.py
            ./src/spaghetti_extractor/relational/register_replay_cli.py
            ./src/spaghetti_extractor/relational/register_replay_format.py
            ./src/spaghetti_extractor/relational/semantic_products.py
            ./src/spaghetti_extractor/relational/semantic_products_artifact.py
            ./src/spaghetti_extractor/relational/semantic_products_cli.py
            ./src/spaghetti_extractor/relational/semantic_products_format.py
          ] spaghettiExtractorAnalysisPythonFiles;
          spaghettiExtractorProposalSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              (pkgs.lib.fileset.unions spaghettiExtractorProposalPythonFiles)
              (pkgs.lib.fileset.unions (
                map (
                  module: ./src/spaghetti_extractor/lean/StageA + "/${module}.lean"
                ) relationalAnalysisKernelModules
              ))
            ];
          };
          spaghettiExtractorAssemblySource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./src/spaghetti_extractor/__init__.py
              ./src/spaghetti_extractor/artifact_formats.py
              ./src/spaghetti_extractor/errors.py
              ./src/spaghetti_extractor/pe.py
              ./src/spaghetti_extractor/stage_binary.py
              ./src/spaghetti_extractor/util.py
              ./src/spaghetti_extractor/relational/__init__.py
              ./src/spaghetti_extractor/relational/analysis_artifact.py
              ./src/spaghetti_extractor/relational/analysis_reference.py
              ./src/spaghetti_extractor/relational/assembly.py
              ./src/spaghetti_extractor/relational/assembly_cli.py
              ./src/spaghetti_extractor/relational/composition_products_artifact.py
              ./src/spaghetti_extractor/relational/composition_products_format.py
              ./src/spaghetti_extractor/relational/memory_products_artifact.py
              ./src/spaghetti_extractor/relational/memory_products_format.py
              ./src/spaghetti_extractor/relational/proposal_artifact.py
              ./src/spaghetti_extractor/relational/register_replay_artifact.py
              ./src/spaghetti_extractor/relational/register_replay_format.py
              ./src/spaghetti_extractor/relational/runtime_frame_artifact.py
              ./src/spaghetti_extractor/relational/schema.py
              ./src/spaghetti_extractor/relational/semantic_products_artifact.py
              ./src/spaghetti_extractor/relational/semantic_products_format.py
            ];
          };
          spaghettiExtractorRegisterReplaySource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./src/spaghetti_extractor/__init__.py
              ./src/spaghetti_extractor/artifact_formats.py
              ./src/spaghetti_extractor/errors.py
              ./src/spaghetti_extractor/pe.py
              ./src/spaghetti_extractor/stage_binary.py
              ./src/spaghetti_extractor/util.py
              ./src/spaghetti_extractor/relational/__init__.py
              ./src/spaghetti_extractor/relational/analysis_artifact.py
              ./src/spaghetti_extractor/relational/artifacts.py
              ./src/spaghetti_extractor/relational/callsite_preservation.py
              ./src/spaghetti_extractor/relational/contract.py
              ./src/spaghetti_extractor/relational/semantic_cutpoints.py
              ./src/spaghetti_extractor/relational/diagnostics.py
              ./src/spaghetti_extractor/relational/extraction.py
              ./src/spaghetti_extractor/relational/model.py
              ./src/spaghetti_extractor/relational/pair_normalization.py
              ./src/spaghetti_extractor/relational/pair_normalization_artifact.py
              ./src/spaghetti_extractor/relational/preflight.py
              ./src/spaghetti_extractor/relational/x87_profile.py
              ./src/spaghetti_extractor/relational/proposal_artifact.py
              ./src/spaghetti_extractor/relational/region_facts.py
              ./src/spaghetti_extractor/relational/region_facts_artifact.py
              ./src/spaghetti_extractor/relational/register_dataflow_aggregate.py
              ./src/spaghetti_extractor/relational/register_dataflow_artifact.py
              ./src/spaghetti_extractor/relational/register_dataflow_formats.py
              ./src/spaghetti_extractor/relational/register_dataflow_seed.py
              ./src/spaghetti_extractor/relational/register_dataflow_solution.py
              ./src/spaghetti_extractor/relational/register_dataflow_solver.py
              ./src/spaghetti_extractor/relational/register_dataflow_summary_format.py
              ./src/spaghetti_extractor/relational/register_replay.py
              ./src/spaghetti_extractor/relational/register_replay_artifact.py
              ./src/spaghetti_extractor/relational/register_replay_cli.py
              ./src/spaghetti_extractor/relational/register_replay_format.py
              ./src/spaghetti_extractor/relational/register_transfer_core.py
              ./src/spaghetti_extractor/relational/register_transfer_ir.py
              ./src/spaghetti_extractor/relational/schema.py
              ./src/spaghetti_extractor/relational/side_extraction_artifact.py
              ./src/spaghetti_extractor/relational/analyses/__init__.py
              ./src/spaghetti_extractor/relational/analyses/callsite.py
              ./src/spaghetti_extractor/relational/analyses/control.py
              ./src/spaghetti_extractor/relational/analyses/dataflow.py
              ./src/spaghetti_extractor/relational/analyses/external.py
              ./src/spaghetti_extractor/relational/analyses/fixedpoint.py
              ./src/spaghetti_extractor/relational/analyses/memory.py
              ./src/spaghetti_extractor/relational/analyses/predicates.py
              ./src/spaghetti_extractor/relational/analyses/region_local.py
              ./src/spaghetti_extractor/relational/analyses/register_lattice.py
              ./src/spaghetti_extractor/relational/analyses/register_static.py
              ./src/spaghetti_extractor/relational/analyses/registers.py
              ./src/spaghetti_extractor/relational/analyses/semantic_control.py
              ./src/spaghetti_extractor/relational/analyses/segments.py
              ./src/spaghetti_extractor/relational/analyses/stack.py
              ./src/spaghetti_extractor/relational/lean/__init__.py
              ./src/spaghetti_extractor/relational/lean/analysis_source.py
              ./src/spaghetti_extractor/relational/lean/common.py
              ./src/spaghetti_extractor/relational/lean/compiler.py
              ./src/spaghetti_extractor/relational/lean/expressions.py
            ];
          };
          spaghettiExtractorSemanticProductsSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./src/spaghetti_extractor/__init__.py
              ./src/spaghetti_extractor/artifact_formats.py
              ./src/spaghetti_extractor/errors.py
              ./src/spaghetti_extractor/pe.py
              ./src/spaghetti_extractor/stage_binary.py
              ./src/spaghetti_extractor/util.py
              ./src/spaghetti_extractor/relational/__init__.py
              ./src/spaghetti_extractor/relational/analysis_artifact.py
              ./src/spaghetti_extractor/relational/artifacts.py
              ./src/spaghetti_extractor/relational/contract.py
              ./src/spaghetti_extractor/relational/semantic_cutpoints.py
              ./src/spaghetti_extractor/relational/extraction.py
              ./src/spaghetti_extractor/relational/model.py
              ./src/spaghetti_extractor/relational/preflight.py
              ./src/spaghetti_extractor/relational/x87_profile.py
              ./src/spaghetti_extractor/relational/proposal_artifact.py
              ./src/spaghetti_extractor/relational/schema.py
              ./src/spaghetti_extractor/relational/semantic_products.py
              ./src/spaghetti_extractor/relational/semantic_products_artifact.py
              ./src/spaghetti_extractor/relational/semantic_products_cli.py
              ./src/spaghetti_extractor/relational/semantic_products_format.py
              ./src/spaghetti_extractor/relational/analyses/external.py
              ./src/spaghetti_extractor/relational/analyses/invariants.py
              ./src/spaghetti_extractor/relational/analyses/semantic_control.py
              ./src/spaghetti_extractor/relational/lean/__init__.py
              ./src/spaghetti_extractor/relational/lean/analysis_source.py
              ./src/spaghetti_extractor/relational/lean/common.py
              ./src/spaghetti_extractor/relational/lean/compiler.py
              ./src/spaghetti_extractor/relational/lean/expressions.py
            ];
          };
          spaghettiExtractorMemoryProductsSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./src/spaghetti_extractor/__init__.py
              ./src/spaghetti_extractor/artifact_formats.py
              ./src/spaghetti_extractor/errors.py
              ./src/spaghetti_extractor/pe.py
              ./src/spaghetti_extractor/stage_binary.py
              ./src/spaghetti_extractor/util.py
              ./src/spaghetti_extractor/relational/__init__.py
              ./src/spaghetti_extractor/relational/analysis_artifact.py
              ./src/spaghetti_extractor/relational/artifacts.py
              ./src/spaghetti_extractor/relational/contract.py
              ./src/spaghetti_extractor/relational/semantic_cutpoints.py
              ./src/spaghetti_extractor/relational/extraction.py
              ./src/spaghetti_extractor/relational/memory_products.py
              ./src/spaghetti_extractor/relational/memory_products_artifact.py
              ./src/spaghetti_extractor/relational/memory_products_cli.py
              ./src/spaghetti_extractor/relational/memory_products_format.py
              ./src/spaghetti_extractor/relational/model.py
              ./src/spaghetti_extractor/relational/preflight.py
              ./src/spaghetti_extractor/relational/x87_profile.py
              ./src/spaghetti_extractor/relational/proposal_artifact.py
              ./src/spaghetti_extractor/relational/register_replay_artifact.py
              ./src/spaghetti_extractor/relational/register_replay_format.py
              ./src/spaghetti_extractor/relational/schema.py
              ./src/spaghetti_extractor/relational/analyses/external.py
              ./src/spaghetti_extractor/relational/lean/__init__.py
              ./src/spaghetti_extractor/relational/lean/analysis_source.py
              ./src/spaghetti_extractor/relational/lean/common.py
              ./src/spaghetti_extractor/relational/lean/compiler.py
              ./src/spaghetti_extractor/relational/lean/expressions.py
            ];
          };
          spaghettiExtractorCompositionProductsSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./src/spaghetti_extractor/__init__.py
              ./src/spaghetti_extractor/artifact_formats.py
              ./src/spaghetti_extractor/_contract_tools/common.py
              ./src/spaghetti_extractor/_contract_tools/map_generation.py
              ./src/spaghetti_extractor/errors.py
              ./src/spaghetti_extractor/isa_semantic_forms.py
              ./src/spaghetti_extractor/pe.py
              ./src/spaghetti_extractor/stage_binary.py
              ./src/spaghetti_extractor/util.py
              ./src/spaghetti_extractor/relational/__init__.py
              ./src/spaghetti_extractor/relational/analysis_artifact.py
              ./src/spaghetti_extractor/relational/artifacts.py
              ./src/spaghetti_extractor/relational/binary_inventory.py
              ./src/spaghetti_extractor/relational/composition_products.py
              ./src/spaghetti_extractor/relational/composition_products_artifact.py
              ./src/spaghetti_extractor/relational/composition_products_cli.py
              ./src/spaghetti_extractor/relational/composition_products_format.py
              ./src/spaghetti_extractor/relational/contract.py
              ./src/spaghetti_extractor/relational/semantic_cutpoints.py
              ./src/spaghetti_extractor/relational/diagnostics.py
              ./src/spaghetti_extractor/relational/extraction.py
              ./src/spaghetti_extractor/relational/ir.py
              ./src/spaghetti_extractor/relational/isa_requirements.py
              ./src/spaghetti_extractor/relational/memory_products_artifact.py
              ./src/spaghetti_extractor/relational/memory_products_format.py
              ./src/spaghetti_extractor/relational/model.py
              ./src/spaghetti_extractor/relational/phases.py
              ./src/spaghetti_extractor/relational/preflight.py
              ./src/spaghetti_extractor/relational/x87_profile.py
              ./src/spaghetti_extractor/relational/proposal_artifact.py
              ./src/spaghetti_extractor/relational/register_replay_artifact.py
              ./src/spaghetti_extractor/relational/register_replay_format.py
              ./src/spaghetti_extractor/relational/runtime_frame_artifact.py
              ./src/spaghetti_extractor/relational/schema.py
              ./src/spaghetti_extractor/relational/semantic_products_artifact.py
              ./src/spaghetti_extractor/relational/semantic_products_format.py
              ./src/spaghetti_extractor/relational/side_extraction.py
              ./src/spaghetti_extractor/relational/side_extraction_artifact.py
              ./src/spaghetti_extractor/relational/side_isa_artifact.py
              ./src/spaghetti_extractor/relational/analyses/__init__.py
              ./src/spaghetti_extractor/relational/analyses/control.py
              ./src/spaghetti_extractor/relational/analyses/dataflow.py
              ./src/spaghetti_extractor/relational/analyses/external.py
              ./src/spaghetti_extractor/relational/analyses/frames.py
              ./src/spaghetti_extractor/relational/analyses/invariants.py
              ./src/spaghetti_extractor/relational/analyses/predicates.py
              ./src/spaghetti_extractor/relational/analyses/semantic_control.py
              ./src/spaghetti_extractor/relational/analyses/segments.py
              ./src/spaghetti_extractor/relational/lean/__init__.py
              ./src/spaghetti_extractor/relational/lean/analysis_source.py
              ./src/spaghetti_extractor/relational/lean/common.py
              ./src/spaghetti_extractor/relational/lean/compiler.py
              ./src/spaghetti_extractor/relational/lean/expressions.py
              (pkgs.lib.fileset.unions (
                map (
                  module: ./src/spaghetti_extractor/lean/StageA + "/${module}.lean"
                ) relationalAnalysisKernelModules
              ))
            ];
          };
          spaghettiExtractorRegisterDataflowProblemSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./src/spaghetti_extractor/__init__.py
              ./src/spaghetti_extractor/artifact_formats.py
              ./src/spaghetti_extractor/errors.py
              ./src/spaghetti_extractor/pe.py
              ./src/spaghetti_extractor/stage_binary.py
              ./src/spaghetti_extractor/util.py
              ./src/spaghetti_extractor/relational/__init__.py
              ./src/spaghetti_extractor/relational/analysis_artifact.py
              ./src/spaghetti_extractor/relational/artifacts.py
              ./src/spaghetti_extractor/relational/callsite_preservation.py
              ./src/spaghetti_extractor/relational/contract.py
              ./src/spaghetti_extractor/relational/semantic_cutpoints.py
              ./src/spaghetti_extractor/relational/diagnostics.py
              ./src/spaghetti_extractor/relational/extraction.py
              ./src/spaghetti_extractor/relational/model.py
              ./src/spaghetti_extractor/relational/preflight.py
              ./src/spaghetti_extractor/relational/x87_profile.py
              ./src/spaghetti_extractor/relational/register_dataflow_artifact.py
              ./src/spaghetti_extractor/relational/register_dataflow_compile.py
              ./src/spaghetti_extractor/relational/register_dataflow_formats.py
              ./src/spaghetti_extractor/relational/register_dataflow_problem.py
              ./src/spaghetti_extractor/relational/register_dataflow_problem_cli.py
              ./src/spaghetti_extractor/relational/register_dataflow_seed.py
              ./src/spaghetti_extractor/relational/register_transfer_core.py
              ./src/spaghetti_extractor/relational/register_transfer_ir.py
              ./src/spaghetti_extractor/relational/schema.py
              ./src/spaghetti_extractor/relational/analyses/__init__.py
              ./src/spaghetti_extractor/relational/analyses/callsite.py
              ./src/spaghetti_extractor/relational/analyses/control.py
              ./src/spaghetti_extractor/relational/analyses/dataflow.py
              ./src/spaghetti_extractor/relational/analyses/external.py
              ./src/spaghetti_extractor/relational/analyses/fixedpoint.py
              ./src/spaghetti_extractor/relational/analyses/predicates.py
              ./src/spaghetti_extractor/relational/analyses/region_local.py
              ./src/spaghetti_extractor/relational/analyses/register_lattice.py
              ./src/spaghetti_extractor/relational/analyses/register_static.py
              ./src/spaghetti_extractor/relational/analyses/registers.py
              ./src/spaghetti_extractor/relational/analyses/semantic_control.py
              ./src/spaghetti_extractor/relational/analyses/segments.py
              ./src/spaghetti_extractor/relational/analyses/stack.py
              ./src/spaghetti_extractor/relational/lean/__init__.py
              ./src/spaghetti_extractor/relational/lean/analysis_source.py
              ./src/spaghetti_extractor/relational/lean/common.py
              ./src/spaghetti_extractor/relational/lean/compiler.py
              ./src/spaghetti_extractor/relational/lean/expressions.py
            ];
          };
          spaghetti-extractor-analysis = mkPythonWorker {
            name = "spaghetti-extractor-analysis";
            source = spaghettiExtractorAssemblySource;
            module = "spaghetti_extractor.relational.assembly_cli";
            runtimeInputs = [ pythonEnv ];
          };
          spaghetti-extractor-proposal = mkPythonWorker {
            name = "spaghetti-extractor-proposal";
            source = spaghettiExtractorProposalSource;
            module = "spaghetti_extractor.relational.proposal_cli";
            runtimeInputs = [ pythonEnv ];
          };
          spaghetti-extractor-register-replay = mkPythonWorker {
            name = "spaghetti-extractor-register-replay";
            source = spaghettiExtractorRegisterReplaySource;
            module = "spaghetti_extractor.relational.register_replay_cli";
            runtimeInputs = [ pythonEnv ];
          };
          spaghetti-extractor-semantic-products = mkPythonWorker {
            name = "spaghetti-extractor-semantic-products";
            source = spaghettiExtractorSemanticProductsSource;
            module = "spaghetti_extractor.relational.semantic_products_cli";
            runtimeInputs = [ pythonEnv ];
          };
          spaghetti-extractor-memory-products = mkPythonWorker {
            name = "spaghetti-extractor-memory-products";
            source = spaghettiExtractorMemoryProductsSource;
            module = "spaghetti_extractor.relational.memory_products_cli";
            runtimeInputs = [ pythonEnv ];
          };
          spaghetti-extractor-composition-products = mkPythonWorker {
            name = "spaghetti-extractor-composition-products";
            source = spaghettiExtractorCompositionProductsSource;
            module = "spaghetti_extractor.relational.composition_products_cli";
            runtimeInputs = [ pythonEnv ];
          };
          spaghetti-extractor-register-dataflow-problem = mkPythonWorker {
            name = "spaghetti-extractor-register-dataflow-problem";
            source = spaghettiExtractorRegisterDataflowProblemSource;
            module = "spaghetti_extractor.relational.register_dataflow_problem_cli";
            runtimeInputs = [ pythonEnv ];
          };
          spaghettiExtractorPreparationSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./src/spaghetti_extractor/__init__.py
              ./src/spaghetti_extractor/artifact_formats.py
              ./src/spaghetti_extractor/contract_tools.py
              ./src/spaghetti_extractor/_contract_tools
              ./src/spaghetti_extractor/errors.py
              ./src/spaghetti_extractor/isa_semantic_forms.py
              ./src/spaghetti_extractor/pe.py
              ./src/spaghetti_extractor/stage_binary.py
              ./src/spaghetti_extractor/util.py
              ./src/spaghetti_extractor/relational
              ./src/spaghetti_extractor/lean/StageA
            ];
          };
          spaghetti-extractor-preparation = mkPythonWorker {
            name = "spaghetti-extractor-preparation";
            source = spaghettiExtractorPreparationSource;
            module = "spaghetti_extractor.relational.preparation_cli";
            runtimeInputs = [
              pythonEnv
              pkgs.lean4
            ];
          };
          spaghettiExtractorRegionFactsPythonFiles = [
            ./src/spaghetti_extractor/__init__.py
            ./src/spaghetti_extractor/artifact_formats.py
            ./src/spaghetti_extractor/errors.py
            ./src/spaghetti_extractor/pe.py
            ./src/spaghetti_extractor/stage_binary.py
            ./src/spaghetti_extractor/util.py
            ./src/spaghetti_extractor/relational/__init__.py
            ./src/spaghetti_extractor/relational/artifacts.py
            ./src/spaghetti_extractor/relational/contract.py
            ./src/spaghetti_extractor/relational/semantic_cutpoints.py
            ./src/spaghetti_extractor/relational/diagnostics.py
            ./src/spaghetti_extractor/relational/extraction.py
            ./src/spaghetti_extractor/relational/model.py
            ./src/spaghetti_extractor/relational/pair_normalization.py
            ./src/spaghetti_extractor/relational/pair_normalization_artifact.py
            ./src/spaghetti_extractor/relational/preflight.py
            ./src/spaghetti_extractor/relational/x87_profile.py
            ./src/spaghetti_extractor/relational/region_facts.py
            ./src/spaghetti_extractor/relational/region_facts_artifact.py
            ./src/spaghetti_extractor/relational/region_facts_cli.py
            ./src/spaghetti_extractor/relational/schema.py
            ./src/spaghetti_extractor/relational/side_extraction_artifact.py
            ./src/spaghetti_extractor/relational/analyses/__init__.py
            ./src/spaghetti_extractor/relational/analyses/control.py
            ./src/spaghetti_extractor/relational/analyses/external.py
            ./src/spaghetti_extractor/relational/analyses/memory.py
            ./src/spaghetti_extractor/relational/analyses/predicates.py
            ./src/spaghetti_extractor/relational/analyses/region_local.py
            ./src/spaghetti_extractor/relational/analyses/register_static.py
            ./src/spaghetti_extractor/relational/analyses/semantic_control.py
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
                map (
                  module: ./src/spaghetti_extractor/lean/StageA + "/${module}.lean"
                ) relationalAnalysisKernelModules
              ))
            ];
          };
          spaghetti-extractor-region-facts = mkPythonWorker {
            name = "spaghetti-extractor-region-facts";
            source = spaghettiExtractorRegionFactsSource;
            module = "spaghetti_extractor.relational.region_facts_cli";
            runtimeInputs = [
              pythonEnv
              pkgs.lean4
            ];
          };
          spaghettiExtractorMappingPythonFiles = [
            ./src/spaghetti_extractor/__init__.py
            ./src/spaghetti_extractor/_contract_tools/common.py
            ./src/spaghetti_extractor/_contract_tools/map_generation.py
            ./src/spaghetti_extractor/errors.py
            ./src/spaghetti_extractor/pe.py
            ./src/spaghetti_extractor/stage_binary.py
            ./src/spaghetti_extractor/util.py
            ./src/spaghetti_extractor/relational/__init__.py
            ./src/spaghetti_extractor/relational/artifacts.py
            ./src/spaghetti_extractor/relational/contract.py
            ./src/spaghetti_extractor/relational/semantic_cutpoints.py
            ./src/spaghetti_extractor/relational/mapping.py
            ./src/spaghetti_extractor/relational/mapping_cli.py
            ./src/spaghetti_extractor/relational/model.py
            ./src/spaghetti_extractor/relational/schema.py
            ./src/spaghetti_extractor/relational/x87_profile.py
          ];
          spaghettiExtractorMappingSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions spaghettiExtractorMappingPythonFiles;
          };
          spaghetti-extractor-mapping = mkPythonWorker {
            name = "spaghetti-extractor-mapping";
            source = spaghettiExtractorMappingSource;
            module = "spaghetti_extractor.relational.mapping_cli";
            runtimeInputs = [ pythonEnv ];
          };
          spaghettiExtractorSidePythonFiles = [
            ./src/spaghetti_extractor/__init__.py
            ./src/spaghetti_extractor/artifact_formats.py
            ./src/spaghetti_extractor/_contract_tools/common.py
            ./src/spaghetti_extractor/_contract_tools/map_generation.py
            ./src/spaghetti_extractor/errors.py
            ./src/spaghetti_extractor/isa_semantic_forms.py
            ./src/spaghetti_extractor/pe.py
            ./src/spaghetti_extractor/stage_binary.py
            ./src/spaghetti_extractor/util.py
            ./src/spaghetti_extractor/relational/__init__.py
            ./src/spaghetti_extractor/relational/artifacts.py
            ./src/spaghetti_extractor/relational/binary_inventory.py
            ./src/spaghetti_extractor/relational/contract.py
            ./src/spaghetti_extractor/relational/semantic_cutpoints.py
            ./src/spaghetti_extractor/relational/extraction.py
            ./src/spaghetti_extractor/relational/isa_requirements.py
            ./src/spaghetti_extractor/relational/model.py
            ./src/spaghetti_extractor/relational/preflight.py
            ./src/spaghetti_extractor/relational/x87_profile.py
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
                map (
                  module: ./src/spaghetti_extractor/lean/StageA + "/${module}.lean"
                ) relationalAnalysisKernelModules
              ))
            ];
          };
          spaghetti-extractor-side = mkPythonWorker {
            name = "spaghetti-extractor-side";
            source = spaghettiExtractorSideSource;
            module = "spaghetti_extractor.relational.side_cli";
            runtimeInputs = [ pythonEnv ];
          };
          spaghettiExtractorNormalizationPythonFiles = [
            ./src/spaghetti_extractor/__init__.py
            ./src/spaghetti_extractor/artifact_formats.py
            ./src/spaghetti_extractor/errors.py
            ./src/spaghetti_extractor/pe.py
            ./src/spaghetti_extractor/stage_binary.py
            ./src/spaghetti_extractor/util.py
            ./src/spaghetti_extractor/relational/__init__.py
            ./src/spaghetti_extractor/relational/artifacts.py
            ./src/spaghetti_extractor/relational/contract.py
            ./src/spaghetti_extractor/relational/semantic_cutpoints.py
            ./src/spaghetti_extractor/relational/extraction.py
            ./src/spaghetti_extractor/relational/model.py
            ./src/spaghetti_extractor/relational/pair_normalization.py
            ./src/spaghetti_extractor/relational/pair_normalization_artifact.py
            ./src/spaghetti_extractor/relational/pair_normalization_cli.py
            ./src/spaghetti_extractor/relational/preflight.py
            ./src/spaghetti_extractor/relational/x87_profile.py
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
                map (
                  module: ./src/spaghetti_extractor/lean/StageA + "/${module}.lean"
                ) relationalAnalysisKernelModules
              ))
            ];
          };
          spaghetti-extractor-normalize = mkPythonWorker {
            name = "spaghetti-extractor-normalize";
            source = spaghettiExtractorNormalizationSource;
            module = "spaghetti_extractor.relational.pair_normalization_cli";
            runtimeInputs = [ pythonEnv ];
          };
          spaghettiExtractorDataflowPythonFiles = [
            ./src/spaghetti_extractor/__init__.py
            ./src/spaghetti_extractor/errors.py
            ./src/spaghetti_extractor/util.py
            ./src/spaghetti_extractor/relational/__init__.py
            ./src/spaghetti_extractor/relational/schema.py
            ./src/spaghetti_extractor/relational/register_dataflow_aggregate.py
            ./src/spaghetti_extractor/relational/register_dataflow_artifact.py
            ./src/spaghetti_extractor/relational/register_dataflow_formats.py
            ./src/spaghetti_extractor/relational/register_dataflow_problem.py
            ./src/spaghetti_extractor/relational/register_transfer_core.py
            ./src/spaghetti_extractor/relational/register_dataflow_cli.py
            ./src/spaghetti_extractor/relational/register_dataflow_compare.py
            ./src/spaghetti_extractor/relational/register_dataflow_packs.py
            ./src/spaghetti_extractor/relational/register_dataflow_solver.py
            ./src/spaghetti_extractor/relational/register_dataflow_summary_format.py
            ./src/spaghetti_extractor/relational/analyses/__init__.py
            ./src/spaghetti_extractor/relational/analyses/dataflow.py
            ./src/spaghetti_extractor/relational/analyses/dataflow_schedule.py
            ./src/spaghetti_extractor/relational/analyses/fixedpoint.py
            ./src/spaghetti_extractor/relational/analyses/register_lattice.py
          ];
          spaghettiExtractorDataflowSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions spaghettiExtractorDataflowPythonFiles;
          };
          spaghetti-extractor-dataflow = mkPythonWorker {
            name = "spaghetti-extractor-dataflow";
            source = spaghettiExtractorDataflowSource;
            module = "spaghetti_extractor.relational.register_dataflow_cli";
            runtimeInputs = [ pkgs.python3 ];
            preferLocalBuild = true;
          };
          spaghettiExtractorDataflowWorkerPythonFiles = [
            ./src/spaghetti_extractor/__init__.py
            ./src/spaghetti_extractor/errors.py
            ./src/spaghetti_extractor/util.py
            ./src/spaghetti_extractor/relational/__init__.py
            ./src/spaghetti_extractor/relational/schema.py
            ./src/spaghetti_extractor/relational/register_dataflow_artifact.py
            ./src/spaghetti_extractor/relational/register_dataflow_formats.py
            ./src/spaghetti_extractor/relational/register_transfer_core.py
            ./src/spaghetti_extractor/relational/register_dataflow_solver.py
            ./src/spaghetti_extractor/relational/register_dataflow_summary_format.py
            ./src/spaghetti_extractor/relational/register_dataflow_worker_cli.py
            ./src/spaghetti_extractor/relational/analyses/__init__.py
            ./src/spaghetti_extractor/relational/analyses/dataflow.py
            ./src/spaghetti_extractor/relational/analyses/fixedpoint.py
            ./src/spaghetti_extractor/relational/analyses/register_lattice.py
          ];
          spaghettiExtractorDataflowWorkerSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions spaghettiExtractorDataflowWorkerPythonFiles;
          };
          spaghetti-extractor-dataflow-worker = mkPythonWorker {
            name = "spaghetti-extractor-dataflow-worker";
            source = spaghettiExtractorDataflowWorkerSource;
            module = "spaghetti_extractor.relational.register_dataflow_worker_cli";
            runtimeInputs = [ pkgs.python3 ];
            preferLocalBuild = true;
          };
          spaghettiExtractorDataflowSummarySource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions (
              spaghettiExtractorDataflowWorkerPythonFiles
              ++ [
                ./src/spaghetti_extractor/relational/register_dataflow_summary.py
                ./src/spaghetti_extractor/relational/register_dataflow_summary_cli.py
              ]
            );
          };
          spaghetti-extractor-dataflow-summary = mkPythonWorker {
            name = "spaghetti-extractor-dataflow-summary";
            source = spaghettiExtractorDataflowSummarySource;
            module = "spaghetti_extractor.relational.register_dataflow_summary_cli";
            runtimeInputs = [ pkgs.python3 ];
            preferLocalBuild = true;
          };
          spaghettiExtractorDataflowPlanPythonFiles = [
            ./src/spaghetti_extractor/__init__.py
            ./src/spaghetti_extractor/errors.py
            ./src/spaghetti_extractor/util.py
            ./src/spaghetti_extractor/relational/__init__.py
            ./src/spaghetti_extractor/relational/schema.py
            ./src/spaghetti_extractor/relational/register_dataflow_artifact.py
            ./src/spaghetti_extractor/relational/register_dataflow_formats.py
            ./src/spaghetti_extractor/relational/register_dataflow_problem.py
            ./src/spaghetti_extractor/relational/register_transfer_core.py
            ./src/spaghetti_extractor/relational/register_dataflow_packs.py
            ./src/spaghetti_extractor/relational/register_dataflow_plan_cli.py
            ./src/spaghetti_extractor/relational/analyses/__init__.py
            ./src/spaghetti_extractor/relational/analyses/dataflow.py
            ./src/spaghetti_extractor/relational/analyses/dataflow_schedule.py
            ./src/spaghetti_extractor/relational/analyses/register_lattice.py
          ];
          spaghettiExtractorDataflowPlanSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions spaghettiExtractorDataflowPlanPythonFiles;
          };
          spaghetti-extractor-dataflow-plan = mkPythonWorker {
            name = "spaghetti-extractor-dataflow-plan";
            source = spaghettiExtractorDataflowPlanSource;
            module = "spaghetti_extractor.relational.register_dataflow_plan_cli";
            runtimeInputs = [ pkgs.python3 ];
            preferLocalBuild = true;
          };
          spaghettiExtractorDataflowAggregateSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions (
              spaghettiExtractorDataflowWorkerPythonFiles
              ++ [
                ./src/spaghetti_extractor/relational/register_dataflow_aggregate.py
                ./src/spaghetti_extractor/relational/register_dataflow_aggregate_cli.py
              ]
            );
          };
          spaghetti-extractor-dataflow-aggregate = mkPythonWorker {
            name = "spaghetti-extractor-dataflow-aggregate";
            source = spaghettiExtractorDataflowAggregateSource;
            module = "spaghetti_extractor.relational.register_dataflow_aggregate_cli";
            runtimeInputs = [ pkgs.python3 ];
            preferLocalBuild = true;
          };
          spaghettiExtractorDataflowCompareSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions (
              spaghettiExtractorDataflowWorkerPythonFiles
              ++ [
                ./src/spaghetti_extractor/relational/register_dataflow_aggregate.py
                ./src/spaghetti_extractor/relational/register_dataflow_compare.py
                ./src/spaghetti_extractor/relational/register_dataflow_compare_cli.py
              ]
            );
          };
          spaghetti-extractor-dataflow-compare = mkPythonWorker {
            name = "spaghetti-extractor-dataflow-compare";
            source = spaghettiExtractorDataflowCompareSource;
            module = "spaghetti_extractor.relational.register_dataflow_compare_cli";
            runtimeInputs = [ pkgs.python3 ];
            preferLocalBuild = true;
          };
          stageARelationalAnalysisTools = {
            side = spaghetti-extractor-side;
            normalize = spaghetti-extractor-normalize;
            regionFacts = spaghetti-extractor-region-facts;
            proposal = spaghetti-extractor-proposal;
            semanticProducts = spaghetti-extractor-semantic-products;
            registerDataflowProblem = spaghetti-extractor-register-dataflow-problem;
            dataflowPlan = spaghetti-extractor-dataflow-plan;
            dataflowWorker = spaghetti-extractor-dataflow-worker;
            dataflowAggregate = spaghetti-extractor-dataflow-aggregate;
            dataflowSummary = spaghetti-extractor-dataflow-summary;
            dataflowCompare = spaghetti-extractor-dataflow-compare;
            registerReplay = spaghetti-extractor-register-replay;
            memoryProducts = spaghetti-extractor-memory-products;
            compositionProducts = spaghetti-extractor-composition-products;
            analysis = spaghetti-extractor-analysis;
            preparation = spaghetti-extractor-preparation;
          };
          stage-a-analysis-source-boundary-check =
            pkgs.runCommand "stage-a-analysis-source-boundary-check" { preferLocalBuild = true; }
              ''
                source="${spaghettiExtractorAssemblySource}/src/spaghetti_extractor"
                test -f "$source/relational/assembly.py"
                test -f "$source/relational/assembly_cli.py"
                test -f "$source/relational/analysis_artifact.py"
                test -f "$source/relational/analysis_reference.py"
                test -f "$source/relational/register_replay_artifact.py"
                test ! -e "$source/relational/register_replay.py"
                test ! -e "$source/relational/register_replay_cli.py"
                test ! -e "$source/relational/register_dataflow_solution.py"
                test ! -e "$source/relational/register_dataflow_aggregate.py"
                test -f "$source/relational/semantic_products_artifact.py"
                test ! -e "$source/relational/semantic_products.py"
                test ! -e "$source/relational/semantic_products_cli.py"
                test -f "$source/relational/memory_products_artifact.py"
                test ! -e "$source/relational/memory_products.py"
                test ! -e "$source/relational/memory_products_cli.py"
                test -f "$source/relational/composition_products_artifact.py"
                test ! -e "$source/relational/composition_products.py"
                test ! -e "$source/relational/composition_products_cli.py"
                test ! -e "$source/relational/analysis.py"
                test ! -e "$source/relational/pipeline.py"
                test ! -e "$source/relational/analyses"
                test ! -e "$source/relational/lean"
                test ! -e "$source/relational/register_dataflow_compile.py"
                test ! -e "$source/relational/register_dataflow_problem.py"
                test ! -e "$source/relational/register_dataflow_problem_cli.py"
                test ! -e "$source/cli.py"
                test ! -e "$source/stage_b.py"
                test ! -e "$source/relational/build.py"
                test ! -e "$source/relational/executor.py"
                test ! -e "$source/relational/preparation_cli.py"
                test ! -e "$source/relational/proof_diagnostics.py"
                ${spaghetti-extractor-analysis}/bin/spaghetti-extractor-analysis --help >/dev/null
                proposal="${spaghettiExtractorProposalSource}/src/spaghetti_extractor"
                test -f "$proposal/relational/proposal_cli.py"
                test -f "$proposal/relational/proposal_artifact.py"
                test ! -e "$proposal/relational/analysis.py"
                test ! -e "$proposal/relational/analysis_reference.py"
                test ! -e "$proposal/relational/assembly.py"
                test ! -e "$proposal/relational/register_dataflow_solution.py"
                test ! -e "$proposal/relational/register_dataflow_aggregate.py"
                test ! -e "$proposal/relational/register_dataflow_solver.py"
                test ! -e "$proposal/relational/semantic_products.py"
                test ! -e "$proposal/relational/semantic_products_artifact.py"
                test ! -e "$proposal/relational/memory_products.py"
                test ! -e "$proposal/relational/memory_products_artifact.py"
                test ! -e "$proposal/relational/composition_products.py"
                test ! -e "$proposal/relational/composition_products_artifact.py"
                test ! -e "$proposal/relational/analyses/invariants.py"
                test ! -e "$proposal/relational/lean/axiom_audit.py"
                ${spaghetti-extractor-proposal}/bin/spaghetti-extractor-proposal --help >/dev/null
                replay="${spaghettiExtractorRegisterReplaySource}/src/spaghetti_extractor"
                test -f "$replay/relational/register_replay.py"
                test -f "$replay/relational/register_replay_artifact.py"
                test -f "$replay/relational/register_replay_cli.py"
                test -f "$replay/relational/register_dataflow_solution.py"
                test -f "$replay/relational/analyses/semantic_control.py"
                test ! -e "$replay/relational/register_dataflow_packs.py"
                test ! -e "$replay/relational/analyses/dataflow_schedule.py"
                test ! -e "$replay/relational/analyses/invariants.py"
                test ! -e "$replay/relational/pipeline.py"
                test ! -e "$replay/relational/assembly.py"
                test ! -e "$replay/relational/proposal_cli.py"
                test ! -e "$replay/relational/lean/axiom_audit.py"
                ${spaghetti-extractor-register-replay}/bin/spaghetti-extractor-register-replay --help >/dev/null
                semantics="${spaghettiExtractorSemanticProductsSource}/src/spaghetti_extractor"
                test -f "$semantics/relational/semantic_products.py"
                test -f "$semantics/relational/semantic_products_artifact.py"
                test -f "$semantics/relational/semantic_products_cli.py"
                test -f "$semantics/relational/analyses/invariants.py"
                test -f "$semantics/relational/analyses/semantic_control.py"
                test ! -e "$semantics/relational/pipeline.py"
                test ! -e "$semantics/relational/assembly.py"
                test ! -e "$semantics/relational/register_replay.py"
                test ! -e "$semantics/relational/lean/axiom_audit.py"
                ${spaghetti-extractor-semantic-products}/bin/spaghetti-extractor-semantic-products --help >/dev/null
                memory="${spaghettiExtractorMemoryProductsSource}/src/spaghetti_extractor"
                test -f "$memory/relational/memory_products.py"
                test -f "$memory/relational/memory_products_artifact.py"
                test -f "$memory/relational/memory_products_cli.py"
                test ! -e "$memory/relational/pipeline.py"
                test ! -e "$memory/relational/assembly.py"
                test ! -e "$memory/relational/semantic_products.py"
                test ! -e "$memory/relational/lean/axiom_audit.py"
                ${spaghetti-extractor-memory-products}/bin/spaghetti-extractor-memory-products --help >/dev/null
                composition="${spaghettiExtractorCompositionProductsSource}/src/spaghetti_extractor"
                test -f "$composition/relational/composition_products.py"
                test -f "$composition/relational/composition_products_artifact.py"
                test -f "$composition/relational/composition_products_cli.py"
                test -f "$composition/relational/analyses/control.py"
                test -f "$composition/relational/analyses/semantic_control.py"
                test -f "$composition/relational/analyses/segments.py"
                test "$(find "$composition/lean/StageA" -type f -name '*.lean' | wc -l)" \
                  -eq ${toString (builtins.length relationalAnalysisKernelModules)}
                test ! -e "$composition/relational/pipeline.py"
                test ! -e "$composition/relational/assembly.py"
                test ! -e "$composition/relational/register_replay.py"
                test ! -e "$composition/relational/semantic_products.py"
                test ! -e "$composition/relational/memory_products.py"
                test ! -e "$composition/relational/lean/axiom_audit.py"
                ${spaghetti-extractor-composition-products}/bin/spaghetti-extractor-composition-products --help >/dev/null
                problem="${spaghettiExtractorRegisterDataflowProblemSource}/src/spaghetti_extractor"
                test -f "$problem/relational/register_dataflow_compile.py"
                test -f "$problem/relational/register_dataflow_problem.py"
                test -f "$problem/relational/register_dataflow_problem_cli.py"
                test -f "$problem/relational/analyses/semantic_control.py"
                test ! -e "$problem/relational/pipeline.py"
                test ! -e "$problem/relational/assembly.py"
                test ! -e "$problem/relational/register_dataflow_solution.py"
                test ! -e "$problem/relational/register_dataflow_aggregate.py"
                test ! -e "$problem/relational/analyses/invariants.py"
                test ! -e "$problem/relational/lean/axiom_audit.py"
                ${spaghetti-extractor-register-dataflow-problem}/bin/spaghetti-extractor-register-dataflow-problem --help >/dev/null
                preparation="${spaghettiExtractorPreparationSource}/src/spaghetti_extractor"
                test -f "$preparation/relational/build.py"
                test -f "$preparation/relational/preparation_cli.py"
                test -f "$preparation/relational/analysis_reference.py"
                test -f "$preparation/relational/report_schema.py"
                test -f "$preparation/relational/lean/generation.py"
                test -f "$preparation/relational/lean/acceptance.py"
                test -f "$preparation/relational/lean/axiom_audit.py"
                test -f "$preparation/relational/lean/affine_frames.py"
                test -f "$preparation/relational/lean/affine_linked_control.py"
                test -f "$preparation/relational/analyses/affine_linked_control.py"
                test -f "$preparation/relational/analyses/linked_control.py"
                test ! -e "$preparation/cli.py"
                test ! -e "$preparation/stage_b.py"
                test ! -e "$preparation/relational/executor.py"
                test "$(find "$preparation/lean/StageA" -type f -name '*.lean' | wc -l)" \
                  -eq ${toString (builtins.length relationalLeanModules)}
                ${spaghetti-extractor-preparation}/bin/spaghetti-extractor-preparation --help >/dev/null
                side="${spaghettiExtractorSideSource}/src/spaghetti_extractor"
                test -f "$side/relational/side_extraction.py"
                test -f "$side/relational/binary_inventory.py"
                test -f "$side/relational/side_cli.py"
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
                test ! -e "$mapping/relational/extraction.py"
                test ! -e "$mapping/relational/pipeline.py"
                test ! -e "$mapping/relational/report_schema.py"
                ${spaghetti-extractor-mapping}/bin/spaghetti-extractor-mapping --help >/dev/null
                normalization="${spaghettiExtractorNormalizationSource}/src/spaghetti_extractor"
                test -f "$normalization/relational/pair_normalization.py"
                test -f "$normalization/relational/pair_normalization_artifact.py"
                test ! -e "$normalization/relational/analysis.py"
                test ! -e "$normalization/relational/analysis_artifact.py"
                test ! -e "$normalization/relational/pipeline.py"
                test ! -e "$normalization/relational/phases.py"
                test ! -e "$normalization/relational/verdict.py"
                ${spaghetti-extractor-normalize}/bin/spaghetti-extractor-normalize --help >/dev/null
                dataflow="${spaghettiExtractorDataflowSource}/src/spaghetti_extractor"
                test -f "$dataflow/relational/register_dataflow_cli.py"
                test -f "$dataflow/relational/analyses/register_lattice.py"
                test ! -e "$dataflow/stage_binary.py"
                test ! -e "$dataflow/relational/pipeline.py"
                test ! -e "$dataflow/relational/analyses/registers.py"
                ${spaghetti-extractor-dataflow}/bin/spaghetti-extractor-dataflow --help >/dev/null
                worker="${spaghettiExtractorDataflowWorkerSource}/src/spaghetti_extractor"
                test -f "$worker/relational/register_dataflow_worker_cli.py"
                test -f "$worker/relational/register_dataflow_solver.py"
                test -f "$worker/relational/register_transfer_core.py"
                test ! -e "$worker/stage_binary.py"
                test ! -e "$worker/relational/register_transfer_ir.py"
                test ! -e "$worker/relational/register_dataflow_cli.py"
                test ! -e "$worker/relational/register_dataflow_compare.py"
                test ! -e "$worker/relational/pipeline.py"
                ${spaghetti-extractor-dataflow-worker}/bin/spaghetti-extractor-dataflow-worker --help >/dev/null
                ${spaghetti-extractor-dataflow-summary}/bin/spaghetti-extractor-dataflow-summary --help >/dev/null
                planner="${spaghettiExtractorDataflowPlanSource}/src/spaghetti_extractor"
                test -f "$planner/relational/register_dataflow_plan_cli.py"
                test -f "$planner/relational/register_dataflow_problem.py"
                test -f "$planner/relational/register_transfer_core.py"
                test ! -e "$planner/stage_binary.py"
                test ! -e "$planner/relational/register_transfer_ir.py"
                test ! -e "$planner/relational/register_dataflow_solver.py"
                test ! -e "$planner/relational/register_dataflow_compare.py"
                ${spaghetti-extractor-dataflow-plan}/bin/spaghetti-extractor-dataflow-plan --help >/dev/null
                ${spaghetti-extractor-dataflow-aggregate}/bin/spaghetti-extractor-dataflow-aggregate --help >/dev/null
                ${spaghetti-extractor-dataflow-compare}/bin/spaghetti-extractor-dataflow-compare --help >/dev/null
                region_facts="${spaghettiExtractorRegionFactsSource}/src/spaghetti_extractor"
                test -f "$region_facts/relational/region_facts.py"
                test -f "$region_facts/relational/region_facts_artifact.py"
                test -f "$region_facts/relational/region_facts_cli.py"
                test -f "$region_facts/relational/analyses/region_local.py"
                test -f "$region_facts/relational/analyses/register_static.py"
                test -f "$region_facts/relational/analyses/semantic_control.py"
                test ! -e "$region_facts/relational/pipeline.py"
                test ! -e "$region_facts/relational/analyses/registers.py"
                test ! -e "$region_facts/relational/analyses/callsite.py"
                test ! -e "$region_facts/relational/analyses/invariants.py"
                test ! -e "$region_facts/relational/analysis.py"
                test ! -e "$region_facts/relational/analysis_artifact.py"
                test ! -e "$region_facts/relational/build.py"
                test ! -e "$region_facts/relational/lean/generation.py"
                ${spaghetti-extractor-region-facts}/bin/spaghetti-extractor-region-facts --help >/dev/null
                touch "$out"
              '';
          singlestep-80386-conformance = pkgs.callPackage ./nix/singlestep-80386-conformance.nix {
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
          stageABochs80386Shards = pkgs.lib.concatMap (
            opcode:
            map (
              shardIndex:
              let
                imported = singlestep-80386-conformance.importDerivations.${opcode}.${toString shardIndex};
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
                  spaghetti-extractor stage-a-check-isa-conformance-worker \
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
                  spaghetti-extractor stage-a-check-isa-conformance-worker \
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
                  spaghetti-extractor stage-a-check-isa-conformance-worker \
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
                ''
            ) stageABochs80386ShardIndices
          ) stageABochs80386Opcodes;
          stageABochs80386EvidenceIndex = pkgs.lib.concatMap (
            opcode:
            map (shardIndex: {
              inherit opcode;
              shard_index = shardIndex;
              shard_count = 16;
              path = "${opcode}/shard-${toString shardIndex}-of-16/execution-manifest.json";
            }) stageABochs80386ShardIndices
          ) stageABochs80386Opcodes;
          stage-a-isa-conformance-bochs-80386 = pkgs.runCommand "stage-a-isa-conformance-bochs-80386" { } ''
            mkdir -p "$out"
            ${pkgs.lib.concatMapStringsSep "\n" (
              opcode:
              pkgs.lib.concatMapStringsSep "\n" (
                shardIndex:
                let
                  shard = builtins.elemAt stageABochs80386Shards (
                    (pkgs.lib.lists.findFirstIndex (value: value == opcode) 0 stageABochs80386Opcodes)
                    * builtins.length stageABochs80386ShardIndices
                    + shardIndex
                  );
                  relative = "${opcode}/shard-${toString shardIndex}-of-16";
                in
                ''
                  mkdir -p "$out/${opcode}"
                  ln -s "${shard}/${relative}" "$out/${relative}"
                ''
              ) stageABochs80386ShardIndices
            ) stageABochs80386Opcodes}
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
                postInstall = (old.postInstall or "") + ''
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
              postInstall = (old.postInstall or "") + ''
                map_path="$(find . -name 'hello-${label}.map' -print -quit)"
                if [ -z "$map_path" ]; then
                  echo "missing hello-${label}.map" >&2
                  exit 1
                fi
                archive_path="$(find . -path '*/lib/libhello.a' -type f -print -quit)"
                if [ -z "$archive_path" ]; then
                  echo "missing exact linked libhello.a" >&2
                  exit 1
                fi
                fixture_dir="$out/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/${label}"
                mkdir -p "$fixture_dir"
                cp "$map_path" "$fixture_dir/hello.map"
                cp "$out/bin/hello.exe" "$fixture_dir/hello.exe"
                cp "$archive_path" "$fixture_dir/libhello.a"
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
          stage-a-minimal-hello-original = mkStageAMinimalHello "original" stageAMinimalHelloOriginalCflags;
          stage-a-minimal-hello-candidate = mkStageAMinimalHello "candidate" stageAMinimalHelloCandidateCflags;
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
          stage-a-fixtures-relation-contract =
            pkgs.runCommand "stage-a-fixtures-relation-contract"
              {
                nativeBuildInputs = [ spaghetti-extractor-mapping ];
              }
              ''
                fixture_dir="${stage-a-fixtures}/share/spaghetti-extractor/stage-a-fixtures/relational-v3"
                mkdir -p "$out"
                spaghetti-extractor-mapping generate-relation-contract \
                  --original "$fixture_dir/stage-a-loop-original.exe" \
                  --candidate "$fixture_dir/stage-a-loop-candidate.exe" \
                  --mapping "$fixture_dir/block-map-loop.json" \
                  --out "$out/relation-contract.json" \
                  > "$out/generate-relation.stdout"
              '';
          stageAFixturesAnalysisGraph = import ./nix/stage-a-relational-analysis-graph.nix {
            inherit pkgs;
            name = "stage-a-fixtures";
            original.binary = "${stage-a-fixtures}/share/spaghetti-extractor/stage-a-fixtures/relational-v3/stage-a-loop-original.exe";
            candidate.binary = "${stage-a-fixtures}/share/spaghetti-extractor/stage-a-fixtures/relational-v3/stage-a-loop-candidate.exe";
            relationContract = "${stage-a-fixtures-relation-contract}/relation-contract.json";
            analysisKernelCache = stage-a-relational-analysis-ifd-kernel-cache;
            tools = stageARelationalAnalysisTools;
            # A pure flake check must IFD-read this preparation to instantiate
            # its generated Lean graph. Floating CA outputs use the public
            # two-phase coordinator instead.
            dataflowContentAddressed = false;
          };
          stage-a-fixtures-prepared-proof = stageAFixturesAnalysisGraph.preparedProof;
          stage-a-fixtures-proof-audit = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = true;
            prepared = stage-a-fixtures-prepared-proof + "/report/relational-v3";
          };
          stage-a-fixtures-check =
            pkgs.runCommand "stage-a-fixtures-check"
              {
                nativeBuildInputs = [ pkgs.jq ];
              }
              ''
                prepared="${stage-a-fixtures-prepared-proof}/report/relational-v3"
                jq -e '
                  .format == "stage-a-whole-program-acceptance-v1" and
                  .status == "ready" and
                  .theorem ==
                    "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked" and
                  .required_theorem ==
                    "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked"
                ' "$prepared/whole-program-acceptance.json" >/dev/null
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
                ' "$prepared/composition-progress.json" >/dev/null
                jq -e '
                  (
                    .format == "stage-a-lean-module-graph-v1" or
                    .format == "stage-a-lean-module-graph-v2"
                  ) and
                  .expected_final_theorem ==
                    "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked" and
                  (.approved_axioms | sort) ==
                    (["propext", "Classical.choice", "Quot.sound"] | sort) and
                  .acceptance.status == "ready" and
                  .acceptance.theorem ==
                    "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked" and
                  .acceptance.blockers == []
                ' "$prepared/module-graph.json" >/dev/null
                jq -e '
                  .format == "stage-a-relational-lean-audit-v1" and
                  .status == "checked" and
                  .lean_trust == 0 and
                  .theorem ==
                    "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked" and
                  .unexpected_axioms == []
                ' "${stage-a-fixtures-proof-audit}/audit.json" >/dev/null
                mkdir -p "$out"
                cp "$prepared/prepared-proof.json" \
                  "$prepared/composition-progress.json" \
                  "$prepared/whole-program-acceptance.json" \
                  "${stage-a-fixtures-proof-audit}/audit.json" \
                  "$out/"
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
          stage-a-exit-static-map =
            pkgs.runCommand "stage-a-exit-static-map"
              {
                nativeBuildInputs = [ spaghetti-extractor-mapping ];
              }
              ''
                fixture_dir="${stage-a-exit-fixtures}/share/spaghetti-extractor/stage-a-fixtures/exit-distinct"
                mkdir -p "$out"
                spaghetti-extractor-mapping generate-map \
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
          stage-a-exit-relation-contract =
            pkgs.runCommand "stage-a-exit-relation-contract"
              {
                nativeBuildInputs = [ spaghetti-extractor-mapping ];
              }
              ''
                fixture_dir="${stage-a-exit-fixtures}/share/spaghetti-extractor/stage-a-fixtures/exit-distinct"
                mkdir -p "$out"
                spaghetti-extractor-mapping generate-relation-contract \
                  --original "$fixture_dir/exit-original.exe" \
                  --candidate "$fixture_dir/exit-candidate.exe" \
                  --mapping "${stage-a-exit-static-map}/exit-block-map.json" \
                  --external-profile "${./profiles/pe32-kernel32-console-lockstep-v1.json}" \
                  --out "$out/exit-relation-contract.json" \
                  > "$out/generate-relation.stdout"
              '';
          stage-a-exit-prepared-proof =
            pkgs.runCommand "stage-a-exit-prepared-proof"
              {
                nativeBuildInputs = [ spaghetti-extractor-preparation ];
              }
              ''
                fixture_dir="${stage-a-exit-fixtures}/share/spaghetti-extractor/stage-a-fixtures/exit-distinct"
                work="$TMPDIR/stage-a-exit"
                mkdir -p "$work"
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-relational-ifd-kernel-cache}"
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_JOBS=4
                SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$work/cache" \
                  spaghetti-extractor-preparation prepare-relational \
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
          stage-a-exit-proof-audit = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = true;
            prepared = stage-a-exit-prepared-proof + "/report/relational-v3";
          };
          stage-a-exit-check =
            pkgs.runCommand "stage-a-exit-check"
              {
                nativeBuildInputs = [ pkgs.jq ];
              }
              ''
                prepared="${stage-a-exit-prepared-proof}/report/relational-v3"
                jq -e '
                  .status == "prepared" and
                  .original_sha256 != .candidate_sha256 and
                  .expected_final_theorem ==
                    "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked" and
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
                  .format == "stage-a-relational-lean-audit-v1" and
                  .status == "checked" and
                  .theorem ==
                    "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked" and
                  .lean_trust == 0 and
                  .unexpected_axioms == []
                ' "${stage-a-exit-proof-audit.verdict}/audit.json" >/dev/null
                mkdir -p "$out"
                cp "$prepared/prepared-proof.json" "$out/"
                cp "${stage-a-exit-proof-audit.verdict}/audit.json" \
                  "$out/lean-audit.json"
                cp "${stage-a-exit-proof-audit.verdict}/verdict.json" \
                  "$out/proof-verdict.json"
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
                nativeBuildInputs = [ spaghetti-extractor-mapping ];
              }
              ''
                fixture_dir="${stage-a-winapi-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/winapi-hello"
                mkdir -p "$out"
                spaghetti-extractor-mapping generate-map \
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
                nativeBuildInputs = [ spaghetti-extractor-mapping ];
              }
              ''
                fixture_dir="${stage-a-winapi-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/winapi-hello"
                mkdir -p "$out"
                spaghetti-extractor-mapping generate-relation-contract \
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
                nativeBuildInputs = [ spaghetti-extractor-preparation ];
              }
              ''
                fixture_dir="${stage-a-winapi-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/winapi-hello"
                work="$TMPDIR/stage-a-winapi-hello"
                mkdir -p "$work"
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-relational-ifd-kernel-cache}"
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_JOBS=8
                SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$work/cache" \
                  spaghetti-extractor-preparation prepare-relational \
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
                  .expected_final_theorem == null and
                  .acceptance.status == "incomplete" and
                  .acceptance.theorem == null and
                  .acceptance.linked_acceptance.status == "incomplete" and
                  .acceptance.linked_acceptance.theorem == null and
                  .acceptance.launch_realizability.profile ==
                    "paired-preferred-base-import-stack-v1" and
                  (.acceptance.launch_realizability.import_bindings | length) == 3 and
                  .composition_progress.status == "incomplete" and
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
                  .composition_progress.counts.acceptance_blockers > 0
                ' "$prepared/prepared-proof.json" >/dev/null
                jq -e '
                  .format == "stage-a-whole-program-acceptance-v1" and
                  .status == "incomplete" and
                  .theorem == null and
                  any(.blockers[];
                    .code == "opaque_lockstep_memory_observation_unextractable"
                  ) and
                  .opaque_lockstep_environment.status == "incomplete" and
                  any(.opaque_lockstep_environment.gaps[];
                    .code == "opaque_lockstep_memory_observation_unextractable" and
                    .node_id == 2
                  )
                ' "$prepared/whole-program-acceptance.json" >/dev/null
                jq -e '
                  . as $graph |
                  (
                    .format == "stage-a-lean-module-graph-v1" or
                    .format == "stage-a-lean-module-graph-v2"
                  ) and
                  .expected_final_theorem == null and
                  .acceptance.status == "incomplete" and
                  ([.nodes[] |
                    select(
                      (.modules | length) == 1 and
                      (.modules[0] | startswith("RelationalLaunch")) and
                      (.modules[0] | contains("Leaf"))
                    )] | length) > 0 and
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
                    .resource_class == "high-memory" and
                    .estimated_memory_mb >= 4096
                  ) and
                  any(.nodes[];
                    .modules == ["RelationalLaunchCheckCertificate"] and
                    (.dependencies | length) > 0 and
                    all(.dependencies[];
                      . as $dependency |
                      any($graph.nodes[]; .id == $dependency))
                  )
                ' "$prepared/module-graph.json" >/dev/null
                mkdir -p "$out"
                cp "$prepared/prepared-proof.json" \
                  "$prepared/whole-program-acceptance.json" \
                  "$prepared/composition-progress.json" \
                  "$out/"
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
          stage-a-jq-fixtures =
            pkgs.runCommand "stage-a-jq-fixtures"
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
          stage-a-gnu-hello-fixtures =
            pkgs.runCommand "stage-a-gnu-hello-fixtures"
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
          mkStageAGnuHelloInventory =
            label: fixture:
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
          stage-a-gnu-hello-original-inventory = mkStageAGnuHelloInventory "original" stage-a-gnu-hello-original;
          stage-a-gnu-hello-candidate-inventory = mkStageAGnuHelloInventory "candidate" stage-a-gnu-hello-candidate;
          mkStageAGnuHelloSideExtraction =
            label: fixture: inventory:
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
            mkStageAGnuHelloSideExtraction "original" stage-a-gnu-hello-original
              stage-a-gnu-hello-original-inventory;
          stage-a-gnu-hello-candidate-extraction =
            mkStageAGnuHelloSideExtraction "candidate" stage-a-gnu-hello-candidate
              stage-a-gnu-hello-candidate-inventory;
          mkStageAGnuHelloSideIsa =
            label: fixture: inventory:
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
            mkStageAGnuHelloSideIsa "original" stage-a-gnu-hello-original
              stage-a-gnu-hello-original-inventory;
          stage-a-gnu-hello-candidate-isa =
            mkStageAGnuHelloSideIsa "candidate" stage-a-gnu-hello-candidate
              stage-a-gnu-hello-candidate-inventory;
          stage-a-gnu-hello-static-map =
            pkgs.runCommand "stage-a-gnu-hello-static-map"
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
          stage-a-gnu-hello-relation-contract =
            pkgs.runCommand "stage-a-gnu-hello-relation-contract"
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
          mkStageAGnuHelloSupplementRequest =
            label: fixture: inventory:
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
            mkStageAGnuHelloSupplementRequest "original" stage-a-gnu-hello-original
              stage-a-gnu-hello-original-inventory;
          stage-a-gnu-hello-candidate-supplement-request =
            mkStageAGnuHelloSupplementRequest "candidate" stage-a-gnu-hello-candidate
              stage-a-gnu-hello-candidate-inventory;
          mkStageAGnuHelloSupplementExtraction =
            label: fixture: request:
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
            mkStageAGnuHelloSupplementExtraction "original" stage-a-gnu-hello-original
              stage-a-gnu-hello-original-supplement-request;
          stage-a-gnu-hello-candidate-supplement-extraction =
            mkStageAGnuHelloSupplementExtraction "candidate" stage-a-gnu-hello-candidate
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
            mkStageAGnuHelloMergedExtraction "original" stage-a-gnu-hello-original
              stage-a-gnu-hello-original-extraction
              stage-a-gnu-hello-original-supplement-extraction;
          stage-a-gnu-hello-candidate-merged-extraction =
            mkStageAGnuHelloMergedExtraction "candidate" stage-a-gnu-hello-candidate
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
          stage-a-gnu-hello-proposal-raw =
            pkgs.runCommand "stage-a-gnu-hello-proposal-raw"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-proposal
                  pkgs.lean4
                  pkgs.jq
                ];
              }
              ''
                fixture_dir="${stage-a-gnu-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/gnu-hello-o2-alignment"
                work="$TMPDIR/stage-a-gnu-hello-proposals"
                mkdir -p "$work"
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-relational-analysis-kernel-cache}"
                export SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_MEMORY_MB=8192
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_JOBS=16
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_NORMALIZATION_JOBS=8
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_NORMALIZATION_BATCH=128
                set +e
                SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$work/relational-cache" \
                  spaghetti-extractor-proposal discover-proposals \
                    --original "$fixture_dir/hello-original.exe" \
                    --candidate "$fixture_dir/hello-candidate.exe" \
                    --relation-contract "${stage-a-gnu-hello-relation-contract}/hello-relation-contract.json" \
                    --original-extraction "${stage-a-gnu-hello-original-merged-extraction}/extraction.json" \
                    --candidate-extraction "${stage-a-gnu-hello-candidate-merged-extraction}/extraction.json" \
                    --normalized-behaviors "${stage-a-gnu-hello-normalized-behaviors}/normalized-behaviors.json" \
                    --region-facts "${stage-a-gnu-hello-region-facts}/region-facts.json" \
                    --out "$work/proposal" \
                    > "$work/proposal.stdout" \
                    2> "$work/proposal.stderr"
                proposal_status=$?
                set -e
                if [ "$proposal_status" -ne 0 ]; then
                  cat "$work/proposal.stderr" >&2
                  cat "$work/proposal.stdout" >&2
                  exit "$proposal_status"
                fi
                mkdir -p "$out"
                cp -R "$work/proposal" "$out/proposal"
                cp "$work/proposal.stdout" "$work/proposal.stderr" "$out/"
              '';
          stage-a-gnu-hello-proposals =
            pkgs.runCommand "stage-a-gnu-hello-proposals"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-proposal
                  pkgs.jq
                ];
                preferLocalBuild = true;
                allowSubstitutes = true;
              }
              ''
                proposal="${stage-a-gnu-hello-proposal-raw}/proposal"
                mkdir -p "$out"
                spaghetti-extractor-proposal validate-proposal \
                  --proposal "$proposal" \
                  > "$out/proposal-validation.json"
                jq -e '
                  .format == "stage-a-relational-proposal-closure-v1" and
                  .status == "untrusted_proposal_requires_lean_replay" and
                  .acceptance_authority == false
                ' "$proposal/relational-proposal-manifest.json" >/dev/null
                test ! -e "$proposal/lean"
                test ! -e "$proposal/relational-product-graph.json"
                ln -s "$proposal" "$out/proposal"
              '';
          stage-a-gnu-hello-semantic-products =
            pkgs.runCommand "stage-a-gnu-hello-semantic-products"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-semantic-products
                  pkgs.jq
                ];
                preferLocalBuild = false;
                allowSubstitutes = true;
              }
              ''
                spaghetti-extractor-semantic-products \
                  --proposal "${stage-a-gnu-hello-proposals}/proposal" \
                  --out "$out" \
                  > "$TMPDIR/semantic-products.json"
                jq -e '
                  .format == "stage-a-relational-semantic-products-v1" and
                  .status == "untrusted_proposal_requires_lean_replay" and
                  .acceptance_authority == false and
                  (.semantic_ir_sha256 | type == "string") and
                  (.invariants_sha256 | type == "string")
                ' "$out/semantic-products-manifest.json" >/dev/null
              '';
          stage-a-gnu-hello-register-dataflow-problem =
            pkgs.runCommand "stage-a-gnu-hello-register-dataflow-problem"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-register-dataflow-problem
                  pkgs.jq
                ];
                preferLocalBuild = false;
                allowSubstitutes = true;
              }
              ''
                proposal="${stage-a-gnu-hello-proposals}/proposal"
                mkdir -p "$out"
                spaghetti-extractor-register-dataflow-problem \
                  --original "$proposal/artifacts/original.pe" \
                  --candidate "$proposal/artifacts/candidate.pe" \
                  --seed "$proposal/relational-register-dataflow-problem-seed.json" \
                  --contract "$proposal/relation-contract.json" \
                  --decoded-behaviors "$proposal/relational-decoded-behaviors.json" \
                  --out "$out/problem.json" \
                  > "$out/result.json"
                jq -e --slurpfile contract "$proposal/relation-contract.json" '
                  .format == "stage-a-register-dataflow-problem-v1" and
                  .acceptance_authority == false and
                  (.transfer_programs.region_count > 0) and
                  (.transfer_programs.region_count == ($contract[0].regions | length))
                ' "$out/problem.json" >/dev/null
              '';
          stage-a-gnu-hello-register-dataflow-plan =
            pkgs.runCommand "stage-a-gnu-hello-register-dataflow-plan"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-dataflow-plan
                  pkgs.jq
                ];
                preferLocalBuild = true;
                allowSubstitutes = true;
              }
              ''
                spaghetti-extractor-dataflow-plan \
                  --problem "${stage-a-gnu-hello-register-dataflow-problem}/problem.json" \
                  --out-dir "$out" \
                  > "$TMPDIR/plan.json"
                jq -e '
                  .format == "stage-a-register-dataflow-pack-manifest-v1" and
                  .acceptance_authority == false and
                  (.transfer_context_sha256 | type == "string") and
                  .pack_count == (.packs | length) and
                  .pack_count > 0
                ' "$out/manifest.json" >/dev/null
                test -f "$out/transfer-context.json"
                jq -se '
                  all(.[];
                    all(.regions[];
                      has("program") and (has("observations") | not)))
                ' "$out"/packs/*.json >/dev/null
              '';
          stage-a-gnu-hello-register-dataflow = import ./nix/stage-a-register-dataflow-graph.nix {
            inherit pkgs;
            dataflowAggregator = spaghetti-extractor-dataflow-aggregate;
            dataflowSummary = spaghetti-extractor-dataflow-summary;
            dataflowWorker = spaghetti-extractor-dataflow-worker;
            planned = stage-a-gnu-hello-register-dataflow-plan;
            fineGrained = true;
          };
          stage-a-gnu-hello-register-replay =
            pkgs.runCommand "stage-a-gnu-hello-register-replay"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-register-replay
                  pkgs.jq
                ];
                preferLocalBuild = false;
                allowSubstitutes = true;
              }
              ''
                spaghetti-extractor-register-replay \
                  --proposal "${stage-a-gnu-hello-proposals}/proposal" \
                  --register-dataflow-aggregate \
                    "${stage-a-gnu-hello-register-dataflow}/aggregate.json" \
                  --out "$out" \
                  > "$TMPDIR/register-replay.json"
                jq -e '
                  .format == "stage-a-relational-register-replay-v1" and
                  .status == "untrusted_proposal_requires_lean_replay" and
                  .acceptance_authority == false and
                  (.proposal_closure_sha256 | type == "string") and
                  (.aggregate_sha256 | type == "string")
                ' "$out/register-replay-manifest.json" >/dev/null
              '';
          stage-a-gnu-hello-memory-products =
            pkgs.runCommand "stage-a-gnu-hello-memory-products"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-memory-products
                  pkgs.jq
                ];
                preferLocalBuild = false;
                allowSubstitutes = true;
              }
              ''
                spaghetti-extractor-memory-products \
                  --proposal "${stage-a-gnu-hello-proposals}/proposal" \
                  --register-replay "${stage-a-gnu-hello-register-replay}" \
                  --out "$out" \
                  > "$TMPDIR/memory-products.json"
                jq -e '
                  .format == "stage-a-relational-memory-products-v1" and
                  .status == "untrusted_proposal_requires_lean_replay" and
                  .acceptance_authority == false and
                  (.memory_contracts_sha256 | type == "string") and
                  (.external_call_sites_sha256 | type == "string")
                ' "$out/memory-products-manifest.json" >/dev/null
              '';
          stage-a-gnu-hello-composition-products =
            pkgs.runCommand "stage-a-gnu-hello-composition-products"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-composition-products
                  pkgs.jq
                ];
                preferLocalBuild = false;
                allowSubstitutes = true;
              }
              ''
                spaghetti-extractor-composition-products \
                  --proposal "${stage-a-gnu-hello-proposals}/proposal" \
                  --register-replay "${stage-a-gnu-hello-register-replay}" \
                  --semantic-products "${stage-a-gnu-hello-semantic-products}" \
                  --memory-products "${stage-a-gnu-hello-memory-products}" \
                  --original-isa "${stage-a-gnu-hello-original-isa}/isa.json" \
                  --candidate-isa "${stage-a-gnu-hello-candidate-isa}/isa.json" \
                  --out "$out" \
                  > "$TMPDIR/composition-products.json"
                jq -e '
                  .format == "stage-a-relational-composition-products-v1" and
                  .status == "untrusted_proposal_requires_lean_replay" and
                  .acceptance_authority == false and
                  .isa_mode == "side_artifacts" and
                  (.products_sha256 | type == "string") and
                  (.files | length) == 7
                ' "$out/composition-products-manifest.json" >/dev/null
              '';
          stage-a-gnu-hello-analysis =
            pkgs.runCommand "stage-a-gnu-hello-analysis"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-analysis
                  pkgs.jq
                ];
                preferLocalBuild = false;
                allowSubstitutes = true;
              }
              ''
                work="$TMPDIR/stage-a-gnu-hello-analysis"
                mkdir -p "$work"
                set +e
                spaghetti-extractor-analysis assemble-relational \
                  --proposal "${stage-a-gnu-hello-proposals}/proposal" \
                  --register-replay \
                    "${stage-a-gnu-hello-register-replay}" \
                  --semantic-products \
                    "${stage-a-gnu-hello-semantic-products}" \
                  --memory-products \
                    "${stage-a-gnu-hello-memory-products}" \
                  --composition-products \
                    "${stage-a-gnu-hello-composition-products}" \
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
                jq -e '
                  .format == "stage-a-relational-analysis-v1" and
                  .status == "analyzed" and
                  (.files | length) > 20
                ' "$work/analysis/relational-analysis-manifest.json" >/dev/null
                if [ -e "$work/analysis/lean" ] || \
                   [ -e "$work/analysis/certificates" ] || \
                   [ -e "$work/analysis/relational-proposal-manifest.json" ]; then
                  find "$work/analysis" -maxdepth 2 -print >&2
                  echo "assembled analysis contains non-analysis products" >&2
                  exit 1
                fi
                mkdir -p "$out"
                cp -R "$work/analysis" "$out/analysis"
                cp "$work/analysis.stdout" "$work/analysis.stderr" \
                  "$work/analysis-validation.json" "$out/"
              '';
          stage-a-gnu-hello-register-dataflow-check =
            pkgs.runCommand "stage-a-gnu-hello-register-dataflow-check"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-dataflow-compare
                  pkgs.jq
                ];
                preferLocalBuild = true;
                allowSubstitutes = true;
              }
              ''
                mkdir -p "$out"
                spaghetti-extractor-dataflow-compare \
                  --aggregate \
                    "${stage-a-gnu-hello-register-dataflow}/aggregate.json" \
                  --register-relations \
                    "${stage-a-gnu-hello-analysis}/analysis/relational-register-relations.json" \
                  --out "$out/comparison.json" \
                  > "$out/compare-command.json"
                jq -e --slurpfile problem \
                  "${stage-a-gnu-hello-register-dataflow-problem}/problem.json" '
                  .format == "stage-a-register-dataflow-comparison-v1" and
                  .status == "match" and
                  .acceptance_authority == false and
                  .region_count == $problem[0].transfer_programs.region_count and
                  .mismatch_count == 0
                ' "$out/comparison.json" >/dev/null
              '';
          stage-a-gnu-hello-preflight =
            pkgs.runCommand "stage-a-gnu-hello-preflight"
              {
                preferLocalBuild = true;
                nativeBuildInputs = [
                  spaghetti-extractor-preparation
                  pkgs.jq
                ];
              }
              ''
                work="$TMPDIR/stage-a-gnu-hello"
                mkdir -p "$work"
                set +e
                spaghetti-extractor-preparation generate-relational \
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
                  (.acceptance.blockers | length) > 0 and
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
          stage-a-gnu-hello-proof = pkgs.writeShellApplication {
            name = "stage-a-gnu-hello-proof";
            runtimeInputs = [
              spaghetti-extractor
            ];
            text = ''
              if [ "$#" -gt 1 ]; then
                echo "usage: stage-a-gnu-hello-proof [OUTPUT-DIRECTORY]" >&2
                exit 2
              fi
              out="''${1:-$PWD/build/stage-a-gnu-hello-launch-proof}"
              export SPAGHETTI_EXTRACTOR_STAGE_A_NIX_CONTENT_ADDRESSED=true
              exec spaghetti-extractor stage-a-build-relational \
                --prepared-nix-ref "${self}#stage-a-gnu-hello-preflight" \
                --prepared-subpath report/relational-v3 \
                --flake "${self}" \
                --builders-file "${./nix/stage-a-builders}" \
                --builder-trusted-public-keys-file "${./nix/stage-a-builder-public-keys}" \
                --target-node relationallaunchrealizabilitycertificate \
                --out "$out"
            '';
          };
          stage-a-minimal-hello-fixtures =
            pkgs.runCommand "stage-a-minimal-hello-fixtures"
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
          stage-a-minimal-hello-static-map =
            pkgs.runCommand "stage-a-minimal-hello-static-map"
              {
                nativeBuildInputs = [ spaghetti-extractor-mapping ];
              }
              ''
                fixture_dir="${stage-a-minimal-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/minimal-hello-o2-alignment"
                mkdir -p "$out"
                spaghetti-extractor-mapping generate-map \
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
          stage-a-minimal-hello-relation-contract =
            pkgs.runCommand "stage-a-minimal-hello-relation-contract"
              {
                nativeBuildInputs = [ spaghetti-extractor-mapping ];
              }
              ''
                fixture_dir="${stage-a-minimal-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/minimal-hello-o2-alignment"
                mkdir -p "$out"
                spaghetti-extractor-mapping generate-relation-contract \
                  --original "$fixture_dir/hello-original.exe" \
                  --candidate "$fixture_dir/hello-candidate.exe" \
                  --mapping "${stage-a-minimal-hello-static-map}/hello-block-map.json" \
                  --external-profile "${./profiles/pe32-kernel32-lockstep-v1.json}" \
                  --external-profile "${./profiles/pe32-msvcrt-lockstep-v1.json}" \
                  --out "$out/hello-relation-contract.json" \
                  > "$out/generate-relation.stdout"
              '';
          stageAMinimalHelloAnalysisGraph = import ./nix/stage-a-relational-analysis-graph.nix {
            inherit pkgs;
            name = "stage-a-minimal-hello";
            original = {
              binary = "${stage-a-minimal-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/minimal-hello-o2-alignment/hello-original.exe";
              linkerMap = "${stage-a-minimal-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/minimal-hello-o2-alignment/hello-original.map";
            };
            candidate = {
              binary = "${stage-a-minimal-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/minimal-hello-o2-alignment/hello-candidate.exe";
              linkerMap = "${stage-a-minimal-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/minimal-hello-o2-alignment/hello-candidate.map";
            };
            relationContract = "${stage-a-minimal-hello-relation-contract}/hello-relation-contract.json";
            analysisKernelCache = stage-a-relational-analysis-ifd-kernel-cache;
            tools = stageARelationalAnalysisTools;
            # Keep the static check graph evaluable in one pure flake
            # evaluation. Dynamic production preparation remains CA-backed.
            dataflowContentAddressed = false;
          };
          stage-a-minimal-hello-prepared-proof = stageAMinimalHelloAnalysisGraph.preparedProof;
          stage-a-minimal-hello-proof-smoke = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = true;
            prepared = stage-a-minimal-hello-prepared-proof + "/report/relational-v3";
            targetNodes = [ "relationalsegmentrefinementedge127" ];
            targetBundle = true;
          };
          stage-a-minimal-hello-launch-proof = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = true;
            prepared = stage-a-minimal-hello-prepared-proof + "/report/relational-v3";
            targetNodes = [ "relationallaunchrealizabilitycertificate" ];
            targetBundle = true;
          };
          stage-a-minimal-hello-segment-proofs = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = true;
            prepared = stage-a-minimal-hello-prepared-proof + "/report/relational-v3";
            targetNodes = [ "relationalsegmentrefinementcertificate" ];
            targetBundle = true;
          };
          stage-a-minimal-hello-evidence-bundle = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = true;
            prepared = stage-a-minimal-hello-prepared-proof + "/report/relational-v3";
            targetNodes = [ "relationalbundle" ];
            targetBundle = true;
          };
          stage-a-minimal-hello-check =
            pkgs.runCommand "stage-a-minimal-hello-check"
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
          stage-a-jq-static-map =
            pkgs.runCommand "stage-a-jq-static-map"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-mapping
                ];
              }
              ''
                fixture_dir="${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment"
                mkdir -p "$out"
                spaghetti-extractor-mapping generate-map \
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
          stage-a-jq-relation-contract =
            pkgs.runCommand "stage-a-jq-relation-contract"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-mapping
                ];
              }
              ''
                fixture_dir="${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment"
                profile_dir="${spaghetti-extractor-profiles}/share/spaghetti-extractor/profiles"
                mkdir -p "$out"
                spaghetti-extractor-mapping generate-relation-contract \
                  --original "$fixture_dir/jq-original.exe" \
                  --candidate "$fixture_dir/jq-candidate.exe" \
                  --mapping "${stage-a-jq-static-map}/jq-block-map.json" \
                  --external-profile "$profile_dir/pe32-kernel32-lockstep-v1.json" \
                  --external-profile "$profile_dir/pe32-msvcrt-lockstep-v1.json" \
                  --out "$out/jq-relation-contract.json" \
                  > "$out/generate-relation.stdout"
              '';
          stageAJqRelationalGraph =
            let
              fixtureDir = "${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment";
            in
            import ./nix/stage-a-relational-analysis-graph.nix {
              inherit pkgs;
              name = "stage-a-jq";
              original = {
                binary = "${fixtureDir}/jq-original.exe";
                linkerMap = "${fixtureDir}/jq-original.map";
              };
              candidate = {
                binary = "${fixtureDir}/jq-candidate.exe";
                linkerMap = "${fixtureDir}/jq-candidate.map";
              };
              relationContract = "${stage-a-jq-relation-contract}/jq-relation-contract.json";
              analysisKernelCache = stage-a-relational-analysis-kernel-cache;
              extractionJobs = 16;
              tools = {
                side = spaghetti-extractor-side;
                normalize = spaghetti-extractor-normalize;
                regionFacts = spaghetti-extractor-region-facts;
                proposal = spaghetti-extractor-proposal;
                semanticProducts = spaghetti-extractor-semantic-products;
                registerDataflowProblem = spaghetti-extractor-register-dataflow-problem;
                dataflowPlan = spaghetti-extractor-dataflow-plan;
                dataflowWorker = spaghetti-extractor-dataflow-worker;
                dataflowAggregate = spaghetti-extractor-dataflow-aggregate;
                dataflowSummary = spaghetti-extractor-dataflow-summary;
                dataflowCompare = spaghetti-extractor-dataflow-compare;
                registerReplay = spaghetti-extractor-register-replay;
                memoryProducts = spaghetti-extractor-memory-products;
                compositionProducts = spaghetti-extractor-composition-products;
                analysis = spaghetti-extractor-analysis;
                preparation = spaghetti-extractor-preparation;
              };
              extraReportArtifacts = [
                {
                  source = "${stage-a-jq-static-map}/jq-block-map.json";
                  target = "jq-block-map.json";
                }
                {
                  source = "${stage-a-jq-static-map}/jq-layout-contract.json";
                  target = "jq-layout-contract.json";
                }
                {
                  source = "${stage-a-jq-relation-contract}/jq-relation-contract.json";
                  target = "jq-relation-contract.json";
                }
              ];
            };
          stage-a-jq-original-inventory = stageAJqRelationalGraph.originalInventory;
          stage-a-jq-candidate-inventory = stageAJqRelationalGraph.candidateInventory;
          stage-a-jq-original-extraction = stageAJqRelationalGraph.originalExtraction;
          stage-a-jq-candidate-extraction = stageAJqRelationalGraph.candidateExtraction;
          stage-a-jq-original-isa = stageAJqRelationalGraph.originalIsa;
          stage-a-jq-candidate-isa = stageAJqRelationalGraph.candidateIsa;
          stage-a-jq-original-supplement-request = stageAJqRelationalGraph.originalSupplementRequest;
          stage-a-jq-candidate-supplement-request = stageAJqRelationalGraph.candidateSupplementRequest;
          stage-a-jq-original-supplement-extraction = stageAJqRelationalGraph.originalSupplementExtraction;
          stage-a-jq-candidate-supplement-extraction = stageAJqRelationalGraph.candidateSupplementExtraction;
          stage-a-jq-original-merged-extraction = stageAJqRelationalGraph.originalMergedExtraction;
          stage-a-jq-candidate-merged-extraction = stageAJqRelationalGraph.candidateMergedExtraction;
          stage-a-jq-normalized-behaviors = stageAJqRelationalGraph.normalizedBehaviors;
          stage-a-jq-region-facts = stageAJqRelationalGraph.regionFacts;
          stage-a-jq-proposals = stageAJqRelationalGraph.proposal;
          stage-a-jq-semantic-products = stageAJqRelationalGraph.semanticProducts;
          stage-a-jq-register-dataflow-problem = stageAJqRelationalGraph.registerDataflowProblem;
          stage-a-jq-register-dataflow-plan = stageAJqRelationalGraph.registerDataflowPlan;
          stage-a-jq-register-dataflow = stageAJqRelationalGraph.registerDataflow;
          stage-a-jq-register-replay = stageAJqRelationalGraph.registerReplay;
          stage-a-jq-memory-products = stageAJqRelationalGraph.memoryProducts;
          stage-a-jq-composition-products = stageAJqRelationalGraph.compositionProducts;
          stage-a-jq-analysis = stageAJqRelationalGraph.analysis;
          stage-a-jq-register-dataflow-check = stageAJqRelationalGraph.registerDataflowCheck;
          stage-a-jq-prepared-proof = stageAJqRelationalGraph.preparedProof;
          stage-a-jq-reference-contract =
            pkgs.runCommand "stage-a-jq-reference-contract"
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
          stage-a-jq-fixtures-check =
            pkgs.runCommand "stage-a-jq-fixtures-check"
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
            fileset = relationalLeanModuleDirectory;
          };
          relationalAnalysisLeanSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions (
              map (
                module: ./src/spaghetti_extractor/lean/StageA + "/${module}.lean"
              ) relationalAnalysisKernelModules
            );
          };
          relationalKernelModules = relationalAcceptanceKernelModules;
          isaKernelModules = [
            "X87"
            "Formal"
            "ISAQualification"
            "ISAConformance"
            "ISAConformanceRunner"
          ];
          stage-a-isa-kernel-cache = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            standaloneSourceRoot = relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
            standaloneModules = isaKernelModules;
            targetNodes = isaKernelModules;
            targetBundle = true;
          };
          stage-a-isa-kernel-identity = pkgs.runCommand
            "stage-a-isa-kernel-identity"
            {
              nativeBuildInputs = [ pkgs.jq ];
              preferLocalBuild = false;
              allowSubstitutes = true;
              __contentAddressed = true;
            }
            ''
              bundle=${stage-a-isa-kernel-cache}/bundle.json
              decoder_sha256="$(
                jq -er '
                  .nodes
                  | map(select(.id == "ISAQualification"))
                  | if length == 1 then .[0].semantic_id else error("decoder node") end
                ' "$bundle"
              )"
              semantics_sha256="$(
                jq -cS '
                  .nodes
                  | map(select(
                      .id == "X87"
                      or .id == "Formal"
                      or .id == "ISAConformance"
                      or .id == "ISAConformanceRunner"
                    ))
                  | sort_by(.id)
                  | map({
                      id,
                      semantic_id,
                      semantic_recipe_version,
                      source_sha256
                    })
                ' "$bundle" | sha256sum | cut -d ' ' -f 1
              )"
              lean_version="$(jq -er '.lean_version' "$bundle")"
              mkdir -p "$out"
              jq -n \
                --arg decoder_sha256 "$decoder_sha256" \
                --arg semantics_sha256 "$semantics_sha256" \
                --arg lean_version "$lean_version" \
                --arg bundle_store_path ${pkgs.lib.escapeShellArg (toString stage-a-isa-kernel-cache)} \
                '{
                  format: "stage-a-isa-semantic-kernel-binding-v1",
                  id: "stage-a-pe32-i686-lean-kernel-v1",
                  decoder_sha256: $decoder_sha256,
                  semantics_sha256: $semantics_sha256,
                  lean_version: $lean_version,
                  source: {
                    bundle_store_path: $bundle_store_path,
                    bundle: "bundle.json"
                  },
                  trust: {
                    role: "compiled_lean_semantic_kernel_identity",
                    proof_authority: false,
                    closes_stage_a_proof: false
                  }
                }' > "$out/kernel.json"
            '';
          stage-a-isa-core-smoke-corpus = pkgs.runCommand
            "stage-a-isa-core-smoke-corpus"
            {
              nativeBuildInputs = [
                pkgs.jq
                spaghetti-extractor
              ];
              preferLocalBuild = false;
              allowSubstitutes = true;
              __contentAddressed = true;
            }
            ''
              mkdir -p "$out"
              spaghetti-extractor stage-a-generate-isa-corpus \
                --catalog ${./isa-catalogs/pe32-i686-core-smoke-v1.json} \
                --seed 0 \
                --out "$out" \
                > "$out/result.json"
              jq -e '
                .format == "stage-a-generated-isa-corpus-result-v1"
                and .status == "generated"
                and .proof_authority == false
                and .closes_stage_a_proof == false
              ' "$out/result.json" > /dev/null
            '';
          stageAISAQualificationSmoke =
            import ./nix/stage-a-isa-qualification-graph.nix {
              inherit pkgs;
              name = "stage-a-isa-core-smoke";
              spaghettiExtractor = spaghetti-extractor;
              kernelCache = stage-a-isa-kernel-cache;
              semanticKernel = stage-a-isa-kernel-identity + "/kernel.json";
              corpus = stage-a-isa-core-smoke-corpus + "/corpus.json";
              generatedCorpus =
                stage-a-isa-core-smoke-corpus + "/generated-corpus.json";
              bochsRunner =
                bochs-conformance
                + "/bin/spaghetti-bochs-conformance-runner";
              xedCatalog =
                stage-a-isa-xed-catalog + "/xed-inst-catalog.json";
              contentAddressed = true;
            };
          stage-a-isa-core-smoke-qualification =
            stageAISAQualificationSmoke.qualificationCheck;
          stage-a-isa-core-smoke-campaign =
            stageAISAQualificationSmoke.campaign;
          stage-a-isa-core-smoke-bundle =
            stageAISAQualificationSmoke.bundle;
          stage-a-relational-analysis-kernel-cache = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = true;
            standaloneSourceRoot = relationalAnalysisLeanSource + "/src/spaghetti_extractor/lean/StageA";
            standaloneModules = relationalAnalysisKernelModules;
            targetNodes = relationalAnalysisKernelModules;
            targetBundle = true;
          };
          stage-a-relational-analysis-ifd-kernel-cache = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = false;
            standaloneSourceRoot = relationalAnalysisLeanSource + "/src/spaghetti_extractor/lean/StageA";
            standaloneModules = relationalAnalysisKernelModules;
            targetNodes = relationalAnalysisKernelModules;
            targetBundle = true;
          };
          stage-a-relational-acceptance-kernel-cache = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            standaloneSourceRoot = relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
            standaloneModules = relationalAcceptanceKernelModules;
            standaloneModuleResources = relationalRoundtripKernelResources;
            targetNodes = relationalAcceptanceKernelRoots;
            targetBundle = true;
          };
          stage-a-relational-kernel-cache = stage-a-relational-acceptance-kernel-cache;
          stage-a-relational-acceptance-graph-smoke = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = true;
            standaloneSourceRoot = relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
            standaloneModules = relationalAcceptanceKernelModules;
            standaloneModuleResources = relationalRoundtripKernelResources;
            targetNodes = relationalAcceptanceKernelRoots;
            graphSmoke = true;
          };
          # Generated-proof IFD consumers need a stable source-root path during
          # pure evaluation. Keep this input-addressed while the main kernel
          # cache remains eligible for CA reuse by non-IFD proof graphs.
          stage-a-relational-ifd-kernel-cache = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = false;
            standaloneSourceRoot = relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
            standaloneModules = relationalAcceptanceKernelModules;
            standaloneModuleResources = relationalRoundtripKernelResources;
            targetNodes = relationalAcceptanceKernelRoots;
            targetBundle = true;
          };
          stage-a-roundtrip-lean-graph-smoke = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = true;
            standaloneSourceRoot = relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
            standaloneModules = relationalRoundtripKernelModules;
            standaloneModuleResources = relationalRoundtripKernelResources;
            targetNodes = relationalRoundtripKernelRoots;
            graphSmoke = true;
          };
          stage-a-roundtrip-lean-remote-smoke = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = true;
            standaloneSourceRoot = ./nix/fixtures/stage-a-remote-lean-smoke;
            standaloneModules = [
              "RemoteSmokeA"
              "RemoteSmokeB"
            ];
            targetNodes = [
              "RemoteSmokeA"
              "RemoteSmokeB"
            ];
            targetBundle = true;
            targetAxiomAudit = {
              module = "RemoteSmokeA";
              declaration = "inputAddressedRemoteSmokeA";
              approved_axioms = [ ];
            };
          };
          mkStageARoundtripLeanTarget =
            targetNodes:
            let
              standaloneModules = relationalLeanModuleClosure targetNodes;
            in
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs targetNodes;
              contentAddressed = true;
              standaloneSourceRoot = relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
              inherit standaloneModules;
              standaloneModuleResources = relationalRoundtripKernelResources;
              targetBundle = true;
            };
          stage-a-roundtrip-lean-engine = mkStageARoundtripLeanTarget [
            "RelationalEngine"
          ];
          stage-a-roundtrip-lean-definedness = mkStageARoundtripLeanTarget [
            "RelationalDefinedness"
          ];
          stage-a-roundtrip-lean-identity = mkStageARoundtripLeanTarget [
            "RelationalIdentity"
          ];
          stage-a-roundtrip-lean-interpreter = mkStageARoundtripLeanTarget [
            "RelationalInterpreter"
          ];
          stage-a-roundtrip-lean-transfer = mkStageARoundtripLeanTarget [
            "RelationalInterpreterTransfer"
          ];
          stage-a-roundtrip-lean-x87 = mkStageARoundtripLeanTarget [
            "RelationalInterpreterX87"
          ];
          stage-a-roundtrip-lean-compiled-kernel = mkStageARoundtripLeanTarget [
            "RelationalInterpreterKernel"
          ];
          stage-a-roundtrip-lean-symbolic-soundness = mkStageARoundtripLeanTarget [
            "RelationalSymbolicSoundness"
          ];
          stage-a-roundtrip-lean-mixed-replay = mkStageARoundtripLeanTarget [
            "RelationalInterpreterKernelMixedReplay"
          ];
          stage-a-roundtrip-lean-mixed-replay-world = mkStageARoundtripLeanTarget [
            "RelationalInterpreterKernelMixedReplayWorld"
          ];
          stage-a-roundtrip-lean-x87-replay-bridge-runtime =
            mkStageARoundtripLeanTarget [
              "RelationalInterpreterX87ReplayBridgeRuntime"
            ];
          stage-a-roundtrip-lean-x87-kernel-execution =
            mkStageARoundtripLeanTarget [
              "RelationalInterpreterKernelX87Execution"
            ];
          stage-a-roundtrip-lean-environment = mkStageARoundtripLeanTarget [
            "RelationalLockstepEnvironment"
            "RelationalOpaqueLockstepEnvironment"
          ];
          # The stable kernel is shared as a CA derivation graph. Each Lean
          # module remains its own derivation, so proof-only changes invalidate
          # only the affected descendants.
          stage-a-roundtrip-lean-kernel-cache = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = true;
            standaloneSourceRoot = relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
            standaloneModules = relationalRoundtripKernelModules;
            standaloneModuleResources = relationalRoundtripKernelResources;
            targetNodes = relationalRoundtripKernelRoots;
            targetBundle = true;
          };
          stage-a-roundtrip-interpreter-kernel-cache = stage-a-roundtrip-lean-kernel-cache;
          stage-a-roundtrip-interpreter-native-kernel-cache = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = true;
            standaloneSourceRoot = relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
            standaloneModules = relationalInterpreterNativeKernelModules;
            standaloneModuleResources = relationalRoundtripKernelResources;
            targetNodes = relationalInterpreterNativeKernelRoots;
            targetBundle = true;
          };
          stage-a-roundtrip-lean-kernel-lookup-native = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = true;
            standaloneSourceRoot = relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
            standaloneModules = relationalProgramLookupNativeKernelModules;
            standaloneModuleResources = relationalRoundtripKernelResources;
            targetNodes = relationalProgramLookupNativeKernelRoots;
            targetBundle = true;
          };
          stage-a-roundtrip-lean-program-lookup-operation = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = true;
            standaloneSourceRoot = relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
            standaloneModules = relationalProgramLookupOperationKernelModules;
            standaloneModuleResources = relationalRoundtripKernelResources;
            targetNodes = relationalProgramLookupOperationKernelRoots;
            targetBundle = true;
          };
          tinyC0Assembly = pkgs.writeText "tiny-c0-original.S" ''
            .text
            .globl _mainCRTStartup
            _mainCRTStartup:
              movl $7, %eax
              ret
          '';
          stage-a-tiny-c0-original = pkgs.runCommand
            "stage-a-tiny-c0-original-pe32"
            {
              nativeBuildInputs = [ mingw32.stdenv.cc ];
              preferLocalBuild = false;
              allowSubstitutes = true;
              __contentAddressed = true;
            }
            ''
              mkdir -p "$out"
              i686-w64-mingw32-gcc \
                -nostdlib -Wl,--entry,_mainCRTStartup \
                -Wl,--subsystem,console -Wl,--no-insert-timestamp \
                -Wl,-Map,"$out/original.map" \
                -o "$out/original.exe" ${tinyC0Assembly}
            '';
          stage-b-tiny-c0-source = pkgs.runCommand
            "stage-b-tiny-c0-source-v1"
            ({
              nativeBuildInputs = [ spaghetti-extractor ];
              preferLocalBuild = false;
              allowSubstitutes = true;
              __contentAddressed = true;
            })
            ''
              set +e
              spaghetti-extractor stage-a-prepare-source-equivalence \
                --original ${stage-a-tiny-c0-original}/original.exe \
                --linker-map ${stage-a-tiny-c0-original}/original.map \
                --out-dir "$out"
              result=$?
              set -e
              test "$result" -eq 0 -o "$result" -eq 1
              test -f "$out/source-manifest.json"
            '';
          tinyC0SourceEquivalence = import ./nix/stage-a-source-equivalence.nix {
            inherit pkgs;
            sourceProject = stage-b-tiny-c0-source;
            name = "stage-a-tiny-c0-source-equivalence";
            contentAddressed = true;
          };
          stage-a-tiny-c0-toolchain-profile =
            tinyC0SourceEquivalence.toolchainProfile;
          stage-b-tiny-c0-candidate = tinyC0SourceEquivalence.candidate;
          tinyC0GeneratedProofSources = pkgs.runCommand
            "stage-a-tiny-c0-generated-proof-sources-v1"
            {
              nativeBuildInputs = [ spaghetti-extractor ];
              preferLocalBuild = false;
              allowSubstitutes = true;
              __contentAddressed = true;
            }
            ''
              spaghetti-extractor stage-a-generate-c0-proof-sources \
                --original ${stage-a-tiny-c0-original}/original.exe \
                --candidate ${stage-b-tiny-c0-candidate}/bin/candidate.exe \
                --state-machine ${stage-b-tiny-c0-source}/state-machine.jsonl \
                --source-manifest ${stage-b-tiny-c0-source}/source-manifest.json \
                --toolchain-profile \
                  ${stage-a-tiny-c0-toolchain-profile}/profile.json \
                --candidate-build-identity \
                  ${stage-b-tiny-c0-candidate.drvPath} \
                --out-dir "$out"
            '';
          tinyC0LeanSource = pkgs.runCommand
            "stage-a-tiny-c0-lean-source-v1"
            {
              preferLocalBuild = false;
              allowSubstitutes = true;
              __contentAddressed = true;
            }
            ''
              mkdir -p "$out"
              cp ${relationalLeanSource}/src/spaghetti_extractor/lean/StageA/*.lean "$out/"
              cp ${stage-b-tiny-c0-source}/GeneratedC0Program.lean \
                "$out/GeneratedC0Program.lean"
              cp ${tinyC0GeneratedProofSources}/StageA/*.lean "$out/"
            '';
          tinyC0GeneratedProofModules = builtins.fromJSON (
            builtins.readFile
              "${tinyC0GeneratedProofSources}/generated-modules.json"
          );
          tinyC0LeanModules = pkgs.lib.unique (
            relationalLeanModuleClosure [
              "RelationalSource"
              "RelationalInterpreterSemanticRefinement"
              "RelationalPEBytePacks"
            ] ++ [ "GeneratedC0Program" ] ++ tinyC0GeneratedProofModules
          );
          tinyC0LeanGraph = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = true;
            standaloneSourceRoot = tinyC0LeanSource;
            standaloneModules = tinyC0LeanModules;
            targetNodes = [ "GeneratedC0SourceAcceptanceAudit" ];
            targetBundle = true;
          };
          stage-a-tiny-c0-source-proof = pkgs.runCommand
            "stage-a-tiny-c0-source-proof-v1"
            {
              preferLocalBuild = false;
              allowSubstitutes = true;
              __contentAddressed = true;
            }
            ''
              mkdir -p "$out"
              cp ${tinyC0LeanGraph}/bundle.json "$out/bundle.json"
              cp -r ${tinyC0LeanGraph}/node-results "$out/node-results"
              cp ${tinyC0GeneratedProofSources}/proof-binding.json \
                "$out/proof-binding.json"
            '';
          stage-a-tiny-c0-source-behavior-smoke = pkgs.runCommand
            "stage-a-tiny-c0-source-behavior-smoke-v1"
            {
              nativeBuildInputs = [
                pkgs.jq
                pkgs.wineWow64Packages.stable
                pkgs.xvfb-run
              ];
              preferLocalBuild = false;
              allowSubstitutes = true;
              __contentAddressed = true;
            }
            ''
              jq -e '
                .acceptance_theorem ==
                  "StageA.GeneratedRelational.generatedOriginalCompiledEquivalent"
              ' ${stage-a-tiny-c0-source-proof}/proof-binding.json >/dev/null
              jq -e '
                any(.nodes[].outputs[];
                  (.axiom_audit.complete // false) and
                  ((.axiom_audit.requested // []) | index(
                    "StageA.GeneratedRelational.generatedOriginalCompiledEquivalent"
                  ) != null) and
                  ((.axiom_audit.inventories[
                    "StageA.GeneratedRelational.generatedOriginalCompiledEquivalent"
                  ] // []) | all(. == "propext" or
                    . == "Classical.choice" or . == "Quot.sound")))
              ' ${stage-a-tiny-c0-source-proof}/bundle.json >/dev/null
              jq -e '.status == "complete" and .omitted_transfer_count == 0' \
                ${stage-b-tiny-c0-source}/source-manifest.json >/dev/null
              binding=${stage-a-tiny-c0-source-proof}/proof-binding.json
              test "$(jq -r .candidate_sha256 "$binding")" = \
                "$(sha256sum ${stage-b-tiny-c0-candidate}/bin/candidate.exe | cut -d ' ' -f 1)"
              test "$(jq -r .source_manifest_sha256 "$binding")" = \
                "$(sha256sum ${stage-b-tiny-c0-source}/source-manifest.json | cut -d ' ' -f 1)"
              test "$(jq -r .toolchain_profile_sha256 "$binding")" = \
                "$(sha256sum ${stage-a-tiny-c0-toolchain-profile}/profile.json | cut -d ' ' -f 1)"
              test "$(jq -r .candidate_build_identity "$binding")" = \
                '${stage-b-tiny-c0-candidate.drvPath}'
              export HOME="$TMPDIR/home"
              export WINEPREFIX="$TMPDIR/wine"
              export WINEDEBUG=-all
              export WINEDLLOVERRIDES="mscoree,mshtml="
              mkdir -p "$HOME"
              set +e
              xvfb-run -a wine \
                ${stage-b-tiny-c0-candidate}/bin/candidate.exe \
                > "$TMPDIR/stdout" 2> "$TMPDIR/stderr"
              status=$?
              set -e
              if [ "$status" -ne 7 ]; then
                cat "$TMPDIR/stdout" >&2
                cat "$TMPDIR/stderr" >&2
                echo "candidate exit status was $status, expected 7" >&2
                exit 1
              fi
              test ! -s "$TMPDIR/stdout"
              mkdir -p "$out"
              cp ${stage-a-tiny-c0-source-proof}/proof-binding.json \
                "$out/proof-binding.json"
              printf '%s\n' 7 > "$out/candidate-exit-status"
            '';
          gnuHelloRoundtrip = import ./nix/gnu-hello-roundtrip.nix {
            inherit pkgs pythonEnv mingw32;
            spaghettiExtractor = spaghetti-extractor;
            sideTool = spaghetti-extractor-side;
            analysisKernelCache = stage-a-relational-analysis-kernel-cache;
            isaKernelCache = stage-a-isa-kernel-cache;
            isaSemanticKernel = stage-a-isa-kernel-identity + "/kernel.json";
            bochsRunner =
              bochs-conformance
              + "/bin/spaghetti-bochs-conformance-runner";
            sourceRoot = spaghettiExtractorCoreSource;
            leanSourceRoot = relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
            originalFixture = stage-a-gnu-hello-original;
            linkedIslands =
              "${stageBGnuHelloLinkedLibraryAnalysis.linkedIslands}/linked-islands.json";
            nativeSourceApprovedToolchainAxiom =
              "StageA.GeneratedRelational.GnuHelloNativeSourceEnvironmentFamily.pinnedCompilerLoweringCorrect";
          };
          stage-a-gnu-hello-roundtrip-smoke = gnuHelloRoundtrip.smoke;
          stage-a-gnu-hello-opaque-original-inventory =
            gnuHelloRoundtrip.opaqueOriginalInventory;
          stage-a-gnu-hello-opaque-static-export =
            gnuHelloRoundtrip.opaqueStaticExport;
          stage-b-gnu-hello-opaque-state-machine =
            gnuHelloRoundtrip.opaqueStateMachine;
          stage-a-gnu-hello-machine-ir = gnuHelloRoundtrip.machineIr;
          stage-b-gnu-hello-machine-ir-interpreter =
            gnuHelloRoundtrip.reconstructionInterpreter;
          stage-b-gnu-hello-machine-ir-native-engine =
            gnuHelloRoundtrip.reconstructionNativeEngine;
          stage-b-gnu-hello-machine-ir-native-runtime =
            gnuHelloRoundtrip.reconstructionNativeRuntime;
          stage-b-gnu-hello-reconstruction-plan =
            gnuHelloRoundtrip.reconstructionPlan;
          stage-b-gnu-hello-semantic-components =
            gnuHelloRoundtrip.semanticComponents;
          stage-b-gnu-hello-component-proposals =
            gnuHelloRoundtrip.componentProposals;
          stage-b-gnu-hello-selected-component-declarations =
            gnuHelloRoundtrip.selectedComponentDeclarations;
          stage-b-gnu-hello-selected-component-catalog =
            gnuHelloRoundtrip.selectedSemanticComponents;
          stage-b-gnu-hello-component-interfaces =
            gnuHelloRoundtrip.semanticComponentWorkspaceDag.componentInterfaces;
          stage-b-gnu-hello-component-slices =
            gnuHelloRoundtrip.semanticComponentWorkspaceDag.componentSlices;
          stage-b-gnu-hello-regional-interpreter-kernel =
            gnuHelloRoundtrip.semanticComponentWorkspaceDag.regionalKernel;
          stage-b-gnu-hello-component-registry =
            gnuHelloRoundtrip.semanticComponentRegistry;
          stage-b-gnu-hello-branch-component-qualification =
            gnuHelloRoundtrip.semanticComponentWorkspaceDag.qualifications.branch;
          stage-b-gnu-hello-external-call-component-qualification =
            gnuHelloRoundtrip.semanticComponentWorkspaceDag.qualifications.external-call;
          stage-b-gnu-hello-internal-call-component-qualification =
            gnuHelloRoundtrip.semanticComponentWorkspaceDag.qualifications.internal-call;
          stage-b-gnu-hello-short-option-component-qualification =
            gnuHelloRoundtrip.semanticComponentWorkspaceDag.qualifications.short-option;
          stage-b-gnu-hello-rotate-component-qualification =
            gnuHelloRoundtrip.semanticComponentWorkspaceDag.qualifications.rotate;
          stage-b-gnu-hello-windows-error-component-qualification =
            gnuHelloRoundtrip.semanticComponentWorkspaceDag.qualifications.windows-error;
          stage-b-gnu-hello-bounded-string-length-component-qualification =
            gnuHelloRoundtrip.semanticComponentWorkspaceDag.qualifications.bounded-string-length;
          stage-b-gnu-hello-atomic-component-qualification =
            gnuHelloRoundtrip.semanticComponentWorkspaceDag.qualifications.atomic;
          stage-b-gnu-hello-callback-component-qualification =
            gnuHelloRoundtrip.semanticComponentWorkspaceDag.qualifications.callback;
          stage-b-gnu-hello-dispatch-component-qualification =
            gnuHelloRoundtrip.semanticComponentWorkspaceDag.qualifications.dispatch;
          stage-b-gnu-hello-typed-memory-component-qualification =
            gnuHelloRoundtrip.semanticComponentWorkspaceDag.qualifications.typed-memory;
          stage-b-gnu-hello-ascii-to-lower-component-qualification =
            gnuHelloRoundtrip.semanticComponentWorkspaceDag.qualifications.ascii-to-lower;
          stage-b-gnu-hello-ascii-string-compare-component-qualification =
            gnuHelloRoundtrip.semanticComponentWorkspaceDag.qualifications.ascii-string-compare;
          stage-b-gnu-hello-last-path-component-qualification =
            gnuHelloRoundtrip.semanticComponentWorkspaceDag.qualifications.last-path-component;
          stage-b-gnu-hello-memory-regions-equal-qualification =
            gnuHelloRoundtrip.semanticComponentWorkspaceDag.qualifications.memory-regions-equal;
          stage-b-gnu-hello-program-name-selection-qualification =
            gnuHelloRoundtrip.semanticComponentWorkspaceDag.qualifications.program-name-selection;
          stage-b-gnu-hello-component-hybrid-candidate =
            gnuHelloRoundtrip.semanticComponentHybridCandidate;
          stage-b-gnu-hello-component-hybrid-functional-suite =
            gnuHelloRoundtrip.semanticComponentHybridFunctionalSuite;
          stage-b-gnu-hello-idiomatic-source-binding =
            gnuHelloRoundtrip.idiomaticSourceBinding;
          stage-b-gnu-hello-idiomatic-candidate =
            gnuHelloRoundtrip.idiomaticCandidate;
          stage-b-gnu-hello-idiomatic-functional-suite =
            gnuHelloRoundtrip.idiomaticFunctionalSuite;
          stage-b-gnu-hello-idiomatic-upstream-suite =
            gnuHelloRoundtrip.idiomaticUpstreamSuite;
          stage-b-gnu-hello-idiomatic-assurance =
            gnuHelloRoundtrip.idiomaticAssurance;
          stage-b-gnu-hello-lifting-evidence =
            gnuHelloRoundtrip.reconstructionLiftingEvidence;
          stage-b-gnu-hello-branch-workspace =
            gnuHelloRoundtrip.reconstructionBranchWorkspace;
          stage-b-gnu-hello-external-call-workspace =
            gnuHelloRoundtrip.reconstructionExternalWorkspace;
          stage-b-gnu-hello-internal-call-workspace =
            gnuHelloRoundtrip.reconstructionInternalWorkspace;
          stage-b-gnu-hello-atomic-workspace =
            gnuHelloRoundtrip.reconstructionAtomicWorkspace;
          stage-b-gnu-hello-callback-workspace =
            gnuHelloRoundtrip.reconstructionCallbackWorkspace;
          stage-b-gnu-hello-dispatch-workspace =
            gnuHelloRoundtrip.reconstructionDispatchWorkspace;
          stage-b-gnu-hello-typed-memory-workspace =
            gnuHelloRoundtrip.reconstructionTypedMemoryWorkspace;
          stage-b-gnu-hello-branch-workspace-check =
            gnuHelloRoundtrip.reconstructionBranchWorkspaceCheck;
          stage-b-gnu-hello-external-call-workspace-check =
            gnuHelloRoundtrip.reconstructionExternalWorkspaceCheck;
          stage-b-gnu-hello-internal-call-workspace-check =
            gnuHelloRoundtrip.reconstructionInternalWorkspaceCheck;
          stage-b-gnu-hello-callback-workspace-check =
            gnuHelloRoundtrip.reconstructionCallbackWorkspaceCheck;
          stage-b-gnu-hello-atomic-workspace-check =
            gnuHelloRoundtrip.reconstructionAtomicWorkspaceCheck;
          stage-b-gnu-hello-dispatch-workspace-check =
            gnuHelloRoundtrip.reconstructionDispatchWorkspaceCheck;
          stage-b-gnu-hello-typed-memory-workspace-check =
            gnuHelloRoundtrip.reconstructionTypedMemoryWorkspaceCheck;
          stage-b-gnu-hello-reconstruction-registry =
            gnuHelloRoundtrip.reconstructionWorkspaceRegistry;
          stage-b-gnu-hello-entry-replacement =
            gnuHelloRoundtrip.reconstructionEntryReplacement;
          stage-b-gnu-hello-regional-harness-kernel =
            gnuHelloRoundtrip.reconstructionRegionalHarnessKernel;
          stage-b-gnu-hello-entry-replacement-validation =
            gnuHelloRoundtrip.reconstructionEntryReplacementValidation;
          stage-b-gnu-hello-entry-replacement-mutation =
            gnuHelloRoundtrip.reconstructionEntryReplacementMutation;
          stage-a-gnu-hello-reconstruction-qualification =
            gnuHelloRoundtrip.reconstructionQualification;
          stage-b-gnu-hello-machine-ir-candidate =
            gnuHelloRoundtrip.reconstructionCandidate;
          stage-b-gnu-hello-entry-replacement-candidate =
            gnuHelloRoundtrip.reconstructionEntryReplacementCandidate;
          stage-b-gnu-hello-reconstruction-workspace-candidate =
            gnuHelloRoundtrip.reconstructionWorkspaceCandidate;
          stage-b-gnu-hello-machine-ir-diagnostic-candidate =
            gnuHelloRoundtrip.reconstructionDiagnosticCandidate;
          stage-b-gnu-hello-machine-ir-functional-suite =
            gnuHelloRoundtrip.reconstructionFunctionalSuite;
          stage-b-gnu-hello-entry-replacement-functional-suite =
            gnuHelloRoundtrip.reconstructionEntryReplacementFunctionalSuite;
          stage-b-gnu-hello-reconstruction-workspace-functional-suite =
            gnuHelloRoundtrip.reconstructionWorkspaceFunctionalSuite;
          stage-a-gnu-hello-reconstruction-assurance =
            gnuHelloRoundtrip.reconstructionAssurance;
          stage-a-gnu-hello-roundtrip-static-export = gnuHelloRoundtrip.staticExport;
          stage-b-gnu-hello-source-state-machine =
            gnuHelloRoundtrip.sourceStateMachine;
          stage-b-gnu-hello-c0-source = gnuHelloRoundtrip.sourceC0;
          stage-b-gnu-hello-native-source-interpreter =
            gnuHelloRoundtrip.sourceInterpreter;
          stage-b-gnu-hello-native-source-engine =
            gnuHelloRoundtrip.sourceNativeEngine;
          stage-b-gnu-hello-native-source-runtime =
            gnuHelloRoundtrip.sourceNativeRuntime;
          stage-b-gnu-hello-native-source-candidate =
            gnuHelloRoundtrip.sourceCandidate;
          stage-a-gnu-hello-native-source-candidate-kernel-data =
            gnuHelloRoundtrip.sourceCandidateKernelDataLean;
          stage-a-gnu-hello-native-source-candidate-static-authority =
            gnuHelloRoundtrip.sourceCandidateStaticAuthorityLean;
          stage-a-gnu-hello-native-source-candidate-static-authority-proof-sources =
            gnuHelloRoundtrip.sourceCandidateStaticAuthorityProofSources;
          stage-a-gnu-hello-native-source-candidate-static-authority-proof =
            gnuHelloRoundtrip.sourceCandidateStaticAuthorityProof;
          stage-a-gnu-hello-native-source-bundle =
            gnuHelloRoundtrip.sourceBundle;
          stage-a-gnu-hello-native-source-compilation-attestation =
            gnuHelloRoundtrip.sourceCompilationAttestation;
          stage-a-gnu-hello-native-source-program =
            gnuHelloRoundtrip.sourceProgramLean;
          stage-a-gnu-hello-native-source-normalization =
            gnuHelloRoundtrip.sourceNormalizationLean;
          stage-a-gnu-hello-native-source-semantic-refinement =
            gnuHelloRoundtrip.sourceSemanticRefinementLean;
          stage-a-gnu-hello-native-source-x87 =
            gnuHelloRoundtrip.sourceX87Lean;
          stage-a-gnu-hello-native-source-machine-import-contracts =
            gnuHelloRoundtrip.sourceStaticMachineImportContractsLean;
          stage-a-gnu-hello-native-source-original-base =
            gnuHelloRoundtrip.sourceOriginalBaseLean;
          stage-a-gnu-hello-native-source-original =
            gnuHelloRoundtrip.sourceOriginalLean;
          stage-a-gnu-hello-native-source-original-static-reachability =
            gnuHelloRoundtrip.sourceOriginalStaticReachabilityLean;
          stage-a-gnu-hello-native-source-original-static-reachability-proof-sources =
            gnuHelloRoundtrip.sourceOriginalStaticReachabilityProofSources;
          stage-a-gnu-hello-native-source-original-static-reachability-proof =
            gnuHelloRoundtrip.sourceOriginalStaticReachabilityProof;
          stage-a-gnu-hello-native-source-original-carrier-binding =
            gnuHelloRoundtrip.sourceOriginalCarrierBindingLean;
          stage-a-gnu-hello-native-source-original-carrier-binding-proof-sources =
            gnuHelloRoundtrip.sourceOriginalCarrierBindingProofSources;
          stage-a-gnu-hello-native-source-original-carrier-binding-proof =
            gnuHelloRoundtrip.sourceOriginalCarrierBindingProof;
          stage-a-gnu-hello-native-source-original-combined-declarations =
            gnuHelloRoundtrip.sourceOriginalCombinedDeclarations;
          stage-a-gnu-hello-native-source-original-combined-inventory =
            gnuHelloRoundtrip.sourceOriginalCombinedInventoryLean;
          stage-a-gnu-hello-native-source-original-combined-inventory-proof-sources =
            gnuHelloRoundtrip.sourceOriginalCombinedInventoryProofSources;
          stage-a-gnu-hello-native-source-original-combined-inventory-proof =
            gnuHelloRoundtrip.sourceOriginalCombinedInventoryProof;
          stage-a-gnu-hello-native-source-target-effect-inputs =
            gnuHelloRoundtrip.sourceTargetEffectInputsLean;
          stage-a-gnu-hello-native-source-target-effects =
            gnuHelloRoundtrip.sourceTargetEffectsLean;
          stage-a-gnu-hello-native-source-transition-index =
            gnuHelloRoundtrip.sourceTransitionIndexLean;
          stage-a-gnu-hello-native-source-transition-index-proof-sources =
            gnuHelloRoundtrip.sourceTransitionIndexProofSources;
          stage-a-gnu-hello-native-source-transition-index-proof =
            gnuHelloRoundtrip.sourceTransitionIndexProof;
          stage-a-gnu-hello-native-source-runtime-memory-access-proposal =
            gnuHelloRoundtrip.sourceRuntimeMemoryAccessProposal;
          stage-a-gnu-hello-native-source-original-target-control =
            gnuHelloRoundtrip.sourceOriginalTargetControlEvidence;
          stage-a-gnu-hello-native-source-original-target-control-proof-sources =
            gnuHelloRoundtrip.sourceOriginalTargetControlProofSources;
          stage-a-gnu-hello-native-source-original-target-control-proof =
            gnuHelloRoundtrip.sourceOriginalTargetControlProof;
          stage-a-gnu-hello-native-source-original-target-control-audit =
            gnuHelloRoundtrip.sourceOriginalTargetControlAudit;
          stage-a-gnu-hello-native-source-ordinary-semantic-proof-sources =
            gnuHelloRoundtrip.sourceOrdinarySemanticProofSources;
          stage-a-gnu-hello-native-source-ordinary-semantic-proof =
            gnuHelloRoundtrip.sourceOrdinarySemanticProof;
          stage-a-gnu-hello-native-source-x87-semantic-proof-sources =
            gnuHelloRoundtrip.sourceX87SemanticProofSources;
          stage-a-gnu-hello-native-source-x87-semantic-proof =
            gnuHelloRoundtrip.sourceX87SemanticProof;
          stage-a-gnu-hello-native-source-program-assembly =
            gnuHelloRoundtrip.sourceProgramAssemblyLean;
          stage-a-gnu-hello-native-source-program-assembly-proof-sources =
            gnuHelloRoundtrip.sourceProgramAssemblyProofSources;
          stage-a-gnu-hello-native-source-program-assembly-proof =
            gnuHelloRoundtrip.sourceProgramAssemblyProof;
          stage-a-gnu-hello-native-source-original-execution-evidence =
            gnuHelloRoundtrip.sourceOriginalExecutionEvidence;
          stage-a-gnu-hello-native-source-execution =
            gnuHelloRoundtrip.sourceExecutionLean;
          stage-a-gnu-hello-native-source-execution-proof-sources =
            gnuHelloRoundtrip.sourceExecutionProofSources;
          stage-a-gnu-hello-native-source-execution-proof =
            gnuHelloRoundtrip.sourceExecutionProof;
          stage-a-gnu-hello-native-source-execution-audit =
            gnuHelloRoundtrip.sourceExecutionAudit;
          stage-a-gnu-hello-native-source-compiled-authority-evidence =
            gnuHelloRoundtrip.sourceCompiledAuthorityEvidence;
          stage-a-gnu-hello-native-source-compiled-authority =
            gnuHelloRoundtrip.sourceCompiledAuthorityLean;
          stage-a-gnu-hello-native-source-compiled-authority-proof-sources =
            gnuHelloRoundtrip.sourceCompiledAuthorityProofSources;
          stage-a-gnu-hello-native-source-compiled-authority-proof =
            gnuHelloRoundtrip.sourceCompiledAuthorityProof;
          stage-a-gnu-hello-native-source-compiled-authority-audit =
            gnuHelloRoundtrip.sourceCompiledAuthorityAudit;
          stage-a-gnu-hello-native-source-environment-family-evidence =
            gnuHelloRoundtrip.sourceEnvironmentFamilyEvidence;
          stage-a-gnu-hello-native-source-conditional-acceptance =
            gnuHelloRoundtrip.sourceConditionalAcceptanceLean;
          stage-a-gnu-hello-native-source-conditional-acceptance-proof-sources =
            gnuHelloRoundtrip.sourceConditionalAcceptanceProofSources;
          stage-a-gnu-hello-native-source-conditional-acceptance-proof =
            gnuHelloRoundtrip.sourceConditionalAcceptanceProof;
          stage-a-gnu-hello-native-source-conditional-acceptance-audit =
            gnuHelloRoundtrip.sourceConditionalAcceptanceAudit;
          stage-a-gnu-hello-native-source-conditional-acceptance-checked =
            gnuHelloRoundtrip.sourceConditionalAcceptanceChecked;
          stage-b-gnu-hello-native-source-functional-suite =
            gnuHelloRoundtrip.sourceRuntimeFunctionalSuite;
          stage-a-gnu-hello-native-source-equivalence-report =
            gnuHelloRoundtrip.sourceEquivalenceFinalReport;
          stage-b-gnu-hello-roundtrip-interpreter = gnuHelloRoundtrip.interpreter;
          stage-b-gnu-hello-roundtrip-native-engine = gnuHelloRoundtrip.nativeEngine;
          stage-b-gnu-hello-roundtrip-native-runtime = gnuHelloRoundtrip.nativeRuntime;
          stage-b-gnu-hello-roundtrip-candidate = gnuHelloRoundtrip.candidate;
          stage-a-gnu-hello-roundtrip-original-inventory =
            gnuHelloRoundtrip.originalInventory;
          stage-a-gnu-hello-roundtrip-candidate-inventory =
            gnuHelloRoundtrip.candidateInventory;
          stage-a-gnu-hello-roundtrip-original-isa-request =
            gnuHelloRoundtrip.originalIsaRequest;
          stage-a-gnu-hello-roundtrip-candidate-isa-request =
            gnuHelloRoundtrip.candidateIsaRequest;
          stage-a-gnu-hello-roundtrip-original-isa =
            gnuHelloRoundtrip.originalIsa;
          stage-a-gnu-hello-roundtrip-candidate-isa =
            gnuHelloRoundtrip.candidateIsa;
          stage-a-gnu-hello-roundtrip-original-isa-summary =
            gnuHelloRoundtrip.originalIsaSummary;
          stage-a-gnu-hello-roundtrip-candidate-isa-summary =
            gnuHelloRoundtrip.candidateIsaSummary;
          stage-a-gnu-hello-roundtrip-side-isa-adapter =
            gnuHelloRoundtrip.sideIsaQualificationAdapter;
          stage-a-gnu-hello-roundtrip-side-isa-enrichment =
            gnuHelloRoundtrip.sideIsaCatalogEnrichment;
          stage-a-gnu-hello-roundtrip-side-isa-corpus =
            gnuHelloRoundtrip.sideIsaCorpus;
          stage-a-gnu-hello-roundtrip-side-isa-evidence =
            gnuHelloRoundtrip.sideIsaQualificationEvidence;
          stage-a-gnu-hello-roundtrip-side-isa-qualification =
            gnuHelloRoundtrip.sideIsaQualificationBundle;
          stage-a-gnu-hello-roundtrip-isa-coverage =
            gnuHelloRoundtrip.isaCoverage;
          stage-a-gnu-hello-roundtrip-semantic-coverage =
            gnuHelloRoundtrip.semanticCoverage;
          stage-a-gnu-hello-roundtrip-engine-segments = gnuHelloRoundtrip.engineSegments;
          stage-a-gnu-hello-roundtrip-compiled-kernel-source = gnuHelloRoundtrip.kernelLean;
          stage-a-gnu-hello-roundtrip-static-machine-import-source =
            gnuHelloRoundtrip.staticMachineImportContractsLean;
          stage-a-gnu-hello-roundtrip-universal-paired-external-environment-source =
            gnuHelloRoundtrip.universalPairedExternalEnvironmentLean;
          stage-a-gnu-hello-roundtrip-static-machine-import-proof-sources =
            gnuHelloRoundtrip.staticMachineImportProofSources;
          stage-a-gnu-hello-roundtrip-static-machine-import-proof =
            gnuHelloRoundtrip.staticMachineImportProof;
          stage-a-gnu-hello-roundtrip-mixed-original-source = gnuHelloRoundtrip.mixedOriginalLean;
          stage-a-gnu-hello-roundtrip-mixed-original-static-reachability-source =
            gnuHelloRoundtrip.mixedOriginalStaticReachabilityLean;
          stage-a-gnu-hello-roundtrip-mixed-original-static-reachability-proof-sources =
            gnuHelloRoundtrip.mixedOriginalStaticReachabilityProofSources;
          stage-a-gnu-hello-roundtrip-mixed-original-static-reachability-proof =
            gnuHelloRoundtrip.mixedOriginalStaticReachabilityProof;
          stage-a-gnu-hello-roundtrip-mixed-original-writable-slot-authority-lean =
            gnuHelloRoundtrip.mixedOriginalWritableSlotAuthorityLean;
          stage-b-gnu-hello-callable-external-runtime-contract =
            gnuHelloRoundtrip.callableExternalRuntimeContract;
          stage-a-gnu-hello-roundtrip-mixed-original-register-indirect-authority-source =
            gnuHelloRoundtrip.mixedOriginalRegisterIndirectAuthorityLean;
          stage-a-gnu-hello-roundtrip-mixed-original-register-indirect-authority-proof-sources =
            gnuHelloRoundtrip.mixedOriginalRegisterIndirectAuthorityProofSources;
          stage-a-gnu-hello-roundtrip-mixed-original-register-indirect-authority-proof =
            gnuHelloRoundtrip.mixedOriginalRegisterIndirectAuthorityProof;
          stage-a-gnu-hello-roundtrip-mixed-original-stack-dynamic-authority-source =
            gnuHelloRoundtrip.mixedOriginalStackDynamicAuthorityLean;
          stage-a-gnu-hello-roundtrip-mixed-original-stack-dynamic-authority-proof-sources =
            gnuHelloRoundtrip.mixedOriginalStackDynamicAuthorityProofSources;
          stage-a-gnu-hello-roundtrip-mixed-original-stack-dynamic-authority-proof =
            gnuHelloRoundtrip.mixedOriginalStackDynamicAuthorityProof;
          stage-a-gnu-hello-roundtrip-mixed-original-direct-call-proposals-source =
            gnuHelloRoundtrip.mixedOriginalDirectCallClosureProposalsLean;
          stage-a-gnu-hello-roundtrip-mixed-original-direct-call-proposal-proof-sources =
            gnuHelloRoundtrip.mixedOriginalDirectCallClosureProposalProofSources;
          stage-a-gnu-hello-roundtrip-mixed-original-direct-call-proposal-proof =
            gnuHelloRoundtrip.mixedOriginalDirectCallClosureProposalProof;
          stage-a-gnu-hello-roundtrip-mixed-original-direct-call-semantics-source =
            gnuHelloRoundtrip.mixedOriginalDirectCallClosureSemanticsLean;
          stage-a-gnu-hello-roundtrip-mixed-original-direct-call-semantics-proof-sources =
            gnuHelloRoundtrip.mixedOriginalDirectCallClosureSemanticsProofSources;
          stage-a-gnu-hello-roundtrip-mixed-original-direct-call-semantics-proof =
            gnuHelloRoundtrip.mixedOriginalDirectCallClosureSemanticsProof;
          stage-a-gnu-hello-roundtrip-mixed-original-direct-call-fixed-point-check =
            gnuHelloRoundtrip.mixedOriginalDirectCallFixedPointCheck;
          stage-a-gnu-hello-roundtrip-mixed-original-direct-call-round-1-proposals-source =
            gnuHelloRoundtrip.mixedOriginalDirectCallProposalsLean;
          stage-a-gnu-hello-roundtrip-mixed-original-direct-call-round-1-semantics-source =
            gnuHelloRoundtrip.mixedOriginalDirectCallSemanticsLean;
          stage-a-gnu-hello-roundtrip-mixed-original-carrier-binding-source =
            gnuHelloRoundtrip.mixedOriginalCarrierBindingLean;
          stage-a-gnu-hello-roundtrip-mixed-original-carrier-binding-proof-sources =
            gnuHelloRoundtrip.mixedOriginalCarrierBindingProofSources;
          stage-a-gnu-hello-roundtrip-mixed-original-carrier-binding-proof =
            gnuHelloRoundtrip.mixedOriginalCarrierBindingProof;
          stage-a-gnu-hello-roundtrip-mixed-original-diagnostic = gnuHelloRoundtrip.mixedOriginalDiagnostic;
          stage-a-gnu-hello-roundtrip-kernel-data-source = gnuHelloRoundtrip.kernelDataLean;
          stage-a-gnu-hello-roundtrip-kernel-data-native-projection-proof =
            gnuHelloRoundtrip.kernelDataNativeProjectionProof;
          stage-a-gnu-hello-roundtrip-kernel-data-native-projection-benchmark =
            gnuHelloRoundtrip.kernelDataNativeProjectionBenchmark;
          stage-a-gnu-hello-roundtrip-access-fault-qualification-source =
            gnuHelloRoundtrip.accessFaultQualificationLean;
          stage-a-gnu-hello-roundtrip-access-fault-qualification-proof-sources =
            gnuHelloRoundtrip.accessFaultQualificationProofSources;
          stage-a-gnu-hello-roundtrip-access-fault-qualification-proof =
            gnuHelloRoundtrip.accessFaultQualificationProof;
          stage-a-gnu-hello-roundtrip-kernel-abi-source = gnuHelloRoundtrip.kernelAbiLean;
          stage-a-gnu-hello-roundtrip-constructive-source-coverage-source =
            gnuHelloRoundtrip.constructiveSourceCoverageLean;
          stage-a-gnu-hello-roundtrip-constructive-source-coverage-proof-sources =
            gnuHelloRoundtrip.constructiveSourceCoverageProofSources;
          stage-a-gnu-hello-roundtrip-constructive-source-coverage-proof =
            gnuHelloRoundtrip.constructiveSourceCoverageProof;
          stage-a-gnu-hello-roundtrip-canonical-relation-core-source =
            gnuHelloRoundtrip.canonicalRelationCoreLean;
          stage-a-gnu-hello-roundtrip-canonical-relation-core-proof-sources =
            gnuHelloRoundtrip.canonicalRelationCoreProofSources;
          stage-a-gnu-hello-roundtrip-canonical-relation-core-proof =
            gnuHelloRoundtrip.canonicalRelationCoreProof;
          stage-a-gnu-hello-roundtrip-acceptance-requirements-source =
            gnuHelloRoundtrip.acceptanceRequirementsLean;
          stage-a-gnu-hello-roundtrip-acceptance-requirements-proof-sources =
            gnuHelloRoundtrip.acceptanceRequirementsProofSources;
          stage-a-gnu-hello-roundtrip-acceptance-requirements-proof =
            gnuHelloRoundtrip.acceptanceRequirementsProof;
          stage-a-gnu-hello-roundtrip-runtime-foundation-source =
            gnuHelloRoundtrip.runtimeFoundationLean;
          stage-a-gnu-hello-roundtrip-runtime-foundation-proof-sources =
            gnuHelloRoundtrip.runtimeFoundationProofSources;
          stage-a-gnu-hello-roundtrip-runtime-foundation-proof =
            gnuHelloRoundtrip.runtimeFoundationProof;
          stage-a-gnu-hello-roundtrip-launch-binding-source =
            gnuHelloRoundtrip.launchBindingLean;
          stage-a-gnu-hello-roundtrip-launch-binding-proof-sources =
            gnuHelloRoundtrip.launchBindingProofSources;
          stage-a-gnu-hello-roundtrip-launch-binding-proof =
            gnuHelloRoundtrip.launchBindingProof;
          stage-a-gnu-hello-roundtrip-external-component-source =
            gnuHelloRoundtrip.externalComponentLean;
          stage-a-gnu-hello-roundtrip-external-component-proof-sources =
            gnuHelloRoundtrip.externalComponentProofSources;
          stage-a-gnu-hello-roundtrip-external-component-proof =
            gnuHelloRoundtrip.externalComponentProof;
          stage-a-gnu-hello-roundtrip-mixed-semantic-operation-component-source =
            gnuHelloRoundtrip.mixedSemanticOperationComponentLean;
          stage-a-gnu-hello-roundtrip-mixed-semantic-operation-component-proof-sources =
            gnuHelloRoundtrip.mixedSemanticOperationComponentProofSources;
          stage-a-gnu-hello-roundtrip-mixed-semantic-operation-component-proof =
            gnuHelloRoundtrip.mixedSemanticOperationComponentProof;
          stage-a-gnu-hello-roundtrip-mixed-fused-semantic-evidence-source =
            gnuHelloRoundtrip.mixedFusedSemanticEvidenceLean;
          stage-a-gnu-hello-roundtrip-mixed-fused-semantic-evidence-proof-sources =
            gnuHelloRoundtrip.mixedFusedSemanticEvidenceProofSources;
          stage-a-gnu-hello-roundtrip-mixed-fused-semantic-evidence-proof =
            gnuHelloRoundtrip.mixedFusedSemanticEvidenceProof;
          stage-a-gnu-hello-roundtrip-mixed-direct-call-semantic-evidence-source =
            gnuHelloRoundtrip.mixedDirectCallSemanticEvidenceLean;
          stage-a-gnu-hello-roundtrip-mixed-direct-call-semantic-evidence-proof-sources =
            gnuHelloRoundtrip.mixedDirectCallSemanticEvidenceProofSources;
          stage-a-gnu-hello-roundtrip-mixed-direct-call-semantic-evidence-proof =
            gnuHelloRoundtrip.mixedDirectCallSemanticEvidenceProof;
          stage-a-gnu-hello-roundtrip-mixed-indirect-import-call-semantic-evidence-source =
            gnuHelloRoundtrip.mixedIndirectImportCallSemanticEvidenceLean;
          stage-a-gnu-hello-roundtrip-mixed-indirect-import-call-semantic-evidence-proof-sources =
            gnuHelloRoundtrip.mixedIndirectImportCallSemanticEvidenceProofSources;
          stage-a-gnu-hello-roundtrip-mixed-indirect-import-call-semantic-evidence-proof =
            gnuHelloRoundtrip.mixedIndirectImportCallSemanticEvidenceProof;
          stage-a-gnu-hello-roundtrip-mixed-external-tail-semantic-evidence-source =
            gnuHelloRoundtrip.mixedExternalTailSemanticEvidenceLean;
          stage-a-gnu-hello-roundtrip-mixed-external-tail-semantic-evidence-proof-sources =
            gnuHelloRoundtrip.mixedExternalTailSemanticEvidenceProofSources;
          stage-a-gnu-hello-roundtrip-mixed-external-tail-semantic-evidence-proof =
            gnuHelloRoundtrip.mixedExternalTailSemanticEvidenceProof;
          stage-a-gnu-hello-roundtrip-runtime-indirect-composition-source =
            gnuHelloRoundtrip.runtimeIndirectCompositionLean;
          stage-a-gnu-hello-roundtrip-runtime-indirect-composition-proof-sources =
            gnuHelloRoundtrip.runtimeIndirectCompositionProofSources;
          stage-a-gnu-hello-roundtrip-runtime-indirect-composition-proof =
            gnuHelloRoundtrip.runtimeIndirectCompositionProof;
          stage-a-gnu-hello-roundtrip-program-lookup-native-world-bridge-source =
            gnuHelloRoundtrip.programLookupNativeWorldBridgeLean;
          stage-a-gnu-hello-roundtrip-program-lookup-native-world-bridge-proof-sources =
            gnuHelloRoundtrip.programLookupNativeWorldBridgeProofSources;
          stage-a-gnu-hello-roundtrip-program-lookup-native-world-bridge-proof =
            gnuHelloRoundtrip.programLookupNativeWorldBridgeProof;
          stage-a-gnu-hello-roundtrip-interpreter-step-world-program-lookup-source =
            gnuHelloRoundtrip.interpreterStepWorldProgramLookupLean;
          stage-a-gnu-hello-roundtrip-interpreter-step-program-lookup-call-behavior-extraction =
            gnuHelloRoundtrip.interpreterStepProgramLookupCallBehaviorExtraction;
          stage-a-gnu-hello-roundtrip-interpreter-step-program-lookup-call-behaviors-source =
            gnuHelloRoundtrip.interpreterStepProgramLookupCallBehaviorsLean;
          stage-a-gnu-hello-roundtrip-interpreter-step-program-lookup-projection-proof-sources =
            gnuHelloRoundtrip.interpreterStepProgramLookupProjectionProofSources;
          stage-a-gnu-hello-roundtrip-interpreter-step-program-lookup-projection-proof =
            gnuHelloRoundtrip.interpreterStepProgramLookupProjectionProof;
          stage-a-gnu-hello-roundtrip-interpreter-step-world-program-lookup-proof-sources =
            gnuHelloRoundtrip.interpreterStepWorldProgramLookupProofSources;
          stage-a-gnu-hello-roundtrip-interpreter-step-world-program-lookup-proof =
            gnuHelloRoundtrip.interpreterStepWorldProgramLookupProof;
          stage-a-gnu-hello-roundtrip-kernel-operation-instantiation-source =
            gnuHelloRoundtrip.kernelOperationInstantiationLean;
          stage-a-gnu-hello-roundtrip-kernel-operation-instantiation-proof-sources =
            gnuHelloRoundtrip.kernelOperationInstantiationProofSources;
          stage-a-gnu-hello-roundtrip-kernel-operation-instantiation-proof =
            gnuHelloRoundtrip.kernelOperationInstantiationProof;
          stage-a-gnu-hello-roundtrip-kernel-run-entry-route-source =
            gnuHelloRoundtrip.kernelRunEntryRouteLean;
          stage-a-gnu-hello-roundtrip-kernel-run-entry-route-proof-sources =
            gnuHelloRoundtrip.kernelRunEntryRouteProofSources;
          stage-a-gnu-hello-roundtrip-kernel-run-entry-route-proof =
            gnuHelloRoundtrip.kernelRunEntryRouteProof;
          stage-a-gnu-hello-roundtrip-kernel-run-entry-behavior-extraction =
            gnuHelloRoundtrip.kernelRunEntryBehaviorExtraction;
          stage-a-gnu-hello-roundtrip-kernel-run-entry-behaviors-source =
            gnuHelloRoundtrip.kernelRunEntryBehaviorsLean;
          stage-a-gnu-hello-roundtrip-kernel-run-entry-behaviors-proof-sources =
            gnuHelloRoundtrip.kernelRunEntryBehaviorsProofSources;
          stage-a-gnu-hello-roundtrip-kernel-run-entry-behaviors-proof =
            gnuHelloRoundtrip.kernelRunEntryBehaviorsProof;
          stage-a-gnu-hello-roundtrip-kernel-run-entry-abi-source =
            gnuHelloRoundtrip.kernelRunEntryAbiLean;
          stage-a-gnu-hello-roundtrip-kernel-run-entry-abi-proof-sources =
            gnuHelloRoundtrip.kernelRunEntryAbiProofSources;
          stage-a-gnu-hello-roundtrip-kernel-run-entry-abi-proof =
            gnuHelloRoundtrip.kernelRunEntryAbiProof;
          stage-a-gnu-hello-roundtrip-mixed-acceptance-source =
            gnuHelloRoundtrip.gnuHelloMixedAcceptanceLean;
          stage-a-gnu-hello-roundtrip-mixed-chunked-acceptance-source =
            gnuHelloRoundtrip.mixedChunkedAcceptanceLean;
          stage-a-gnu-hello-roundtrip-mixed-chunked-acceptance-proof-sources =
            gnuHelloRoundtrip.mixedChunkedAcceptanceProofSources;
          stage-a-gnu-hello-roundtrip-mixed-chunked-acceptance-proof =
            gnuHelloRoundtrip.mixedChunkedAcceptanceProof;
          stage-a-gnu-hello-roundtrip-native-launch-graph-source = gnuHelloRoundtrip.nativeLaunchGraphLean;
          stage-a-gnu-hello-roundtrip-native-launch-graph-proof-sources =
            gnuHelloRoundtrip.nativeLaunchGraphProofSources;
          stage-a-gnu-hello-roundtrip-native-launch-graph-proof = gnuHelloRoundtrip.nativeLaunchGraphProof;
          stage-a-gnu-hello-roundtrip-proof-sources = gnuHelloRoundtrip.proofSources;
          stage-a-gnu-hello-roundtrip-acceptance-source = gnuHelloRoundtrip.acceptanceLean;
          stage-a-gnu-hello-roundtrip-final-proof-sources = gnuHelloRoundtrip.finalProofSources;
          stage-a-gnu-hello-roundtrip-proof-fragments = gnuHelloRoundtrip.proofFragments;
          stage-a-gnu-hello-roundtrip-x87-schedule-benchmark = gnuHelloRoundtrip.x87ScheduleBenchmark;
          stage-a-gnu-hello-roundtrip-ordinary-refinement = gnuHelloRoundtrip.ordinaryRefinementFragments;
          stage-a-gnu-hello-roundtrip-x87-candidate-replay-source = gnuHelloRoundtrip.x87CandidateReplayLean;
          stage-a-gnu-hello-roundtrip-x87-candidate-replay = gnuHelloRoundtrip.x87CandidateReplayFragments;
          stage-a-gnu-hello-roundtrip-x87-replay-bridge-runtime-source =
            gnuHelloRoundtrip.x87ReplayBridgeRuntimeLean;
          stage-a-gnu-hello-roundtrip-x87-replay-bridge-runtime =
            gnuHelloRoundtrip.x87ReplayBridgeRuntimeFragments;
          stage-a-gnu-hello-roundtrip-x87-kernel-execution-source = gnuHelloRoundtrip.x87KernelExecutionLean;
          stage-a-gnu-hello-roundtrip-x87-kernel-execution = gnuHelloRoundtrip.x87KernelExecutionFragments;
          stage-a-gnu-hello-roundtrip-kernel-lookup-source = gnuHelloRoundtrip.kernelLookupLean;
          stage-a-gnu-hello-roundtrip-kernel-lookup-native-source = gnuHelloRoundtrip.kernelLookupNativeLean;
          stage-a-gnu-hello-roundtrip-kernel-lookup-operation-source =
            gnuHelloRoundtrip.kernelLookupOperationLean;
          stage-a-gnu-hello-roundtrip-kernel-step-source = gnuHelloRoundtrip.kernelStepLean;
          stage-a-gnu-hello-roundtrip-kernel-step-native-source = gnuHelloRoundtrip.kernelStepNativeLean;
          stage-a-gnu-hello-roundtrip-kernel-step-operation-source =
            gnuHelloRoundtrip.kernelStepOperationLean;
          stage-a-gnu-hello-roundtrip-kernel-step-program-lookup-call-source =
            gnuHelloRoundtrip.kernelStepProgramLookupCallLean;
          stage-a-gnu-hello-roundtrip-kernel-step-program-lookup-call-closure-source =
            gnuHelloRoundtrip.kernelStepProgramLookupCallClosureLean;
          stage-a-gnu-hello-roundtrip-kernel-step-program-lookup-call-closure-proof =
            gnuHelloRoundtrip.kernelStepProgramLookupCallClosureProof;
          stage-a-gnu-hello-roundtrip-kernel-step-program-lookup-exact-computation-source =
            gnuHelloRoundtrip.kernelStepProgramLookupExactComputationLean;
          stage-a-gnu-hello-roundtrip-kernel-step-program-lookup-exact-computation-proof =
            gnuHelloRoundtrip.kernelStepProgramLookupExactComputationProof;
          stage-a-gnu-hello-roundtrip-kernel-operation-frame-parametric-source =
            gnuHelloRoundtrip.kernelOperationFrameParametricLean;
          stage-a-gnu-hello-roundtrip-kernel-frame-executor-source =
            gnuHelloRoundtrip.kernelFrameExecutorLean;
          stage-a-gnu-hello-roundtrip-kernel-run-source = gnuHelloRoundtrip.kernelRunLean;
          stage-a-gnu-hello-roundtrip-kernel-run-native-source = gnuHelloRoundtrip.kernelRunNativeLean;
          stage-a-gnu-hello-roundtrip-kernel-run-native-proof = gnuHelloRoundtrip.kernelRunNativeProof;
          stage-a-gnu-hello-roundtrip-kernel-run-operation-source = gnuHelloRoundtrip.kernelRunOperationLean;
          stage-a-gnu-hello-roundtrip-kernel-run-operation-proof = gnuHelloRoundtrip.kernelRunOperationProof;
          stage-a-gnu-hello-roundtrip-kernel-run-iteration-proof =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              contentAddressed = true;
              standaloneSourceRoot =
                relationalLeanSource
                + "/src/spaghetti_extractor/lean/StageA";
              standaloneModules = relationalRunIterationKernelModules;
              standaloneModuleResources =
                relationalRoundtripKernelResources;
              targetNodes = relationalRunIterationKernelRoots;
              targetBundle = true;
              targetAxiomAudit = {
                module = "RelationalInterpreterKernelRunIteration";
                declaration =
                  "RunFunctionNativeCheckedLocalSemantics.executeHead";
                approved_axioms = [
                  "propext"
                  "Classical.choice"
                  "Quot.sound"
                ];
              };
            };
          stage-a-gnu-hello-roundtrip-kernel-operation-state-route-proof =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              contentAddressed = true;
              standaloneSourceRoot =
                relationalLeanSource
                + "/src/spaghetti_extractor/lean/StageA";
              standaloneModules = relationalOperationStateRouteKernelModules;
              standaloneModuleResources =
                relationalRoundtripKernelResources;
              targetNodes = relationalOperationStateRouteKernelRoots;
              targetBundle = true;
              targetAxiomAudit = {
                module =
                  "RelationalInterpreterKernelOperationStateRouteChecker";
                declaration = "CheckedNativeOperationStateRoute.path";
                approved_axioms = [
                  "propext"
                  "Classical.choice"
                  "Quot.sound"
                ];
              };
            };
          stage-a-gnu-hello-roundtrip-kernel-operation-ranked-state-route-proof =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              contentAddressed = true;
              standaloneSourceRoot =
                relationalLeanSource
                + "/src/spaghetti_extractor/lean/StageA";
              standaloneModules =
                relationalOperationRankedStateRouteKernelModules;
              standaloneModuleResources =
                relationalRoundtripKernelResources;
              targetNodes =
                relationalOperationRankedStateRouteKernelRoots;
              targetBundle = true;
              targetAxiomAudit = {
                module =
                  "RelationalInterpreterKernelOperationRankedStateRoute";
                declaration =
                  "CheckedNativeOperationStateRouteToStop.path";
                approved_axioms = [
                  "propext"
                  "Classical.choice"
                  "Quot.sound"
                ];
              };
            };
          stage-a-gnu-hello-roundtrip-kernel-operation-route-invariant-proof =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              contentAddressed = true;
              standaloneSourceRoot =
                relationalLeanSource
                + "/src/spaghetti_extractor/lean/StageA";
              standaloneModules =
                relationalOperationRouteInvariantKernelModules;
              standaloneModuleResources =
                relationalRoundtripKernelResources;
              targetNodes =
                relationalOperationRouteInvariantKernelRoots;
              targetBundle = true;
              targetAxiomAudit = {
                module =
                  "RelationalInterpreterKernelOperationRouteInvariant";
                declaration =
                  "CheckedNativeOperationStateRouteToStop.finalRvaExact";
                approved_axioms = [
                  "propext"
                  "Classical.choice"
                  "Quot.sound"
                ];
              };
            };
          stage-a-gnu-hello-roundtrip-kernel-operation-predicate-route-proof =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              contentAddressed = true;
              standaloneSourceRoot =
                relationalLeanSource
                + "/src/spaghetti_extractor/lean/StageA";
              standaloneModules =
                relationalOperationPredicateRouteKernelModules;
              standaloneModuleResources =
                relationalRoundtripKernelResources;
              targetNodes =
                relationalOperationPredicateRouteKernelRoots;
              targetBundle = true;
              targetAxiomAudit = {
                module =
                  "RelationalInterpreterKernelOperationPredicateRoute";
                declaration =
                  "CheckedNativeOperationPredicateRoute.execute";
                approved_axioms = [
                  "propext"
                  "Classical.choice"
                  "Quot.sound"
                ];
              };
            };
          stage-a-gnu-hello-roundtrip-kernel-operation-effect-checker-proof =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              contentAddressed = true;
              standaloneSourceRoot =
                relationalLeanSource
                + "/src/spaghetti_extractor/lean/StageA";
              standaloneModules =
                relationalOperationEffectCheckerKernelModules;
              standaloneModuleResources =
                relationalRoundtripKernelResources;
              targetNodes =
                relationalOperationEffectCheckerKernelRoots;
              targetBundle = true;
              targetAxiomAudit = {
                module =
                  "RelationalInterpreterKernelOperationEffectChecker";
                declaration =
                  "CheckedNativeOperationEffectfulBlockStep.execute";
                approved_axioms = [
                  "propext"
                  "Classical.choice"
                  "Quot.sound"
                ];
              };
            };
          stage-a-gnu-hello-roundtrip-kernel-operation-memory-route-proof =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              contentAddressed = true;
              standaloneSourceRoot =
                relationalLeanSource
                + "/src/spaghetti_extractor/lean/StageA";
              standaloneModules =
                relationalOperationMemoryRouteKernelModules;
              standaloneModuleResources =
                relationalRoundtripKernelResources;
              targetNodes =
                relationalOperationMemoryRouteKernelRoots;
              targetBundle = true;
              targetAxiomAudit = {
                module =
                  "RelationalInterpreterKernelOperationMemoryRoute";
                declaration =
                  "checkedNativeOperationPredicateRoute_memoryAgreesOn";
                approved_axioms = [
                  "propext"
                  "Classical.choice"
                  "Quot.sound"
                ];
              };
            };
          stage-a-kernel-cdecl-static-preservation-proof =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              contentAddressed = true;
              standaloneSourceRoot =
                relationalLeanSource
                + "/src/spaghetti_extractor/lean/StageA";
              standaloneModules =
                relationalCdeclStaticPreservationKernelModules;
              standaloneModuleResources =
                relationalRoundtripKernelResources;
              targetNodes =
                relationalCdeclStaticPreservationKernelRoots;
              targetBundle = true;
              targetAxiomAudit = {
                module =
                  "RelationalInterpreterKernelCdeclEpilogueStaticPreservation";
                declaration =
                  "workspaceFrame_preservesOriginalProgramTable";
                approved_axioms = [
                  "propext"
                  "Quot.sound"
                ];
              };
            };
          stage-a-gnu-hello-roundtrip-kernel-engine-copy-proof =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              contentAddressed = true;
              standaloneSourceRoot =
                relationalLeanSource
                + "/src/spaghetti_extractor/lean/StageA";
              standaloneModules =
                relationalInterpreterKernelEngineCopyModules;
              standaloneModuleResources =
                relationalRoundtripKernelResources;
              targetNodes =
                relationalInterpreterKernelEngineCopyRoots;
              targetBundle = true;
              targetAxiomAudit = {
                module =
                  "RelationalInterpreterKernelEngineCopy";
                declaration =
                  "EngineStateHolds.rebase";
                approved_axioms = [
                  "propext"
                  "Classical.choice"
                  "Quot.sound"
                ];
              };
            };
          stage-a-gnu-hello-roundtrip-kernel-operation-state-boundary-proof =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              contentAddressed = true;
              standaloneSourceRoot =
                relationalLeanSource
                + "/src/spaghetti_extractor/lean/StageA";
              standaloneModules =
                relationalOperationStateBoundaryKernelModules;
              standaloneModuleResources =
                relationalRoundtripKernelResources;
              targetNodes =
                relationalOperationStateBoundaryKernelRoots;
              targetBundle = true;
              targetAxiomAudit = {
                module =
                  "RelationalInterpreterKernelOperationStateBoundaryChecker";
                declaration =
                  "CheckedNativeOperationStateBoundaryRoute.execute";
                approved_axioms = [
                  "propext"
                  "Classical.choice"
                  "Quot.sound"
                ];
              };
            };
          stage-a-gnu-hello-roundtrip-kernel-operation-state-route-run-adapter-proof =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              contentAddressed = true;
              standaloneSourceRoot =
                relationalLeanSource
                + "/src/spaghetti_extractor/lean/StageA";
              standaloneModules =
                relationalOperationStateRouteRunAdapterKernelModules;
              standaloneModuleResources =
                relationalRoundtripKernelResources;
              targetNodes =
                relationalOperationStateRouteRunAdapterKernelRoots;
              targetBundle = true;
              targetAxiomAudit = {
                module =
                  "RelationalInterpreterKernelOperationStateRouteRunAdapter";
                declaration =
                  "runFunctionChunkOfStateRoute_resultExact";
                approved_axioms = [
                  "propext"
                  "Classical.choice"
                  "Quot.sound"
                ];
              };
            };
          stage-a-gnu-hello-roundtrip-kernel-operation-step-route-adapter-proof =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              contentAddressed = true;
              standaloneSourceRoot =
                relationalLeanSource
                + "/src/spaghetti_extractor/lean/StageA";
              standaloneModules =
                relationalOperationStepRouteAdapterKernelModules;
              standaloneModuleResources =
                relationalRoundtripKernelResources;
              targetNodes =
                relationalOperationStepRouteAdapterKernelRoots;
              targetBundle = true;
              targetAxiomAudit = {
                module =
                  "RelationalInterpreterKernelOperationStepRouteAdapter";
                declaration =
                  "exactInterpreterStepProgramLookupCallReplayOfCheckedBlock";
                approved_axioms = [
                  "propext"
                  "Classical.choice"
                  "Quot.sound"
                ];
              };
            };
          stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-source =
            gnuHelloRoundtrip.kernelCdeclEpilogueLean;
          stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-symbolic-closure-source =
            gnuHelloRoundtrip.kernelCdeclEpilogueSymbolicClosureLean;
          stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-symbolic-closure-proof =
            gnuHelloRoundtrip.kernelCdeclEpilogueSymbolicClosureProof;
          stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-static-preservation-source =
            gnuHelloRoundtrip.kernelCdeclEpilogueStaticPreservationLean;
          stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-static-preservation-proof =
            gnuHelloRoundtrip.kernelCdeclEpilogueStaticPreservationProof;
          stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-external-payload-source =
            gnuHelloRoundtrip.kernelCdeclEpilogueExternalPayloadLean;
          stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-external-payload-proof =
            gnuHelloRoundtrip.kernelCdeclEpilogueExternalPayloadProof;
          stage-a-gnu-hello-roundtrip-kernel-operation-result-encoding-source =
            gnuHelloRoundtrip.kernelOperationResultEncodingLean;
          stage-a-gnu-hello-roundtrip-kernel-operation-result-encoding-proof =
            gnuHelloRoundtrip.kernelOperationResultEncodingProof;
          stage-a-gnu-hello-roundtrip-kernel-abstract-operation-transition-source =
            gnuHelloRoundtrip.kernelAbstractOperationTransitionLean;
          stage-a-gnu-hello-roundtrip-kernel-abstract-operation-transition-proof =
            gnuHelloRoundtrip.kernelAbstractOperationTransitionProof;
          stage-a-gnu-hello-roundtrip-kernel-invoke-source = gnuHelloRoundtrip.kernelInvokeLean;
          stage-a-gnu-hello-roundtrip-kernel-invoke-native-source = gnuHelloRoundtrip.kernelInvokeNativeLean;
          stage-a-gnu-hello-roundtrip-kernel-invoke-operation-source =
            gnuHelloRoundtrip.kernelInvokeOperationLean;
          stage-a-gnu-hello-roundtrip-mixed-candidate-authority-source =
            gnuHelloRoundtrip.mixedCandidateAuthorityLean;
          stage-a-gnu-hello-roundtrip-proof = gnuHelloRoundtrip.proofReport;
          stage-a-gnu-hello-roundtrip-final = gnuHelloRoundtrip.final;
          stage-a-nix-graph-integration =
            pkgs.runCommand "stage-a-nix-graph-integration"
              {
                nativeBuildInputs = [ pkgs.jq ];
                preferLocalBuild = true;
              }
              ''
                manifest="${stage-a-roundtrip-lean-graph-smoke}/graph-smoke.json"
                jq -e \
                  --argjson expected '${builtins.toJSON relationalRoundtripKernelRoots}' \
                  --argjson required '${builtins.toJSON relationalRoundtripRequiredModules}' \
                  '
                    . as $manifest |
                    .format == "stage-a-lean-graph-smoke-v1" and
                    .status == "ready" and
                    .lean_trust == 0 and
                    (.module_count == (.modules | length)) and
                    (.node_count == (.nodes | length)) and
                    ((.target_nodes | sort) == ($expected | sort)) and
                    ($required | all(. as $module |
                      $manifest.modules | index($module) != null)) and
                    ($expected | all(. as $module |
                      $manifest.modules | index($module) != null)) and
                    (.nodes | all(
                      (.resource_class == "light" or
                       .resource_class == "medium" or
                       .resource_class == "high-memory") and
                      .estimated_memory_mb > 0))
                  ' "$manifest" >/dev/null
                acceptance_manifest="${stage-a-relational-acceptance-graph-smoke}/graph-smoke.json"
                jq -e \
                  --argjson expected '${builtins.toJSON relationalAcceptanceKernelRoots}' \
                  '
                    . as $manifest |
                    .format == "stage-a-lean-graph-smoke-v1" and
                    .status == "ready" and
                    .lean_trust == 0 and
                    ((.target_nodes | sort) == ($expected | sort)) and
                    (.modules | index("RelationalInterpreterKernelLookupNative") == null) and
                    (.modules | index("RelationalInterpreterKernelProgramLookupOperation") == null) and
                    (.modules | index("RelationalInterpreterWholeProgramAcceptance") == null)
                  ' "$acceptance_manifest" >/dev/null
                mkdir -p "$out"
                cp "$manifest" "$out/graph-smoke.json"
                cp "$acceptance_manifest" "$out/acceptance-graph-smoke.json"
                cat > "$out/commands.txt" <<'COMMANDS'
                nix build .#stage-a-roundtrip-lean-graph-smoke --no-link
                nix build .#stage-a-relational-acceptance-graph-smoke --no-link
                nix build .#stage-a-roundtrip-lean-remote-smoke --no-link --max-jobs 0 --builders "@${./nix/stage-a-builders}" --option builders-use-substitutes true
                nix build .#stage-a-roundtrip-lean-transfer .#stage-a-roundtrip-lean-x87 --no-link --max-jobs 0 --builders "@${./nix/stage-a-builders}" --option builders-use-substitutes true
                nix build .#stage-a-roundtrip-lean-kernel-cache --no-link --max-jobs 0 --builders "@${./nix/stage-a-builders}" --option builders-use-substitutes true
                COMMANDS
              '';
          mkStageARelationalTestWithKernel =
            precompiledKernel: name: module: testFiles:
            let
              usesLean =
                builtins.elem name [
                  "state"
                  "lean"
                  "pipeline"
                ]
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
                  ++ pkgs.lib.optionals usesLean [ ./src/spaghetti_extractor/lean/StageA ]
                  ++ pkgs.lib.optionals (pkgs.lib.hasPrefix "contract" name) [ ./nix/stage-a-lean-graph.nix ]
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
                ${pkgs.lib.optionalString (usesLean && precompiledKernel != null) ''
                  export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${precompiledKernel}"
                ''}
                export PYTHONPATH="${spaghetti-extractor}/${pkgs.python3.sitePackages}:${pythonEnv}/${pkgs.python3.sitePackages}:${testSource}:${testSource}/tests"
                mkdir -p "$HOME" "$XDG_CACHE_HOME" "$SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE"
                cd "$TMPDIR"
                python -m unittest -v ${module}
                mkdir -p "$out/${name}"
                printf '%s\n' '${module}' > "$out/${name}/test-module.txt"
              '';
          mkStageARelationalTest = mkStageARelationalTestWithKernel stage-a-relational-acceptance-kernel-cache;
          mkStageARelationalTestSuite =
            name: module: className: testFile:
            let
              testFiles = if builtins.isList testFile then testFile else [ testFile ];
              testSourceText = pkgs.lib.concatStringsSep "\n" (map builtins.readFile testFiles);
              testMethods = builtins.filter (method: method != null) (
                map (
                  line:
                  let
                    matched = builtins.match "^    def (test_[A-Za-z0-9_]+)\\(self.*$" line;
                  in
                  if matched == null then null else builtins.head matched
                ) (pkgs.lib.splitString "\n" testSourceText)
              );
              cases = builtins.listToAttrs (
                map (
                  method:
                  let
                    caseName = pkgs.lib.removePrefix "test_" method;
                  in
                  {
                    name = caseName;
                    value = mkStageARelationalTest "${name}-${caseName}" "${module}.${className}.${method}" testFiles;
                  }
                ) testMethods
              );
            in
            {
              inherit cases;
              aggregate = pkgs.symlinkJoin {
                name = "stage-a-relational-tests-${name}";
                paths = builtins.attrValues cases;
              };
            };
          stage-a-relational-tests-schema =
            mkStageARelationalTest "schema"
              "tests.test_relational_schema tests.test_contract_tools.ContractToolTests.test_cli_exposes_one_stage_a_authority_and_candidate_only_stage_b_tools"
              [
                ./tests/test_relational_schema.py
                ./tests/test_contract_tools.py
                ./tests/contract_fixtures.py
                ./tests/pe_fixtures.py
              ];
          stage-a-relational-tests-build-graph =
            mkStageARelationalTest "build-graph" "tests.test_stage_a_build_graph"
              [
                ./tests/test_stage_a_build_graph.py
                ./flake.lock
              ];
          stage-a-relational-tests-static-word-relations =
            mkStageARelationalTest "acceptance-static-word-relations" "tests.test_stage_a_static_word_relations"
              [ ./tests/test_stage_a_static_word_relations.py ];
          stage-a-relational-tests-external-protocol =
            mkStageARelationalTest "external-protocol" "tests.test_stage_a_external_protocol"
              [
                ./tests/test_stage_a_external_protocol.py
                ./profiles/pe32-kernel32-lockstep-v1.json
                ./profiles/pe32-msvcrt-lockstep-v1.json
              ];
          stage-a-relational-tests-external-contract-selection =
            mkStageARelationalTest "external-contract-selection"
              "tests.test_stage_a_external_contract_selection"
              [ ./tests/test_stage_a_external_contract_selection.py ];
          stage-a-relational-tests-external-stateful-memory =
            mkStageARelationalTest "external-stateful-memory" "tests.test_stage_a_external_stateful_memory"
              [
                ./tests/test_stage_a_external_stateful_memory.py
                ./profiles/pe32-msvcrt-lockstep-v1.json
              ];
          stage-a-relational-tests-external-stateful-memory-kernel =
            mkStageARelationalTest "lean-external-stateful-memory"
              "tests.test_stage_a_external_stateful_memory_kernel"
              [ ./tests/test_stage_a_external_stateful_memory_kernel.py ];
          stage-a-relational-tests-reachable-acceptance =
            mkStageARelationalTest "reachable-acceptance" "tests.test_stage_a_reachable_acceptance"
              [ ./tests/test_stage_a_reachable_acceptance.py ];
          stage-a-relational-tests-pe-entry-surface =
            mkStageARelationalTest "pe-entry-surface" "tests.test_stage_a_pe_entry_surface"
              [
                ./tests/test_stage_a_pe_entry_surface.py
                ./tests/pe_fixtures.py
              ];
          stage-a-relational-tests-formal-pe-entry-surface =
            mkStageARelationalTest "lean-formal-pe-entry-surface" "tests.test_stage_a_formal_pe_entry_surface"
              [ ./tests/test_stage_a_formal_pe_entry_surface.py ];
          stage-a-relational-tests-proof-blocked =
            mkStageARelationalTest "lean-proof-blocked" "tests.test_stage_a_proof_blocked"
              [ ./tests/test_stage_a_proof_blocked.py ];
          stage-a-relational-tests-loader-image-diagnostics =
            mkStageARelationalTest "loader-image-diagnostics" "tests.test_stage_a_loader_image_diagnostics"
              [
                ./tests/test_stage_a_loader_image_diagnostics.py
                ./tests/pe_fixtures.py
              ];
          stage-a-relational-tests-loader-image-valid =
            mkStageARelationalTest "lean-loader-image-valid" "tests.test_stage_a_loader_image_valid"
              [ ./tests/test_stage_a_loader_image_valid.py ];
          stage-a-relational-tests-raw-eip-execution =
            mkStageARelationalTest "lean-raw-eip-execution" "tests.test_stage_a_raw_eip_execution"
              [
                ./tests/test_stage_a_raw_eip_execution.py
                ./tests/pe_fixtures.py
              ];
          stage-a-relational-tests-indirect-control =
            mkStageARelationalTest "indirect-control"
              "tests.test_stage_a_indirect_control tests.test_stage_a_initial_static_code_pointers"
              [
                ./tests/test_stage_a_indirect_control.py
                ./tests/test_stage_a_initial_static_code_pointers.py
              ];
          stage-a-relational-tests-control-provenance =
            mkStageARelationalTest "control-provenance" "tests.test_stage_a_control_provenance"
              [ ./tests/test_stage_a_control_provenance.py ];
          stage-a-relational-tests-isa-conformance =
            mkStageARelationalTest "isa-conformance" "tests.test_stage_a_isa_conformance"
              [ ./tests/test_stage_a_isa_conformance.py ];
          stage-a-relational-tests-isa-conformance-kernel =
            mkStageARelationalTest "lean-isa-conformance-kernel" "tests.test_stage_a_isa_conformance_kernel"
              [ ./tests/test_stage_a_isa_conformance_kernel.py ];
          stage-a-relational-tests-isa-conformance-lean =
            mkStageARelationalTest "lean-isa-conformance-runner" "tests.test_stage_a_isa_conformance_lean"
              [
                ./tests/test_stage_a_isa_conformance.py
                ./tests/test_stage_a_isa_conformance_lean.py
              ];
          stage-a-relational-tests-isa-conformance-unicorn =
            mkStageARelationalTest "isa-conformance-unicorn" "tests.test_stage_a_isa_conformance_unicorn"
              [ ./tests/test_stage_a_isa_conformance_unicorn.py ];
          stage-a-relational-tests-isa-conformance-bochs =
            mkStageARelationalTest "isa-conformance-bochs" "tests.test_stage_a_isa_conformance_bochs"
              [
                ./tests/test_stage_a_isa_conformance_bochs.py
                ./tools/bochs-conformance/instrument.cc
              ];
          stage-a-relational-tests-isa-conformance-differential =
            mkStageARelationalTest "lean-isa-conformance-differential"
              "tests.test_stage_a_isa_conformance_differential"
              [
                ./tests/test_stage_a_isa_conformance_differential.py
                ./tests/test_stage_a_isa_conformance_unicorn.py
              ];
          stage-a-relational-tests-isa-conformance-80386 =
            mkStageARelationalTest "isa-conformance-80386-import" "tests.test_stage_a_isa_conformance_80386"
              [ ./tests/test_stage_a_isa_conformance_80386.py ];
          stage-a-relational-tests-isa-conformance-80386-differential =
            mkStageARelationalTest "lean-isa-conformance-80386-differential"
              "tests.test_stage_a_isa_conformance_80386_differential"
              [
                ./tests/test_stage_a_isa_conformance_80386.py
                ./tests/test_stage_a_isa_conformance_80386_differential.py
              ];
          stage-a-relational-tests-isa-qualification-tooling =
            mkStageARelationalTest "isa-qualification-tooling"
              "tests.test_stage_a_isa_catalog tests.test_stage_a_isa_corpus_generator tests.test_stage_a_isa_kernel_qualification tests.test_stage_a_isa_campaign tests.test_stage_a_isa_cli tests.test_stage_a_nix_pipeline"
              [
                ./tests/test_stage_a_isa_catalog.py
                ./tests/test_stage_a_isa_corpus_generator.py
                ./tests/test_stage_a_isa_kernel_qualification.py
                ./tests/test_stage_a_isa_campaign.py
                ./tests/test_stage_a_isa_cli.py
                ./tests/test_stage_a_nix_pipeline.py
              ];
          stage-a-relational-tests-bounded-table-call-generation =
            mkStageARelationalTest "bounded-table-call-generation"
              "tests.test_stage_a_bounded_table_call_generation"
              [ ./tests/test_stage_a_bounded_table_call_generation.py ];
          stage-a-relational-tests-bounded-table-call-kernel =
            mkStageARelationalTest "lean-bounded-table-call-kernel"
              "tests.test_stage_a_bounded_table_call_kernel"
              [ ./tests/test_stage_a_bounded_table_call_kernel.py ];
          stage-a-relational-tests-reverse-sentinel-scanner-integration =
            mkStageARelationalTest "lean-reverse-sentinel-scanner-integration"
              "tests.test_stage_a_reverse_sentinel_scanner_integration"
              [ ./tests/test_stage_a_reverse_sentinel_scanner_integration.py ];
          stage-a-relational-tests-callsite-preservation =
            mkStageARelationalTest "callsite-preservation" "tests.test_stage_a_callsite_preservation"
              [ ./tests/test_stage_a_callsite_preservation.py ];
          stage-a-relational-tests-callsite-summary-generation =
            mkStageARelationalTest "callsite-summary-generation"
              "tests.test_stage_a_callsite_summary_generation"
              [ ./tests/test_stage_a_callsite_summary_generation.py ];
          stage-a-relational-tests-call-return-summary =
            mkStageARelationalTest "call-return-summary" "tests.test_stage_a_call_return_summary"
              [ ./tests/test_stage_a_call_return_summary.py ];
          stage-a-relational-tests-callsite-preservation-schema =
            mkStageARelationalTest "callsite-preservation-schema"
              "tests.test_stage_a_callsite_preservation_schema"
              [ ./tests/test_stage_a_callsite_preservation_schema.py ];
          stage-a-relational-tests-register-analysis =
            mkStageARelationalTest "register-analysis" "tests.test_stage_a_register_analysis"
              [ ./tests/test_stage_a_register_analysis.py ];
          stage-a-relational-tests-linked-control-analysis =
            mkStageARelationalTest "linked-control-analysis" "tests.test_stage_a_linked_control_analysis"
              [ ./tests/test_stage_a_linked_control_analysis.py ];
          stage-a-relational-tests-lean-runtime-frame-import-environment =
            mkStageARelationalTest "lean-runtime-frame-import-environment"
              "tests.test_stage_a_runtime_frame_import_environment"
              [ ./tests/test_stage_a_runtime_frame_import_environment.py ];
          stage-a-relational-tests-acceptance-runtime-frame-import =
            mkStageARelationalTest "acceptance-runtime-frame-import"
              "tests.test_stage_a_runtime_frame_import_acceptance"
              [ ./tests/test_stage_a_runtime_frame_import_acceptance.py ];
          stage-a-relational-tests-acceptance-runtime-frame-register =
            mkStageARelationalTest "acceptance-runtime-frame-register"
              "tests.test_stage_a_runtime_frame_register_acceptance"
              [ ./tests/test_stage_a_runtime_frame_register_acceptance.py ];
          stage-a-relational-tests-opaque-lockstep =
            mkStageARelationalTest "acceptance-opaque-lockstep"
              "tests.test_stage_a_opaque_lockstep_acceptance tests.test_stage_a_opaque_lockstep_environment_generation tests.test_stage_a_opaque_lockstep_environment_kernel"
              [
                ./tests/test_stage_a_opaque_lockstep_acceptance.py
                ./tests/test_stage_a_opaque_lockstep_environment_generation.py
                ./tests/test_stage_a_opaque_lockstep_environment_kernel.py
              ];
          stageARelationalContractSuite =
            mkStageARelationalTestSuite "contract" "tests.test_stage_a_relational_contract"
              "StageARelationalContractTests"
              ./tests/test_stage_a_relational_contract.py;
          stageARelationalStateSuite =
            mkStageARelationalTestSuite "state" "tests.test_stage_a_relational_state"
              "StageARelationalStateTests"
              ./tests/test_stage_a_relational_state.py;
          stageARelationalPipelineSuite =
            mkStageARelationalTestSuite "pipeline" "tests.test_stage_a_relational_pipeline"
              "StageARelationalPipelineTests"
              ./tests/test_stage_a_relational_pipeline.py;
          stageARelationalLeanSuite =
            mkStageARelationalTestSuite "lean" "tests.test_stage_a_relational_lean" "StageARelationalLeanTests"
              ./tests/test_stage_a_relational_lean.py;
          stageARelationalAcceptanceSuite =
            mkStageARelationalTestSuite "acceptance" "tests.test_stage_a_relational_acceptance"
              "StageARelationalAcceptanceTests"
              [
                ./tests/test_stage_a_relational_acceptance.py
                ./tests/test_stage_a_acceptance_launch.py
                ./tests/test_stage_a_acceptance_control_flow.py
                ./tests/test_stage_a_acceptance_calls_frames.py
                ./tests/test_stage_a_acceptance_external_environment.py
                ./tests/test_stage_a_acceptance_final_nix.py
              ];
          stageARelationalStaticWordSlotCertificateSuite =
            mkStageARelationalTestSuite "lean-static-word-slot-certificate"
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
          stage-a-relational-tests-lean-linked-execution =
            stageARelationalLeanSuite.cases.linked_execution_step_accepts_an_arbitrary_dormant_tail;
          stage-a-relational-tests-lean-active-frame-guard =
            stageARelationalLeanSuite.cases.active_frame_exact_register_guard_is_checked_by_lean;
          stage-a-relational-tests-contract-machine-import =
            stageARelationalContractSuite.cases.machine_import_call_contract_validation_fails_closed;
          stage-a-relational-tests-acceptance = stageARelationalAcceptanceSuite.aggregate;
          stage-a-relational-tests-static-word-slot-certificate =
            stageARelationalStaticWordSlotCertificateSuite.aggregate;
          stage-a-relational-tests-acceptance-whole-program-kernel =
            stageARelationalAcceptanceSuite.cases.whole_program_equivalence_kernel_checks_without_sorry;
          stage-a-relational-tests-acceptance-nested-linked-calls =
            stageARelationalAcceptanceSuite.cases.nested_direct_calls_require_native_linked_frame_acceptance;
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
          stage-a-relational-tests-acceptance-direct-call-return =
            stageARelationalAcceptanceSuite.cases.direct_call_return_loop_checks_runtime_frames_end_to_end;
          stage-a-relational-tests-acceptance-linked-active-jump =
            stageARelationalAcceptanceSuite.cases.internal_callee_jump_uses_linked_active_frame_transfer;
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
          stage-a-relational-tests-acceptance-direct-import-thunk =
            stageARelationalAcceptanceSuite.cases.direct_import_thunk_checks_runtime_frame_and_environment_end_to_end;
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
              stage-a-relational-tests-isa-qualification-tooling
              stage-a-relational-tests-bounded-table-call-generation
              stage-a-relational-tests-bounded-table-call-kernel
              stage-a-relational-tests-callsite-preservation
              stage-a-relational-tests-callsite-summary-generation
              stage-a-relational-tests-call-return-summary
              stage-a-relational-tests-callsite-preservation-schema
              stage-a-relational-tests-register-analysis
              stage-a-relational-tests-linked-control-analysis
              stage-a-relational-tests-lean-runtime-frame-import-environment
              stage-a-relational-tests-acceptance-runtime-frame-import
              stage-a-relational-tests-acceptance-runtime-frame-register
              stage-a-relational-tests-opaque-lockstep
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
          roundtripCaseArtifact =
            args: role:
            let
              matches = builtins.filter (artifact: artifact.role == role) args.case.artifacts;
            in
            assert builtins.length matches == 1;
            builtins.head matches;
          mkRoundtripCaseCheckedInputs =
            args:
            let
              original = roundtripCaseArtifact args "original_pe";
              candidate = roundtripCaseArtifact args "candidate_pe";
              relation = roundtripCaseArtifact args "relation_contract";
            in
            pkgs.runCommand (pkgs.lib.strings.sanitizeDerivationName "${args.caseId}-roundtrip-inputs")
              {
                nativeBuildInputs = [
                  pkgs.coreutils
                  pkgs.jq
                ];
                preferLocalBuild = true;
                allowSubstitutes = true;
                passthru = {
                  caseId = args.caseId;
                  phase = "checked-inputs";
                };
              }
              ''
                jq -e '
                  .format == "stage-a-relational-static-preflight-v1" and
                  .status == "ready" and
                  .acceptance_authority == false
                ' ${pkgs.lib.escapeShellArg args.staticPreflight} >/dev/null
                printf '%s  %s\n' \
                  ${pkgs.lib.escapeShellArg original.sha256} \
                  ${pkgs.lib.escapeShellArg "${args.caseRoot}/${original.path}"} \
                  > "$TMPDIR/input-hashes"
                printf '%s  %s\n' \
                  ${pkgs.lib.escapeShellArg candidate.sha256} \
                  ${pkgs.lib.escapeShellArg "${args.caseRoot}/${candidate.path}"} \
                  >> "$TMPDIR/input-hashes"
                printf '%s  %s\n' \
                  ${pkgs.lib.escapeShellArg relation.sha256} \
                  ${pkgs.lib.escapeShellArg "${args.caseRoot}/${relation.path}"} \
                  >> "$TMPDIR/input-hashes"
                sha256sum --check --strict "$TMPDIR/input-hashes"
                mkdir -p "$out"
                cp ${pkgs.lib.escapeShellArg "${args.caseRoot}/${original.path}"} \
                  "$out/original.pe"
                cp ${pkgs.lib.escapeShellArg "${args.caseRoot}/${candidate.path}"} \
                  "$out/candidate.pe"
                cp ${pkgs.lib.escapeShellArg "${args.caseRoot}/${relation.path}"} \
                  "$out/relation-contract.json"
              '';
          mkRoundtripCasePreparation =
            args:
            let
              checkedInputs = mkRoundtripCaseCheckedInputs args;
              analysisGraph = import ./nix/stage-a-relational-analysis-graph.nix {
                inherit pkgs;
                name = pkgs.lib.strings.sanitizeDerivationName "${args.caseId}-roundtrip";
                original.binary = "${checkedInputs}/original.pe";
                candidate.binary = "${checkedInputs}/candidate.pe";
                relationContract = "${checkedInputs}/relation-contract.json";
                analysisKernelCache = stage-a-relational-analysis-ifd-kernel-cache;
                tools = stageARelationalAnalysisTools;
                # Corpus generation is already an IFD boundary. These tiny
                # fuzz cases use one coarse dataflow worker so evaluation does
                # not need a second, nested manifest read. Large binary graphs
                # retain fine-grained CA dataflow packs. The coarse preparation
                # remains input-addressed until its generated Lean graph has a
                # concrete path; the proof DAG itself is still CA.
                dataflowFineGrained = false;
                dataflowContentAddressed = false;
              };
              prepared = "${analysisGraph.preparedProof}/report/relational-v3";
              violatedCase = args.case.expectation.disposition == "violated";
            in
            pkgs.runCommand (pkgs.lib.strings.sanitizeDerivationName "${args.caseId}-roundtrip-preparation")
              {
                nativeBuildInputs = [
                  pkgs.coreutils
                  pkgs.jq
                ]
                ++ pkgs.lib.optional violatedCase spaghetti-extractor-roundtrip;
                preferLocalBuild = false;
                allowSubstitutes = true;
                passthru = {
                  caseId = args.caseId;
                  phase = "proof-preparation";
                };
              }
              ''
                ${
                  if violatedCase then
                    ''
                      ${spaghetti-extractor-roundtrip}/bin/spaghetti-extractor \
                        stage-a-prepare-violation \
                        --case ${pkgs.lib.escapeShellArg args.caseManifest} \
                        --case-root ${pkgs.lib.escapeShellArg args.caseRoot} \
                        --prepared ${pkgs.lib.escapeShellArg prepared} \
                        --out "$out" \
                        > "$TMPDIR/violation-preparation-command.json"
                      cp "$TMPDIR/violation-preparation-command.json" \
                        "$out/violation-preparation-command.json"
                    ''
                  else
                    ''
                      cp -R ${pkgs.lib.escapeShellArg prepared} "$out"
                    ''
                }
                jq -e '
                  .format == "stage-a-prepared-relational-v1" and
                  .status == "prepared"
                  or
                  .format == "stage-a-prepared-relational-v2" and
                  .status == "prepared"
                ' "$out/prepared-proof.json" >/dev/null
                test -f "$out/module-graph.json"
              '';
          mkRoundtripCaseProofDag =
            args:
            let
              graph = builtins.fromJSON (builtins.readFile args.preparationGraph);
              nodeIds = map (node: node.id) graph.nodes;
              counterexampleNode = "relationalcounterexample";
              fallbackNegativeNode = "relationallaunchrealizabilitycertificate";
              negativeNode =
                if builtins.elem counterexampleNode nodeIds then counterexampleNode else fallbackNegativeNode;
            in
            if args.case.expectation.disposition == "pass" then
              import ./nix/stage-a-lean-graph.nix {
                inherit pkgs;
                schedulingMode = "dag";
                prepared = args.preparation;
                precompiledKernel = stage-a-relational-acceptance-kernel-cache;
                contentAddressed = args.contentAddressed;
              }
            else
              assert builtins.elem negativeNode nodeIds;
              import ./nix/stage-a-lean-graph.nix {
                inherit pkgs;
                schedulingMode = "dag";
                prepared = args.preparation;
                precompiledKernel = stage-a-relational-acceptance-kernel-cache;
                targetNodes = [ negativeNode ];
                targetBundle = true;
                contentAddressed = args.contentAddressed;
              };
          mkRoundtripCaseAudit =
            args:
            let
              passCase = args.case.expectation.disposition == "pass";
              proofEvidence = if passCase then args.proofDag.verdict else args.proofDag;
              preparedEvidence = if passCase then proofEvidence else args.preparation;
            in
            pkgs.runCommand (pkgs.lib.strings.sanitizeDerivationName "${args.caseId}-roundtrip-audit")
              (
                {
                  nativeBuildInputs = [
                    pkgs.python3
                    pkgs.coreutils
                  ];
                }
                // pkgs.lib.optionalAttrs args.contentAddressed {
                  __contentAddressed = true;
                }
                // {
                  preferLocalBuild = true;
                  allowSubstitutes = true;
                  passthru = {
                    caseId = args.caseId;
                    phase = "acceptance-audit";
                  };
                }
              )
              ''
                mkdir -p "$out"
                python3 - \
                  ${pkgs.lib.escapeShellArg args.caseManifest} \
                  ${pkgs.lib.escapeShellArg (toString preparedEvidence)} \
                  ${pkgs.lib.escapeShellArg (toString proofEvidence)} \
                  "$out/result.json" <<'PY'
                import hashlib
                import json
                import pathlib
                import sys

                case_path = pathlib.Path(sys.argv[1])
                prepared = pathlib.Path(sys.argv[2])
                proof = pathlib.Path(sys.argv[3])
                result_path = pathlib.Path(sys.argv[4])
                case = json.loads(case_path.read_text(encoding="utf-8"))
                manifest = json.loads(
                    (prepared / "prepared-proof.json").read_text(encoding="utf-8")
                )
                expectation = case["expectation"]["disposition"]
                supported_theorems = {
                    "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked",
                }

                def digest(path):
                    return hashlib.sha256(path.read_bytes()).hexdigest()

                acceptance = None
                violation = None
                actual = "incomplete"
                proof_status = "incomplete"
                reason_code = "final_theorem_not_checked"
                if expectation == "pass" and (proof / "audit.json").is_file():
                    audit = json.loads((proof / "audit.json").read_text(encoding="utf-8"))
                    verdict = json.loads(
                        (proof / "verdict.json").read_text(encoding="utf-8")
                    )
                    theorem = manifest.get("expected_final_theorem")
                    graph_matches = (
                        (proof / "module-graph.json").is_file()
                        and digest(proof / "module-graph.json")
                            == manifest.get("module_graph_sha256")
                    )
                    manifest_matches = (
                        (proof / "prepared-proof.json").is_file()
                        and digest(proof / "prepared-proof.json")
                            == digest(prepared / "prepared-proof.json")
                    )
                    approved = set(manifest.get("approved_axioms", []))
                    observed = audit.get("observed_axioms")
                    checked = (
                        manifest.get("acceptance", {}).get("status") == "ready"
                        and theorem in supported_theorems
                        and audit.get("format") == "stage-a-relational-lean-audit-v1"
                        and audit.get("status") == "checked"
                        and audit.get("lean_trust") == 0
                        and audit.get("proposition_type_checked") is True
                        and audit.get("theorem") == theorem
                        and isinstance(observed, list)
                        and set(observed).issubset(approved)
                        and audit.get("unexpected_axioms") == []
                        and verdict.get("format")
                            == "stage-a-relational-proof-verdict-v1"
                        and verdict.get("status") == "checked"
                        and verdict.get("theorem") == theorem
                        and verdict.get("lean_trust") == 0
                        and isinstance(verdict.get("root_semantic_id"), str)
                        and len(verdict["root_semantic_id"]) == 64
                        and graph_matches
                        and manifest_matches
                        and (proof / "node-provenance.json").is_file()
                    )
                    if checked:
                        actual = "pass"
                        proof_status = "pass"
                        reason_code = None
                        acceptance = {
                            "theorem": theorem,
                            "authority": "whole_program_lean",
                            "root_semantic_id": verdict["root_semantic_id"],
                        }
                elif expectation == "violated":
                    import subprocess
                    violation_out = result_path.parent / "violation-audit-work"
                    command = [
                        "${spaghetti-extractor-roundtrip}/bin/spaghetti-extractor",
                        "stage-a-audit-violation",
                        "--case", str(case_path),
                        "--case-root", ${builtins.toJSON args.caseRoot},
                        "--prepared", str(prepared),
                        "--proof-node", str(proof),
                        "--out", str(violation_out),
                    ]
                    completed = subprocess.run(
                        command, text=True, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, check=False,
                    )
                    if completed.returncode != 0:
                        raise SystemExit(
                            "checked violation audit failed:\n" + completed.stderr
                        )
                    violation_path = violation_out / "violation-audit.json"
                    if violation_path.is_file():
                        candidate = json.loads(
                            violation_path.read_text(encoding="utf-8")
                        )
                        checks = candidate.get("checks")
                        checked = (
                            candidate.get("format")
                                == "stage-a-checked-violation-result-v1"
                            and candidate.get("status") == "violated"
                            and isinstance(checks, dict)
                            and bool(checks)
                            and all(value is True for value in checks.values())
                            and candidate.get("trust", {}).get("role")
                                == "checked_inequivalence_witness"
                            and candidate.get("trust", {}).get("can_authorize_pass")
                                is False
                        )
                        if checked:
                            actual = "violated"
                            proof_status = "violated"
                            reason_code = None
                            violation = candidate
                    if actual != "violated" and (proof / "bundle.json").is_file():
                        reason_code = "checked_counterexample_audit_pending"

                phases = [
                    {"id": "static-preflight", "status": "ready"},
                    {
                        "id": "proof-preparation",
                        "status": (
                            "ready"
                            if manifest.get("status") == "prepared"
                            else "incomplete"
                        ),
                    },
                ]
                if actual == "violated":
                    phases.append({
                        "id": "checked-violation-replay",
                        "status": "violated",
                    })
                else:
                    phases.append({
                        "id": "proof-build-and-audit",
                        "status": proof_status,
                        "reason_code": reason_code,
                    })
                payload = {
                    "format": "stage-a-roundtrip-case-result-v1",
                    "case_id": case["id"],
                    "mode": "proof-core",
                    "expected_disposition": expectation,
                    "actual_disposition": actual,
                    "expectation_matched": actual == expectation,
                    "phases": phases,
                    "acceptance": acceptance,
                    "frontiers": (
                        manifest.get("acceptance", {}).get("blockers", [])
                        if actual == "incomplete" else []
                    ),
                    "violation": violation,
                    "error": None,
                    "proof_artifact": {
                        "prepared_manifest_sha256": digest(
                            prepared / "prepared-proof.json"
                        ),
                        "module_graph_sha256": digest(
                            prepared / "module-graph.json"
                        ),
                        "audit_sha256": (
                            digest(proof / "audit.json")
                            if (proof / "audit.json").is_file()
                            else None
                        ),
                        "root_semantic_id": (
                            acceptance.get("root_semantic_id")
                            if isinstance(acceptance, dict)
                            else None
                        ),
                        "proof_phases_are_content_addressed": ${if args.contentAddressed then "True" else "False"},
                        "recursive_nix_invocations": 0,
                    },
                }
                result_path.write_text(
                    json.dumps(payload, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                PY
              '';
          mkStageARoundtripQualification =
            {
              name,
              count,
              checkDeterminism ? true,
              expectedCounts ? null,
              # Qualification cases schedule as independent CA derivations on
              # the heterogeneous remote builder pool.
              contentAddressed ? true,
            }:
            import ./nix/stage-a-roundtrip-corpus.nix {
              inherit pkgs name contentAddressed;
              spaghettiExtractor = spaghetti-extractor-roundtrip;
              # Conservative class estimates calibrated from the first compact
              # 36-case proof run. They affect scheduling only, never proof
              # inputs or acceptance authority.
              caseMeasurementDefaults = {
                pass = {
                  estimatedSeconds = 300;
                  estimatedMemoryMB = 4096;
                  resourceClass = "whole-program-proof";
                  measurementSource = "compact-spike-calibration-2026-07-22";
                };
                violated = {
                  estimatedSeconds = 120;
                  estimatedMemoryMB = 2048;
                  resourceClass = "checked-witness";
                  measurementSource = "compact-spike-calibration-2026-07-22";
                };
                incomplete = {
                  estimatedSeconds = 15;
                  estimatedMemoryMB = 1024;
                  resourceClass = "static-frontier";
                  measurementSource = "compact-spike-calibration-2026-07-22";
                };
              };
              mkCasePreparation = mkRoundtripCasePreparation;
              mkCaseProofDag = mkRoundtripCaseProofDag;
              mkCaseAudit = mkRoundtripCaseAudit;
              generation = {
                inherit count checkDeterminism expectedCounts;
                seed = 1000;
                profile = "structured-spike-v1";
                toolchain = "gnu";
                nativeBuildInputs = [ mingw32.stdenv.cc ];
              };
            };
          stageARoundtripProofSmokeQualification = mkStageARoundtripQualification {
            name = "stage-a-roundtrip-proof-smoke";
            count = 1;
            checkDeterminism = false;
            expectedCounts = {
              pass = 1;
              violated = 0;
              incomplete = 0;
            };
          };
          stageARoundtripViolationSmokeQualification = mkStageARoundtripQualification {
            name = "stage-a-roundtrip-violation-smoke";
            count = 3;
            checkDeterminism = false;
            expectedCounts = {
              pass = 2;
              violated = 1;
              incomplete = 0;
            };
          };
          stageARoundtripSmokeQualification = mkStageARoundtripQualification {
            name = "stage-a-roundtrip-smoke";
            count = 4;
            checkDeterminism = false;
          };
          stageARoundtripSpikeQualification = mkStageARoundtripQualification {
            name = "stage-a-roundtrip-spike";
            count = 36;
            expectedCounts = {
              pass = 24;
              violated = 12;
              incomplete = 0;
            };
            contentAddressed = true;
          };
          stageARoundtripPromotedQualification = mkStageARoundtripQualification {
            name = "stage-a-roundtrip-promoted";
            count = 75;
            expectedCounts = {
              pass = 50;
              violated = 25;
              incomplete = 0;
            };
            contentAddressed = true;
          };
          stage-a-roundtrip-smoke-corpus = stageARoundtripSmokeQualification.corpus;
          stage-a-roundtrip-static-smoke = stageARoundtripSmokeQualification.smoke;
          stage-a-roundtrip-proof-smoke = stageARoundtripProofSmokeQualification.check;
          stage-a-roundtrip-violation-smoke = stageARoundtripViolationSmokeQualification.check;
          stage-a-roundtrip-spike-corpus = stageARoundtripSpikeQualification.corpus;
          stage-a-roundtrip-spike-pack-plan = stageARoundtripSpikeQualification.packPlan;
          stage-a-roundtrip-spike-check = stageARoundtripSpikeQualification.check;
          stage-a-roundtrip-promoted-corpus = stageARoundtripPromotedQualification.corpus;
          stage-a-roundtrip-promoted-pack-plan = stageARoundtripPromotedQualification.packPlan;
          stage-a-roundtrip-promoted-check = stageARoundtripPromotedQualification.check;
          stage-a-roundtrip-spike-corpus-root = pkgs.writeShellApplication {
            name = "stage-a-roundtrip-spike-corpus-root";
            text = ''
              printf '%s\n' "${stage-a-roundtrip-spike-corpus}"
            '';
          };
          stageBJqComponentAnalysis =
            let
              fixtureDir = "${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment";
              profileDir = "${spaghetti-extractor-profiles}/share/spaghetti-extractor/profiles";
            in
            import ./nix/stage-b-component-analysis.nix {
              inherit pkgs pythonEnv;
              sideTool = spaghetti-extractor-side;
              staticPythonSource = stageBStaticAnalysisPythonSource;
              planningPythonSource = stageBPlanningPythonSource;
              componentDiscoveryPythonSource = stageBComponentDiscoveryPythonSource;
              original = "${fixtureDir}/jq-original.exe";
              externalProfile = "${profileDir}/pe32-msvcrt-machine-runtime-v1.json";
              indirectTargetProfile = "${profileDir}/pe32-static-cutpoints-and-paired-callables-v1.json";
              namePrefix = "stage-b-jq";
            };
          stageBMinimalHelloComponentAnalysis =
            let
              fixtureDir = "${stage-a-minimal-hello-original}/share/spaghetti-extractor/stage-a-minimal-hello-fixtures/original";
              profileDir = "${spaghetti-extractor-profiles}/share/spaghetti-extractor/profiles";
            in
            import ./nix/stage-b-component-analysis.nix {
              inherit pkgs pythonEnv;
              sideTool = spaghetti-extractor-side;
              staticPythonSource = stageBStaticAnalysisPythonSource;
              planningPythonSource = stageBPlanningPythonSource;
              componentDiscoveryPythonSource = stageBComponentDiscoveryPythonSource;
              original = "${fixtureDir}/hello.exe";
              externalProfile = "${profileDir}/pe32-msvcrt-machine-runtime-v1.json";
              indirectTargetProfile = "${profileDir}/pe32-static-cutpoints-and-paired-callables-v1.json";
              namePrefix = "stage-b-minimal-hello";
              maxUnits = 64;
            };
          stageBMingwRuntimeArtifactCorpus =
            pkgs.runCommand "stage-b-mingw-runtime-artifact-corpus-v1"
              {
                nativeBuildInputs = [ ];
                preferLocalBuild = false;
                allowSubstitutes = true;
                __contentAddressed = true;
              }
              ''
                set -euo pipefail
                mkdir -p "$out/artifacts"
                cp ${mingw32.windows.mingw_w64}/lib/libmingw32.a \
                  "$out/artifacts/libmingw32.a"
                cp ${mingw32.windows.mingw_w64}/lib/libmingwex.a \
                  "$out/artifacts/libmingwex.a"
                cp ${mingw32.windows.pthreads}/lib/libpthread.a \
                  "$out/artifacts/libpthread.a"
              '';
          stageBMingwRuntimeArtifactInputs =
            pkgs.runCommand "stage-b-mingw-runtime-artifact-inputs-v1"
              {
                nativeBuildInputs = [ pythonEnv ];
                preferLocalBuild = false;
                allowSubstitutes = true;
                __contentAddressed = true;
              }
              ''
                set -euo pipefail
                export PYTHONHASHSEED=0
                export LC_ALL=C.UTF-8
                export SOURCE_DATE_EPOCH=1
                export PYTHONPATH=${stageBLinkedLibraryPythonSource}/src
                ${pythonEnv}/bin/python3 - "$out" <<'PY'
                import pathlib
                import sys
                from spaghetti_extractor.linked_libraries import (
                    bind_library_artifact_inputs,
                )
                from spaghetti_extractor.util import write_json

                payload = bind_library_artifact_inputs({
                    "format": "stage-b-library-artifact-inputs-v2",
                    "catalog_id": "nixpkgs-mingw32-runtime-v1",
                    "snapshot": {
                        "id": "nixpkgs-mingw32-runtime-v1",
                        "target": {
                            "architecture": "i686",
                            "object_format": "coff",
                            "abi": "mingw32",
                        },
                    },
                    "artifacts": [
                        {
                            "id": name.removesuffix(".a"),
                            "path": f"artifacts/{name}",
                            "visibility": "public",
                            "redistributable": True,
                            "island_kind": "compiler_linker_support",
                            "retention_model": "unknown",
                            "library_identity": {
                                "family_id": (
                                    "winpthreads" if name == "libpthread.a"
                                    else "mingw-w64-crt"
                                ),
                                "component_id": name.removeprefix("lib").removesuffix(".a"),
                                "release_id": "nixpkgs-pinned",
                                "build_id": "nixpkgs-mingw32-runtime-v1",
                                "abi_id": "mingw32",
                            },
                            "provenance": {
                                "kind": "pinned_nix_store_artifact",
                                "names_are_authoritative": False,
                            },
                        }
                        for name in (
                            "libmingw32.a",
                            "libmingwex.a",
                            "libpthread.a",
                        )
                    ],
                })
                write_json(pathlib.Path(sys.argv[1]), payload)
                PY
              '';
          stageBGnuHelloArtifactCorpus =
            pkgs.runCommand "stage-b-gnu-hello-library-artifact-corpus-v1"
              {
                nativeBuildInputs = [ ];
                preferLocalBuild = false;
                allowSubstitutes = true;
                __contentAddressed = true;
              }
              ''
                set -euo pipefail
                mkdir -p "$out/artifacts"
                cp ${stageBMingwRuntimeArtifactCorpus}/artifacts/*.a "$out/artifacts/"
                cp \
                  ${stage-a-gnu-hello-original}/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/original/libhello.a \
                  "$out/artifacts/libhello.a"
              '';
          stageBGnuHelloArtifactInputs =
            pkgs.runCommand "stage-b-gnu-hello-library-artifact-inputs-v1"
              {
                nativeBuildInputs = [ pythonEnv ];
                preferLocalBuild = false;
                allowSubstitutes = true;
                __contentAddressed = true;
              }
              ''
                set -euo pipefail
                export PYTHONHASHSEED=0
                export LC_ALL=C.UTF-8
                export SOURCE_DATE_EPOCH=1
                export PYTHONPATH=${stageBLinkedLibraryPythonSource}/src
                ${pythonEnv}/bin/python3 - "$out" <<'PY'
                import pathlib
                import sys
                from spaghetti_extractor.linked_libraries import bind_library_artifact_inputs
                from spaghetti_extractor.util import write_json

                artifacts = []
                for name in ("libmingw32.a", "libmingwex.a", "libpthread.a"):
                    artifacts.append({
                        "id": name.removesuffix(".a"),
                        "path": f"artifacts/{name}",
                        "visibility": "public",
                        "redistributable": True,
                        "island_kind": "compiler_linker_support",
                        "retention_model": "unknown",
                        "library_identity": {
                            "family_id": "winpthreads" if name == "libpthread.a" else "mingw-w64-crt",
                            "component_id": name.removeprefix("lib").removesuffix(".a"),
                            "release_id": "nixpkgs-pinned",
                            "build_id": "nixpkgs-mingw32-runtime-v1",
                            "abi_id": "mingw32",
                        },
                        "provenance": {
                            "kind": "pinned_nix_store_artifact",
                            "names_are_authoritative": False,
                        },
                    })
                artifacts.append({
                    "id": "gnu-hello-libhello",
                    "path": "artifacts/libhello.a",
                    "visibility": "public",
                    "redistributable": True,
                    "island_kind": "linked_dependency",
                    "retention_model": "archive_member",
                    "library_identity": {
                        "family_id": "gnu-hello-gnulib",
                        "component_id": "libhello",
                        "release_id": "2.12.3",
                        "build_id": "nixpkgs-stage-a-gnu-hello-original",
                        "abi_id": "mingw32",
                    },
                    "provenance": {
                        "kind": "exact_link_input_from_pinned_nix_build",
                        "names_are_authoritative": False,
                    },
                })
                payload = bind_library_artifact_inputs({
                    "format": "stage-b-library-artifact-inputs-v2",
                    "catalog_id": "gnu-hello-2.12.3-mingw32-link-inputs-v1",
                    "snapshot": {
                        "id": "gnu-hello-2.12.3-mingw32-link-inputs-v1",
                        "target": {
                            "architecture": "i686",
                            "object_format": "coff",
                            "abi": "mingw32",
                        },
                    },
                    "artifacts": artifacts,
                })
                write_json(pathlib.Path(sys.argv[1]), payload)
                PY
              '';
          stageBOpenWatcom19ArtifactCorpus =
            pkgs.runCommand "stage-b-openwatcom19-artifact-corpus-v1"
              {
                nativeBuildInputs = [ vintagePkgs.open-watcom-bin ];
                preferLocalBuild = false;
                allowSubstitutes = true;
                __contentAddressed = true;
              }
              ''
                set -euo pipefail
                mkdir -p "$out/artifacts"
                cat > vintage.c <<'C'
                unsigned long vintage_rotate(unsigned long value) {
                  return (value << 5) | (value >> 27);
                }
                C
                wcc386 -q -bt=nt \
                  -fo="$out/artifacts/openwatcom19-vintage.obj" vintage.c
              '';
          stageBOpenWatcom19ArtifactInputs =
            pkgs.runCommand "stage-b-openwatcom19-artifact-inputs-v1"
              {
                nativeBuildInputs = [ pythonEnv ];
                preferLocalBuild = false;
                allowSubstitutes = true;
                __contentAddressed = true;
              }
              ''
                set -euo pipefail
                export PYTHONHASHSEED=0
                export LC_ALL=C.UTF-8
                export SOURCE_DATE_EPOCH=1
                export PYTHONPATH=${stageBLinkedLibraryPythonSource}/src
                ${pythonEnv}/bin/python3 - "$out" <<'PY'
                import pathlib
                import sys
                from spaghetti_extractor.linked_libraries import (
                    bind_library_artifact_inputs,
                )
                from spaghetti_extractor.util import write_json

                payload = bind_library_artifact_inputs({
                    "format": "stage-b-library-artifact-inputs-v2",
                    "catalog_id": "openwatcom19-vintage-v1",
                    "snapshot": {
                        "id": "openwatcom19-vintage-v1",
                        "target": {
                            "architecture": "i686",
                            "object_format": "omf",
                            "abi": "watcom-nt",
                        },
                    },
                    "artifacts": [{
                        "id": "openwatcom19-vintage-object",
                        "path": "artifacts/openwatcom19-vintage.obj",
                        "visibility": "public",
                        "redistributable": True,
                        "island_kind": "compiler_linker_support",
                        "retention_model": "unknown",
                        "library_identity": {
                            "family_id": "open-watcom-runtime",
                            "component_id": "vintage-object",
                            "release_id": "1.9",
                            "build_id": "openwatcom19-vintage-v1",
                            "abi_id": "watcom-nt",
                        },
                        "provenance": {
                            "kind": "pinned_nix_toolchain_fixture",
                            "toolchain": "Open Watcom 1.9",
                            "names_are_authoritative": False,
                        },
                    }],
                })
                write_json(pathlib.Path(sys.argv[1]), payload)
                PY
              '';
          stageBOpenWatcom19ArtifactAnalysis =
            import ./nix/stage-b-linked-libraries.nix {
              inherit pkgs pythonEnv;
              pythonSource = stageBLinkedLibraryPythonSource;
              original = null;
              machineIr = null;
              artifactInputs = stageBOpenWatcom19ArtifactInputs;
              artifactRoot = stageBOpenWatcom19ArtifactCorpus;
              namePrefix = "stage-b-openwatcom19";
            };
          stageBJqLinkedLibraryAnalysis =
            let
              fixtureDir = "${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment";
            in
            import ./nix/stage-b-linked-libraries.nix {
              inherit pkgs pythonEnv;
              pythonSource = stageBLinkedLibraryPythonSource;
              original = "${fixtureDir}/jq-original.exe";
              machineIr = stageBJqComponentAnalysis.machineIr;
              review = ./fixtures/jq/linked-island-review.json;
              artifactInputs = stageBMingwRuntimeArtifactInputs;
              artifactRoot = stageBMingwRuntimeArtifactCorpus;
              namePrefix = "stage-b-jq";
            };
          stageBGnuHelloLinkedLibraryAnalysis =
            import ./nix/stage-b-linked-libraries.nix {
              inherit pkgs pythonEnv;
              pythonSource = stageBLinkedLibraryPythonSource;
              original = "${stage-a-gnu-hello-original}/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/original/hello.exe";
              machineIr = gnuHelloRoundtrip.machineIr;
              review = ./fixtures/gnu-hello/linked-island-review.json;
              artifactInputs = stageBGnuHelloArtifactInputs;
              artifactRoot = stageBGnuHelloArtifactCorpus;
              machineImportReport =
                "${gnuHelloRoundtrip.staticMachineImportContractsLean}/machine-import-contract-report.json";
              namePrefix = "stage-b-gnu-hello";
            };
          stageBGnuHelloSourceAst =
            pkgs.runCommand "stage-b-gnu-hello-source-clang-ast-v1"
              {
                nativeBuildInputs = [ mingw32.stdenv.cc pkgs.clang ];
                preferLocalBuild = false;
                allowSubstitutes = true;
                __contentAddressed = true;
              }
              ''
                set -euo pipefail
                export LC_ALL=C.UTF-8
                mkdir -p "$out"
                gcc_include="$(${mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc \
                  -print-file-name=include)"
                gcc_include_fixed="$(${mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc \
                  -print-file-name=include-fixed)"
                mingw_headers="$(realpath "$gcc_include/../../../../../i686-w64-mingw32/sys-include")"
                ${pkgs.clang}/bin/clang \
                  --target=i686-w64-windows-gnu \
                  -std=c11 -fsyntax-only \
                  -nostdinc \
                  -I ${./fixtures/gnu-hello/idiomatic} \
                  -isystem "$gcc_include" \
                  -isystem "$gcc_include_fixed" \
                  -isystem "$mingw_headers" \
                  -Wno-everything \
                  -Xclang -ast-dump=json \
                  ${./fixtures/gnu-hello/idiomatic}/hello.c \
                  > "$out/clang-ast.json"
                test -s "$out/clang-ast.json"
              '';
          stageBGnuHelloToolchainRuntimeImports =
            pkgs.runCommand "stage-b-gnu-hello-toolchain-runtime-imports-v1"
              {
                nativeBuildInputs = [ mingw32.stdenv.cc pythonEnv ];
                preferLocalBuild = false;
                allowSubstitutes = true;
                __contentAddressed = true;
              }
              ''
                set -euo pipefail
                export PYTHONHASHSEED=0
                export LC_ALL=C.UTF-8
                export SOURCE_DATE_EPOCH=1
                export PYTHONPATH=${stageBSourceCallSubstitutionPythonSource}/src
                mkdir -p "$out"
                cat > baseline.c <<'C'
                int main(void) { return 0; }
                C
                ${mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc \
                  -std=c11 -O2 -Wall -Wextra -Werror \
                  -o baseline.exe baseline.c
                ${pythonEnv}/bin/python3 - baseline.exe \
                  "$out/allowed-runtime-imports.json" <<'PY'
                import pathlib
                import sys

                from spaghetti_extractor.stage_binary import _parse_stage_a_pe
                from spaghetti_extractor.source_call_substitution import (
                    bind_allowed_runtime_imports,
                )
                from spaghetti_extractor.util import write_json

                binary = _parse_stage_a_pe(pathlib.Path(sys.argv[1]))
                imports = sorted(
                    (
                        {
                            "dll": item.dll.lower(),
                            "symbol": item.symbol,
                            "ordinal": item.ordinal,
                        }
                        for item in binary.imports
                    ),
                    key=lambda item: (
                        item["dll"], item["symbol"] or "", item["ordinal"] or -1
                    ),
                )
                write_json(pathlib.Path(sys.argv[2]), bind_allowed_runtime_imports({
                    "format": "stage-b-allowed-runtime-imports-v1",
                    "profile_id": "nixpkgs-mingw32-c11-o2-console-baseline-v1",
                    "executes_original_binary": False,
                    "imports": imports,
                    "authority": {
                        "derived_from_candidate": False,
                        "pinned_toolchain_baseline": True,
                        "proves_source_semantics": False,
                    },
                }))
                PY
              '';
          stageBGnuHelloDependencyEnvelope =
            pkgs.runCommand "stage-b-gnu-hello-dependency-envelope-v1"
              {
                nativeBuildInputs = [ pkgs.jq pythonEnv ];
                preferLocalBuild = false;
                allowSubstitutes = true;
                __contentAddressed = true;
              }
              ''
                set -euo pipefail
                export PYTHONHASHSEED=0
                export LC_ALL=C.UTF-8
                export PYTHONPATH=${stageBSourceCallSubstitutionPythonSource}/src
                mkdir -p "$out"
                jq -s '
                  {
                    format: "stage-b-allowed-runtime-imports-v1",
                    profile_id: "gnu-hello-2.12.3-idiomatic-mingw32-v1",
                    executes_original_binary: false,
                    inputs: {
                      toolchain_profile: .[0].profile_id,
                      source_profile: .[1].profile_id
                    },
                    imports: (
                      ([.[0].imports[], .[1].imports[]]) |
                      unique_by([.dll, (.symbol // ""), (.ordinal // -1)]) |
                      sort_by([.dll, (.symbol // ""), (.ordinal // -1)])
                    ),
                    authority: {
                      derived_from_candidate_during_audit: false,
                      pinned_toolchain_baseline: true,
                      reviewed_source_runtime_closure: true,
                      proves_source_semantics: false
                    }
                  }
                ' \
                  ${stageBGnuHelloToolchainRuntimeImports}/allowed-runtime-imports.json \
                  ${./fixtures/gnu-hello/idiomatic/source-runtime-imports.json} \
                  > envelope.json
                jq -e '.imports | length == 53' \
                  envelope.json >/dev/null
                ${pythonEnv}/bin/python3 - envelope.json \
                  "$out/allowed-runtime-imports.json" <<'PY'
                import json
                import pathlib
                import sys

                from spaghetti_extractor.source_call_substitution import (
                    bind_allowed_runtime_imports,
                )
                from spaghetti_extractor.util import write_json

                payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
                write_json(pathlib.Path(sys.argv[2]), bind_allowed_runtime_imports(payload))
                PY
              '';
          stageBGnuHelloSourceCallPipeline =
            import ./nix/stage-b-source-call-substitutions.nix {
              inherit pkgs pythonEnv;
              pythonSource = stageBSourceCallSubstitutionPythonSource;
              sourceBinding =
                "${gnuHelloRoundtrip.idiomaticSourceBinding}/source-project-binding.json";
              original =
                "${stage-a-gnu-hello-original}/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/original/hello.exe";
              machineIr = gnuHelloRoundtrip.machineIr;
              linkedIslands =
                "${stageBGnuHelloLinkedLibraryAnalysis.linkedIslands}/linked-islands.json";
              dynamicRequirements =
                "${stageBGnuHelloLinkedLibraryAnalysis.dynamicRequirements}/dynamic-library-requirements.json";
              clangAst = "${stageBGnuHelloSourceAst}/clang-ast.json";
              sourceRoot = ./fixtures/gnu-hello/idiomatic;
              proposeSourceComponents = true;
              candidate = "${gnuHelloRoundtrip.idiomaticCandidate}/candidate.exe";
              allowedRuntimeImports =
                "${stageBGnuHelloDependencyEnvelope}/allowed-runtime-imports.json";
              namePrefix = "stage-b-gnu-hello";
            };
          stage-b-gnu-hello-proposed-source-components =
            stageBGnuHelloSourceCallPipeline.proposedSourceComponents;
          stage-b-gnu-hello-call-frontier =
            stageBGnuHelloSourceCallPipeline.callFrontier;
          stage-b-gnu-hello-toolchain-runtime-imports =
            stageBGnuHelloToolchainRuntimeImports;
          stage-b-gnu-hello-dependency-envelope =
            stageBGnuHelloDependencyEnvelope;
          stage-b-gnu-hello-call-substitution-plan =
            stageBGnuHelloSourceCallPipeline.callPlan;
          stage-b-gnu-hello-source-call-inventory =
            stageBGnuHelloSourceCallPipeline.sourceInventory;
          stage-b-gnu-hello-source-call-binding-report =
            stageBGnuHelloSourceCallPipeline.sourceBindingReport;
          stage-b-gnu-hello-candidate-dependency-audit =
            stageBGnuHelloSourceCallPipeline.candidateAudit;
          stage-b-gnu-hello-source-call-substitution-smoke =
            pkgs.runCommand "stage-b-gnu-hello-source-call-substitution-smoke-v1"
              {
                nativeBuildInputs = [ pkgs.jq ];
                preferLocalBuild = false;
                allowSubstitutes = true;
                __contentAddressed = true;
              }
              ''
                set -euo pipefail
                frontier=${stageBGnuHelloSourceCallPipeline.callFrontier}/call-frontier.json
                plan=${stageBGnuHelloSourceCallPipeline.callPlan}/call-substitution-plan.json
                source_report=${stageBGnuHelloSourceCallPipeline.sourceBindingReport}/source-call-binding-report.json
                dependency_audit=${stageBGnuHelloSourceCallPipeline.candidateAudit}/candidate-dependency-audit.json
                jq -e '
                  .status == "complete" and .counts.calls == 41 and
                  .counts.resolved == 41 and .counts.incomplete == 0 and
                  (.issues | length) == 0
                ' "$frontier" >/dev/null
                jq -e '
                  .status == "incomplete" and
                  .counts.frontier_calls == 41 and
                  .counts.assigned_frontier_calls == 41 and
                  .counts.plans == 3 and .counts.ready == 0 and
                  .counts.incomplete == 3 and .counts.violated == 0 and
                  all(.issues[]; .status == "incomplete" and
                    .code == "callable_interface_unqualified")
                ' "$plan" >/dev/null
                jq -e '
                  .status == "incomplete" and .counts.plans == 3 and
                  .counts.bindings == 3 and .counts.source_calls == 45 and
                  .counts.covered_by_source_component == 45 and
                  .counts.unbound_source_local == 0 and
                  all(.issues[]; .status == "incomplete" and
                    .code == "call_plan_not_ready")
                ' "$source_report" >/dev/null
                jq -e '
                  .status == "pass" and .counts.expected == 53 and
                  .counts.observed == 53 and .counts.unexpected == 0 and
                  (.executes_original_binary | not)
                ' "$dependency_audit" >/dev/null
                mkdir -p "$out"
                ln -s ${stageBGnuHelloSourceCallPipeline.callFrontier} "$out/call-frontier"
                ln -s ${stageBGnuHelloSourceCallPipeline.callPlan} "$out/call-plan"
                ln -s ${stageBGnuHelloSourceCallPipeline.sourceBindingReport} "$out/source-binding-report"
                ln -s ${stageBGnuHelloSourceCallPipeline.candidateAudit} "$out/candidate-audit"
              '';
          stage-b-component-analysis-smoke =
            pkgs.runCommand "stage-b-component-analysis-smoke-v1"
              {
                nativeBuildInputs = [ pkgs.jq ];
                preferLocalBuild = false;
                allowSubstitutes = true;
                __contentAddressed = true;
              }
              ''
                machine="${stageBMinimalHelloComponentAnalysis.machineIr}/machine-ir-manifest.json"
                plan="${stageBMinimalHelloComponentAnalysis.reconstructionPlan}/reconstruction-plan.json"
                proposals="${stageBMinimalHelloComponentAnalysis.componentProposals}/component-proposals.json"
                jq -e '
                  .format == "stage-a-machine-ir-v2" and
                  (.status == "qualified" or .status == "incomplete") and
                  .counts.units > 0 and .coverage.counts.unknown_bytes == 0 and
                  .counts.violated_issues == 0 and
                  (.authority | contains("no original execution"))
                ' "$machine" >/dev/null
                jq -e '
                  .format == "stage-b-reconstruction-plan-v1" and
                  (.status == "qualified" or .status == "incomplete") and
                  .counts.clusters > 0 and (.executes_original_binary | not)
                ' "$plan" >/dev/null
                jq -e '
                  .format == "stage-b-component-proposal-set-v1" and
                  (.executes_original_binary | not) and
                  (.authority.can_authorize_replacement | not) and
                  .coverage.exact.complete and .coverage.potential.complete and
                  (.proposals | length) > 0
                ' "$proposals" >/dev/null
                mkdir -p "$out"
                ln -s "${stageBMinimalHelloComponentAnalysis.machineIr}" "$out/machine-ir"
                ln -s "${stageBMinimalHelloComponentAnalysis.reconstructionPlan}" "$out/reconstruction-plan"
                ln -s "${stageBMinimalHelloComponentAnalysis.componentProposals}" "$out/component-proposals"
              '';
          stage-b-linked-library-analysis-smoke =
            pkgs.runCommand "stage-b-linked-library-analysis-smoke-v1"
              {
                nativeBuildInputs = [ pkgs.jq ];
                preferLocalBuild = false;
                allowSubstitutes = true;
                __contentAddressed = true;
              }
              ''
                mkdir -p "$out"
                for manifest in \
                  ${stageBJqLinkedLibraryAnalysis.linkedIslands}/linked-islands.json \
                  ${stageBGnuHelloLinkedLibraryAnalysis.linkedIslands}/linked-islands.json
                do
                  jq -e '
                    .format == "stage-b-linked-island-manifest-v2" and
                    (.executes_original_binary | not) and
                    .coverage.classified_exactly_once and
                    .coverage.classified_units == .coverage.machine_units and
                    .coverage.units_by_kind.application > 0 and
                    (.authority.artifact_recognition_authorizes_replacement | not)
                  ' "$manifest" >/dev/null
                done
                watcom_index="${stageBOpenWatcom19ArtifactAnalysis.artifactIndex}/library-artifact-index.json"
                jq -e '
                  .format == "stage-b-library-artifact-index-v2" and
                  .status == "indexed" and (.executes_original_binary | not) and
                  .counts.function_fingerprints == 1 and
                  any(.artifacts[];
                    .index.kind == "omf_object" and
                    any(.index.public_symbols[]; .name == "vintage_rotate_") and
                    any(.index.function_fingerprints[];
                      .matchable == false and
                      .blocker == "unresolved_omf_fixupp_records"))
                ' "$watcom_index" >/dev/null
                gnu_hypotheses="${stageBGnuHelloLinkedLibraryAnalysis.libraryHypotheses}/library-hypotheses.json"
                jq -e '
                  .format == "stage-b-library-hypothesis-set-v1" and
                  .status == "inferred" and (.executes_original_binary | not) and
                  .counts.hypotheses >= 2 and
                  .counts.exact_artifact >= 10 and
                  .counts.ambiguous == 0 and
                  (.authority.can_authorize_replacement | not) and
                  all(.selected_placements[];
                    .identity_status == "exact_artifact" and
                    (.target.unit_ids | length) > 0)
                ' "$gnu_hypotheses" >/dev/null
                gnu_dynamic="${stageBGnuHelloLinkedLibraryAnalysis.dynamicRequirements}/dynamic-library-requirements.json"
                jq -e '
                  .format == "stage-b-dynamic-library-requirements-v1" and
                  (.executes_original_binary | not) and
                  .counts.import_identities == (.imports | length) and
                  .counts.callsites == (.callsites | length) and
                  .counts.callsites > 0 and
                  .counts.qualified_reachable_callsites > 0 and
                  all(.callsites[];
                    (.status == "qualified" or .status == "incomplete") and
                    (.import.dll | length) > 0 and
                    ((.import.symbol | length) > 0 or .import.ordinal != null))
                ' "$gnu_dynamic" >/dev/null
                gnu_plan="${stageBGnuHelloLinkedLibraryAnalysis.replacementPlan}/replacement-plan.json"
                jq -e --arg dynamic_hash "$(jq -r .requirements_sha256 "$gnu_dynamic")" '
                  .format == "stage-b-library-replacement-plan-v1" and
                  (.executes_original_binary | not) and
                  .bindings.dynamic_requirements_sha256 == $dynamic_hash and
                  .counts.dynamic_callsites == (.dynamic_callsites | length) and
                  .counts.ready_dynamic_callsites > 0 and
                  .counts.incomplete_dynamic_callsites > 0 and
                  .counts.ready_dynamic_callsites + .counts.incomplete_dynamic_callsites == .counts.dynamic_callsites and
                  (.completion.fallback_counts_as_lifting_progress | not) and
                  (.completion.idiomatic_source_complete | not)
                ' "$gnu_plan" >/dev/null
                cp ${stageBJqLinkedLibraryAnalysis.linkedIslands}/linked-islands.json \
                  "$out/jq-linked-islands.json"
                cp ${stageBGnuHelloLinkedLibraryAnalysis.linkedIslands}/linked-islands.json \
                  "$out/gnu-hello-linked-islands.json"
                cp "$gnu_hypotheses" \
                  "$out/gnu-hello-library-hypotheses.json"
                cp "$gnu_dynamic" \
                  "$out/gnu-hello-dynamic-library-requirements.json"
                cp "$gnu_plan" \
                  "$out/gnu-hello-library-replacement-plan.json"
                cp "$watcom_index" "$out/openwatcom19-artifact-index.json"
              '';
          stage-b-jq-machine-ir = stageBJqComponentAnalysis.machineIr;
          stage-b-jq-linked-islands = stageBJqLinkedLibraryAnalysis.linkedIslands;
          stage-b-gnu-hello-linked-islands =
            stageBGnuHelloLinkedLibraryAnalysis.linkedIslands;
          stage-b-gnu-hello-library-hypotheses =
            stageBGnuHelloLinkedLibraryAnalysis.libraryHypotheses;
          stage-b-gnu-hello-dynamic-library-requirements =
            stageBGnuHelloLinkedLibraryAnalysis.dynamicRequirements;
          stage-b-gnu-hello-library-replacement-plan =
            stageBGnuHelloLinkedLibraryAnalysis.replacementPlan;
          stage-b-openwatcom19-library-artifact-index =
            stageBOpenWatcom19ArtifactAnalysis.artifactIndex;
          stage-b-jq-machine-ir-interpreter =
            import ./nix/stage-b-interpreter-package.nix {
              inherit pkgs pythonEnv;
              pythonSource = stageBInterpreterPythonSource;
              machineIr = stageBJqComponentAnalysis.machineIr;
              namePrefix = "stage-b-jq";
            };
          stage-b-jq-reconstruction-plan =
            stageBJqComponentAnalysis.reconstructionPlan;
          stage-b-jq-component-proposals =
            stageBJqComponentAnalysis.componentProposals;
          stage-b-jq-selected-component-declarations =
            import ./nix/stage-b-component-selection.nix {
              inherit pkgs pythonEnv;
              pythonSource = stageBComponentSelectionPythonSource;
              componentProposals = stageBJqComponentAnalysis.componentProposals;
              selection = ./fixtures/jq/component-selection.json;
              namePrefix = "stage-b-jq";
            };
          stage-b-jq-selected-component-catalog =
            import ./nix/stage-b-semantic-components.nix {
              inherit pkgs pythonEnv;
              pythonSource = stageBSemanticComponentPythonSource;
              machineIr = stageBJqComponentAnalysis.machineIr;
              reconstructionPlan = stageBJqComponentAnalysis.reconstructionPlan;
              declarations = "${stage-b-jq-selected-component-declarations}/semantic-component-declarations.json";
              namePrefix = "stage-b-jq-selected";
            };
          stageBJqSelection = builtins.fromJSON (builtins.readFile ./fixtures/jq/component-selection.json);
          stageBJqSelectedComponents = map
            (component: {
              name = component.id;
              componentId = component.id;
            selection = component;
            selectionProgramId = stageBJqSelection.program_id;
            selectionProposalSetSha256 = stageBJqSelection.proposal_set_sha256;
          })
            stageBJqSelection.components;
          stageBJqComponentInterfaceDag =
            import ./nix/stage-b-component-interfaces.nix {
              inherit pkgs pythonEnv;
              pythonSource = stageBComponentInterfacePythonSource;
              machineIr = stageBJqComponentAnalysis.machineIr;
              semanticComponentCatalog = stage-b-jq-selected-component-catalog;
              namePrefix = "stage-b-jq-selected";
              components = stageBJqSelectedComponents;
            };
          stage-b-jq-component-interfaces =
            stageBJqComponentInterfaceDag.bundle;
          stageBJqMutableTokenCursorProfilePythonSource =
            pkgs.lib.fileset.toSource {
              root = ./.;
              fileset =
                ./src/spaghetti_extractor_component_profiles/mutable_token_cursor_match_v1.py;
            };
          stageBJqPrefixedUnaryBytePredicateProfilePythonSource =
            pkgs.lib.fileset.toSource {
              root = ./.;
              fileset =
                ./src/spaghetti_extractor_component_profiles/prefixed_unary_byte_predicate_v1.py;
            };
          stageBJqOpaqueValueServicePrefixProfilePythonSource =
            pkgs.lib.fileset.toSource {
              root = ./.;
              fileset =
                ./src/spaghetti_extractor_component_profiles/opaque_value_service_prefix_v1.py;
            };
          stageBJqStatusNormalizeTerminalServiceProfilePythonSource =
            pkgs.lib.fileset.toSource {
              root = ./.;
              fileset =
                ./src/spaghetti_extractor_component_profiles/status_normalize_terminal_service_v1.py;
            };
          stageBJqConstantBufferWriteProfilePythonSource =
            pkgs.lib.fileset.toSource {
              root = ./.;
              fileset =
                ./src/spaghetti_extractor_component_profiles/constant_buffer_write_v1.py;
            };
          stageBJqConstantStringCollectionProfilePythonSource =
            pkgs.lib.fileset.toSource {
              root = ./.;
              fileset =
                ./src/spaghetti_extractor_component_profiles/constant_string_collection_v1.py;
            };
          stageBJqOpaqueValueConsumerProfilePythonSource =
            pkgs.lib.fileset.toSource {
              root = ./.;
              fileset =
                ./src/spaghetti_extractor_component_profiles/opaque_value_consumer_v1.py;
            };
          stageBJqOpaqueOutputPipelineProfilePythonSource =
            pkgs.lib.fileset.toSource {
              root = ./.;
              fileset =
                ./src/spaghetti_extractor_component_profiles/opaque_output_pipeline_v1.py;
            };
          stageBJqOpaqueValueLabelPrefixProfilePythonSource =
            pkgs.lib.fileset.toSource {
              root = ./.;
              fileset =
                ./src/spaghetti_extractor_component_profiles/opaque_value_label_prefix_v1.py;
            };
          stageBJqStdcallWideConversionIterationProfilePythonSource =
            pkgs.lib.fileset.toSource {
              root = ./.;
              fileset =
                ./src/spaghetti_extractor_component_profiles/stdcall_wide_conversion_iteration_v1.py;
            };
          stageBJqOptionalFp64RecordCallbackProfilePythonSource =
            pkgs.lib.fileset.toSource {
              root = ./.;
              fileset =
                ./src/spaghetti_extractor_component_profiles/optional_fp64_record_callback_v1.py;
            };
          stageBJqPe32HeaderQueryProfilePythonSource =
            pkgs.lib.fileset.toSource {
              root = ./.;
              fileset =
                ./src/spaghetti_extractor_component_profiles/pe32_header_query_v1.py;
            };
          stageBJqWindowsPathInfoScanProfilePythonSource =
            pkgs.lib.fileset.toSource {
              root = ./.;
              fileset =
                ./src/spaghetti_extractor_component_profiles/windows_path_info_scan_v1.py;
            };
          stageBJqStaticAtomicWordProfilePythonSource =
            pkgs.lib.fileset.toSource {
              root = ./.;
              fileset =
                ./src/spaghetti_extractor_component_profiles/static_atomic_word_v1.py;
            };
          stageBJqBoundedWideStringLengthProfilePythonSource =
            pkgs.lib.fileset.toSource {
              root = ./.;
              fileset =
                ./src/spaghetti_extractor_component_profiles/bounded_wide_string_length_v1.py;
            };
          stageBJqFrontendProfilePythonSources = {
                mutable_token_cursor_match_v1 =
                  stageBJqMutableTokenCursorProfilePythonSource;
                prefixed_unary_byte_predicate_v1 =
                  stageBJqPrefixedUnaryBytePredicateProfilePythonSource;
                opaque_value_service_prefix_v1 =
                  stageBJqOpaqueValueServicePrefixProfilePythonSource;
                status_normalize_terminal_service_v1 =
                  stageBJqStatusNormalizeTerminalServiceProfilePythonSource;
                constant_buffer_write_v1 =
                  stageBJqConstantBufferWriteProfilePythonSource;
                constant_string_collection_v1 =
                  stageBJqConstantStringCollectionProfilePythonSource;
                opaque_value_consumer_v1 =
                  stageBJqOpaqueValueConsumerProfilePythonSource;
                opaque_output_pipeline_v1 =
                  stageBJqOpaqueOutputPipelineProfilePythonSource;
                opaque_value_label_prefix_v1 =
                  stageBJqOpaqueValueLabelPrefixProfilePythonSource;
                stdcall_wide_conversion_iteration_v1 =
                  stageBJqStdcallWideConversionIterationProfilePythonSource;
                optional_fp64_record_callback_v1 =
                  stageBJqOptionalFp64RecordCallbackProfilePythonSource;
                pe32_header_query_v1 =
                  stageBJqPe32HeaderQueryProfilePythonSource;
                windows_path_info_scan_v1 =
                  stageBJqWindowsPathInfoScanProfilePythonSource;
                static_atomic_word_v1 =
                  stageBJqStaticAtomicWordProfilePythonSource;
                bounded_wide_string_length_v1 =
                  stageBJqBoundedWideStringLengthProfilePythonSource;
              };
              stageBJqFrontendComponentConfigurations = [
                {
                  name = "option-name-match";
                  componentId = "option-name-match";
                  proofProfile = "mutable_token_cursor_match_v1";
                  expectedCases = 10;
                  portableSource =
                    ./fixtures/jq/components/option-name-match.c;
                  staticImage =
                    "${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment/jq-original.exe";
                }
                {
                  name = "option-token-classifier";
                  componentId = "option-token-classifier";
                  proofProfile = "prefixed_unary_byte_predicate_v1";
                  expectedCases = 10;
                  portableSource =
                    ./fixtures/jq/components/option-token-classifier.c;
                }
                {
                  name = "stderr-value-kind-route";
                  componentId = "stderr-value-kind-route";
                  proofProfile = "opaque_value_service_prefix_v1";
                  expectedCases = 10;
                  portableSource =
                    ./fixtures/jq/components/stderr-value-kind-route.c;
                }
                {
                  name = "debug-value-prefix";
                  componentId = "debug-value-prefix";
                  proofProfile = "opaque_value_label_prefix_v1";
                  expectedCases = 10;
                  portableSource =
                    ./fixtures/jq/components/debug-value-prefix.c;
                  staticImage =
                    "${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment/jq-original.exe";
                }
                {
                  name = "usage-exit-route";
                  componentId = "usage-exit-route";
                  proofProfile = "status_normalize_terminal_service_v1";
                  expectedCases = 10;
                  portableSource =
                    ./fixtures/jq/components/usage-exit-route.c;
                }
                {
                  name = "usage-write-route";
                  componentId = "usage-write-route";
                  proofProfile = "constant_buffer_write_v1";
                  expectedCases = 10;
                  portableSource =
                    ./fixtures/jq/components/usage-write-route.c;
                  staticImage =
                    "${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment/jq-original.exe";
                }
                {
                  name = "option-value-collection";
                  componentId = "option-value-collection";
                  proofProfile = "constant_string_collection_v1";
                  expectedCases = 10;
                  portableSource =
                    ./fixtures/jq/components/option-value-collection.c;
                  staticImage =
                    "${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment/jq-original.exe";
                }
                {
                  name = "output-value-release";
                  componentId = "output-value-release";
                  proofProfile = "opaque_value_consumer_v1";
                  expectedCases = 10;
                  portableSource =
                    ./fixtures/jq/components/output-value-release.c;
                }
                {
                  name = "output-value-dump";
                  componentId = "output-value-dump";
                  proofProfile = "opaque_value_consumer_v1";
                  expectedCases = 10;
                  portableSource =
                    ./fixtures/jq/components/output-value-dump.c;
                }
                {
                  name = "output-value-pipeline";
                  componentId = "output-value-pipeline";
                  proofProfile = "opaque_output_pipeline_v1";
                  expectedCases = 10;
                  portableSource =
                    ./fixtures/jq/components/output-value-pipeline.c;
                }
                {
                  name = "wide-argument-conversion-tail";
                  componentId = "wide-argument-conversion-tail";
                  proofProfile = "stdcall_wide_conversion_iteration_v1";
                  expectedCases = 10;
                  portableSource =
                    ./fixtures/jq/components/wide-argument-conversion-tail.c;
                }
                {
                  name = "math-error-callback-dispatch";
                  componentId = "math-error-callback-dispatch";
                  proofProfile = "optional_fp64_record_callback_v1";
                  expectedCases = 10;
                  portableSource =
                    ./fixtures/jq/components/math-error-callback-dispatch.c;
                  staticImage =
                    "${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment/jq-original.exe";
                }
                {
                  name = "pe32-section-count";
                  componentId = "pe32-section-count";
                  proofProfile = "pe32_header_query_v1";
                  expectedCases = 10;
                  portableSource =
                    ./fixtures/jq/components/pe32-section-count.c;
                }
                {
                  name = "pe32-image-base";
                  componentId = "pe32-image-base";
                  proofProfile = "pe32_header_query_v1";
                  expectedCases = 10;
                  portableSource =
                    ./fixtures/jq/components/pe32-image-base.c;
                }
                {
                  name = "pe32-section-for-address";
                  componentId = "pe32-section-for-address";
                  proofProfile = "pe32_header_query_v1";
                  expectedCases = 10;
                  portableSource =
                    ./fixtures/jq/components/pe32-section-for-address.c;
                }
                {
                  name = "windows-path-info-scan";
                  componentId = "windows-path-info-scan";
                  proofProfile = "windows_path_info_scan_v1";
                  expectedCases = 10;
                  portableSource =
                    ./fixtures/jq/components/windows-path-info-scan.c;
                }
                {
                  name = "invalid-parameter-handler-get";
                  componentId = "invalid-parameter-handler-get";
                  proofProfile = "static_atomic_word_v1";
                  expectedCases = 10;
                  portableSource =
                    ./fixtures/jq/components/invalid-parameter-handler-get.c;
                }
                {
                  name = "invalid-parameter-handler-exchange";
                  componentId = "invalid-parameter-handler-exchange";
                  proofProfile = "static_atomic_word_v1";
                  expectedCases = 10;
                  portableSource =
                    ./fixtures/jq/components/invalid-parameter-handler-exchange.c;
                }
                {
                  name = "bounded-string-length";
                  componentId = "bounded-string-length";
                  proofProfile = "bounded_string_length_v1";
                  expectedCases = 153;
                  portableSource =
                    ./fixtures/jq/components/bounded-string-length.c;
                }
                {
                  name = "bounded-wide-string-length";
                  componentId = "bounded-wide-string-length";
                  proofProfile = "bounded_wide_string_length_v1";
                  expectedCases = 153;
                  portableSource =
                    ./fixtures/jq/components/bounded-wide-string-length.c;
                }
              ];
            stageBJqFrontendComponents = map (
            componentConfig:
            componentConfig
            // {
              selection =
                (builtins.head (
                  builtins.filter (
                    selected: selected.componentId == componentConfig.componentId
                  ) stageBJqSelectedComponents
                )).selection;
              selectionProgramId = stageBJqSelection.program_id;
              selectionProposalSetSha256 = stageBJqSelection.proposal_set_sha256;
            }
          ) stageBJqFrontendComponentConfigurations;
          mkStageBJqFrontendWorkspaceDag =
            components:
            import ./nix/stage-b-semantic-component-workspaces.nix {
              inherit pkgs pythonEnv;
              pythonSource = stageBComponentWorkspacePythonSource;
              componentSelectionPythonSource = stageBComponentSelectionPythonSource;
              semanticComponentPythonSource = stageBSemanticComponentPythonSource;
              componentInterfacePythonSource = stageBComponentInterfacePythonSource;
              profilePythonSources = stageBJqFrontendProfilePythonSources;
              machineIr = stageBJqComponentAnalysis.machineIr;
              interpreterPackage = stage-b-jq-machine-ir-interpreter;
              reconstructionPlan = stageBJqComponentAnalysis.reconstructionPlan;
              semanticComponentCatalog = stage-b-jq-selected-component-catalog;
              componentProposals = stageBJqComponentAnalysis.componentProposals;
              linkedIslands =
                "${stageBJqLinkedLibraryAnalysis.linkedIslands}/linked-islands.json";
              namePrefix = "stage-b-jq";
              inherit components;
            };
          stageBJqFrontendWorkspaceDag = mkStageBJqFrontendWorkspaceDag stageBJqFrontendComponents;
          stageBJqOptionNameMatchIsolatedDag = mkStageBJqFrontendWorkspaceDag (
            builtins.filter (component: component.name == "option-name-match") stageBJqFrontendComponents
          );
          stage-b-jq-component-granularity-smoke =
            assert
              toString stageBJqFrontendWorkspaceDag.qualifications.option-name-match
              == toString stageBJqOptionNameMatchIsolatedDag.qualifications.option-name-match;
            pkgs.runCommand "stage-b-jq-component-granularity-smoke-v1" { } ''
              mkdir -p "$out"
              ln -s ${stageBJqFrontendWorkspaceDag.qualifications.option-name-match} \
                "$out/option-name-match-qualification"
            '';
          stage-b-jq-option-name-match-workspace =
            stageBJqFrontendWorkspaceDag.workspaces.option-name-match;
          stage-b-jq-option-name-match-qualification =
            stageBJqFrontendWorkspaceDag.qualifications.option-name-match;
          stage-b-jq-option-token-classifier-workspace =
            stageBJqFrontendWorkspaceDag.workspaces.option-token-classifier;
          stage-b-jq-option-token-classifier-qualification =
            stageBJqFrontendWorkspaceDag.qualifications.option-token-classifier;
          stage-b-jq-stderr-value-kind-route-workspace =
            stageBJqFrontendWorkspaceDag.workspaces.stderr-value-kind-route;
          stage-b-jq-stderr-value-kind-route-qualification =
            stageBJqFrontendWorkspaceDag.qualifications.stderr-value-kind-route;
          stage-b-jq-debug-value-prefix-workspace =
            stageBJqFrontendWorkspaceDag.workspaces.debug-value-prefix;
          stage-b-jq-debug-value-prefix-qualification =
            stageBJqFrontendWorkspaceDag.qualifications.debug-value-prefix;
          stage-b-jq-usage-exit-route-workspace =
            stageBJqFrontendWorkspaceDag.workspaces.usage-exit-route;
          stage-b-jq-usage-exit-route-qualification =
            stageBJqFrontendWorkspaceDag.qualifications.usage-exit-route;
          stage-b-jq-usage-write-route-workspace =
            stageBJqFrontendWorkspaceDag.workspaces.usage-write-route;
          stage-b-jq-usage-write-route-qualification =
            stageBJqFrontendWorkspaceDag.qualifications.usage-write-route;
          stage-b-jq-option-value-collection-workspace =
            stageBJqFrontendWorkspaceDag.workspaces.option-value-collection;
          stage-b-jq-option-value-collection-qualification =
            stageBJqFrontendWorkspaceDag.qualifications.option-value-collection;
          stage-b-jq-output-value-release-workspace =
            stageBJqFrontendWorkspaceDag.workspaces.output-value-release;
          stage-b-jq-output-value-release-qualification =
            stageBJqFrontendWorkspaceDag.qualifications.output-value-release;
          stage-b-jq-output-value-dump-workspace =
            stageBJqFrontendWorkspaceDag.workspaces.output-value-dump;
          stage-b-jq-output-value-dump-qualification =
            stageBJqFrontendWorkspaceDag.qualifications.output-value-dump;
          stage-b-jq-output-value-pipeline-workspace =
            stageBJqFrontendWorkspaceDag.workspaces.output-value-pipeline;
          stage-b-jq-output-value-pipeline-qualification =
            stageBJqFrontendWorkspaceDag.qualifications.output-value-pipeline;
          stage-b-jq-wide-argument-conversion-tail-workspace =
            stageBJqFrontendWorkspaceDag.workspaces.wide-argument-conversion-tail;
          stage-b-jq-wide-argument-conversion-tail-qualification =
            stageBJqFrontendWorkspaceDag.qualifications.wide-argument-conversion-tail;
          stage-b-jq-math-error-callback-dispatch-workspace =
            stageBJqFrontendWorkspaceDag.workspaces.math-error-callback-dispatch;
          stage-b-jq-math-error-callback-dispatch-qualification =
            stageBJqFrontendWorkspaceDag.qualifications.math-error-callback-dispatch;
          stage-b-jq-pe32-section-count-workspace =
            stageBJqFrontendWorkspaceDag.workspaces.pe32-section-count;
          stage-b-jq-pe32-section-count-qualification =
            stageBJqFrontendWorkspaceDag.qualifications.pe32-section-count;
          stage-b-jq-pe32-image-base-workspace =
            stageBJqFrontendWorkspaceDag.workspaces.pe32-image-base;
          stage-b-jq-pe32-image-base-qualification =
            stageBJqFrontendWorkspaceDag.qualifications.pe32-image-base;
          stage-b-jq-pe32-section-for-address-workspace =
            stageBJqFrontendWorkspaceDag.workspaces.pe32-section-for-address;
          stage-b-jq-pe32-section-for-address-qualification =
            stageBJqFrontendWorkspaceDag.qualifications.pe32-section-for-address;
          stage-b-jq-windows-path-info-scan-workspace =
            stageBJqFrontendWorkspaceDag.workspaces.windows-path-info-scan;
          stage-b-jq-windows-path-info-scan-qualification =
            stageBJqFrontendWorkspaceDag.qualifications.windows-path-info-scan;
          stage-b-jq-invalid-parameter-handler-get-workspace =
            stageBJqFrontendWorkspaceDag.workspaces.invalid-parameter-handler-get;
          stage-b-jq-invalid-parameter-handler-get-qualification =
            stageBJqFrontendWorkspaceDag.qualifications.invalid-parameter-handler-get;
          stage-b-jq-invalid-parameter-handler-exchange-workspace =
            stageBJqFrontendWorkspaceDag.workspaces.invalid-parameter-handler-exchange;
          stage-b-jq-invalid-parameter-handler-exchange-qualification =
            stageBJqFrontendWorkspaceDag.qualifications.invalid-parameter-handler-exchange;
          stage-b-jq-bounded-string-length-workspace =
            stageBJqFrontendWorkspaceDag.workspaces.bounded-string-length;
          stage-b-jq-bounded-string-length-qualification =
            stageBJqFrontendWorkspaceDag.qualifications.bounded-string-length;
          stage-b-jq-bounded-wide-string-length-workspace =
            stageBJqFrontendWorkspaceDag.workspaces.bounded-wide-string-length;
          stage-b-jq-bounded-wide-string-length-qualification =
            stageBJqFrontendWorkspaceDag.qualifications.bounded-wide-string-length;
          stage-b-jq-component-registry =
            stageBJqFrontendWorkspaceDag.registry;
          stage-b-jq-skeleton =
            pkgs.runCommand "stage-b-jq-skeleton"
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
            xed-isa-catalog
            stage-a-isa-xed-catalog
            stage-a-isa-core-smoke-corpus
            stage-a-isa-core-smoke-qualification
            stage-a-isa-core-smoke-campaign
            stage-a-isa-core-smoke-bundle
            singlestep-80386-conformance
            spaghetti-extractor
            spaghetti-extractor-analysis
            spaghetti-extractor-dataflow
            spaghetti-extractor-dataflow-aggregate
            spaghetti-extractor-dataflow-compare
            spaghetti-extractor-dataflow-plan
            spaghetti-extractor-dataflow-summary
            spaghetti-extractor-dataflow-worker
            spaghetti-extractor-mapping
            spaghetti-extractor-composition-products
            spaghetti-extractor-memory-products
            spaghetti-extractor-normalize
            spaghetti-extractor-preparation
            spaghetti-extractor-proposal
            spaghetti-extractor-register-dataflow-problem
            spaghetti-extractor-register-replay
            spaghetti-extractor-semantic-products
            spaghetti-extractor-region-facts
            spaghetti-extractor-side
            stage-b-tiny-c0-source
            stage-a-tiny-c0-toolchain-profile
            stage-a-tiny-c0-original
            stage-b-tiny-c0-candidate
            stage-a-tiny-c0-source-proof
            stage-a-tiny-c0-source-behavior-smoke
            stage-a-analysis-source-boundary-check
            stage-a-isa-conformance-bochs-80386
            stage-a-isa-kernel-cache
            stage-a-isa-kernel-identity
            stage-a-fixtures
            stage-a-fixtures-check
            stage-a-fixtures-root
            stage-a-exit-fixtures
            stage-a-exit-static-map
            stage-a-exit-relation-contract
            stage-a-exit-prepared-proof
            stage-a-exit-proof-audit
            stage-a-exit-check
            stage-a-exit-behavior-smoke
            stage-a-winapi-hello-fixtures
            stage-a-winapi-hello-static-map
            stage-a-winapi-hello-relation-contract
            stage-a-winapi-hello-prepared-proof
            stage-a-winapi-hello-check
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
            stage-a-gnu-hello-composition-products
            stage-a-gnu-hello-memory-products
            stage-a-gnu-hello-semantic-products
            stage-a-gnu-hello-analysis
            stage-a-gnu-hello-register-dataflow-plan
            stage-a-gnu-hello-register-dataflow
            stage-a-gnu-hello-register-replay
            stage-a-gnu-hello-register-dataflow-check
            stage-a-gnu-hello-preflight
            stage-a-gnu-hello-proof
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
            stage-a-roundtrip-smoke-corpus
            stage-a-roundtrip-static-smoke
            stage-a-roundtrip-proof-smoke
            stage-a-roundtrip-violation-smoke
            stage-a-roundtrip-spike-corpus
            stage-a-roundtrip-spike-pack-plan
            stage-a-roundtrip-spike-check
            stage-a-roundtrip-spike-corpus-root
            stage-a-roundtrip-promoted-corpus
            stage-a-roundtrip-promoted-pack-plan
            stage-a-roundtrip-promoted-check
            stage-a-jq-fixtures
            stage-a-jq-static-map
            stage-a-jq-relation-contract
            stage-a-jq-original-inventory
            stage-a-jq-candidate-inventory
            stage-a-jq-original-extraction
            stage-a-jq-candidate-extraction
            stage-a-jq-original-isa
            stage-a-jq-candidate-isa
            stage-a-jq-original-supplement-request
            stage-a-jq-candidate-supplement-request
            stage-a-jq-original-supplement-extraction
            stage-a-jq-candidate-supplement-extraction
            stage-a-jq-original-merged-extraction
            stage-a-jq-candidate-merged-extraction
            stage-a-jq-normalized-behaviors
            stage-a-jq-region-facts
            stage-a-jq-proposals
            stage-a-jq-semantic-products
            stage-a-jq-register-dataflow-problem
            stage-a-jq-register-dataflow-plan
            stage-a-jq-register-dataflow
            stage-a-jq-register-replay
            stage-a-jq-memory-products
            stage-a-jq-composition-products
            stage-a-jq-analysis
            stage-a-jq-register-dataflow-check
            stage-a-jq-prepared-proof
            stage-a-jq-reference-contract
            stage-a-jq-fixtures-check
            stage-a-jq-fixtures-root
            stage-a-relational-analysis-kernel-cache
            stage-a-relational-analysis-ifd-kernel-cache
            stage-a-relational-acceptance-kernel-cache
            stage-a-relational-acceptance-graph-smoke
            stage-a-relational-kernel-cache
            stage-a-roundtrip-lean-graph-smoke
            stage-a-roundtrip-lean-remote-smoke
            stage-a-roundtrip-lean-engine
            stage-a-roundtrip-lean-definedness
            stage-a-roundtrip-lean-identity
            stage-a-roundtrip-lean-interpreter
            stage-a-roundtrip-lean-transfer
            stage-a-roundtrip-lean-x87
            stage-a-roundtrip-lean-compiled-kernel
            stage-a-roundtrip-lean-symbolic-soundness
            stage-a-roundtrip-lean-mixed-replay
            stage-a-roundtrip-lean-mixed-replay-world
            stage-a-roundtrip-lean-x87-replay-bridge-runtime
            stage-a-roundtrip-lean-x87-kernel-execution
            stage-a-roundtrip-lean-environment
            stage-a-roundtrip-lean-kernel-cache
            stage-a-roundtrip-interpreter-kernel-cache
            stage-a-roundtrip-interpreter-native-kernel-cache
            stage-a-roundtrip-lean-kernel-lookup-native
            stage-a-roundtrip-lean-program-lookup-operation
            stage-a-gnu-hello-opaque-original-inventory
            stage-a-gnu-hello-opaque-static-export
            stage-b-gnu-hello-opaque-state-machine
            stage-a-gnu-hello-machine-ir
            stage-b-gnu-hello-machine-ir-interpreter
            stage-b-gnu-hello-machine-ir-native-engine
            stage-b-gnu-hello-machine-ir-native-runtime
            stage-b-gnu-hello-reconstruction-plan
            stage-b-gnu-hello-semantic-components
            stage-b-gnu-hello-selected-component-catalog
            stage-b-gnu-hello-component-proposals
            stage-b-gnu-hello-selected-component-declarations
            stage-b-gnu-hello-component-interfaces
            stage-b-gnu-hello-component-slices
            stage-b-gnu-hello-regional-interpreter-kernel
            stage-b-gnu-hello-component-registry
            stage-b-gnu-hello-branch-component-qualification
            stage-b-gnu-hello-external-call-component-qualification
            stage-b-gnu-hello-internal-call-component-qualification
            stage-b-gnu-hello-short-option-component-qualification
            stage-b-gnu-hello-rotate-component-qualification
            stage-b-gnu-hello-windows-error-component-qualification
            stage-b-gnu-hello-bounded-string-length-component-qualification
            stage-b-gnu-hello-atomic-component-qualification
            stage-b-gnu-hello-callback-component-qualification
            stage-b-gnu-hello-dispatch-component-qualification
            stage-b-gnu-hello-typed-memory-component-qualification
            stage-b-gnu-hello-ascii-to-lower-component-qualification
            stage-b-gnu-hello-ascii-string-compare-component-qualification
            stage-b-gnu-hello-last-path-component-qualification
            stage-b-gnu-hello-memory-regions-equal-qualification
            stage-b-gnu-hello-program-name-selection-qualification
            stage-b-gnu-hello-component-hybrid-candidate
            stage-b-gnu-hello-component-hybrid-functional-suite
            stage-b-gnu-hello-idiomatic-source-binding
            stage-b-gnu-hello-idiomatic-candidate
            stage-b-gnu-hello-idiomatic-functional-suite
            stage-b-gnu-hello-idiomatic-upstream-suite
            stage-b-gnu-hello-idiomatic-assurance
            stage-b-gnu-hello-lifting-evidence
            stage-b-gnu-hello-branch-workspace
            stage-b-gnu-hello-external-call-workspace
            stage-b-gnu-hello-internal-call-workspace
            stage-b-gnu-hello-atomic-workspace
            stage-b-gnu-hello-callback-workspace
            stage-b-gnu-hello-dispatch-workspace
            stage-b-gnu-hello-typed-memory-workspace
            stage-b-gnu-hello-branch-workspace-check
            stage-b-gnu-hello-atomic-workspace-check
            stage-b-gnu-hello-callback-workspace-check
            stage-b-gnu-hello-dispatch-workspace-check
            stage-b-gnu-hello-typed-memory-workspace-check
            stage-b-gnu-hello-external-call-workspace-check
            stage-b-gnu-hello-internal-call-workspace-check
            stage-b-gnu-hello-reconstruction-registry
            stage-b-gnu-hello-entry-replacement
            stage-b-gnu-hello-regional-harness-kernel
            stage-b-gnu-hello-entry-replacement-validation
            stage-b-gnu-hello-entry-replacement-mutation
            stage-b-gnu-hello-machine-ir-candidate
            stage-b-gnu-hello-entry-replacement-candidate
            stage-b-gnu-hello-reconstruction-workspace-candidate
            stage-b-gnu-hello-machine-ir-diagnostic-candidate
            stage-b-gnu-hello-callable-external-runtime-contract
            stage-a-gnu-hello-roundtrip-smoke
            stage-a-gnu-hello-roundtrip-static-export
            stage-b-gnu-hello-source-state-machine
            stage-b-gnu-hello-c0-source
            stage-b-gnu-hello-native-source-interpreter
            stage-b-gnu-hello-native-source-engine
            stage-b-gnu-hello-native-source-runtime
            stage-b-gnu-hello-native-source-candidate
            stage-a-gnu-hello-native-source-candidate-kernel-data
            stage-a-gnu-hello-native-source-candidate-static-authority
            stage-a-gnu-hello-native-source-candidate-static-authority-proof-sources
            stage-a-gnu-hello-native-source-candidate-static-authority-proof
            stage-a-gnu-hello-native-source-bundle
            stage-a-gnu-hello-native-source-compilation-attestation
            stage-a-gnu-hello-native-source-program
            stage-a-gnu-hello-native-source-normalization
            stage-a-gnu-hello-native-source-semantic-refinement
            stage-a-gnu-hello-native-source-x87
            stage-a-gnu-hello-native-source-machine-import-contracts
            stage-a-gnu-hello-native-source-original-base
            stage-a-gnu-hello-native-source-original
            stage-a-gnu-hello-native-source-original-static-reachability
            stage-a-gnu-hello-native-source-original-static-reachability-proof-sources
            stage-a-gnu-hello-native-source-original-static-reachability-proof
            stage-a-gnu-hello-native-source-original-carrier-binding
            stage-a-gnu-hello-native-source-original-carrier-binding-proof-sources
            stage-a-gnu-hello-native-source-original-carrier-binding-proof
            stage-a-gnu-hello-native-source-original-combined-declarations
            stage-a-gnu-hello-native-source-original-combined-inventory
            stage-a-gnu-hello-native-source-original-combined-inventory-proof-sources
            stage-a-gnu-hello-native-source-original-combined-inventory-proof
            stage-a-gnu-hello-native-source-target-effect-inputs
            stage-a-gnu-hello-native-source-target-effects
            stage-a-gnu-hello-native-source-transition-index
            stage-a-gnu-hello-native-source-transition-index-proof-sources
            stage-a-gnu-hello-native-source-transition-index-proof
            stage-a-gnu-hello-native-source-runtime-memory-access-proposal
            stage-a-gnu-hello-native-source-original-target-control
            stage-a-gnu-hello-native-source-original-target-control-proof-sources
            stage-a-gnu-hello-native-source-original-target-control-proof
            stage-a-gnu-hello-native-source-original-target-control-audit
            stage-a-gnu-hello-native-source-ordinary-semantic-proof-sources
            stage-a-gnu-hello-native-source-ordinary-semantic-proof
            stage-a-gnu-hello-native-source-x87-semantic-proof-sources
            stage-a-gnu-hello-native-source-x87-semantic-proof
            stage-a-gnu-hello-native-source-program-assembly
            stage-a-gnu-hello-native-source-program-assembly-proof-sources
            stage-a-gnu-hello-native-source-program-assembly-proof
            stage-a-gnu-hello-native-source-original-execution-evidence
            stage-a-gnu-hello-native-source-execution
            stage-a-gnu-hello-native-source-execution-proof-sources
            stage-a-gnu-hello-native-source-execution-proof
            stage-a-gnu-hello-native-source-execution-audit
            stage-a-gnu-hello-native-source-compiled-authority-evidence
            stage-a-gnu-hello-native-source-compiled-authority
            stage-a-gnu-hello-native-source-compiled-authority-proof-sources
            stage-a-gnu-hello-native-source-compiled-authority-proof
            stage-a-gnu-hello-native-source-compiled-authority-audit
            stage-a-gnu-hello-native-source-environment-family-evidence
            stage-a-gnu-hello-native-source-conditional-acceptance
            stage-a-gnu-hello-native-source-conditional-acceptance-proof-sources
            stage-a-gnu-hello-native-source-conditional-acceptance-proof
            stage-a-gnu-hello-native-source-conditional-acceptance-audit
            stage-a-gnu-hello-native-source-conditional-acceptance-checked
            stage-a-gnu-hello-native-source-equivalence-report
            stage-b-gnu-hello-native-source-functional-suite
            stage-b-gnu-hello-roundtrip-interpreter
            stage-b-gnu-hello-roundtrip-native-engine
            stage-b-gnu-hello-roundtrip-native-runtime
            stage-b-gnu-hello-roundtrip-candidate
            stage-a-gnu-hello-roundtrip-original-inventory
            stage-a-gnu-hello-roundtrip-candidate-inventory
            stage-a-gnu-hello-roundtrip-original-isa-request
            stage-a-gnu-hello-roundtrip-candidate-isa-request
            stage-a-gnu-hello-roundtrip-original-isa
            stage-a-gnu-hello-roundtrip-candidate-isa
            stage-a-gnu-hello-roundtrip-original-isa-summary
            stage-a-gnu-hello-roundtrip-candidate-isa-summary
            stage-a-gnu-hello-roundtrip-side-isa-adapter
            stage-a-gnu-hello-roundtrip-side-isa-enrichment
            stage-a-gnu-hello-roundtrip-side-isa-corpus
            stage-a-gnu-hello-roundtrip-side-isa-evidence
            stage-a-gnu-hello-roundtrip-side-isa-qualification
            stage-a-gnu-hello-roundtrip-isa-coverage
            stage-a-gnu-hello-roundtrip-semantic-coverage
            stage-a-gnu-hello-roundtrip-engine-segments
            stage-a-gnu-hello-roundtrip-compiled-kernel-source
            stage-a-gnu-hello-roundtrip-static-machine-import-source
            stage-a-gnu-hello-roundtrip-universal-paired-external-environment-source
            stage-a-gnu-hello-roundtrip-static-machine-import-proof-sources
            stage-a-gnu-hello-roundtrip-static-machine-import-proof
            stage-a-gnu-hello-roundtrip-mixed-original-source
            stage-a-gnu-hello-roundtrip-mixed-original-static-reachability-source
            stage-a-gnu-hello-roundtrip-mixed-original-static-reachability-proof-sources
            stage-a-gnu-hello-roundtrip-mixed-original-static-reachability-proof
            stage-a-gnu-hello-roundtrip-mixed-original-writable-slot-authority-lean
            stage-a-gnu-hello-roundtrip-mixed-original-register-indirect-authority-source
            stage-a-gnu-hello-roundtrip-mixed-original-register-indirect-authority-proof-sources
            stage-a-gnu-hello-roundtrip-mixed-original-register-indirect-authority-proof
            stage-a-gnu-hello-roundtrip-mixed-original-stack-dynamic-authority-source
            stage-a-gnu-hello-roundtrip-mixed-original-stack-dynamic-authority-proof-sources
            stage-a-gnu-hello-roundtrip-mixed-original-stack-dynamic-authority-proof
            stage-a-gnu-hello-roundtrip-mixed-original-direct-call-proposals-source
            stage-a-gnu-hello-roundtrip-mixed-original-direct-call-proposal-proof-sources
            stage-a-gnu-hello-roundtrip-mixed-original-direct-call-proposal-proof
            stage-a-gnu-hello-roundtrip-mixed-original-direct-call-semantics-source
            stage-a-gnu-hello-roundtrip-mixed-original-direct-call-semantics-proof-sources
            stage-a-gnu-hello-roundtrip-mixed-original-direct-call-semantics-proof
            stage-a-gnu-hello-roundtrip-mixed-original-direct-call-fixed-point-check
            stage-a-gnu-hello-roundtrip-mixed-original-direct-call-round-1-proposals-source
            stage-a-gnu-hello-roundtrip-mixed-original-direct-call-round-1-semantics-source
            stage-a-gnu-hello-roundtrip-mixed-original-carrier-binding-source
            stage-a-gnu-hello-roundtrip-mixed-original-carrier-binding-proof-sources
            stage-a-gnu-hello-roundtrip-mixed-original-carrier-binding-proof
            stage-a-gnu-hello-roundtrip-mixed-original-diagnostic
            stage-a-gnu-hello-roundtrip-kernel-data-source
            stage-a-gnu-hello-roundtrip-kernel-data-native-projection-benchmark
            stage-a-gnu-hello-roundtrip-kernel-data-native-projection-proof
            stage-a-gnu-hello-roundtrip-access-fault-qualification-source
            stage-a-gnu-hello-roundtrip-access-fault-qualification-proof-sources
            stage-a-gnu-hello-roundtrip-access-fault-qualification-proof
            stage-a-gnu-hello-roundtrip-kernel-abi-source
            stage-a-gnu-hello-roundtrip-constructive-source-coverage-source
            stage-a-gnu-hello-roundtrip-constructive-source-coverage-proof-sources
            stage-a-gnu-hello-roundtrip-constructive-source-coverage-proof
            stage-a-gnu-hello-roundtrip-canonical-relation-core-source
            stage-a-gnu-hello-roundtrip-canonical-relation-core-proof-sources
            stage-a-gnu-hello-roundtrip-canonical-relation-core-proof
            stage-a-gnu-hello-roundtrip-acceptance-requirements-source
            stage-a-gnu-hello-roundtrip-acceptance-requirements-proof-sources
            stage-a-gnu-hello-roundtrip-acceptance-requirements-proof
            stage-a-gnu-hello-roundtrip-runtime-foundation-source
            stage-a-gnu-hello-roundtrip-runtime-foundation-proof-sources
            stage-a-gnu-hello-roundtrip-runtime-foundation-proof
            stage-a-gnu-hello-roundtrip-launch-binding-source
            stage-a-gnu-hello-roundtrip-launch-binding-proof-sources
            stage-a-gnu-hello-roundtrip-launch-binding-proof
            stage-a-gnu-hello-roundtrip-external-component-source
            stage-a-gnu-hello-roundtrip-external-component-proof-sources
            stage-a-gnu-hello-roundtrip-external-component-proof
            stage-a-gnu-hello-roundtrip-mixed-semantic-operation-component-source
            stage-a-gnu-hello-roundtrip-mixed-semantic-operation-component-proof-sources
            stage-a-gnu-hello-roundtrip-mixed-semantic-operation-component-proof
            stage-a-gnu-hello-roundtrip-mixed-fused-semantic-evidence-source
            stage-a-gnu-hello-roundtrip-mixed-fused-semantic-evidence-proof-sources
            stage-a-gnu-hello-roundtrip-mixed-fused-semantic-evidence-proof
            stage-a-gnu-hello-roundtrip-mixed-direct-call-semantic-evidence-source
            stage-a-gnu-hello-roundtrip-mixed-direct-call-semantic-evidence-proof-sources
            stage-a-gnu-hello-roundtrip-mixed-direct-call-semantic-evidence-proof
            stage-a-gnu-hello-roundtrip-mixed-indirect-import-call-semantic-evidence-source
            stage-a-gnu-hello-roundtrip-mixed-indirect-import-call-semantic-evidence-proof-sources
            stage-a-gnu-hello-roundtrip-mixed-indirect-import-call-semantic-evidence-proof
            stage-a-gnu-hello-roundtrip-mixed-external-tail-semantic-evidence-source
            stage-a-gnu-hello-roundtrip-mixed-external-tail-semantic-evidence-proof-sources
            stage-a-gnu-hello-roundtrip-mixed-external-tail-semantic-evidence-proof
            stage-a-gnu-hello-roundtrip-runtime-indirect-composition-source
            stage-a-gnu-hello-roundtrip-runtime-indirect-composition-proof-sources
            stage-a-gnu-hello-roundtrip-runtime-indirect-composition-proof
            stage-a-gnu-hello-roundtrip-program-lookup-native-world-bridge-source
            stage-a-gnu-hello-roundtrip-program-lookup-native-world-bridge-proof-sources
            stage-a-gnu-hello-roundtrip-program-lookup-native-world-bridge-proof
            stage-a-gnu-hello-roundtrip-interpreter-step-world-program-lookup-source
            stage-a-gnu-hello-roundtrip-interpreter-step-program-lookup-call-behavior-extraction
            stage-a-gnu-hello-roundtrip-interpreter-step-program-lookup-call-behaviors-source
            stage-a-gnu-hello-roundtrip-interpreter-step-program-lookup-projection-proof-sources
            stage-a-gnu-hello-roundtrip-interpreter-step-program-lookup-projection-proof
            stage-a-gnu-hello-roundtrip-interpreter-step-world-program-lookup-proof-sources
            stage-a-gnu-hello-roundtrip-interpreter-step-world-program-lookup-proof
            stage-a-gnu-hello-roundtrip-kernel-operation-instantiation-source
            stage-a-gnu-hello-roundtrip-kernel-operation-instantiation-proof-sources
            stage-a-gnu-hello-roundtrip-kernel-operation-instantiation-proof
            stage-a-gnu-hello-roundtrip-kernel-run-entry-route-source
            stage-a-gnu-hello-roundtrip-kernel-run-entry-route-proof-sources
            stage-a-gnu-hello-roundtrip-kernel-run-entry-route-proof
            stage-a-gnu-hello-roundtrip-kernel-run-entry-behavior-extraction
            stage-a-gnu-hello-roundtrip-kernel-run-entry-behaviors-source
            stage-a-gnu-hello-roundtrip-kernel-run-entry-behaviors-proof-sources
            stage-a-gnu-hello-roundtrip-kernel-run-entry-behaviors-proof
            stage-a-gnu-hello-roundtrip-kernel-run-entry-abi-source
            stage-a-gnu-hello-roundtrip-kernel-run-entry-abi-proof-sources
            stage-a-gnu-hello-roundtrip-kernel-run-entry-abi-proof
            stage-a-gnu-hello-roundtrip-mixed-acceptance-source
            stage-a-gnu-hello-roundtrip-mixed-chunked-acceptance-source
            stage-a-gnu-hello-roundtrip-mixed-chunked-acceptance-proof-sources
            stage-a-gnu-hello-roundtrip-mixed-chunked-acceptance-proof
            stage-a-gnu-hello-roundtrip-native-launch-graph-source
            stage-a-gnu-hello-roundtrip-native-launch-graph-proof-sources
            stage-a-gnu-hello-roundtrip-native-launch-graph-proof
            stage-a-gnu-hello-roundtrip-proof-sources
            stage-a-gnu-hello-roundtrip-acceptance-source
            stage-a-gnu-hello-roundtrip-final-proof-sources
            stage-a-gnu-hello-roundtrip-proof-fragments
            stage-a-gnu-hello-roundtrip-x87-schedule-benchmark
            stage-a-gnu-hello-roundtrip-ordinary-refinement
            stage-a-gnu-hello-roundtrip-x87-candidate-replay
            stage-a-gnu-hello-roundtrip-x87-candidate-replay-source
            stage-a-gnu-hello-roundtrip-x87-replay-bridge-runtime-source
            stage-a-gnu-hello-roundtrip-x87-replay-bridge-runtime
            stage-a-gnu-hello-roundtrip-x87-kernel-execution-source
            stage-a-gnu-hello-roundtrip-x87-kernel-execution
            stage-a-gnu-hello-roundtrip-kernel-lookup-source
            stage-a-gnu-hello-roundtrip-kernel-lookup-native-source
            stage-a-gnu-hello-roundtrip-kernel-lookup-operation-source
            stage-a-gnu-hello-roundtrip-kernel-step-source
            stage-a-gnu-hello-roundtrip-kernel-step-native-source
            stage-a-gnu-hello-roundtrip-kernel-step-operation-source
            stage-a-gnu-hello-roundtrip-kernel-step-program-lookup-call-source
            stage-a-gnu-hello-roundtrip-kernel-step-program-lookup-call-closure-source
            stage-a-gnu-hello-roundtrip-kernel-step-program-lookup-call-closure-proof
            stage-a-gnu-hello-roundtrip-kernel-step-program-lookup-exact-computation-source
            stage-a-gnu-hello-roundtrip-kernel-step-program-lookup-exact-computation-proof
            stage-a-gnu-hello-roundtrip-kernel-operation-frame-parametric-source
            stage-a-gnu-hello-roundtrip-kernel-frame-executor-source
            stage-a-gnu-hello-roundtrip-kernel-run-source
            stage-a-gnu-hello-roundtrip-kernel-run-native-source
            stage-a-gnu-hello-roundtrip-kernel-run-native-proof
            stage-a-gnu-hello-roundtrip-kernel-run-operation-source
            stage-a-gnu-hello-roundtrip-kernel-run-operation-proof
            stage-a-gnu-hello-roundtrip-kernel-run-iteration-proof
            stage-a-gnu-hello-roundtrip-kernel-operation-state-route-proof
            stage-a-gnu-hello-roundtrip-kernel-operation-ranked-state-route-proof
            stage-a-gnu-hello-roundtrip-kernel-operation-route-invariant-proof
            stage-a-gnu-hello-roundtrip-kernel-operation-predicate-route-proof
            stage-a-gnu-hello-roundtrip-kernel-operation-effect-checker-proof
            stage-a-gnu-hello-roundtrip-kernel-operation-memory-route-proof
            stage-a-kernel-cdecl-static-preservation-proof
            stage-a-gnu-hello-roundtrip-kernel-engine-copy-proof
            stage-a-gnu-hello-roundtrip-kernel-operation-state-boundary-proof
            stage-a-gnu-hello-roundtrip-kernel-operation-state-route-run-adapter-proof
            stage-a-gnu-hello-roundtrip-kernel-operation-step-route-adapter-proof
            stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-source
            stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-symbolic-closure-source
            stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-symbolic-closure-proof
            stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-static-preservation-source
            stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-static-preservation-proof
            stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-external-payload-source
            stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-external-payload-proof
            stage-a-gnu-hello-roundtrip-kernel-operation-result-encoding-source
            stage-a-gnu-hello-roundtrip-kernel-operation-result-encoding-proof
            stage-a-gnu-hello-roundtrip-kernel-abstract-operation-transition-source
            stage-a-gnu-hello-roundtrip-kernel-abstract-operation-transition-proof
            stage-a-gnu-hello-roundtrip-kernel-invoke-source
            stage-a-gnu-hello-roundtrip-kernel-invoke-native-source
            stage-a-gnu-hello-roundtrip-kernel-invoke-operation-source
            stage-a-gnu-hello-roundtrip-mixed-candidate-authority-source
            stage-a-gnu-hello-roundtrip-proof
            stage-a-gnu-hello-roundtrip-final
            stage-a-nix-graph-integration
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
            stage-a-relational-tests-isa-qualification-tooling
            stage-a-relational-tests-bounded-table-call-generation
            stage-a-relational-tests-bounded-table-call-kernel
            stage-a-relational-tests-reverse-sentinel-scanner-integration
            stage-a-relational-tests-callsite-preservation
            stage-a-relational-tests-callsite-summary-generation
            stage-a-relational-tests-call-return-summary
            stage-a-relational-tests-callsite-preservation-schema
            stage-a-relational-tests-register-analysis
            stage-a-relational-tests-linked-control-analysis
            stage-a-relational-tests-lean-runtime-frame-import-environment
            stage-a-relational-tests-acceptance-runtime-frame-import
            stage-a-relational-tests-acceptance-runtime-frame-register
            stage-a-relational-tests-opaque-lockstep
            stage-a-relational-tests-static-word-slot-certificate
            stage-a-relational-tests-contract
            stage-a-relational-tests-state
            stage-a-relational-tests-pipeline
            stage-a-relational-tests-pipeline-cmov-general-composition
            stage-a-relational-tests-lean
            stage-a-relational-tests-lean-return-slot-inventory
            stage-a-relational-tests-lean-dynamic-range-result
            stage-a-relational-tests-lean-linked-frames
            stage-a-relational-tests-lean-linked-execution
            stage-a-relational-tests-lean-active-frame-guard
            stage-a-relational-tests-contract-machine-import
            stage-a-relational-tests-acceptance
            stage-a-relational-tests-acceptance-whole-program-kernel
            stage-a-relational-tests-acceptance-nested-linked-calls
            stage-a-relational-tests-acceptance-instruction-adequacy
            stage-a-relational-tests-acceptance-instruction-adequacy-tamper
            stage-a-relational-tests-acceptance-instruction-adequacy-multi-chunk
            stage-a-relational-tests-acceptance-entry-surface
            stage-a-relational-tests-acceptance-direct-loop
            stage-a-relational-tests-acceptance-direct-call-return
            stage-a-relational-tests-acceptance-linked-active-jump
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
            stage-a-relational-tests-acceptance-direct-import-thunk
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
            stage-b-component-analysis-smoke
            stage-b-linked-library-analysis-smoke
            stage-b-jq-machine-ir
            stage-b-jq-linked-islands
            stage-b-gnu-hello-linked-islands
            stage-b-gnu-hello-library-hypotheses
            stage-b-gnu-hello-dynamic-library-requirements
            stage-b-gnu-hello-library-replacement-plan
            stage-b-gnu-hello-call-frontier
            stage-b-gnu-hello-toolchain-runtime-imports
            stage-b-gnu-hello-dependency-envelope
            stage-b-gnu-hello-proposed-source-components
            stage-b-gnu-hello-call-substitution-plan
            stage-b-gnu-hello-source-call-inventory
            stage-b-gnu-hello-source-call-binding-report
            stage-b-gnu-hello-candidate-dependency-audit
            stage-b-gnu-hello-source-call-substitution-smoke
            stage-b-openwatcom19-library-artifact-index
            stage-b-jq-machine-ir-interpreter
            stage-b-jq-reconstruction-plan
            stage-b-jq-component-proposals
            stage-b-jq-selected-component-declarations
            stage-b-jq-selected-component-catalog
            stage-b-jq-component-interfaces
            stage-b-jq-option-name-match-workspace
            stage-b-jq-option-name-match-qualification
            stage-b-jq-option-token-classifier-workspace
            stage-b-jq-option-token-classifier-qualification
            stage-b-jq-stderr-value-kind-route-workspace
            stage-b-jq-stderr-value-kind-route-qualification
            stage-b-jq-debug-value-prefix-workspace
            stage-b-jq-debug-value-prefix-qualification
            stage-b-jq-usage-exit-route-workspace
            stage-b-jq-usage-exit-route-qualification
            stage-b-jq-usage-write-route-workspace
            stage-b-jq-usage-write-route-qualification
            stage-b-jq-option-value-collection-workspace
            stage-b-jq-option-value-collection-qualification
            stage-b-jq-output-value-release-workspace
            stage-b-jq-output-value-release-qualification
            stage-b-jq-output-value-dump-workspace
            stage-b-jq-output-value-dump-qualification
            stage-b-jq-output-value-pipeline-workspace
            stage-b-jq-output-value-pipeline-qualification
            stage-b-jq-wide-argument-conversion-tail-workspace
            stage-b-jq-wide-argument-conversion-tail-qualification
            stage-b-jq-math-error-callback-dispatch-workspace
            stage-b-jq-math-error-callback-dispatch-qualification
            stage-b-jq-pe32-section-count-workspace
            stage-b-jq-pe32-section-count-qualification
            stage-b-jq-pe32-image-base-workspace
            stage-b-jq-pe32-image-base-qualification
            stage-b-jq-pe32-section-for-address-workspace
            stage-b-jq-pe32-section-for-address-qualification
            stage-b-jq-windows-path-info-scan-workspace
            stage-b-jq-windows-path-info-scan-qualification
            stage-b-jq-invalid-parameter-handler-get-workspace
            stage-b-jq-invalid-parameter-handler-get-qualification
            stage-b-jq-invalid-parameter-handler-exchange-workspace
            stage-b-jq-invalid-parameter-handler-exchange-qualification
            stage-b-jq-bounded-string-length-workspace
            stage-b-jq-bounded-string-length-qualification
            stage-b-jq-bounded-wide-string-length-workspace
            stage-b-jq-bounded-wide-string-length-qualification
            stage-b-jq-component-granularity-smoke
            stage-b-jq-component-registry
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
          stage-a-gnu-hello-proof = {
            type = "app";
            program = "${packages.stage-a-gnu-hello-proof}/bin/stage-a-gnu-hello-proof";
          };
          stage-a-minimal-hello-fixtures-root = {
            type = "app";
            program = "${packages.stage-a-minimal-hello-fixtures-root}/bin/stage-a-minimal-hello-fixtures-root";
          };
          stage-a-roundtrip-spike-corpus-root = {
            type = "app";
            program = "${packages.stage-a-roundtrip-spike-corpus-root}/bin/stage-a-roundtrip-spike-corpus-root";
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
            stage-a-isa-core-smoke-qualification
            stage-a-fixtures-check
            stage-a-exit-check
            stage-a-exit-behavior-smoke
            stage-a-winapi-hello-check
            stage-a-gnu-hello-preflight
            stage-b-gnu-hello-lifting-evidence
            stage-b-gnu-hello-semantic-components
            stage-b-gnu-hello-selected-component-catalog
            stage-a-gnu-hello-roundtrip-smoke
            stage-a-gnu-hello-roundtrip-runtime-foundation-proof
            stage-a-gnu-hello-roundtrip-launch-binding-proof
            stage-a-gnu-hello-roundtrip-external-component-proof
            stage-a-gnu-hello-roundtrip-runtime-indirect-composition-proof
            stage-a-gnu-hello-roundtrip-kernel-operation-instantiation-proof
            stage-a-gnu-hello-roundtrip-x87-kernel-execution
            stage-a-gnu-hello-roundtrip-mixed-chunked-acceptance-proof
            stage-a-minimal-hello-check
            stage-a-roundtrip-static-smoke
            stage-a-roundtrip-spike-check
            stage-a-roundtrip-promoted-check
            stage-a-jq-fixtures-check
            stage-a-roundtrip-lean-graph-smoke
            stage-a-nix-graph-integration
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
              pkgs.clang
              pkgs.jq
              pkgs.lean4
              pkgs.lld
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
