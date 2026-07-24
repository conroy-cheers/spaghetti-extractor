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
        mkStageARoundtripCorpus = import ./nix/stage-a-roundtrip-corpus.nix;
        mkStageARoundtripSmoke = import ./nix/stage-a-roundtrip-smoke.nix;
      };

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
          relationalLeanModules = map
            (file: pkgs.lib.removeSuffix ".lean" file)
            (builtins.filter
              (file:
                relationalLeanModuleEntries.${file} == "regular"
                && pkgs.lib.hasSuffix ".lean" file)
              (builtins.attrNames relationalLeanModuleEntries));
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
          relationalRoundtripKernelModules = builtins.filter
            (module:
              builtins.elem module relationalRoundtripRequiredModules
              || builtins.any (prefix: pkgs.lib.hasPrefix prefix module) [
                "RelationalInterpreter"
                "RelationalDefinedness"
                "RelationalNormalization"
              ])
            relationalLeanModules;
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
          relationalAnalysisKernelModules = [
            "X87"
            "RelationalX87"
            "Formal"
            "RelationalX87Decode"
            "ISAQualification"
            "RelationalDecode"
            "RelationalLoader"
            "RelationalFiniteIndex"
            "RelationalMachine"
            "Relational"
            "RelationalX87Machine"
            "RelationalPEExecution"
            "RelationalISAQualification"
          ];
          spaghettiExtractorAnalysisPythonFiles = [
            ./src/spaghetti_extractor/__init__.py
            ./src/spaghetti_extractor/contract_tools.py
            ./src/spaghetti_extractor/errors.py
            ./src/spaghetti_extractor/pe.py
            ./src/spaghetti_extractor/stage_binary.py
            ./src/spaghetti_extractor/util.py
            ./src/spaghetti_extractor/relational/__init__.py
            ./src/spaghetti_extractor/relational/analysis.py
            ./src/spaghetti_extractor/relational/analysis_artifact.py
            ./src/spaghetti_extractor/relational/analysis_reference.py
            ./src/spaghetti_extractor/relational/analysis_cli.py
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
            ./src/spaghetti_extractor/relational/verdict.py
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
            ./src/spaghetti_extractor/relational/analysis_cli.py
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
              ./src/spaghetti_extractor/relational/schema.py
              ./src/spaghetti_extractor/relational/semantic_products_artifact.py
              ./src/spaghetti_extractor/relational/semantic_products_format.py
            ];
          };
          spaghettiExtractorRegisterReplaySource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./src/spaghetti_extractor/__init__.py
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
              ./src/spaghetti_extractor/contract_tools.py
              ./src/spaghetti_extractor/errors.py
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
              ./src/spaghetti_extractor/relational/schema.py
              ./src/spaghetti_extractor/relational/semantic_products_artifact.py
              ./src/spaghetti_extractor/relational/semantic_products_format.py
              ./src/spaghetti_extractor/relational/side_extraction.py
              ./src/spaghetti_extractor/relational/side_extraction_artifact.py
              ./src/spaghetti_extractor/relational/side_isa_artifact.py
              ./src/spaghetti_extractor/relational/analyses/__init__.py
              ./src/spaghetti_extractor/relational/analyses/control.py
              ./src/spaghetti_extractor/relational/analyses/external.py
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
          spaghetti-extractor-analysis = pkgs.writeShellApplication {
            name = "spaghetti-extractor-analysis";
            runtimeInputs = [ pythonEnv ];
            text = ''
              export PYTHONPATH="${spaghettiExtractorAssemblySource}/src''${PYTHONPATH:+:$PYTHONPATH}"
              exec python -m spaghetti_extractor.relational.assembly_cli "$@"
            '';
          };
          spaghetti-extractor-proposal = pkgs.writeShellApplication {
            name = "spaghetti-extractor-proposal";
            runtimeInputs = [ pythonEnv ];
            text = ''
              export PYTHONPATH="${spaghettiExtractorProposalSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
              exec python -m spaghetti_extractor.relational.proposal_cli "$@"
            '';
          };
          spaghetti-extractor-register-replay = pkgs.writeShellApplication {
            name = "spaghetti-extractor-register-replay";
            runtimeInputs = [ pythonEnv ];
            text = ''
              export PYTHONPATH="${spaghettiExtractorRegisterReplaySource}/src''${PYTHONPATH:+:$PYTHONPATH}"
              exec python -m spaghetti_extractor.relational.register_replay_cli "$@"
            '';
          };
          spaghetti-extractor-semantic-products = pkgs.writeShellApplication {
            name = "spaghetti-extractor-semantic-products";
            runtimeInputs = [ pythonEnv ];
            text = ''
              export PYTHONPATH="${spaghettiExtractorSemanticProductsSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
              exec python -m spaghetti_extractor.relational.semantic_products_cli "$@"
            '';
          };
          spaghetti-extractor-memory-products = pkgs.writeShellApplication {
            name = "spaghetti-extractor-memory-products";
            runtimeInputs = [ pythonEnv ];
            text = ''
              export PYTHONPATH="${spaghettiExtractorMemoryProductsSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
              exec python -m spaghetti_extractor.relational.memory_products_cli "$@"
            '';
          };
          spaghetti-extractor-composition-products = pkgs.writeShellApplication {
            name = "spaghetti-extractor-composition-products";
            runtimeInputs = [ pythonEnv ];
            text = ''
              export PYTHONPATH="${spaghettiExtractorCompositionProductsSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
              exec python -m spaghetti_extractor.relational.composition_products_cli "$@"
            '';
          };
          spaghetti-extractor-register-dataflow-problem = pkgs.writeShellApplication {
            name = "spaghetti-extractor-register-dataflow-problem";
            runtimeInputs = [ pythonEnv ];
            text = ''
              export PYTHONPATH="${spaghettiExtractorRegisterDataflowProblemSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
              exec python -m spaghetti_extractor.relational.register_dataflow_problem_cli "$@"
            '';
          };
          spaghettiExtractorPreparationPythonFiles = spaghettiExtractorAnalysisPythonFiles ++ [
            ./src/spaghetti_extractor/relational/build.py
            ./src/spaghetti_extractor/relational/preparation_cli.py
            ./src/spaghetti_extractor/relational/analyses/callbacks.py
            ./src/spaghetti_extractor/relational/analyses/frames.py
            ./src/spaghetti_extractor/relational/analyses/linked_control.py
            ./src/spaghetti_extractor/relational/lean/acceptance.py
            ./src/spaghetti_extractor/relational/lean/affine_frames.py
            ./src/spaghetti_extractor/relational/lean/affine_linked_control.py
            ./src/spaghetti_extractor/relational/lean/callbacks.py
            ./src/spaghetti_extractor/relational/lean/composition.py
            ./src/spaghetti_extractor/relational/lean/definitions.py
            ./src/spaghetti_extractor/relational/lean/generation.py
            ./src/spaghetti_extractor/relational/lean/scanner.py
            ./src/spaghetti_extractor/relational/lean/segments.py
          ];
          spaghettiExtractorPreparationSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              (pkgs.lib.fileset.unions spaghettiExtractorPreparationPythonFiles)
              ./src/spaghetti_extractor/lean/StageA
            ];
          };
          spaghetti-extractor-preparation = pkgs.writeShellApplication {
            name = "spaghetti-extractor-preparation";
            runtimeInputs = [
              pythonEnv
              pkgs.lean4
            ];
            text = ''
              export PYTHONPATH="${spaghettiExtractorPreparationSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
              exec python -m spaghetti_extractor.relational.preparation_cli "$@"
            '';
          };
          spaghettiExtractorRegionFactsPythonFiles = [
            ./src/spaghetti_extractor/__init__.py
            ./src/spaghetti_extractor/contract_tools.py
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
          spaghetti-extractor-region-facts = pkgs.writeShellApplication {
            name = "spaghetti-extractor-region-facts";
            runtimeInputs = [
              pythonEnv
              pkgs.lean4
            ];
            text = ''
              export PYTHONPATH="${spaghettiExtractorRegionFactsSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
              exec python -m spaghetti_extractor.relational.region_facts_cli "$@"
            '';
          };
          spaghettiExtractorMappingPythonFiles = [
            ./src/spaghetti_extractor/__init__.py
            ./src/spaghetti_extractor/contract_tools.py
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
            ./src/spaghetti_extractor/errors.py
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
          spaghetti-extractor-normalize = pkgs.writeShellApplication {
            name = "spaghetti-extractor-normalize";
            runtimeInputs = [ pythonEnv ];
            text = ''
              export PYTHONPATH="${spaghettiExtractorNormalizationSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
              exec python -m spaghetti_extractor.relational.pair_normalization_cli "$@"
            '';
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
          spaghetti-extractor-dataflow =
            (pkgs.writeShellApplication {
              name = "spaghetti-extractor-dataflow";
              runtimeInputs = [ pkgs.python3 ];
              text = ''
                export PYTHONPATH="${spaghettiExtractorDataflowSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
                exec python -m spaghetti_extractor.relational.register_dataflow_cli "$@"
              '';
            }).overrideAttrs
              { preferLocalBuild = true; };
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
          spaghetti-extractor-dataflow-worker =
            (pkgs.writeShellApplication {
              name = "spaghetti-extractor-dataflow-worker";
              runtimeInputs = [ pkgs.python3 ];
              text = ''
                export PYTHONPATH="${spaghettiExtractorDataflowWorkerSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
                exec python -m spaghetti_extractor.relational.register_dataflow_worker_cli "$@"
              '';
            }).overrideAttrs
              { preferLocalBuild = true; };
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
          spaghetti-extractor-dataflow-summary =
            (pkgs.writeShellApplication {
              name = "spaghetti-extractor-dataflow-summary";
              runtimeInputs = [ pkgs.python3 ];
              text = ''
                export PYTHONPATH="${spaghettiExtractorDataflowSummarySource}/src''${PYTHONPATH:+:$PYTHONPATH}"
                exec python -m spaghetti_extractor.relational.register_dataflow_summary_cli "$@"
              '';
            }).overrideAttrs
              { preferLocalBuild = true; };
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
          spaghetti-extractor-dataflow-plan =
            (pkgs.writeShellApplication {
              name = "spaghetti-extractor-dataflow-plan";
              runtimeInputs = [ pkgs.python3 ];
              text = ''
                export PYTHONPATH="${spaghettiExtractorDataflowPlanSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
                exec python -m spaghetti_extractor.relational.register_dataflow_plan_cli "$@"
              '';
            }).overrideAttrs
              { preferLocalBuild = true; };
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
          spaghetti-extractor-dataflow-aggregate =
            (pkgs.writeShellApplication {
              name = "spaghetti-extractor-dataflow-aggregate";
              runtimeInputs = [ pkgs.python3 ];
              text = ''
                export PYTHONPATH="${spaghettiExtractorDataflowAggregateSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
                exec python -m spaghetti_extractor.relational.register_dataflow_aggregate_cli "$@"
              '';
            }).overrideAttrs
              { preferLocalBuild = true; };
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
          spaghetti-extractor-dataflow-compare =
            (pkgs.writeShellApplication {
              name = "spaghetti-extractor-dataflow-compare";
              runtimeInputs = [ pkgs.python3 ];
              text = ''
                export PYTHONPATH="${spaghettiExtractorDataflowCompareSource}/src''${PYTHONPATH:+:$PYTHONPATH}"
                exec python -m spaghetti_extractor.relational.register_dataflow_compare_cli "$@"
              '';
            }).overrideAttrs
              { preferLocalBuild = true; };
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
                test ! -e "$source/relational/analysis_cli.py"
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
                test ! -e "$proposal/relational/analysis_cli.py"
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
                ${spaghetti-extractor-semantic-products}/bin/spaghetti-extractor-semantic-products --help >/dev/null
                memory="${spaghettiExtractorMemoryProductsSource}/src/spaghetti_extractor"
                test -f "$memory/relational/memory_products.py"
                test -f "$memory/relational/memory_products_artifact.py"
                test -f "$memory/relational/memory_products_cli.py"
                test ! -e "$memory/relational/pipeline.py"
                test ! -e "$memory/relational/assembly.py"
                test ! -e "$memory/relational/semantic_products.py"
                ${spaghetti-extractor-memory-products}/bin/spaghetti-extractor-memory-products --help >/dev/null
                composition="${spaghettiExtractorCompositionProductsSource}/src/spaghetti_extractor"
                test -f "$composition/relational/composition_products.py"
                test -f "$composition/relational/composition_products_artifact.py"
                test -f "$composition/relational/composition_products_cli.py"
                test -f "$composition/relational/analyses/control.py"
                test -f "$composition/relational/analyses/semantic_control.py"
                test -f "$composition/relational/analyses/segments.py"
                test "$(find "$composition/lean/StageA" -type f -name '*.lean' | wc -l)" -eq 13
                test ! -e "$composition/relational/pipeline.py"
                test ! -e "$composition/relational/assembly.py"
                test ! -e "$composition/relational/register_replay.py"
                test ! -e "$composition/relational/semantic_products.py"
                test ! -e "$composition/relational/memory_products.py"
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
                ${spaghetti-extractor-register-dataflow-problem}/bin/spaghetti-extractor-register-dataflow-problem --help >/dev/null
                preparation="${spaghettiExtractorPreparationSource}/src/spaghetti_extractor"
                test -f "$preparation/relational/build.py"
                test -f "$preparation/relational/preparation_cli.py"
                test -f "$preparation/relational/analysis_reference.py"
                test -f "$preparation/relational/report_schema.py"
                test -f "$preparation/relational/lean/generation.py"
                test -f "$preparation/relational/lean/acceptance.py"
                test -f "$preparation/relational/lean/affine_frames.py"
                test -f "$preparation/relational/lean/affine_linked_control.py"
                test -f "$preparation/relational/analyses/affine_linked_control.py"
                test -f "$preparation/relational/analyses/linked_control.py"
                test ! -e "$preparation/cli.py"
                test ! -e "$preparation/stage_b.py"
                test ! -e "$preparation/relational/executor.py"
                test "$(find "$preparation/lean/StageA" -type f -name '*.lean' | wc -l)" -eq 32
                ${spaghetti-extractor-preparation}/bin/spaghetti-extractor-preparation --help >/dev/null
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
                test ! -e "$mapping/relational/report_schema.py"
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
          stage-a-fixtures-check =
            pkgs.runCommand "stage-a-fixtures-check"
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
          stage-a-exit-evidence-bundle = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = false;
            prepared = stage-a-exit-prepared-proof + "/report/relational-v3";
            targetNodes = [ "relationalacceptance" ];
            targetBundle = true;
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
          stage-a-winapi-hello-proof-audit = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = false;
            prepared = stage-a-winapi-hello-prepared-proof + "/report/relational-v3";
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
                  .acceptance.linked_acceptance.status == "ready" and
                  .acceptance.linked_acceptance.theorem ==
                    "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked" and
                  .acceptance.linked_acceptance.blockers == [] and
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
                  . as $graph |
                  .format == "stage-a-lean-module-graph-v1" and
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
                    .resource_class == "light"
                  ) and
                  any(.nodes[];
                    .modules == ["RelationalLaunchCheckCertificate"] and
                    (.dependencies | length) > 0 and
                    all(.dependencies[];
                      . as $dependency |
                      any($graph.nodes[]; .id == $dependency))
                  )
                ' "$prepared/module-graph.json" >/dev/null
                jq -e '
                  .format == "stage-a-relational-lean-audit-v1" and
                  .status == "checked" and
                  .theorem ==
                    "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked" and
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
                  (.files | length) == 6
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
              pkgs.nix
            ];
            text = ''
              if [ "$#" -gt 1 ]; then
                echo "usage: stage-a-gnu-hello-proof [OUTPUT-DIRECTORY]" >&2
                exit 2
              fi
              out="''${1:-$PWD/build/stage-a-gnu-hello-launch-proof}"
              export SPAGHETTI_EXTRACTOR_STAGE_A_NIX_CONTENT_ADDRESSED=false
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
          stage-a-minimal-hello-prepared-proof =
            pkgs.runCommand "stage-a-minimal-hello-prepared-proof"
              {
                nativeBuildInputs = [
                  spaghetti-extractor-preparation
                ];
              }
              ''
                fixture_dir="${stage-a-minimal-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/minimal-hello-o2-alignment"
                work="$TMPDIR/stage-a-minimal-hello"
                mkdir -p "$work"
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-relational-ifd-kernel-cache}"
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_JOBS=16
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_LAUNCH_CHECK_CHUNK=1024
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_STATIC_CODE_MAP_NIX_PACK_MODULES=1
                SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$work/relational-cache" \
                  spaghetti-extractor-preparation prepare-relational \
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
          stage-a-minimal-hello-proof-smoke = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = false;
            prepared = stage-a-minimal-hello-prepared-proof + "/report/relational-v3";
            targetNodes = [ "relationalsegmentrefinementedge127" ];
            targetBundle = true;
          };
          stage-a-minimal-hello-launch-proof = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = false;
            prepared = stage-a-minimal-hello-prepared-proof + "/report/relational-v3";
            targetNodes = [ "relationallaunchrealizabilitycertificate" ];
            targetBundle = true;
          };
          stage-a-minimal-hello-segment-proofs = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = false;
            prepared = stage-a-minimal-hello-prepared-proof + "/report/relational-v3";
            targetNodes = [ "relationalsegmentrefinementcertificate" ];
            targetBundle = true;
          };
          stage-a-minimal-hello-evidence-bundle = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = false;
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
                mkdir -p "$out"
                spaghetti-extractor-mapping generate-relation-contract \
                  --original "$fixture_dir/jq-original.exe" \
                  --candidate "$fixture_dir/jq-candidate.exe" \
                  --mapping "${stage-a-jq-static-map}/jq-block-map.json" \
                  --external-profile "${./profiles/pe32-kernel32-lockstep-v1.json}" \
                  --external-profile "${./profiles/pe32-msvcrt-lockstep-v1.json}" \
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
          relationalKernelModules = pkgs.lib.unique ([
            "X87"
            "RelationalX87"
            "Formal"
            "RelationalX87Decode"
            "ISAQualification"
            "ISAConformance"
            "ISAConformanceRunner"
            "RelationalDecode"
            "RelationalLoader"
            "RelationalFiniteIndex"
            "RelationalMachine"
            "RelationalPEExecution"
            "RelationalISAQualification"
            "Relational"
            "RelationalX87Machine"
            "RelationalInvariant"
            "RelationalExactExpr"
            "RelationalExecution"
            "RelationalImage"
            "RelationalSegment"
            "RelationalComposition"
            "RelationalLinkedFrames"
            "RelationalEnvironment"
            "RelationalCallbacks"
            "RelationalAffineFrames"
            "RelationalAffineLinkedFrames"
            "RelationalCertificates"
            "RelationalLinkedExecution"
            "RelationalPEWorldExecution"
            "RelationalStaticTree"
          ] ++ relationalRoundtripKernelModules);
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
          stage-a-relational-analysis-kernel-cache = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = false;
            standaloneSourceRoot = relationalAnalysisLeanSource + "/src/spaghetti_extractor/lean/StageA";
            standaloneModules = relationalAnalysisKernelModules;
            targetNodes = relationalAnalysisKernelModules;
            targetBundle = true;
          };
          stage-a-relational-kernel-cache = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            standaloneSourceRoot = relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
            standaloneModules = relationalKernelModules;
            standaloneModuleResources = relationalRoundtripKernelResources;
            targetNodes = relationalKernelModules;
            targetBundle = true;
          };
          # Generated-proof IFD consumers need a stable source-root path during
          # pure evaluation. Keep this input-addressed while the main kernel
          # cache remains eligible for CA reuse by non-IFD proof graphs.
          stage-a-relational-ifd-kernel-cache = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = false;
            standaloneSourceRoot = relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
            standaloneModules = relationalKernelModules;
            standaloneModuleResources = relationalRoundtripKernelResources;
            targetNodes = relationalKernelModules;
            targetBundle = true;
          };
          stage-a-roundtrip-lean-graph-smoke = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = false;
            standaloneSourceRoot = relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
            standaloneModules = relationalKernelModules;
            standaloneModuleResources = relationalRoundtripKernelResources;
            targetNodes = relationalRoundtripKernelModules;
            graphSmoke = true;
          };
          stage-a-roundtrip-lean-remote-smoke = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = false;
            standaloneSourceRoot = ./nix/fixtures/stage-a-remote-lean-smoke;
            standaloneModules = [ "RemoteSmokeA" "RemoteSmokeB" ];
            targetNodes = [ "RemoteSmokeA" "RemoteSmokeB" ];
            targetBundle = true;
            targetAxiomAudit = {
              module = "RemoteSmokeA";
              declaration = "inputAddressedRemoteSmokeA";
              approved_axioms = [];
            };
          };
          mkStageARoundtripLeanTarget = targetNodes:
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs targetNodes;
              contentAddressed = false;
              standaloneSourceRoot = relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
              standaloneModules = relationalKernelModules;
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
          stage-a-roundtrip-lean-environment = mkStageARoundtripLeanTarget [
            "RelationalLockstepEnvironment"
            "RelationalOpaqueLockstepEnvironment"
          ];
          # Input-addressed by design: both configured builders can execute
          # this graph today. Each Lean module remains its own derivation, so
          # proof-only changes invalidate only the affected descendants.
          stage-a-roundtrip-lean-kernel-cache = import ./nix/stage-a-lean-graph.nix {
            inherit pkgs;
            contentAddressed = false;
            standaloneSourceRoot = relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
            standaloneModules = relationalKernelModules;
            standaloneModuleResources = relationalRoundtripKernelResources;
            targetNodes = relationalRoundtripKernelModules;
            targetBundle = true;
          };
          gnuHelloRoundtrip = import ./nix/gnu-hello-roundtrip.nix {
            inherit pkgs pythonEnv mingw32;
            spaghettiExtractor = spaghetti-extractor;
            sourceRoot = spaghettiExtractorCoreSource;
            leanSourceRoot = relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
            originalFixture = stage-a-gnu-hello-original;
          };
          stage-a-gnu-hello-roundtrip-smoke = gnuHelloRoundtrip.smoke;
          stage-a-gnu-hello-roundtrip-static-export = gnuHelloRoundtrip.staticExport;
          stage-b-gnu-hello-roundtrip-interpreter = gnuHelloRoundtrip.interpreter;
          stage-b-gnu-hello-roundtrip-native-engine = gnuHelloRoundtrip.nativeEngine;
          stage-b-gnu-hello-roundtrip-native-runtime = gnuHelloRoundtrip.nativeRuntime;
          stage-b-gnu-hello-roundtrip-candidate = gnuHelloRoundtrip.candidate;
          stage-a-gnu-hello-roundtrip-engine-segments = gnuHelloRoundtrip.engineSegments;
          stage-a-gnu-hello-roundtrip-compiled-kernel-source =
            gnuHelloRoundtrip.kernelLean;
          stage-a-gnu-hello-roundtrip-static-machine-import-source =
            gnuHelloRoundtrip.staticMachineImportContractsLean;
          stage-a-gnu-hello-roundtrip-universal-paired-external-environment-source =
            gnuHelloRoundtrip.universalPairedExternalEnvironmentLean;
          stage-a-gnu-hello-roundtrip-static-machine-import-proof-sources =
            gnuHelloRoundtrip.staticMachineImportProofSources;
          stage-a-gnu-hello-roundtrip-static-machine-import-proof =
            gnuHelloRoundtrip.staticMachineImportProof;
          stage-a-gnu-hello-roundtrip-mixed-original-source =
            gnuHelloRoundtrip.mixedOriginalLean;
          stage-a-gnu-hello-roundtrip-mixed-original-static-reachability-source =
            gnuHelloRoundtrip.mixedOriginalStaticReachabilityLean;
          stage-a-gnu-hello-roundtrip-mixed-original-static-reachability-proof-sources =
            gnuHelloRoundtrip.mixedOriginalStaticReachabilityProofSources;
          stage-a-gnu-hello-roundtrip-mixed-original-static-reachability-proof =
            gnuHelloRoundtrip.mixedOriginalStaticReachabilityProof;
          stage-a-gnu-hello-roundtrip-mixed-original-writable-slot-authority-lean =
            gnuHelloRoundtrip.mixedOriginalWritableSlotAuthorityLean;
          stage-a-gnu-hello-roundtrip-mixed-original-register-indirect-authority-source =
            gnuHelloRoundtrip.mixedOriginalRegisterIndirectAuthorityLean;
          stage-a-gnu-hello-roundtrip-mixed-original-register-indirect-authority-proof-sources =
            gnuHelloRoundtrip.mixedOriginalRegisterIndirectAuthorityProofSources;
          stage-a-gnu-hello-roundtrip-mixed-original-register-indirect-authority-proof =
            gnuHelloRoundtrip.mixedOriginalRegisterIndirectAuthorityProof;
          stage-a-gnu-hello-roundtrip-mixed-original-direct-call-proposals-source =
            gnuHelloRoundtrip.mixedOriginalDirectCallProposalsLean;
          stage-a-gnu-hello-roundtrip-mixed-original-direct-call-proposal-proof-sources =
            gnuHelloRoundtrip.mixedOriginalDirectCallProposalProofSources;
          stage-a-gnu-hello-roundtrip-mixed-original-direct-call-proposal-proof =
            gnuHelloRoundtrip.mixedOriginalDirectCallProposalProof;
          stage-a-gnu-hello-roundtrip-mixed-original-direct-call-semantics-source =
            gnuHelloRoundtrip.mixedOriginalDirectCallSemanticsLean;
          stage-a-gnu-hello-roundtrip-mixed-original-carrier-binding-source =
            gnuHelloRoundtrip.mixedOriginalCarrierBindingLean;
          stage-a-gnu-hello-roundtrip-mixed-original-carrier-binding-proof-sources =
            gnuHelloRoundtrip.mixedOriginalCarrierBindingProofSources;
          stage-a-gnu-hello-roundtrip-mixed-original-carrier-binding-proof =
            gnuHelloRoundtrip.mixedOriginalCarrierBindingProof;
          stage-a-gnu-hello-roundtrip-mixed-original-diagnostic =
            gnuHelloRoundtrip.mixedOriginalDiagnostic;
          stage-a-gnu-hello-roundtrip-kernel-data-source =
            gnuHelloRoundtrip.kernelDataLean;
          stage-a-gnu-hello-roundtrip-kernel-abi-source =
            gnuHelloRoundtrip.kernelAbiLean;
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
          stage-a-gnu-hello-roundtrip-native-launch-graph-source =
            gnuHelloRoundtrip.nativeLaunchGraphLean;
          stage-a-gnu-hello-roundtrip-native-launch-graph-proof-sources =
            gnuHelloRoundtrip.nativeLaunchGraphProofSources;
          stage-a-gnu-hello-roundtrip-native-launch-graph-proof =
            gnuHelloRoundtrip.nativeLaunchGraphProof;
          stage-a-gnu-hello-roundtrip-proof-sources = gnuHelloRoundtrip.proofSources;
          stage-a-gnu-hello-roundtrip-acceptance-source =
            gnuHelloRoundtrip.acceptanceLean;
          stage-a-gnu-hello-roundtrip-final-proof-sources =
            gnuHelloRoundtrip.finalProofSources;
          stage-a-gnu-hello-roundtrip-proof-fragments = gnuHelloRoundtrip.proofFragments;
          stage-a-gnu-hello-roundtrip-x87-schedule-benchmark =
            gnuHelloRoundtrip.x87ScheduleBenchmark;
          stage-a-gnu-hello-roundtrip-ordinary-refinement =
            gnuHelloRoundtrip.ordinaryRefinementFragments;
          stage-a-gnu-hello-roundtrip-x87-candidate-replay-source =
            gnuHelloRoundtrip.x87CandidateReplayLean;
          stage-a-gnu-hello-roundtrip-x87-candidate-replay =
            gnuHelloRoundtrip.x87CandidateReplayFragments;
          stage-a-gnu-hello-roundtrip-x87-replay-bridge-runtime-source =
            gnuHelloRoundtrip.x87ReplayBridgeRuntimeLean;
          stage-a-gnu-hello-roundtrip-x87-replay-bridge-runtime =
            gnuHelloRoundtrip.x87ReplayBridgeRuntimeFragments;
          stage-a-gnu-hello-roundtrip-x87-kernel-execution-source =
            gnuHelloRoundtrip.x87KernelExecutionLean;
          stage-a-gnu-hello-roundtrip-x87-kernel-execution =
            gnuHelloRoundtrip.x87KernelExecutionFragments;
          stage-a-gnu-hello-roundtrip-kernel-lookup-source =
            gnuHelloRoundtrip.kernelLookupLean;
          stage-a-gnu-hello-roundtrip-kernel-lookup-native-source =
            gnuHelloRoundtrip.kernelLookupNativeLean;
          stage-a-gnu-hello-roundtrip-kernel-lookup-operation-source =
            gnuHelloRoundtrip.kernelLookupOperationLean;
          stage-a-gnu-hello-roundtrip-kernel-step-source =
            gnuHelloRoundtrip.kernelStepLean;
          stage-a-gnu-hello-roundtrip-kernel-step-native-source =
            gnuHelloRoundtrip.kernelStepNativeLean;
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
          stage-a-gnu-hello-roundtrip-kernel-run-source =
            gnuHelloRoundtrip.kernelRunLean;
          stage-a-gnu-hello-roundtrip-kernel-run-native-source =
            gnuHelloRoundtrip.kernelRunNativeLean;
          stage-a-gnu-hello-roundtrip-kernel-run-native-proof =
            gnuHelloRoundtrip.kernelRunNativeProof;
          stage-a-gnu-hello-roundtrip-kernel-run-operation-source =
            gnuHelloRoundtrip.kernelRunOperationLean;
          stage-a-gnu-hello-roundtrip-kernel-run-operation-proof =
            gnuHelloRoundtrip.kernelRunOperationProof;
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
          stage-a-gnu-hello-roundtrip-kernel-invoke-source =
            gnuHelloRoundtrip.kernelInvokeLean;
          stage-a-gnu-hello-roundtrip-kernel-invoke-native-source =
            gnuHelloRoundtrip.kernelInvokeNativeLean;
          stage-a-gnu-hello-roundtrip-kernel-invoke-operation-source =
            gnuHelloRoundtrip.kernelInvokeOperationLean;
          stage-a-gnu-hello-roundtrip-mixed-candidate-authority-source =
            gnuHelloRoundtrip.mixedCandidateAuthorityLean;
          stage-a-gnu-hello-roundtrip-proof = gnuHelloRoundtrip.proofReport;
          stage-a-gnu-hello-roundtrip-final = gnuHelloRoundtrip.final;
          stage-a-nix-graph-integration = pkgs.runCommand
            "stage-a-nix-graph-integration"
            {
              nativeBuildInputs = [ pkgs.jq ];
              preferLocalBuild = true;
            }
            ''
              manifest="${stage-a-roundtrip-lean-graph-smoke}/graph-smoke.json"
              jq -e \
                --argjson expected '${builtins.toJSON relationalRoundtripKernelModules}' \
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
              mkdir -p "$out"
              cp "$manifest" "$out/graph-smoke.json"
              cat > "$out/commands.txt" <<'COMMANDS'
              nix build .#stage-a-roundtrip-lean-graph-smoke --no-link
              nix build .#stage-a-roundtrip-lean-remote-smoke --no-link --max-jobs 0 --builders "@${./nix/stage-a-builders}" --option builders-use-substitutes true
              nix build .#stage-a-roundtrip-lean-transfer .#stage-a-roundtrip-lean-x87 --no-link --max-jobs 0 --builders "@${./nix/stage-a-builders}" --option builders-use-substitutes true
              nix build .#stage-a-roundtrip-lean-kernel-cache --no-link --max-jobs 0 --builders "@${./nix/stage-a-builders}" --option builders-use-substitutes true
              COMMANDS
            '';
          mkStageARelationalTest =
            name: module: testFiles:
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
          mkStageARelationalTestSuite =
            name: module: className: testFile:
            let
              testMethods = builtins.filter (method: method != null) (
                map (
                  line:
                  let
                    matched = builtins.match "^    def (test_[A-Za-z0-9_]+)\\(self.*$" line;
                  in
                  if matched == null then null else builtins.head matched
                ) (pkgs.lib.splitString "\n" (builtins.readFile testFile))
              );
              cases = builtins.listToAttrs (
                map (
                  method:
                  let
                    caseName = pkgs.lib.removePrefix "test_" method;
                  in
                  {
                    name = caseName;
                    value = mkStageARelationalTest "${name}-${caseName}" "${module}.${className}.${method}" [
                      testFile
                    ];
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
              [ ./tests/test_stage_a_isa_conformance_bochs.py ];
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
              ./tests/test_stage_a_relational_acceptance.py;
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
          mkRoundtripCasePreparation =
            args:
            let
              original = roundtripCaseArtifact args "original_pe";
              candidate = roundtripCaseArtifact args "candidate_pe";
              relation = roundtripCaseArtifact args "relation_contract";
            in
            pkgs.runCommand (pkgs.lib.strings.sanitizeDerivationName "${args.caseId}-roundtrip-preparation")
              {
                nativeBuildInputs = [
                  spaghetti-extractor
                  pkgs.coreutils
                  pkgs.jq
                  pkgs.lean4
                ];
                # This is the IFD manifest/source boundary. Its output path must
                # be concrete while the generated Lean graph is evaluated;
                # floating CA outputs remain unresolved placeholders there.
                preferLocalBuild = false;
                allowSubstitutes = true;
                passthru = {
                  caseId = args.caseId;
                  phase = "proof-preparation";
                };
              }
              ''
                export HOME="$TMPDIR/home"
                export XDG_CACHE_HOME="$TMPDIR/xdg-cache"
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$TMPDIR/relational-cache"
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-relational-analysis-kernel-cache}"
                mkdir -p "$HOME" "$XDG_CACHE_HOME" \
                  "$SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE"
                test -f ${pkgs.lib.escapeShellArg args.staticPreflight}
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
                ${spaghetti-extractor}/bin/spaghetti-extractor \
                  stage-a-prepare-relational \
                  --original ${pkgs.lib.escapeShellArg "${args.caseRoot}/${original.path}"} \
                  --candidate ${pkgs.lib.escapeShellArg "${args.caseRoot}/${candidate.path}"} \
                  --relation-contract ${pkgs.lib.escapeShellArg "${args.caseRoot}/${relation.path}"} \
                  --out "$TMPDIR/base-prepared" \
                  > "$TMPDIR/preparation-command.json"
                ${
                  if args.case.expectation.disposition == "violated" then
                    ''
                      ${spaghetti-extractor}/bin/spaghetti-extractor \
                        stage-a-prepare-violation \
                        --case ${pkgs.lib.escapeShellArg args.caseManifest} \
                        --case-root ${pkgs.lib.escapeShellArg args.caseRoot} \
                        --prepared "$TMPDIR/base-prepared" \
                        --out "$out" \
                        > "$TMPDIR/violation-preparation-command.json"
                      cp "$TMPDIR/violation-preparation-command.json" \
                        "$out/violation-preparation-command.json"
                    ''
                  else
                    ''
                      cp -R "$TMPDIR/base-prepared" "$out"
                    ''
                }
                cp "$TMPDIR/preparation-command.json" "$out/preparation-command.json"
                jq -e '
                  .format == "stage-a-prepared-relational-v1" and
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
              import ./nix/stage-a-lean-compact.nix {
                inherit pkgs;
                prepared = args.preparation;
                precompiledKernel = stage-a-relational-kernel-cache;
                contentAddressed = args.contentAddressed;
              }
            else
              assert builtins.elem negativeNode nodeIds;
              import ./nix/stage-a-lean-compact.nix {
                inherit pkgs;
                prepared = args.preparation;
                precompiledKernel = stage-a-relational-kernel-cache;
                targetNode = negativeNode;
                targetBundle = true;
                contentAddressed = args.contentAddressed;
              };
          mkRoundtripCaseAudit =
            args:
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
                  ${pkgs.lib.escapeShellArg (toString args.preparation)} \
                  ${pkgs.lib.escapeShellArg (toString args.proofDag)} \
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
                    "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent",
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
                        }
                elif expectation == "violated":
                    import subprocess
                    violation_out = result_path.parent / "violation-audit-work"
                    command = [
                        "${spaghetti-extractor}/bin/spaghetti-extractor",
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
                    "nix": {
                        "preparation_store_path": str(prepared),
                        "proof_dag_store_path": str(proof),
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
              # The qualification must schedule on heterogeneous remote builders;
              # the compact evaluator still supports CA derivations when all
              # configured builders advertise that experimental feature.
              contentAddressed ? false,
            }:
            import ./nix/stage-a-roundtrip-corpus.nix {
              inherit pkgs name contentAddressed;
              spaghettiExtractor = spaghetti-extractor;
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
            contentAddressed = false;
          };
          stageARoundtripPromotedQualification = mkStageARoundtripQualification {
            name = "stage-a-roundtrip-promoted";
            count = 75;
            expectedCounts = {
              pass = 50;
              violated = 25;
              incomplete = 0;
            };
            contentAddressed = false;
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
            spaghetti-extractor-register-dataflow-problem
            spaghetti-extractor-register-replay
            spaghetti-extractor-semantic-products
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
            stage-a-roundtrip-lean-environment
            stage-a-roundtrip-lean-kernel-cache
            stage-a-gnu-hello-roundtrip-smoke
            stage-a-gnu-hello-roundtrip-static-export
            stage-b-gnu-hello-roundtrip-interpreter
            stage-b-gnu-hello-roundtrip-native-engine
            stage-b-gnu-hello-roundtrip-native-runtime
            stage-b-gnu-hello-roundtrip-candidate
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
            stage-a-gnu-hello-roundtrip-mixed-original-direct-call-proposals-source
            stage-a-gnu-hello-roundtrip-mixed-original-direct-call-proposal-proof-sources
            stage-a-gnu-hello-roundtrip-mixed-original-direct-call-proposal-proof
            stage-a-gnu-hello-roundtrip-mixed-original-direct-call-semantics-source
            stage-a-gnu-hello-roundtrip-mixed-original-carrier-binding-source
            stage-a-gnu-hello-roundtrip-mixed-original-carrier-binding-proof-sources
            stage-a-gnu-hello-roundtrip-mixed-original-carrier-binding-proof
            stage-a-gnu-hello-roundtrip-mixed-original-diagnostic
            stage-a-gnu-hello-roundtrip-kernel-data-source
            stage-a-gnu-hello-roundtrip-kernel-abi-source
            stage-a-gnu-hello-roundtrip-constructive-source-coverage-source
            stage-a-gnu-hello-roundtrip-constructive-source-coverage-proof-sources
            stage-a-gnu-hello-roundtrip-constructive-source-coverage-proof
            stage-a-gnu-hello-roundtrip-canonical-relation-core-source
            stage-a-gnu-hello-roundtrip-canonical-relation-core-proof-sources
            stage-a-gnu-hello-roundtrip-canonical-relation-core-proof
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
            stage-a-fixtures-check
            stage-a-exit-check
            stage-a-exit-behavior-smoke
            stage-a-winapi-hello-check
            stage-a-winapi-hello-behavior-smoke
            stage-a-gnu-hello-preflight
            stage-a-gnu-hello-roundtrip-smoke
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
