{ pkgs }:

let
  lib = pkgs.lib;
  root = ../.;
  interpreterFiles = lib.fileset.unions [
    ../src/spaghetti_extractor/__init__.py
    ../src/spaghetti_extractor/artifact_formats.py
    ../src/spaghetti_extractor/errors.py
    ../src/spaghetti_extractor/machine_import_profiles.py
    ../src/spaghetti_extractor/pe.py
    ../src/spaghetti_extractor/relational/__init__.py
    ../src/spaghetti_extractor/relational/definedness.py
    ../src/spaghetti_extractor/stage_b_api_catalog.py
    ../src/spaghetti_extractor/stage_b_c_backend.py
    ../src/spaghetti_extractor/stage_b_interpreter_backend.py
    ../src/spaghetti_extractor/stage_b_state_machine.py
    ../src/spaghetti_extractor/stage_b_typed_x87.py
    ../src/spaghetti_extractor/stage_binary.py
    ../src/spaghetti_extractor/util.py
  ];
  runtimeFiles = lib.fileset.unions [
    ../src/spaghetti_extractor/__init__.py
    ../src/spaghetti_extractor/artifact_formats.py
    ../src/spaghetti_extractor/errors.py
    ../src/spaghetti_extractor/callable_external_runtime.py
    ../src/spaghetti_extractor/import_abi.py
    ../src/spaghetti_extractor/internal_call_summaries.py
    ../src/spaghetti_extractor/machine_abi.py
    ../src/spaghetti_extractor/machine_import_profiles.py
    ../src/spaghetti_extractor/util.py
    ../src/spaghetti_extractor/pe.py
    ../src/spaghetti_extractor/stage_binary.py
    ../src/spaghetti_extractor/contract_tools.py
    ../src/spaghetti_extractor/_contract_tools
    ../src/spaghetti_extractor/roundtrip_fuzz/image_contract.py
    ../src/spaghetti_extractor/relational/__init__.py
    ../src/spaghetti_extractor/relational/lean/__init__.py
    ../src/spaghetti_extractor/relational/lean/callable_external_capability.py
    ../src/spaghetti_extractor/relational/lean/callable_external_execution.py
    ../src/spaghetti_extractor/relational/definedness.py
    ../src/spaghetti_extractor/relational/semantic_cutpoints.py
    ../src/spaghetti_extractor/relational/x87_profile.py
    ../src/spaghetti_extractor/reconstruction_ir.py
    ../src/spaghetti_extractor/reconstruction_control.py
    ../src/spaghetti_extractor/value_provenance.py
    ../src/spaghetti_extractor/reconstruction_composition.py
    ../src/spaghetti_extractor/reconstruction_contract_analysis.py
    ../src/spaghetti_extractor/reconstruction_validation.py
    ../src/spaghetti_extractor/reconstruction_workspace.py
    ../src/spaghetti_extractor/region_replacement.py
    ../src/spaghetti_extractor/stage_b_api_catalog.py
    ../src/spaghetti_extractor/stage_b_c_backend.py
    ../src/spaghetti_extractor/stage_b_engine_layout.py
    ../src/spaghetti_extractor/stage_b_interpreter_backend.py
    ../src/spaghetti_extractor/stage_b_typed_x87.py
    ../src/spaghetti_extractor/stage_b_native_engine.py
    ../src/spaghetti_extractor/stage_b_native_runtime.py
    ../src/spaghetti_extractor/stage_b_state_machine.py
  ];
  workspaceFiles = lib.fileset.unions [
    runtimeFiles
    ../src/spaghetti_extractor/bounded_component_contract.py
    ../src/spaghetti_extractor/component_profile.py
    ../src/spaghetti_extractor/component_workspace.py
    ../src/spaghetti_extractor/component_interface.py
    ../src/spaghetti_extractor/finite_component_contract.py
    ../src/spaghetti_extractor/linked_library_contracts.py
    ../src/spaghetti_extractor/reconstruction_validation.py
  ];
  linkedLibraryFiles = lib.fileset.unions [
    ../src/spaghetti_extractor/__init__.py
    ../src/spaghetti_extractor/artifact_formats.py
    ../src/spaghetti_extractor/errors.py
    ../src/spaghetti_extractor/linked_libraries.py
    ../src/spaghetti_extractor/linked_library_contracts.py
    ../src/spaghetti_extractor/pe.py
    ../src/spaghetti_extractor/stage_binary.py
    ../src/spaghetti_extractor/util.py
  ];
  sourceCallSubstitutionFiles = lib.fileset.unions [
    linkedLibraryFiles
    ../src/spaghetti_extractor/source_graph.py
    ../src/spaghetti_extractor/source_project.py
    ../src/spaghetti_extractor/source_call_substitution.py
  ];
in
{
  inherit
    interpreterFiles
    runtimeFiles
    workspaceFiles
    linkedLibraryFiles
    sourceCallSubstitutionFiles
    ;
  interpreter = lib.fileset.toSource {
    inherit root;
    fileset = interpreterFiles;
  };
  runtime = lib.fileset.toSource {
    inherit root;
    fileset = runtimeFiles;
  };
  workspace = lib.fileset.toSource {
    inherit root;
    fileset = workspaceFiles;
  };
  linkedLibraries = lib.fileset.toSource {
    inherit root;
    fileset = linkedLibraryFiles;
  };
  sourceCallSubstitutions = lib.fileset.toSource {
    inherit root;
    fileset = sourceCallSubstitutionFiles;
  };
  nativeBuild = lib.fileset.toSource {
    inherit root;
    fileset = lib.fileset.unions [
      runtimeFiles
      ../src/spaghetti_extractor/stage_b_interpreter_native_build.py
      ../src/spaghetti_extractor/stage_b_native_binding.py
      ../src/spaghetti_extractor/stage_b_native_build.py
      ../src/spaghetti_extractor/stage_b_pe_composer.py
    ];
  };
}
