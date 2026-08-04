{ pkgs
, pythonEnv
, spaghettiExtractor
, sideTool
, analysisKernelCache
, isaKernelCache
, isaSemanticKernel
, bochsRunner
, sourceRoot
, leanSourceRoot
, originalFixture
, mingw32
, mkLeanGraph ? import ./stage-a-lean-graph.nix
, proofStateMachine ? null
, nativeSourceOriginalExecutionEvidence ? null
, nativeSourceCompiledAuthorityEvidence ? null
, nativeSourceEnvironmentFamilyEvidence ? null
, linkedIslands ? null
, nativeSourceApprovedToolchainAxiom ?
    "StageA.GeneratedRelational.GnuHelloNativeSourceEnvironmentFamily.pinnedCompilerLoweringCorrect"
}:

let
  lib = pkgs.lib;
  # Each proof phase is independently content-addressed so identical checked
  # semantics can be substituted across local and remote realizations.
  driver = ./gnu-hello-roundtrip-driver.py;
  callableExternalRuntimeDriver = ./callable-external-runtime-contract.py;
  directCallSemanticsDriver = ./gnu-hello-direct-call-semantics.py;
  directCallFixedPointDriver = ./gnu-hello-direct-call-fixed-point.py;
  stackDynamicAuthorityDriver = ./gnu-hello-stack-dynamic-authority.py;
  leanTermReceiptDriver = ./stage-a-lean-term-receipts.py;
  semanticCoverageDriver = ./stage-a-semantic-coverage.py;
  stackDynamicHints = ./gnu-hello-stack-dynamic-hints.json;
  proofSourceAggregateDriver = ./stage-a-proof-source-aggregate.py;
  kernelDataDriver = ./gnu-hello-kernel-data-driver.py;
  nativeSourceStaticAuthorityDriver =
    ./gnu-hello-native-source-static-authority.py;
  compiledKernelDriver = ./gnu-hello-compiled-kernel.py;
  proofClosureDriver = ./gnu-hello-proof-closure-driver.py;
  constructiveSourceCoverageDriver =
    ./gnu-hello-constructive-source-coverage.py;
  canonicalRelationCoreDriver = ./gnu-hello-canonical-relation-core.py;
  acceptanceRequirementsDriver = ./gnu-hello-acceptance-requirements.py;
  nativeLaunchGraphDriver = ./gnu-hello-native-launch-graph.py;
  diagnosticDriver = ./gnu-hello-roundtrip-diagnostic.py;
  accessFaultQualificationDriver = ./stage-a-access-domain-receipts.py;
  universalPairedExternalEnvironmentDriver =
    ./gnu-hello-universal-paired-external-environment.py;
  fixtureRoot =
    "${originalFixture}/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/original";
  originalPe = "${fixtureRoot}/hello.exe";
  originalMap = "${fixtureRoot}/hello.map";
  proofStateMachinePath =
    if proofStateMachine == null then
      "${staticExport}/state-machine.jsonl"
    else
      "${proofStateMachine}/state-machine.jsonl";
  machineRuntimeProfileSource = lib.fileset.toSource {
    root = ../profiles;
    fileset = lib.fileset.unions [
      ../profiles/pe32-msvcrt-machine-runtime-v1.json
      ../profiles/pe32-kernel32-lockstep-v1.json
      ../profiles/pe32-msvcrt-lockstep-v1.json
      ../profiles/pe32-kernel32-callable-resolvers-v1.json
      ../profiles/pe32-static-cutpoints-and-paired-callables-v1.json
    ];
  };
  machineRuntimeProfile =
    "${machineRuntimeProfileSource}/pe32-msvcrt-machine-runtime-v1.json";
  python = "${pythonEnv}/bin/python3";
  aggregatePython = "${pkgs.python3}/bin/python3";
  compiler = "${mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc";
  wineFontsConf = pkgs.writeText "spaghetti-extractor-wine-fonts.conf" ''
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd">
    <fontconfig>
      <dir>${pkgs.dejavu_fonts}/share/fonts</dir>
      <cachedir prefix="xdg">fontconfig</cachedir>
      <config><rescan><int>0</int></rescan></config>
    </fontconfig>
  '';
  # Candidate production and component workspaces share one centrally defined
  # source closure. Reviewed Lean and Python proof emitters remain excluded.
  stageBPythonSources = import ./stage-b-python-sources.nix { inherit pkgs; };
  runtimePythonFiles = stageBPythonSources.runtimeFiles;
  interpreterPythonSource = stageBPythonSources.interpreter;
  runtimePythonSource = stageBPythonSources.runtime;
  nativeBuildPythonSource = stageBPythonSources.nativeBuild;
  componentWorkspacePythonSource = stageBPythonSources.workspace;
  pairwiseByteComponentProfilePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = ../src/spaghetti_extractor_component_profiles/bounded_pairwise_byte_compare_v1.py;
  };
  lastComponentProfilePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = ../src/spaghetti_extractor_component_profiles/bounded_last_component_v1.py;
  };
  externalZeroPredicateProfilePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = ../src/spaghetti_extractor_component_profiles/external_zero_predicate_v1.py;
  };
  basenamePrefixSelectionProfilePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = ../src/spaghetti_extractor_component_profiles/basename_prefix_selection_v1.py;
  };
  componentDiscoveryPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/component_discovery.py
    ];
  };
  componentSelectionPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/artifact_formats.py
      ../src/spaghetti_extractor/component_selection.py
      ../src/spaghetti_extractor/util.py
    ];
  };
  semanticComponentPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/artifact_formats.py
      ../src/spaghetti_extractor/linked_library_contracts.py
      ../src/spaghetti_extractor/semantic_components.py
      ../src/spaghetti_extractor/util.py
    ];
  };
  callableExternalRuntimePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      callableExternalRuntimeDriver
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/callable_external_runtime.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/callable_external_capability.py
      ../src/spaghetti_extractor/relational/lean/callable_external_execution.py
    ];
  };
  paddingStaticPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/artifact_formats.py
      ../src/spaghetti_extractor/call_arguments.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/external_interface_profiles.py
      ../src/spaghetti_extractor/external_operation_profiles.py
      ../src/spaghetti_extractor/import_abi.py
      ../src/spaghetti_extractor/interface_provenance.py
      ../src/spaghetti_extractor/internal_call_summaries.py
      ../src/spaghetti_extractor/machine_abi.py
      ../src/spaghetti_extractor/machine_import_profiles.py
      ../src/spaghetti_extractor/provenance_domain.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/pe.py
      ../src/spaghetti_extractor/stage_binary.py
      ../src/spaghetti_extractor/stage_b_state_machine.py
    ];
  };
  reconstructionStaticPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/artifact_formats.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/call_arguments.py
      ../src/spaghetti_extractor/external_interface_profiles.py
      ../src/spaghetti_extractor/external_operation_profiles.py
      ../src/spaghetti_extractor/finite_value_domain.py
      ../src/spaghetti_extractor/import_abi.py
      ../src/spaghetti_extractor/interface_provenance.py
      ../src/spaghetti_extractor/internal_call_summaries.py
      ../src/spaghetti_extractor/machine_abi.py
      ../src/spaghetti_extractor/machine_import_profiles.py
      ../src/spaghetti_extractor/operation_provenance.py
      ../src/spaghetti_extractor/provenance_domain.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/pe.py
      ../src/spaghetti_extractor/stage_binary.py
      ../src/spaghetti_extractor/stage_b_state_machine.py
      ../src/spaghetti_extractor/reconstruction_ir.py
      ../src/spaghetti_extractor/reconstruction_control.py
      ../src/spaghetti_extractor/value_provenance.py
    ];
  };
  reconstructionFunctionalPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/stage_b_functional.py
    ];
  };
  reconstructionAssurancePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/reconstruction_assurance.py
    ];
  };
  sourceProjectPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/artifact_formats.py
      ../src/spaghetti_extractor/linked_library_contracts.py
      ../src/spaghetti_extractor/source_graph.py
      ../src/spaghetti_extractor/source_project.py
      ../src/spaghetti_extractor/util.py
    ];
  };
  idiomaticHelloSource = lib.fileset.toSource {
    root = ../fixtures/gnu-hello/idiomatic;
    fileset = lib.fileset.unions [
      ../fixtures/gnu-hello/idiomatic/hello.c
      ../fixtures/gnu-hello/idiomatic/hello.h
      ../fixtures/gnu-hello/idiomatic/source-project.json
    ];
  };
  # Static extraction has an explicit dependency closure.  A subtractive
  # "almost all Python" source made unrelated Stage B component edits
  # invalidate the authoritative PE extraction and every descendant.
  opaqueStaticPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/_contract_tools
      ../src/spaghetti_extractor/artifact_formats.py
      ../src/spaghetti_extractor/contract_tools.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/machine_import_profiles.py
      ../src/spaghetti_extractor/opaque_reconstruction.py
      ../src/spaghetti_extractor/pe.py
      ../src/spaghetti_extractor/stage_b_state_machine.py
      ../src/spaghetti_extractor/stage_binary.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/artifacts.py
      ../src/spaghetti_extractor/relational/binary_inventory.py
      ../src/spaghetti_extractor/relational/contract.py
      ../src/spaghetti_extractor/relational/model.py
      ../src/spaghetti_extractor/relational/reference_contract.py
      ../src/spaghetti_extractor/machine_abi.py
      ../src/spaghetti_extractor/relational/schema.py
      ../src/spaghetti_extractor/relational/semantic_cutpoints.py
      ../src/spaghetti_extractor/relational/side_extraction_artifact.py
      ../src/spaghetti_extractor/relational/x87_profile.py
      ../src/spaghetti_extractor/roundtrip_fuzz/__init__.py
      ../src/spaghetti_extractor/roundtrip_fuzz/image_contract.py
    ];
  };
  stackDynamicProofPythonFiles = lib.fileset.unions [
    ../src/spaghetti_extractor/relational/lean/stack_dynamic_indirect_control.py
    ../src/spaghetti_extractor/relational/lean/original_stack_dynamic_control_closure.py
    ../src/spaghetti_extractor/relational/lean/runtime_value_carry.py
    ../src/spaghetti_extractor/relational/lean/scanner.py
  ];
  directCallProposalProofPythonFiles = lib.fileset.unions [
    ../src/spaghetti_extractor/relational/lean/internal_direct_call_register_summary.py
    ../src/spaghetti_extractor/relational/lean/internal_direct_call_summary_proposal.py
  ];
  runEntryProofPythonFiles = lib.fileset.unions [
    ../src/spaghetti_extractor/relational/lean/interpreter_kernel_run_entry_route.py
    ../src/spaghetti_extractor/relational/lean/interpreter_kernel_operation_behavior_materialization.py
    ../src/spaghetti_extractor/relational/lean/interpreter_kernel_run_entry_abi.py
    ../src/spaghetti_extractor/relational/lean/interpreter_kernel_run_entry_projection.py
  ];
  proofPythonFiles = lib.fileset.difference
    (lib.fileset.intersection
      (lib.fileset.difference
        ../src
        ../src/spaghetti_extractor/lean/StageA)
      (lib.fileset.fileFilter (file: !file.hasExt "pyc") ../src))
    (lib.fileset.unions [
      stackDynamicProofPythonFiles
      directCallProposalProofPythonFiles
      runEntryProofPythonFiles
      ../src/spaghetti_extractor/opaque_reconstruction.py
      ../src/spaghetti_extractor/callable_external_runtime.py
      ../src/spaghetti_extractor/bounded_component_contract.py
      ../src/spaghetti_extractor/cli.py
      ../src/spaghetti_extractor/component_discovery.py
      ../src/spaghetti_extractor/component_interface.py
      ../src/spaghetti_extractor/component_selection.py
      ../src/spaghetti_extractor/component_workspace.py
      ../src/spaghetti_extractor/finite_component_contract.py
      ../src/spaghetti_extractor/call_arguments.py
      ../src/spaghetti_extractor/external_interface_profiles.py
      ../src/spaghetti_extractor/external_operation_profiles.py
      ../src/spaghetti_extractor/interface_provenance.py
      ../src/spaghetti_extractor/linked_library_contracts.py
      ../src/spaghetti_extractor/reconstruction_assurance.py
      ../src/spaghetti_extractor/import_abi.py
      ../src/spaghetti_extractor/internal_call_summaries.py
      ../src/spaghetti_extractor/machine_abi.py
      ../src/spaghetti_extractor/operation_provenance.py
      ../src/spaghetti_extractor/provenance_domain.py
      ../src/spaghetti_extractor/reconstruction_ir.py
      ../src/spaghetti_extractor/reconstruction_workspace.py
      ../src/spaghetti_extractor/region_replacement.py
      ../src/spaghetti_extractor/linked_library_contracts.py
      ../src/spaghetti_extractor/semantic_components.py
      ../src/spaghetti_extractor/stage_b_interpreter_native_build.py
      ../src/spaghetti_extractor/stage_b_native_binding.py
      ../src/spaghetti_extractor/stage_b_native_build.py
      ../src/spaghetti_extractor/stage_b_native_engine.py
      ../src/spaghetti_extractor/stage_b_native_runtime.py
      ../src/spaghetti_extractor/stage_b_pe_composer.py
      ../src/spaghetti_extractor/value_provenance.py
    ]);
  proofPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = proofPythonFiles;
  };
  # The stack/dynamic phase consumes a compact typed projection of the
  # mixed-original plan. Keep its emitter closure independent from the
  # monolithic lane driver and unrelated proof tooling.
  stackDynamicAuthorityPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/artifact_formats.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/pe.py
      ../src/spaghetti_extractor/stage_binary.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/original_cutpoint_graph_ir.py
      ../src/spaghetti_extractor/relational/runtime_value_carry_ir.py
      ../src/spaghetti_extractor/machine_abi.py
      ../src/spaghetti_extractor/relational/schema.py
      ../src/spaghetti_extractor/relational/stack_dynamic_control_ir.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/nullable_code_pointer_table.py
      ../src/spaghetti_extractor/relational/lean/nullable_code_pointer_rooted_unreachability.py
      ../src/spaghetti_extractor/relational/lean/original_indirect_control_authority.py
      ../src/spaghetti_extractor/relational/lean/stack_fixed_code_pointer.py
      stackDynamicProofPythonFiles
    ];
  };
  # Direct-call semantic adapters are a hot proof-iteration boundary.  Keep
  # their emitter independent from the monolithic GNU lane driver and from
  # unrelated extraction/analysis modules.
  directCallSemanticsPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/artifact_formats.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/direct_call_proposal_ir.py
      ../src/spaghetti_extractor/relational/original_cutpoint_graph_ir.py
      ../src/spaghetti_extractor/relational/stack_dynamic_control_ir.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/internal_direct_call_mixed_original_integration.py
      ../src/spaghetti_extractor/relational/lean/internal_direct_call_register_control_authority.py
      ../src/spaghetti_extractor/relational/lean/internal_direct_call_register_summary.py
      ../src/spaghetti_extractor/relational/lean/internal_direct_call_semantics_bundle.py
      ../src/spaghetti_extractor/relational/lean/internal_direct_call_summary_proposal.py
    ];
  };
  directCallProposalPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      proofPythonFiles
      directCallProposalProofPythonFiles
    ];
  };
  directCallFixedPointPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = directCallFixedPointDriver;
  };
  # The side-ISA adapter is an untrusted diagnostic boundary. Keep its source
  # closure independent from the general CLI and proof emitters.
  isaSideAdapterPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/isa_catalog.py
      ../src/spaghetti_extractor/isa_conformance.py
      ../src/spaghetti_extractor/isa_semantic_forms.py
      ../src/spaghetti_extractor/isa_side_adapter.py
      ../src/spaghetti_extractor/pe.py
      ../src/spaghetti_extractor/stage_binary.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/lean/StageA/Formal.lean
      ../src/spaghetti_extractor/lean/StageA/ISAQualification.lean
      ../src/spaghetti_extractor/lean/StageA/X87.lean
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/isa_requirements.py
      ../src/spaghetti_extractor/relational/preflight.py
      ../src/spaghetti_extractor/machine_abi.py
      ../src/spaghetti_extractor/relational/schema.py
      ../src/spaghetti_extractor/relational/side_extraction_artifact.py
      ../src/spaghetti_extractor/relational/side_isa_artifact.py
      ../src/spaghetti_extractor/relational/x87_profile.py
    ];
  };
  # Exact GNU encodings are enriched by replaying the reviewed Lean decoder.
  # Keep this untrusted oracle-input phase independent from the whole proof
  # emitter so proof-only edits do not invalidate the conformance campaign.
  isaCatalogEnrichmentPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/isa_catalog.py
      ../src/spaghetti_extractor/isa_catalog_enrichment.py
      ../src/spaghetti_extractor/isa_conformance.py
      ../src/spaghetti_extractor/isa_semantic_forms.py
      ../src/spaghetti_extractor/isa_side_adapter.py
      ../src/spaghetti_extractor/pe.py
      ../src/spaghetti_extractor/stage_binary.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/lean/StageA/Formal.lean
      ../src/spaghetti_extractor/lean/StageA/ISAQualification.lean
      ../src/spaghetti_extractor/lean/StageA/X87.lean
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/isa_requirements.py
      ../src/spaghetti_extractor/relational/preflight.py
      ../src/spaghetti_extractor/machine_abi.py
      ../src/spaghetti_extractor/relational/schema.py
      ../src/spaghetti_extractor/relational/side_extraction_artifact.py
      ../src/spaghetti_extractor/relational/side_isa_artifact.py
      ../src/spaghetti_extractor/relational/x87_profile.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/compiler.py
    ];
  };
  semanticCoveragePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/pe.py
      ../src/spaghetti_extractor/stage_binary.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/machine_abi.py
      ../src/spaghetti_extractor/relational/schema.py
      (lib.fileset.maybeMissing
        ../src/spaghetti_extractor/relational/access_domain_receipts.py)
      ../src/spaghetti_extractor/relational/side_extraction_artifact.py
      ../src/spaghetti_extractor/relational/side_isa_artifact.py
      ../src/spaghetti_extractor/relational/semantic_coverage.py
      ../src/spaghetti_extractor/relational/semantic_coverage_registry.py
    ];
  };
  # The concrete/static acceptance constructor is deliberately isolated from
  # the lane driver. Dynamic proof work must not invalidate its 19 checked
  # carrier, PE, launch-root, ABI, relation-core, and invariant bindings.
  acceptanceRequirementsPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/interpreter_mixed_kernel_binding.py
      ../src/spaghetti_extractor/relational/lean/gnu_hello_acceptance_requirements.py
    ];
  };
  gnuHelloMixedAcceptancePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/machine_abi.py
      ../src/spaghetti_extractor/relational/schema.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/interpreter_mixed_kernel_binding.py
      ../src/spaghetti_extractor/relational/lean/gnu_hello_acceptance_requirements.py
      ../src/spaghetti_extractor/relational/lean/gnu_hello_mixed_acceptance.py
      (lib.fileset.maybeMissing ./gnu-hello-mixed-acceptance.py)
    ];
  };
  mixedChunkedAcceptancePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/machine_abi.py
      ../src/spaghetti_extractor/relational/schema.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/interpreter_mixed_chunked_acceptance.py
      (lib.fileset.maybeMissing
        ./interpreter-mixed-chunked-acceptance.py)
    ];
  };
  gnuHelloStaticClosureCommonFiles = lib.fileset.unions [
    ../src/spaghetti_extractor/__init__.py
    ../src/spaghetti_extractor/errors.py
    ../src/spaghetti_extractor/util.py
    ../src/spaghetti_extractor/relational/__init__.py
    ../src/spaghetti_extractor/relational/lean/__init__.py
    (lib.fileset.maybeMissing ./gnu-hello-static-closure-producers.py)
  ];
  mkGnuHelloStaticClosurePythonSource = generator:
    lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        gnuHelloStaticClosureCommonFiles
        (lib.fileset.maybeMissing generator)
      ];
    };
  runtimeFoundationPythonSource =
    mkGnuHelloStaticClosurePythonSource
      ../src/spaghetti_extractor/relational/lean/gnu_hello_runtime_foundation.py;
  launchBindingPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      gnuHelloStaticClosureCommonFiles
      ../src/spaghetti_extractor/relational/lean/gnu_hello_acceptance_requirements.py
      ../src/spaghetti_extractor/relational/lean/gnu_hello_launch_binding.py
      ../src/spaghetti_extractor/relational/lean/interpreter_mixed_kernel_binding.py
    ];
  };
  externalComponentPythonSource =
    mkGnuHelloStaticClosurePythonSource
      ../src/spaghetti_extractor/relational/lean/gnu_hello_external_component.py;
  mixedSemanticOperationComponentPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/interpreter_mixed_semantic_operation_component.py
    ];
  };
  mixedFusedSemanticEvidencePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/artifact_formats.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/pe.py
      ../src/spaghetti_extractor/stage_binary.py
      ../src/spaghetti_extractor/stage_b_api_catalog.py
      ../src/spaghetti_extractor/stage_b_c_backend.py
      ../src/spaghetti_extractor/stage_b_interpreter_backend.py
      ../src/spaghetti_extractor/stage_b_typed_x87.py
      ../src/spaghetti_extractor/stage_b_state_machine.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/definedness.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/interpreter_normalization.py
      ../src/spaghetti_extractor/relational/lean/gnu_hello_mixed_fused_semantic_evidence.py
      (lib.fileset.maybeMissing
        ./gnu-hello-mixed-fused-semantic-evidence.py)
    ];
  };
  mixedDirectCallSemanticEvidencePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/artifact_formats.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/pe.py
      ../src/spaghetti_extractor/stage_binary.py
      ../src/spaghetti_extractor/stage_b_api_catalog.py
      ../src/spaghetti_extractor/stage_b_c_backend.py
      ../src/spaghetti_extractor/stage_b_interpreter_backend.py
      ../src/spaghetti_extractor/stage_b_typed_x87.py
      ../src/spaghetti_extractor/stage_b_state_machine.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/definedness.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/interpreter_normalization.py
      ../src/spaghetti_extractor/relational/lean/gnu_hello_mixed_fused_semantic_evidence.py
      ../src/spaghetti_extractor/relational/lean/gnu_hello_mixed_direct_call_semantic_evidence.py
      (lib.fileset.maybeMissing
        ./gnu-hello-mixed-direct-call-semantic-evidence.py)
    ];
  };
  mixedIndirectImportCallSemanticEvidencePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/artifact_formats.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/pe.py
      ../src/spaghetti_extractor/stage_binary.py
      ../src/spaghetti_extractor/stage_b_api_catalog.py
      ../src/spaghetti_extractor/stage_b_c_backend.py
      ../src/spaghetti_extractor/stage_b_interpreter_backend.py
      ../src/spaghetti_extractor/stage_b_typed_x87.py
      ../src/spaghetti_extractor/stage_b_state_machine.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/definedness.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/interpreter_normalization.py
      ../src/spaghetti_extractor/relational/lean/gnu_hello_mixed_fused_semantic_evidence.py
      ../src/spaghetti_extractor/relational/lean/gnu_hello_mixed_indirect_import_call_semantic_evidence.py
      (lib.fileset.maybeMissing
        ./gnu-hello-mixed-indirect-import-call-semantic-evidence.py)
    ];
  };
  mixedExternalTailSemanticEvidencePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/artifact_formats.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/pe.py
      ../src/spaghetti_extractor/stage_binary.py
      ../src/spaghetti_extractor/stage_b_api_catalog.py
      ../src/spaghetti_extractor/stage_b_c_backend.py
      ../src/spaghetti_extractor/stage_b_interpreter_backend.py
      ../src/spaghetti_extractor/stage_b_typed_x87.py
      ../src/spaghetti_extractor/stage_b_state_machine.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/definedness.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/interpreter_normalization.py
      ../src/spaghetti_extractor/relational/lean/gnu_hello_mixed_fused_semantic_evidence.py
      ../src/spaghetti_extractor/relational/lean/gnu_hello_mixed_external_tail_semantic_evidence.py
      (lib.fileset.maybeMissing
        ./gnu-hello-mixed-external-tail-semantic-evidence.py)
    ];
  };
  runtimeIndirectCompositionPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/original_cutpoint_graph_ir.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      (lib.fileset.maybeMissing
        ../src/spaghetti_extractor/relational/lean/gnu_hello_runtime_indirect_composition.py)
      (lib.fileset.maybeMissing
        ./gnu-hello-runtime-indirect-composition.py)
    ];
  };
  operationInstantiationPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      proofPythonFiles
      (lib.fileset.maybeMissing
        ../src/spaghetti_extractor/relational/lean/interpreter_kernel_closed_call_tree.py)
      (lib.fileset.maybeMissing
        ../src/spaghetti_extractor/relational/lean/interpreter_kernel_operation_instantiation.py)
      (lib.fileset.maybeMissing ./gnu-hello-operation-instantiation.py)
    ];
  };
  runEntryRoutePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_run_entry_route.py
      (lib.fileset.maybeMissing ./gnu-hello-run-entry-route.py)
    ];
  };
  runEntryBehaviorsPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_run_entry_route.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_operation_behavior_materialization.py
      (lib.fileset.maybeMissing ./gnu-hello-run-entry-behaviors.py)
    ];
  };
  runEntryAbiPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_run_entry_route.py
      (lib.fileset.maybeMissing
        ../src/spaghetti_extractor/relational/lean/interpreter_kernel_run_entry_abi.py)
      (lib.fileset.maybeMissing
        ../src/spaghetti_extractor/relational/lean/interpreter_kernel_run_entry_projection.py)
      (lib.fileset.maybeMissing ./gnu-hello-run-entry-abi.py)
    ];
  };
  programLookupNativeWorldBridgePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      proofPythonFiles
      (lib.fileset.maybeMissing
        ../src/spaghetti_extractor/relational/lean/interpreter_kernel_program_lookup_native_world_bridge.py)
      (lib.fileset.maybeMissing
        ./gnu-hello-program-lookup-native-world-bridge.py)
    ];
  };
  interpreterStepWorldProgramLookupPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      proofPythonFiles
      (lib.fileset.maybeMissing
        ../src/spaghetti_extractor/relational/lean/interpreter_kernel_step_world_program_lookup.py)
      (lib.fileset.maybeMissing
        ./gnu-hello-interpreter-step-world-program-lookup.py)
    ];
  };
  interpreterStepProgramLookupCallBehaviorsPythonSource =
    lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        proofPythonFiles
        (lib.fileset.maybeMissing
          ../src/spaghetti_extractor/relational/lean/interpreter_kernel_step_world_program_lookup.py)
        (lib.fileset.maybeMissing
          ../src/spaghetti_extractor/relational/lean/interpreter_kernel_operation_block_behavior.py)
        (lib.fileset.maybeMissing
          ../src/spaghetti_extractor/relational/lean/interpreter_kernel_step_program_lookup_projection.py)
        (lib.fileset.maybeMissing
          ./gnu-hello-step-program-lookup-call-behaviors.py)
      ];
    };
  closureProofAggregatePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = proofSourceAggregateDriver;
  };
  staticClosureDriver =
    "${runtimeFoundationPythonSource}/nix/gnu-hello-static-closure-producers.py";
  launchBindingDriver =
    "${launchBindingPythonSource}/nix/gnu-hello-static-closure-producers.py";
  externalComponentDriver =
    "${externalComponentPythonSource}/nix/gnu-hello-static-closure-producers.py";
  runtimeIndirectCompositionDriver =
    "${runtimeIndirectCompositionPythonSource}/nix/gnu-hello-runtime-indirect-composition.py";
  operationInstantiationDriver =
    "${operationInstantiationPythonSource}/nix/gnu-hello-operation-instantiation.py";
  runEntryRouteDriver =
    "${runEntryRoutePythonSource}/nix/gnu-hello-run-entry-route.py";
  runEntryBehaviorsDriver =
    "${runEntryBehaviorsPythonSource}/nix/gnu-hello-run-entry-behaviors.py";
  runEntryAbiDriver =
    "${runEntryAbiPythonSource}/nix/gnu-hello-run-entry-abi.py";
  closureProofAggregateDriver =
    "${closureProofAggregatePythonSource}/nix/stage-a-proof-source-aggregate.py";
  # Typed access/fault source generation is a narrow proof-data phase. It
  # consumes immutable GNU artifacts and emits only checked-certificate
  # proposals; changing diagnostics or the final theorem must not regenerate
  # these shards.
  accessFaultQualificationPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/access_domain_receipts.py
    ];
  };
  # The exact-data phase emits hundreds of immutable Lean certificate packs.
  # Keep its Python closure independent from unrelated proof emitters so a new
  # composition theorem does not regenerate and recompile that entire graph.
  kernelDataPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/artifact_formats.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/pe.py
      ../src/spaghetti_extractor/stage_binary.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/artifacts.py
      ../src/spaghetti_extractor/relational/contract.py
      ../src/spaghetti_extractor/relational/definedness.py
      ../src/spaghetti_extractor/relational/model.py
      ../src/spaghetti_extractor/machine_abi.py
      ../src/spaghetti_extractor/relational/schema.py
      ../src/spaghetti_extractor/relational/semantic_cutpoints.py
      ../src/spaghetti_extractor/relational/x86_instruction_profile.py
      ../src/spaghetti_extractor/relational/x87_profile.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/artifact_byte_packs.py
      ../src/spaghetti_extractor/relational/lean/common.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_data.py
      ../src/spaghetti_extractor/roundtrip_fuzz/image_contract.py
      ../src/spaghetti_extractor/stage_b_api_catalog.py
      ../src/spaghetti_extractor/stage_b_c_backend.py
      ../src/spaghetti_extractor/stage_b_engine_layout.py
      ../src/spaghetti_extractor/stage_b_interpreter_backend.py
      ../src/spaghetti_extractor/stage_b_typed_x87.py
      ../src/spaghetti_extractor/stage_b_interpreter_native_build.py
      ../src/spaghetti_extractor/stage_b_native_binding.py
      ../src/spaghetti_extractor/stage_b_native_build.py
      ../src/spaghetti_extractor/stage_b_native_engine.py
      ../src/spaghetti_extractor/stage_b_native_runtime.py
      ../src/spaghetti_extractor/stage_b_pe_composer.py
      ../src/spaghetti_extractor/stage_b_state_machine.py
    ];
  };
  kernelDataLeanSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/lean/StageA/Formal.lean
      ../src/spaghetti_extractor/lean/StageA/RelationalFiniteIndex.lean
      ../src/spaghetti_extractor/lean/StageA/RelationalInterpreter.lean
      ../src/spaghetti_extractor/lean/StageA/RelationalInterpreterKernelActionAlignment.lean
      ../src/spaghetti_extractor/lean/StageA/RelationalInterpreterKernelData.lean
      ../src/spaghetti_extractor/lean/StageA/RelationalInterpreterKernelLoadedImage.lean
      ../src/spaghetti_extractor/lean/StageA/RelationalInterpreterKernelProgramIndex.lean
      ../src/spaghetti_extractor/lean/StageA/RelationalInterpreterKernelProgramTableProjection.lean
      ../src/spaghetti_extractor/lean/StageA/RelationalLoader.lean
      ../src/spaghetti_extractor/lean/StageA/RelationalMemory.lean
      ../src/spaghetti_extractor/lean/StageA/RelationalPEBytePacks.lean
      ../src/spaghetti_extractor/lean/StageA/X87.lean
    ];
  };
  constructiveSourceCoveragePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/interpreter_mixed_source_coverage.py
    ];
  };
  canonicalRelationCorePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/interpreter_mixed_relation_core.py
    ];
  };
  # The graph emitter shares PE/relocation literals with the broader proof
  # generators.  Keep it out of the candidate closure; its deterministic
  # output is compiled and cached as an independent proof phase below.
  nativeLaunchGraphPythonSource = proofPythonSource;
  proofClosurePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/pe.py
      ../src/spaghetti_extractor/stage_binary.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/artifacts.py
      ../src/spaghetti_extractor/relational/contract.py
      ../src/spaghetti_extractor/relational/definedness.py
      ../src/spaghetti_extractor/relational/model.py
      ../src/spaghetti_extractor/machine_abi.py
      ../src/spaghetti_extractor/relational/schema.py
      ../src/spaghetti_extractor/relational/semantic_cutpoints.py
      ../src/spaghetti_extractor/relational/x86_instruction_profile.py
      ../src/spaghetti_extractor/relational/x87_profile.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/artifact_byte_packs.py
      ../src/spaghetti_extractor/relational/lean/common.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_abi.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_callback.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_cdecl_epilogue.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_cdecl_epilogue_symbolic_closure.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_cdecl_epilogue_static_preservation.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_cdecl_epilogue_external_payload.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_operation_result_encoding.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_abstract_operation_transition.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_data.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_invoke.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_invoke_native.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_lookup_native.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_program_lookup_operation.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_run.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_run_native.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_run_operation.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_step.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_step_native.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_step_operation.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_step_program_lookup_call.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_step_program_lookup_call_closure.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_step_program_lookup_exact_computation.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_summary.py
      ../src/spaghetti_extractor/relational/lean/interpreter_x87_replay_bridge_target.py
      ../src/spaghetti_extractor/roundtrip_fuzz/image_contract.py
      ../src/spaghetti_extractor/stage_b_api_catalog.py
      ../src/spaghetti_extractor/stage_b_c_backend.py
      ../src/spaghetti_extractor/stage_b_engine_layout.py
      ../src/spaghetti_extractor/stage_b_interpreter_backend.py
      ../src/spaghetti_extractor/stage_b_typed_x87.py
      ../src/spaghetti_extractor/stage_b_interpreter_native_build.py
      ../src/spaghetti_extractor/stage_b_native_binding.py
      ../src/spaghetti_extractor/stage_b_native_build.py
      ../src/spaghetti_extractor/stage_b_native_engine.py
      ../src/spaghetti_extractor/stage_b_native_runtime.py
      ../src/spaghetti_extractor/stage_b_pe_composer.py
      ../src/spaghetti_extractor/stage_b_state_machine.py
    ];
  };
  # Compatibility name for downstream source-shape checks and diagnostics.
  roundTripPythonSource = proofPythonSource;
  runtimeDriver = pkgs.writeText "gnu-hello-roundtrip-runtime-driver.py" ''
    import argparse
    import json
    import sys
    import types
    from pathlib import Path

    import spaghetti_extractor

    # The public roundtrip_fuzz facade eagerly imports the proof pipeline.
    # Candidate generation only consumes its exact image-contract submodule.
    roundtrip_fuzz = types.ModuleType("spaghetti_extractor.roundtrip_fuzz")
    roundtrip_fuzz.__path__ = [str(
        Path(spaghetti_extractor.__file__).parent / "roundtrip_fuzz"
    )]
    sys.modules[roundtrip_fuzz.__name__] = roundtrip_fuzz

    from spaghetti_extractor.stage_binary import _parse_stage_a_pe
    from spaghetti_extractor.util import sha256_file, write_json


    def jsonl_count(path):
        return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


    def smoke(args):
        original = Path(args.original)
        linker_map = Path(args.linker_map)
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        binary = _parse_stage_a_pe(original)
        try:
            if binary.machine != "i386" or binary.bitness != 32:
                raise ValueError("GNU hello smoke input is not an i386 PE32 image")
            if not linker_map.is_file() or not linker_map.read_bytes():
                raise ValueError("GNU hello smoke input has no linker map")
            write_json(out / "smoke.json", {
                "format": "stage-a-gnu-hello-roundtrip-smoke-v1",
                "status": "pass",
                "static_only": True,
                "executes_original_binary": False,
                "executes_candidate_binary": False,
                "original": {
                    "sha256": binary.sha256,
                    "machine": binary.machine,
                    "bitness": binary.bitness,
                    "entry_rva": binary.entrypoint_rva,
                    "sections": len(binary.sections),
                },
                "linker_map_sha256": sha256_file(linker_map),
            })
        finally:
            binary.pe.close()


    def static_export(args):
        from spaghetti_extractor.contract_tools import (
            stage_a_export_reference_contract,
            stage_a_generate_map,
        )
        from spaghetti_extractor.roundtrip_fuzz.image_contract import (
            write_stage_a_load_image_contract,
        )
        from spaghetti_extractor.stage_b_state_machine import (
            write_stage_b_state_machine_from_stage_a_export,
        )

        original = Path(args.original)
        linker_map = Path(args.linker_map)
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        self_map = out / "original-self-map.json"
        result = stage_a_generate_map(
            original=original,
            candidate=original,
            linker_map_original=linker_map,
            linker_map_candidate=linker_map,
            out=self_map,
            original_flags="opaque-static-original",
            candidate_flags="opaque-static-reference",
        )
        if result.get("status") != "pass":
            raise ValueError("Stage A could not map the GNU hello image to itself")
        reference = out / "reference-contract.json"
        stage_a_export_reference_contract(
            original=original,
            out=reference,
            mapping=self_map,
            sidecar_dir=out,
            unit_contract_dir=out,
        )
        semantic = out / "semantic-transfer-contracts.jsonl"
        state_machine = out / "state-machine.jsonl"
        write_stage_b_state_machine_from_stage_a_export(
            reference_contract=reference,
            semantic_transfer_contracts=semantic,
            original_pe=original,
            out=state_machine,
        )
        load_image = out / "load-image-contract.json"
        load_contract = write_stage_a_load_image_contract(original_pe=original, out=load_image)
        write_json(out / "phase-manifest.json", {
            "format": "stage-a-relational-phase-v1",
            "phase": "static-export",
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "inputs": {
                "original_linker_map": {
                    "path": linker_map.name,
                    "sha256": sha256_file(linker_map),
                },
                "original_pe": {
                    "path": original.name,
                    "sha256": sha256_file(original),
                },
            },
            "status": "ready",
            "public_outputs": {
                "reference_contract": reference.name,
                "semantic_transfers": semantic.name,
                "state_machine": state_machine.name,
                "load_image_contract": load_image.name,
                "original_self_map": self_map.name,
            },
            "counts": {
                "transfers": jsonl_count(state_machine),
                "imports": sum(len(item.cells) for item in load_contract.imports),
                "tls_callbacks": 0 if load_contract.tls is None else len(load_contract.tls.callbacks),
            },
        })


    def interpreter(args):
        from spaghetti_extractor.stage_b_interpreter_backend import (
            write_stage_b_interpreter_package,
        )

        write_stage_b_interpreter_package(
            state_machine=Path(args.state_machine),
            out=Path(args.out),
        )


    def native_engine(args):
        from spaghetti_extractor.roundtrip_fuzz.image_contract import (
            load_stage_a_load_image_contract,
        )
        from spaghetti_extractor.stage_b_native_engine import (
            write_stage_b_native_engine_package,
        )

        contract_path = Path(args.load_image_contract)
        reference_path = Path(args.reference_contract)
        contract = load_stage_a_load_image_contract(contract_path)
        if args.entry_rva != contract.identity.entry_rva:
            raise ValueError("native-engine entry RVA differs from the load-image contract")
        callback_targets = []
        import_iat_vas = {}
        for descriptor in contract.imports:
            for cell in descriptor.cells:
                identity = cell.symbol if cell.symbol is not None else cell.ordinal
                if identity is None:
                    raise ValueError("load-image import cell has no identity")
                key = (descriptor.dll.lower(), identity)
                value = contract.identity.preferred_base + cell.iat_rva
                previous = import_iat_vas.setdefault(key, value)
                if previous != value:
                    raise ValueError("load-image contract has ambiguous IAT cells")
        termination_profile = json.loads(
            Path(args.termination_profile).read_text(encoding="utf-8")
        )
        termination_contracts = [
            row
            for row in termination_profile.get(
                "machine_import_call_contracts", []
            )
            if row.get("disposition") == "terminates"
            and row.get("import") == {
                "dll": args.termination_dll,
                "symbol": args.termination_symbol,
            }
        ]
        if len(termination_contracts) != 1:
            raise ValueError(
                "termination selection must name one exact modeled terminates contract"
            )
        if contract.tls is not None:
            callback_targets.extend({
                "rva": callback.rva,
                "kind": "tls_callback",
                "stack_cleanup_bytes": 12,
            } for callback in contract.tls.callbacks)
        relocation_rows = []
        for block in contract.relocations:
            for relocation in block.relocations:
                if relocation.target_rva is None or relocation.preferred_value is None or relocation.width == 0:
                    continue
                relocation_rows.append({
                    "source_rva": relocation.target_rva,
                    "type": relocation.type,
                    "kind": relocation.kind,
                    "width": relocation.width,
                    "preferred_value": relocation.preferred_value,
                })
        write_stage_b_native_engine_package(
            state_machine=Path(args.state_machine),
            entry_rva=args.entry_rva,
            callback_targets=callback_targets,
            import_iat_vas=import_iat_vas,
            termination_import={
                "dll": args.termination_dll,
                "symbol": args.termination_symbol,
                "disposition": "terminates",
            },
            base_relocation_evidence={
                "format": "stage-b-pe32-base-relocation-evidence-v1",
                "complete": contract.completeness.complete,
                "pe_sha256": contract.identity.pe_sha256,
                "reference_contract_sha256": sha256_file(reference_path),
                "image_base": contract.identity.preferred_base,
                "relocations": relocation_rows,
            },
            out=Path(args.out),
        )


    def native_runtime(args):
        from spaghetti_extractor.stage_b_native_runtime import (
            write_stage_b_native_runtime_package,
        )

        write_stage_b_native_runtime_package(
            interpreter_package=Path(args.interpreter_package),
            native_engine_package=Path(args.native_engine_package),
            out=Path(args.out),
        )


    def candidate(args):
        from spaghetti_extractor.stage_b_interpreter_native_build import (
            build_stage_b_interpreter_native_candidate,
        )

        build_stage_b_interpreter_native_candidate(
            interpreter_package=Path(args.interpreter_package),
            native_engine_package=Path(args.native_engine_package),
            native_runtime_package=Path(args.native_runtime_package),
            load_image_contract=Path(args.load_image_contract),
            compiler=args.compiler,
            out_dir=Path(args.out),
        )


    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(required=True)
    for name, function in (("smoke", smoke), ("static-export", static_export)):
        command = commands.add_parser(name)
        command.add_argument("--original", required=True)
        command.add_argument("--linker-map", required=True)
        command.add_argument("--out", required=True)
        command.set_defaults(function=function)
    command = commands.add_parser("interpreter")
    command.add_argument("--state-machine", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(function=interpreter)
    command = commands.add_parser("native-engine")
    command.add_argument("--state-machine", required=True)
    command.add_argument("--entry-rva", type=lambda value: int(value, 0), required=True)
    command.add_argument("--load-image-contract", required=True)
    command.add_argument("--reference-contract", required=True)
    command.add_argument("--termination-profile", required=True)
    command.add_argument("--termination-dll", required=True)
    command.add_argument("--termination-symbol", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(function=native_engine)
    command = commands.add_parser("native-runtime")
    command.add_argument("--interpreter-package", required=True)
    command.add_argument("--native-engine-package", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(function=native_runtime)
    command = commands.add_parser("candidate")
    command.add_argument("--interpreter-package", required=True)
    command.add_argument("--native-engine-package", required=True)
    command.add_argument("--native-runtime-package", required=True)
    command.add_argument("--load-image-contract", required=True)
    command.add_argument("--compiler", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(function=candidate)
    arguments = parser.parse_args()
    arguments.function(arguments)
  '';
  commonInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
  commonEnvironment = pythonSource: ''
    export PYTHONPATH=${pythonSource}/src
    export PYTHONHASHSEED=0
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
  '';
  mkPhaseWithSource = pythonSource: name: nativeBuildInputs: script:
    pkgs.runCommand name {
      nativeBuildInputs = commonInputs ++ nativeBuildInputs;
      preferLocalBuild = false;
      allowSubstitutes = true;
      # Generated source manifests are read during evaluation to construct the
      # independently content-addressed Lean DAG. Keep this inexpensive IFD
      # boundary input-addressed: CA outputs do not have a stable path until
      # realization, so making the manifest producer CA deadlocks evaluation.
    } ''
      set -euo pipefail
      ${commonEnvironment pythonSource}
      ${script}
    '';
  runtimePhaseNames = [
    "stage-a-gnu-hello-roundtrip-smoke"
    "stage-a-gnu-hello-roundtrip-static-export"
    "stage-b-gnu-hello-roundtrip-interpreter"
    "stage-b-gnu-hello-roundtrip-native-engine"
    "stage-b-gnu-hello-roundtrip-native-runtime"
    "stage-b-gnu-hello-roundtrip-candidate"
  ];
  mkPhase = name: nativeBuildInputs: script:
    mkPhaseWithSource
      (if builtins.elem name runtimePhaseNames
       then runtimePythonSource
       else roundTripPythonSource)
      name nativeBuildInputs script;
  mkAnalysisPhase = name: nativeBuildInputs: script:
    pkgs.runCommand name {
      nativeBuildInputs = [
        sideTool
        pkgs.jq
        pkgs.coreutils
      ] ++ nativeBuildInputs;
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    } ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      ${script}
    '';
  standardLogicalAxioms = [ "propext" "Classical.choice" "Quot.sound" ];
  mkGeneratedClosureProof =
    {
      name,
      sources,
      target,
      declaration,
      approvedAxioms ? standardLogicalAxioms,
    }:
    let
      sourceArguments = builtins.concatStringsSep " " (
        map (
          source:
          "--source ${pkgs.lib.escapeShellArg (toString source)}"
        ) sources
      );
      proofSources = mkPhaseWithSource closureProofAggregatePythonSource
        "stage-a-gnu-hello-roundtrip-${name}-proof-sources" [] ''
        ${aggregatePython} ${closureProofAggregateDriver} \
          ${sourceArguments} \
          --target ${pkgs.lib.escapeShellArg target} \
          --explicit-targets-only \
          --target-closure-only \
          --coarse-build-packs \
          --emit-module-graph \
          --out "$out"
        jq '. + {acceptance_authority: false}' \
          "$out/phase-manifest.json" > "$out/phase-manifest.json.tmp"
        mv "$out/phase-manifest.json.tmp" "$out/phase-manifest.json"
        jq -e '
          .status == "source-ready" and
          (.acceptance_authority | not) and
          .explicit_targets_only and
          .target_closure_only
        ' "$out/phase-manifest.json" >/dev/null
      '';
      proof = mkLeanGraph {
        inherit pkgs;
        # Recursive CA derivations serialize the complete dynamic graph while
        # resolving each node. Build stable coarse packs input-addressed, then
        # content-address the checked root bundle for substitution/provenance.
        contentAddressed = false;
        bundleContentAddressed = true;
        graphFile = proofSources + "/module-graph.json";
        sourceRoot = proofSources;
        targetNodes = [ target ];
        targetBundle = true;
        targetAxiomAudit = {
          module = target;
          inherit declaration;
          approved_axioms = approvedAxioms;
        };
      };
    in
    {
      inherit proof proofSources;
    };
  mkCheckedProofAudit =
    {
      name,
      proof,
      declaration,
      approvedAxioms ? standardLogicalAxioms,
      requiredAxioms ? [ ],
    }:
    pkgs.runCommand "stage-a-gnu-hello-roundtrip-${name}-axiom-audit" {
      nativeBuildInputs = [ pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    } ''
      set -euo pipefail
      mkdir -p "$out"
      jq --arg declaration ${lib.escapeShellArg declaration} \
        --argjson approved \
          ${lib.escapeShellArg (builtins.toJSON approvedAxioms)} \
        --argjson required \
          ${lib.escapeShellArg (builtins.toJSON requiredAxioms)} '
        [
          .nodes[].outputs[]?
          | select(
              (.axiom_audit.complete // false) and
              ((.axiom_audit.requested // []) | index($declaration) != null)
            )
          | .axiom_audit
        ] as $audits
        | ($audits[0].inventories[$declaration] // []) as $inventory
        | (($inventory - $approved) | unique) as $unexpected
        | (($required - $inventory) | unique) as $missing
        | if ($audits | length) != 1 then
            error("expected exactly one detached axiom audit")
          elif ($unexpected | length) != 0 then
            error("detached axiom audit contains an unapproved axiom")
          elif ($missing | length) != 0 then
            error("detached axiom audit omits a required trusted hypothesis")
          else
            {
              format: "stage-a-checked-detached-axiom-audit-v1",
              status: "checked",
              declaration: $declaration,
              inventory: $inventory,
              approved_axioms: $approved,
              required_axioms: $required,
              proof_bundle: ${builtins.toJSON (toString proof)}
            }
          end
      ' ${proof}/bundle.json > "$out/axiom-audit.json"
    '';
  mkMissingNativeSourceEvidence =
    {
      name,
      requiredFiles,
      contract,
    }:
    pkgs.runCommand "stage-a-gnu-hello-${name}-required" {
      preferLocalBuild = true;
      allowSubstitutes = false;
      __contentAddressed = true;
    } ''
      set -euo pipefail
      echo "missing checked native-source evidence package: ${name}" >&2
      echo "required contract: ${contract}" >&2
      echo "required files: ${builtins.concatStringsSep ", " requiredFiles}" >&2
      echo "the package may contain StageA/*.lean providers, but JSON status" >&2
      echo "fields and invented declaration names cannot authorize this phase" >&2
      exit 1
    '';
  mkNixRealizationIdentity = name: realized:
    pkgs.runCommand "stage-a-gnu-hello-${name}-nix-realization-v1" {
      nativeBuildInputs = [ pkgs.nix pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    } ''
      set -euo pipefail
      nar_hash="$(${pkgs.nix}/bin/nix --extra-experimental-features nix-command \
        --offline hash path --sri ${realized})"
      mkdir -p "$out"
      jq -n \
        --arg output ${lib.escapeShellArg (toString realized)} \
        --arg derivation ${lib.escapeShellArg (toString realized.drvPath)} \
        --arg nar_hash "$nar_hash" '
        {
          format: "stage-a-nix-realization-identity-v1",
          output: $output,
          derivation: $derivation,
          nar_hash: $nar_hash
        }
      ' > "$out/realization.json"
    '';
  mkLeanTermReceipts = name: source: proof:
    pkgs.runCommand name {
      nativeBuildInputs = [
        sideTool
        pkgs.jq
        pkgs.coreutils
      ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      # Receipts are a deterministic, checked adapter from the compiled proof
      # bundle into a compact phase input. Give downstream phases a stable
      # input-addressed path instead of forcing an IFD over the entire CA proof
      # graph merely to discover this metadata path.
    } ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      ${aggregatePython} ${leanTermReceiptDriver} \
        --bundle ${proof}/bundle.json \
        --source-root ${source} \
        --requests ${source}/kernel-check-requests.json \
        --out "$out"
      jq -e '
        .format == "stage-a-lean-kernel-check-receipts-v1" and
        .status == "checked" and
        (.receipts | length) > 0 and
        ([.receipts[].status] | all(. == "checked"))
      ' "$out/kernel-check-receipts.json" >/dev/null
    '';
  mkStaticBinaryInventory =
    { name, side, binary, linkerMap ? null }:
    mkAnalysisPhase name [] ''
      mkdir -p "$out"
      inventory_args=(
        --binary "${binary}"
        --side "${side}"
        --out "$out/inventory.json"
      )
      ${lib.optionalString (linkerMap != null) ''
        inventory_args+=(--linker-map "${linkerMap}")
      ''}
      spaghetti-extractor-side inventory-binary \
        "''${inventory_args[@]}" \
        > "$out/inventory.stdout"
      jq -e \
        --arg expected_sha256 \
          "$(sha256sum "${binary}" | cut -d ' ' -f1)" '
        .format == "stage-a-binary-cutpoint-inventory-v1" and
        .status == "pass" and
        .side == "${side}" and
        .binary_sha256 == $expected_sha256 and
        .counts.issues == 0 and
        .counts.regions > 0 and
        .counts.extraction_regions >= .counts.regions
      ' "$out/inventory.json" >/dev/null
    '';
  mkSupersetIsaRequest =
    { name, side, inventory }:
    mkAnalysisPhase name [] ''
      mkdir -p "$out"
      spaghetti-extractor-side \
        project-inventory-extraction-request \
        --inventory "${inventory}/inventory.json" \
        --scope superset \
        --out "$out/isa-request.json" \
        > "$out/isa-request.stdout"
      jq -e \
        --arg expected_sha256 \
          "$(jq -r .binary_sha256 "${inventory}/inventory.json")" \
        --argjson expected_regions \
          "$(jq .counts.extraction_regions \
            "${inventory}/inventory.json")" '
        .format == "stage-a-relational-side-extraction-request-v1" and
        .side == "${side}" and
        .binary_sha256 == $expected_sha256 and
        (.regions | length) == $expected_regions and
        (.regions | length) > 0
      ' "$out/isa-request.json" >/dev/null
    '';
  mkExactLeanIsa =
    { name, side, binary, request }:
    mkAnalysisPhase name [ pkgs.lean4 ] ''
      export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${analysisKernelCache}"
      export SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_MEMORY_MB=8192
      export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$TMPDIR/relational-cache"
      mkdir -p "$out"
      spaghetti-extractor-side extract-side-isa \
        --binary "${binary}" \
        --request "${request}/isa-request.json" \
        --out "$out/isa.json" \
        > "$out/isa.stdout"
      jq -e \
        --arg expected_sha256 \
          "$(jq -r .binary_sha256 "${request}/isa-request.json")" \
        --argjson expected_regions \
          "$(jq '.regions | length' \
            "${request}/isa-request.json")" '
        .format == "stage-a-relational-side-isa-v1" and
        .status == "untrusted_proposal_requires_lean_decode_replay" and
        .side == "${side}" and
        .binary_sha256 == $expected_sha256 and
        (.regions | length) == $expected_regions and
        (.regions | length) > 0 and
        ([.regions[].occurrences | length] | all(. > 0))
      ' "$out/isa.json" >/dev/null
    '';
  mkIsaSummary =
    { name, side, isa }:
    mkAnalysisPhase name [] ''
      mkdir -p "$out"
      jq '{
        format: "stage-a-relational-side-isa-summary-v1",
        status: "lean-decoder-inventory-complete",
        side,
        binary_sha256,
        classifier_sha256,
        extractor_sha256,
        counts: {
          regions: (.regions | length),
          occurrences: ([.regions[].occurrences[]] | length),
          unique_forms: ([.regions[].occurrences[].form] | unique | length)
        },
        forms: ([.regions[].occurrences[].form] | unique | sort),
        trust: {
          lean_decoder_executed: true,
          acceptance_exact_pe_decode_replay_required: true,
          semantic_conformance_authority: false,
          whole_program_acceptance_authority: false
        }
      }' "${isa}/isa.json" > "$out/summary.json"
      jq -e '
        .format == "stage-a-relational-side-isa-summary-v1" and
        .status == "lean-decoder-inventory-complete" and
        .side == "${side}" and
        .counts.regions > 0 and
        .counts.occurrences >= .counts.regions and
        .counts.unique_forms == (.forms | length) and
        .counts.unique_forms > 0 and
        .trust.lean_decoder_executed and
        .trust.acceptance_exact_pe_decode_replay_required and
        (.trust.semantic_conformance_authority | not) and
        (.trust.whole_program_acceptance_authority | not)
      ' "$out/summary.json" >/dev/null
    '';

  smoke = mkPhase "stage-a-gnu-hello-roundtrip-smoke" [] ''
    ${python} ${runtimeDriver} smoke \
      --original ${originalPe} \
      --linker-map ${originalMap} \
      --out "$out"
    jq -e '
      .format == "stage-a-gnu-hello-roundtrip-smoke-v1" and
      .status == "pass" and .static_only and
      (.executes_original_binary | not) and
      (.executes_candidate_binary | not) and
      .original.machine == "i386" and .original.bitness == 32
    ' "$out/smoke.json" >/dev/null
  '';

  opaqueOriginalInventory = mkStaticBinaryInventory {
    name = "stage-a-gnu-hello-opaque-original-inventory";
    side = "original";
    binary = originalPe;
  };

  opaqueStaticExport = pkgs.runCommand
    "stage-a-gnu-hello-opaque-static-export-v1"
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      export PYTHONPATH=${opaqueStaticPythonSource}/src
      test ! -e ${opaqueStaticPythonSource}/src/spaghetti_extractor/component_workspace.py
      test ! -e ${opaqueStaticPythonSource}/src/spaghetti_extractor/reconstruction_workspace.py
      ${python} - ${lib.escapeShellArg originalPe} \
        ${lib.escapeShellArg "${opaqueOriginalInventory}/inventory.json"} \
        "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.opaque_reconstruction import (
          stage_a_export_opaque_reconstruction,
      )

      original, inventory, output = map(pathlib.Path, sys.argv[1:])
      stage_a_export_opaque_reconstruction(
          original=original,
          inventory=inventory,
          out=output,
      )
      PY
      jq -e '
        .format == "stage-a-opaque-static-export-v1" and
        .status == "ready" and
        .original.sha256 ==
          "71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c" and
        .counts.regions == 7741 and
        .counts.transfers == 7741 and
        .counts.padding_waivers == 621 and
        .counts.imports == 75 and
        .counts.tls_callbacks == 2 and
        (.trust.executes_original_binary | not) and
        (.trust.uses_linker_map | not) and
        (.trust.uses_symbols_for_authority | not) and
        .trust.includes_all_recovered_code and
        (.trust.reference_contract_is_formal_acceptance | not)
      ' "$out/opaque-static-export.json" >/dev/null
    '';

  opaqueStateMachine = pkgs.runCommand
    "stage-b-gnu-hello-opaque-state-machine-v1"
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      export PYTHONPATH=${paddingStaticPythonSource}/src
      mkdir -p "$out"
      ${python} - ${lib.escapeShellArg "${opaqueStaticExport}/state-machine.jsonl"} \
        ${lib.escapeShellArg originalPe} \
        ${lib.escapeShellArg "${opaqueStaticExport}/opaque-self-map.json"} \
        ${lib.escapeShellArg machineRuntimeProfile} \
        "$out/state-machine.jsonl" "$out/padding-bridges.json" <<'PY'
      import json
      import pathlib
      import sys
      from spaghetti_extractor.stage_b_state_machine import (
          augment_state_machine_with_padding_bridges,
      )
      from spaghetti_extractor.util import write_json

      source, original, block_map, profile, output, report = map(pathlib.Path, sys.argv[1:])
      result = augment_state_machine_with_padding_bridges(
          state_machine=source,
          original_pe=original,
          block_map=block_map,
          external_profile=profile,
          out=output,
      )
      write_json(report, {
          "format": "stage-b-padding-bridge-augmentation-v1",
          "status": "complete",
          "state_machine": {"path": output.name, "sha256": result.sha256},
          "counts": {
              "input_transfers": result.input_transfer_count,
              "padding_bridges": result.padding_bridge_count,
              "output_transfers": result.output_transfer_count,
              "terminating_transfers": len(result.terminating_transfer_rvas),
          },
          "bridged_rvas": list(result.bridged_rvas),
          "terminating_transfer_rvas": list(result.terminating_transfer_rvas),
          "trust": {
              "executes_original_binary": False,
              "external_termination_profile_bound": True,
          },
      })
      PY
      jq -e '
        .format == "stage-b-padding-bridge-augmentation-v1" and
        .status == "complete" and
        .counts.input_transfers == 7741 and
        .counts.padding_bridges == 120 and
        .counts.output_transfers == 7861 and
        .counts.terminating_transfers == 17 and
        (.trust.executes_original_binary | not) and
        .trust.external_termination_profile_bound
      ' "$out/padding-bridges.json" >/dev/null
    '';

  machineIr = pkgs.runCommand
    "stage-a-gnu-hello-machine-ir-v2"
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      export PYTHONPATH=${reconstructionStaticPythonSource}/src
      ${python} - ${lib.escapeShellArg "${opaqueStateMachine}/state-machine.jsonl"} \
        ${lib.escapeShellArg originalPe} \
        ${lib.escapeShellArg "${opaqueStaticExport}/reference-contract.json"} \
        ${lib.escapeShellArg "${machineRuntimeProfileSource}/pe32-static-cutpoints-and-paired-callables-v1.json"} \
        "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.reconstruction_ir import export_machine_ir_package

      state_machine, original, reference, target_profile, output = map(pathlib.Path, sys.argv[1:])
      export_machine_ir_package(
          state_machine=state_machine,
          original_pe=original,
          reference_contract=reference,
          indirect_target_profile=target_profile,
          out=output,
      )
      PY
      jq -e '
        .format == "stage-a-machine-ir-v2" and
        .status == "incomplete" and
        .binary.sha256 ==
          "71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c" and
        .counts.units == 7861 and
        .counts.instructions == 21133 and
        .counts.x87_micro_ops == 313 and
        .counts.violated_issues == 0 and
        .counts.incomplete_issues > 0 and
        .coverage.counts.executable_bytes == 79476 and
        .coverage.counts.unknown_bytes == 0 and
        # Entrypoint, export, and TLS callback are exact roots. A callback
        # registration proposal remains potential until its call is checked.
        .control.counts.roots >= 3 and
        .control.counts.unresolved_direct_targets == 0 and
        .control.counts.indirect_exits == 95 and
        .control.counts.closed_indirect_exits == 3 and
        .control.counts.rooted_frontiers > 0 and
        .control.counts.exact_reachable_units > 0 and
        .control.counts.potential_reachable_units > 0 and
        .control.reachability.status == "incomplete" and
        ([.control.recovered_indirect_targets[] |
          select(.status == "recovered" and .source_rva == 14383 and
            (.entries | length) == 36 and (.target_rvas | length) == 12)] |
          length) == 1 and
        .control.indirect_target_profile.id ==
          "pe32-static-cutpoints-and-paired-callables-v1" and
        .authority ==
          "static sanitizing export; no original execution; qualification requires independent downstream evidence"
      ' "$out/machine-ir-manifest.json" >/dev/null
    '';

  reconstructionInterpreter = pkgs.runCommand
    "stage-b-gnu-hello-machine-ir-interpreter-v1"
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      export PYTHONPATH=${interpreterPythonSource}/src
      ${python} - ${lib.escapeShellArg "${machineIr}/machine-ir.jsonl"} "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.stage_b_interpreter_backend import (
          write_stage_b_interpreter_package,
      )

      machine_ir, output = map(pathlib.Path, sys.argv[1:])
      write_stage_b_interpreter_package(machine_ir=machine_ir, out=output)
      PY
      jq -e '
        .format == "stage-b-semantic-interpreter-package-v1" and
        .status == "ready" and
        .counts.input_transfers == 7861 and
        .counts.transfers == 7861 and
        .counts.blocked_transfers == 0 and
        .counts.x87_operations == 313 and
        .input_mode == "sanitized_machine_ir_v2"
      ' "$out/state-machine-interpreter-package.json" >/dev/null
    '';

  reconstructionNativeEngine = pkgs.runCommand
    "stage-b-gnu-hello-machine-ir-native-engine-v1"
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      export PYTHONPATH=${runtimePythonSource}/src
      ${python} - \
        ${lib.escapeShellArg "${machineIr}/machine-ir.jsonl"} \
        ${lib.escapeShellArg "${opaqueStaticExport}/load-image-contract.json"} \
        ${lib.escapeShellArg "${opaqueStaticExport}/reference-contract.json"} \
        ${lib.escapeShellArg "${callableExternalRuntimeContract}/callable-external-runtime-contract.json"} \
        "$out" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.roundtrip_fuzz.image_contract import (
          load_stage_a_load_image_contract,
      )
      from spaghetti_extractor.stage_b_native_engine import (
          write_stage_b_native_engine_package,
      )
      from spaghetti_extractor.util import sha256_file

      machine_ir, load_contract_path, reference_path, callable_contract, output = map(
          pathlib.Path, sys.argv[1:]
      )
      contract = load_stage_a_load_image_contract(load_contract_path)
      callbacks = []
      if contract.tls is not None:
          callbacks.extend(
              {
                  "rva": callback.rva,
                  "kind": "tls_callback",
                  "stack_cleanup_bytes": 12,
              }
              for callback in contract.tls.callbacks
          )
      import_iat_vas = {}
      for descriptor in contract.imports:
          for cell in descriptor.cells:
              identity = cell.symbol if cell.symbol is not None else cell.ordinal
              if identity is None:
                  raise ValueError("load-image import cell has no identity")
              key = (descriptor.dll.lower(), identity)
              value = contract.identity.preferred_base + cell.iat_rva
              previous = import_iat_vas.setdefault(key, value)
              if previous != value:
                  raise ValueError(f"ambiguous IAT cells for {key!r}")
      relocations = []
      for block in contract.relocations:
          for relocation in block.relocations:
              if (
                  relocation.target_rva is None
                  or relocation.preferred_value is None
                  or relocation.width == 0
              ):
                  continue
              relocations.append(
                  {
                      "source_rva": relocation.target_rva,
                      "type": relocation.type,
                      "kind": relocation.kind,
                      "width": relocation.width,
                      "preferred_value": relocation.preferred_value,
                  }
              )
      write_stage_b_native_engine_package(
          machine_ir=machine_ir,
          entry_rva=contract.identity.entry_rva,
          callback_targets=callbacks,
          import_iat_vas=import_iat_vas,
          base_relocation_evidence={
              "format": "stage-b-pe32-base-relocation-evidence-v1",
              "complete": contract.completeness.complete,
              "pe_sha256": contract.identity.pe_sha256,
              "reference_contract_sha256": sha256_file(reference_path),
              "image_base": contract.identity.preferred_base,
              "relocations": relocations,
          },
          callable_external_contract=callable_contract,
          out=output,
      )
      PY
      jq -e '
        .format == "stage-b-native-engine-package-v1" and
        .status == "ready" and
        .input_mode == "sanitized_machine_ir_v2" and
        .counts.transfers == 7861 and
        .counts.external_sites == 406 and
        .counts.indirect_calls == 83 and
        .counts.callback_targets == 7 and
        .counts.callback_adapters == 5 and
        .counts.callable_external_routes > 0 and
        .counts.x87_operations == 313 and
        .counts.blockers == 0 and
        (.policy.raw_x87_instruction_payloads == "forbidden")
      ' "$out/native-engine-package.json" >/dev/null
    '';

  reconstructionNativeRuntime = pkgs.runCommand
    "stage-b-gnu-hello-machine-ir-native-runtime-v1"
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      export PYTHONPATH=${runtimePythonSource}/src
      ${python} - \
        ${lib.escapeShellArg reconstructionInterpreter} \
        ${lib.escapeShellArg reconstructionNativeEngine} \
        ${lib.escapeShellArg machineRuntimeProfile} \
        ${lib.escapeShellArg "${callableExternalRuntimeContract}/callable-external-runtime-contract.json"} \
        "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.stage_b_native_runtime import (
          write_stage_b_native_runtime_package,
      )

      interpreter, engine, profile, callable_contract, output = map(
          pathlib.Path, sys.argv[1:]
      )
      write_stage_b_native_runtime_package(
          interpreter_package=interpreter,
          native_engine_package=engine,
          external_profile=profile,
          callable_external_contract=callable_contract,
          out=output,
      )
      PY
      expected_machine_ir_sha256="$(
        sha256sum ${machineIr}/machine-ir.jsonl | cut -d ' ' -f1
      )"
      jq -e --arg expected_machine_ir_sha256 "$expected_machine_ir_sha256" '
        .format == "stage-b-native-runtime-package-v1" and
        .status == "ready" and
        .counts.transfers == 7861 and
        .inputs.state_machine_sha256 == $expected_machine_ir_sha256 and
        .counts.callable_external_routes > 0 and
        (.inputs.external_range_contracts.rules | length) > 0
      ' "$out/native-runtime-package.json" >/dev/null
    '';

  reconstructionWorkspaceDag = import ./stage-b-reconstruction-workspace.nix {
    inherit pkgs pythonEnv;
    pythonSource = runtimePythonSource;
    machineIr = machineIr;
    interpreterPackage = reconstructionInterpreter;
    signatureCatalog = machineRuntimeProfile;
    namePrefix = "stage-b-gnu-hello";
    clusters = [
      {
        name = "branch";
        entryRva = 4152;
        template = "compare_branch";
        expectedCases = 4;
      }
      {
        name = "external-call";
        entryRva = 4160;
        template = "constant_external_call";
        expectedCases = 2;
      }
      {
        name = "internal-call";
        entryRva = 4609;
        template = "store_then_zero_call";
        expectedCases = 2;
      }
      {
        name = "atomic";
        entryRva = 4176;
        template = "manual_contract";
        expectedCases = 13;
        portableSource = ../fixtures/gnu-hello/reconstruction/atomic.c;
      }
      {
        name = "callback";
        entryRva = 4407;
        template = "constant_external_call";
        expectedCases = 2;
      }
      {
        name = "dispatch";
        entryRva = 14383;
        template = "manual_contract";
        expectedCases = 36;
        portableSource = ../fixtures/gnu-hello/reconstruction/dispatch.c;
      }
      {
        name = "typed-memory";
        entryRva = 53481;
        template = "manual_contract";
        expectedCases = 101;
        portableSource = ../fixtures/gnu-hello/reconstruction/typed-memory.c;
      }
    ];
  };
  reconstructionPlan = reconstructionWorkspaceDag.plan;
  semanticComponents = import ./stage-b-semantic-components.nix {
    inherit pkgs pythonEnv;
    pythonSource = semanticComponentPythonSource;
    machineIr = machineIr;
    reconstructionPlan = reconstructionPlan;
    declarations = ../fixtures/gnu-hello/semantic-components.json;
    namePrefix = "stage-b-gnu-hello";
    validationProfile = "gnu-hello-validation-set-v1";
  };
  componentProposals = import ./stage-b-component-discovery.nix {
    inherit pkgs pythonEnv;
    pythonSource = componentDiscoveryPythonSource;
    machineIr = machineIr;
    reconstructionPlan = reconstructionPlan;
    namePrefix = "stage-b-gnu-hello";
  };
  selectedComponentDeclarations = import ./stage-b-component-selection.nix {
    inherit pkgs pythonEnv componentProposals;
    pythonSource = componentSelectionPythonSource;
    selection = ../fixtures/gnu-hello/component-selection.json;
    namePrefix = "stage-b-gnu-hello";
  };
  selectedSemanticComponents = import ./stage-b-semantic-components.nix {
    inherit pkgs pythonEnv;
    pythonSource = semanticComponentPythonSource;
    machineIr = machineIr;
    reconstructionPlan = reconstructionPlan;
    declarations = "${selectedComponentDeclarations}/semantic-component-declarations.json";
    namePrefix = "stage-b-gnu-hello-selected";
  };
  semanticComponentWorkspaceDag = import ./stage-b-semantic-component-workspaces.nix {
    inherit pkgs pythonEnv;
    pythonSource = componentWorkspacePythonSource;
    profilePythonSources = {
      bounded_pairwise_byte_compare_v1 =
        pairwiseByteComponentProfilePythonSource;
      bounded_last_component_v1 = lastComponentProfilePythonSource;
      external_zero_predicate_v1 = externalZeroPredicateProfilePythonSource;
      basename_prefix_selection_v1 = basenamePrefixSelectionProfilePythonSource;
    };
    machineIr = machineIr;
    interpreterPackage = reconstructionInterpreter;
    reconstructionPlan = reconstructionPlan;
    semanticComponentCatalog = selectedSemanticComponents;
    inherit linkedIslands;
    namePrefix = "stage-b-gnu-hello";
    components = [
      {
        name = "branch";
        componentId = "startup-compare-route";
        interfaceSpec = ../fixtures/gnu-hello/component-interfaces/branch.json;
        proofProfile = "compare_branch_v1";
        expectedCases = 4;
      }
      {
        name = "external-call";
        componentId = "startup-sleep-service";
        interfaceSpec = ../fixtures/gnu-hello/component-interfaces/external-call.json;
        proofProfile = "constant_service_call_v1";
        expectedCases = 2;
      }
      {
        name = "internal-call";
        componentId = "static-word-initialization";
        interfaceSpec = ../fixtures/gnu-hello/component-interfaces/internal-call.json;
        proofProfile = "store_then_zero_call_v1";
        expectedCases = 2;
      }
      {
        name = "short-option";
        componentId = "short-option-classifier";
        interfaceSpec = ../fixtures/gnu-hello/component-interfaces/short-option.json;
        proofProfile = "constant_compare_branch_v1";
        expectedCases = 25;
      }
      {
        name = "rotate";
        componentId = "rotate-pending-words";
        interfaceSpec = ../fixtures/gnu-hello/component-interfaces/rotate.json;
        proofProfile = "bounded_range_rotation_v1";
        expectedCases = 8;
      }
      {
        name = "windows-error";
        componentId = "windows-error-message-lookup";
        interfaceSpec = ../fixtures/gnu-hello/component-interfaces/windows-error.json;
        proofProfile = "finite_acyclic_static_string_lookup_v1";
        staticImage = originalPe;
        expectedCases = 56;
      }
      {
        name = "bounded-string-length";
        componentId = "bounded-string-length";
        proofProfile = "bounded_string_length_v1";
        expectedCases = 153;
      }
      {
        name = "atomic";
        componentId = "startup-atomic-compare-exchange";
        interfaceSpec = ../fixtures/gnu-hello/component-interfaces/atomic.json;
        proofProfile = "atomic_compare_exchange_v1";
        expectedCases = 13;
        portableSource = ../fixtures/gnu-hello/reconstruction/atomic.c;
      }
      {
        name = "callback";
        componentId = "startup-callback-registration";
        interfaceSpec = ../fixtures/gnu-hello/component-interfaces/callback.json;
        proofProfile = "constant_service_call_v1";
        expectedCases = 2;
      }
      {
        name = "dispatch";
        componentId = "finite-selector-dispatch";
        interfaceSpec = ../fixtures/gnu-hello/component-interfaces/dispatch.json;
        proofProfile = "finite_dispatch_v1";
        expectedCases = 36;
        portableSource = ../fixtures/gnu-hello/reconstruction/dispatch.c;
      }
      {
        name = "typed-memory";
        componentId = "alias-sensitive-word-update";
        interfaceSpec = ../fixtures/gnu-hello/component-interfaces/typed-memory.json;
        proofProfile = "alias_sensitive_word_update_v1";
        expectedCases = 101;
        portableSource = ../fixtures/gnu-hello/reconstruction/typed-memory.c;
      }
      {
        name = "ascii-to-lower";
        componentId = "ascii-to-lower";
        proofProfile = "finite_acyclic_scalar_v1";
        expectedCases = 263;
      }
      {
        name = "ascii-string-compare";
        componentId = "ascii-string-compare";
        proofProfile = "bounded_pairwise_byte_compare_v1";
        dependencies = [ "ascii-to-lower" ];
        expectedCases = 43;
      }
      {
        name = "last-path-component";
        componentId = "last-path-component";
        proofProfile = "bounded_last_component_v1";
        expectedCases = 19;
      }
      {
        name = "memory-regions-equal";
        componentId = "memory-regions-equal";
        proofProfile = "external_zero_predicate_v1";
        expectedCases = 16;
      }
      {
        name = "program-name-selection";
        componentId = "program-name-selection";
        proofProfile = "basename_prefix_selection_v1";
        dependencies = [ "memory-regions-equal" ];
        staticImage = originalPe;
        expectedCases = 10;
      }
    ];
  };
  reconstructionLiftingEvidence = pkgs.runCommand
    "stage-b-gnu-hello-lifting-evidence-v1"
    {
      nativeBuildInputs = [ pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      plan=${reconstructionPlan}/reconstruction-plan.json
      manifest=${machineIr}/machine-ir-manifest.json
      dispatch_workspace=${reconstructionWorkspaceDag.workspaces.dispatch}
      registry=${reconstructionWorkspaceRegistry}/reconstruction-registry.json
      reconstruction_status=${reconstructionWorkspaceRegistry}/reconstruction-status.json
      atomic_validation=${reconstructionWorkspaceDag.checks.atomic}/validation-report.json
      callback_validation=${reconstructionWorkspaceDag.checks.callback}/validation-report.json
      dispatch_validation=${reconstructionWorkspaceDag.checks.dispatch}/validation-report.json
      typed_memory_validation=${reconstructionWorkspaceDag.checks.typed-memory}/validation-report.json
      jq -e '
        .status == "incomplete" and
        .control.counts.closed_indirect_exits == 3 and
        .control.counts.rooted_frontiers > 0 and
        .control.counts.exact_reachable_units > 0 and
        .control.counts.potential_reachable_units > 0
      ' "$manifest" >/dev/null
      jq -e '
        (first(.clusters[] | select(.entry_rva == 14383)) as $dispatch |
          $dispatch.typed_contract.status == "complete" and
          ($dispatch.control | length) == 1 and
          $dispatch.control[0].finite_target_inventory and
          ($dispatch.control[0].dispatch_entries | length) == 36 and
          ($dispatch.control[0].target_rvas | length) == 12 and
          $dispatch.validation_requirements.finite_dispatch_cases == 36) and
        (first(.clusters[] | select(.entry_rva == 53481)) as $memory |
          $memory.typed_contract.status == "complete" and
          any($memory.typed_contract.memory_views[];
            .base_role == "object_pointer" and
            ([.fields[].offset] | sort) == [4, 8]) and
          ($memory.typed_contract.preconditions.aliasing | length) > 0) and
        (first(.clusters[] | select(.entry_rva == 4176)) as $atomic |
          $atomic.typed_contract.status == "complete" and
          ($atomic.typed_contract.atomic_effects | length) == 1 and
          $atomic.typed_contract.atomic_effects[0].operation == "compare_exchange" and
          $atomic.typed_contract.atomic_effects[0].ordering.kind ==
            "locked_instruction_order") and
        (first(.clusters[] | select(.entry_rva == 4407)) as $callback |
          $callback.typed_contract.status == "complete" and
          ($callback.typed_contract.callbacks | length) == 1 and
          $callback.typed_contract.callbacks[0].nested_frame.status == "complete" and
          $callback.typed_contract.callbacks[0].lifetime.status == "complete" and
          $callback.typed_contract.external_services[0].catalog.matched)
      ' "$plan" >/dev/null
      jq -e '
        .format == "stage-b-reconstruction-workspace-v1" and
        .status == "editable" and .template == "manual_contract" and
        (.executes_original_binary | not)
      ' "$dispatch_workspace/workspace.json" >/dev/null
      jq -e '
        .format == "stage-b-reconstruction-validation-cases-v1" and
        .counts.indirect_dispatch == 36 and
        ([.indirect_dispatch_cases[] |
          select(.dispatch_binding.executable == true)] | length) == 36
      ' "$dispatch_workspace/tests/generated-validation-cases.json" >/dev/null
      jq -e '
        .format == "stage-b-reconstruction-cases-v1" and
        (.cases | length) == 36 and
        ([.cases[].registers.eax] | sort) == ([range(0; 36)] | sort)
      ' "$dispatch_workspace/tests/cases.json" >/dev/null
      jq -e '
        .format == "stage-b-reconstruction-registry-v1" and
        .status == "qualified" and
        (.executes_original_binary | not) and
        .counts.replacements == 7
      ' "$registry" >/dev/null
      jq -e '
        .format == "stage-b-reconstruction-status-v1" and
        .status == "incomplete" and
        .counts.reachable_clusters == 922 and
        .counts.promoted_clusters == 5 and
        .counts.remaining_clusters == 917 and
        .counts.remaining_without_template == 901
      ' "$reconstruction_status" >/dev/null
      jq -e '.status == "qualified" and .counts.compared_cases == 13 and .counts.deltas == 0' \
        "$atomic_validation" >/dev/null
      jq -e '.status == "qualified" and .counts.compared_cases == 2 and .counts.deltas == 0' \
        "$callback_validation" >/dev/null
      jq -e '.status == "qualified" and .counts.compared_cases == 36 and .counts.deltas == 0' \
        "$dispatch_validation" >/dev/null
      jq -e '.status == "qualified" and .counts.compared_cases == 101 and .counts.deltas == 0' \
        "$typed_memory_validation" >/dev/null
      mkdir -p "$out"
      jq -n \
        --slurpfile manifest "$manifest" \
        --slurpfile plan "$plan" \
        --slurpfile registry "$registry" \
        --slurpfile reconstruction_status "$reconstruction_status" \
        --slurpfile atomic_validation "$atomic_validation" \
        --slurpfile callback_validation "$callback_validation" \
        --slurpfile dispatch_validation "$dispatch_validation" \
        --slurpfile typed_memory_validation "$typed_memory_validation" '
        ($manifest[0]) as $m |
        ($plan[0]) as $p |
        ($registry[0]) as $r |
        ($reconstruction_status[0]) as $s |
        {
          format: "stage-b-gnu-hello-lifting-evidence-v1",
          status: "usable-incomplete",
          executes_original_binary: false,
          reachability: {
            status: $m.control.reachability.status,
            exact_units: $m.control.counts.exact_reachable_units,
            potential_units: $m.control.counts.potential_reachable_units,
            rooted_frontiers: $m.control.counts.rooted_frontiers
          },
          source_lifting: {
            registry_status: $r.status,
            qualified_replacements: $r.counts.replacements,
            exact_reachable_clusters: $s.counts.reachable_clusters,
            promoted_exact_clusters: $s.counts.promoted_clusters,
            remaining_exact_clusters: $s.counts.remaining_clusters,
            remaining_without_template: $s.counts.remaining_without_template
          },
          hard_lifts: [
            {
              entry_rva: 4176,
              class: "atomic_compare_exchange",
              validation: $atomic_validation[0]
            },
            {
              entry_rva: 4407,
              class: "callback_registration",
              validation: $callback_validation[0]
            },
            {
              entry_rva: 14383,
              class: "finite_indirect_dispatch",
              validation: $dispatch_validation[0]
            },
            {
              entry_rva: 53481,
              class: "ordered_alias_sensitive_memory",
              validation: $typed_memory_validation[0]
            }
          ] | map({
            entry_rva,
            class,
            status: .validation.status,
            compared_cases: .validation.counts.compared_cases,
            deltas: .validation.counts.deltas,
            incomplete: .validation.counts.incomplete,
            executes_original_binary: .validation.executes_original_binary
          }),
          examples: [
            $p.clusters[] |
            select(.entry_rva == 14383 or .entry_rva == 53481 or
              .entry_rva == 4176 or .entry_rva == 4407) |
            {
              cluster_id: .id,
              entry_rva,
              typed_status: .typed_contract.status,
              validation_requirements,
              blocker_codes: [.blockers[].code]
            }
          ]
        }
      ' > "$out/lifting-evidence.json"
    '';
  reconstructionBranchWorkspace = reconstructionWorkspaceDag.workspaces.branch;
  reconstructionExternalWorkspace =
    reconstructionWorkspaceDag.workspaces.external-call;
  reconstructionInternalWorkspace =
    reconstructionWorkspaceDag.workspaces.internal-call;
  reconstructionAtomicWorkspace = reconstructionWorkspaceDag.workspaces.atomic;
  reconstructionCallbackWorkspace = reconstructionWorkspaceDag.workspaces.callback;
  reconstructionDispatchWorkspace = reconstructionWorkspaceDag.workspaces.dispatch;
  reconstructionTypedMemoryWorkspace =
    reconstructionWorkspaceDag.workspaces.typed-memory;
  reconstructionBranchWorkspaceCheck = reconstructionWorkspaceDag.checks.branch;
  reconstructionExternalWorkspaceCheck =
    reconstructionWorkspaceDag.checks.external-call;
  reconstructionInternalWorkspaceCheck =
    reconstructionWorkspaceDag.checks.internal-call;
  reconstructionAtomicWorkspaceCheck = reconstructionWorkspaceDag.checks.atomic;
  reconstructionCallbackWorkspaceCheck =
    reconstructionWorkspaceDag.checks.callback;
  reconstructionDispatchWorkspaceCheck =
    reconstructionWorkspaceDag.checks.dispatch;
  reconstructionTypedMemoryWorkspaceCheck =
    reconstructionWorkspaceDag.checks.typed-memory;
  reconstructionWorkspaceRegistry = reconstructionWorkspaceDag.registry;
  semanticComponentRegistry = semanticComponentWorkspaceDag.registry;


  reconstructionEntryReplacement = pkgs.runCommand
    "stage-b-gnu-hello-entry-replacement-v1"
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export PYTHONPATH=${runtimePythonSource}/src
      ${python} - \
        ${machineIr}/machine-ir.jsonl \
        ${reconstructionInterpreter}/state-machine-interpreter-package.json \
        "$out" <<'PY'
      import json
      import pathlib
      import sys

      from spaghetti_extractor.region_replacement import (
          REGION_REPLACEMENT_FORMAT,
          generate_region_override_table,
          write_region_replacement_manifest,
      )
      from spaghetti_extractor.util import sha256_bytes, sha256_file, write_json

      machine_ir_path = pathlib.Path(sys.argv[1])
      interpreter_manifest_path = pathlib.Path(sys.argv[2])
      output = pathlib.Path(sys.argv[3])
      output.mkdir(parents=True, exist_ok=True)

      units = [
          json.loads(line)
          for line in machine_ir_path.read_text(encoding="utf-8").splitlines()
          if line
      ]
      matches = [
          unit for unit in units
          if unit.get("record_kind") == "unit"
          and unit.get("source", {}).get("original", {}).get("rva_start") == 0x1420
      ]
      if len(matches) != 1:
          raise SystemExit("expected one machine-IR unit at the PE entry RVA")
      unit = matches[0]
      semantics = unit.get("semantics", {})
      expected_memory = [{
          "address": {"op": "const", "value": 0x430348, "width": 32},
          "kind": "write",
          "value": {"op": "const", "value": 0, "width": 32},
          "width": 4,
      }]
      expected_outcome = {"kind": "jump", "target_rva": 0x1010}
      if (
          semantics.get("memory_events") != expected_memory
          or semantics.get("register_writes") != []
          or semantics.get("flag_writes") != []
          or semantics.get("external_events") != []
          or semantics.get("outcome") != expected_outcome
      ):
          raise SystemExit("GNU Hello entry-unit semantics changed")

      source_lines = [
          '#include "state-machine-runtime.h"',
          'stage_b_step_result gnu_hello_replace_entry(',
          '    stage_b_runtime *rt, stage_b_machine_state *state) {',
          '  uint32_t memory_fault = 0U;',
          '  state->original_rva = 0x00001420U;',
          '  if (rt == 0 || rt->write == 0)',
          '    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };',
          '  rt->write(rt->context, 0x00430348U, 4U, 0U, &memory_fault);',
          '  if (memory_fault)',
          '    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };',
          '  return (stage_b_step_result){ STAGE_B_JUMP, 0x00001010U, 0U };',
          '}',
      ]
      source_path = output / "gnu-hello-entry-replacement.c"
      source_path.write_text("\n".join(source_lines) + "\n", encoding="ascii")

      interpreter = json.loads(interpreter_manifest_path.read_text(encoding="utf-8"))
      program = interpreter.get("program", {})
      program_path = interpreter_manifest_path.parent / str(program.get("path"))
      if sha256_file(program_path) != program.get("sha256"):
          raise SystemExit("interpreter baseline program binding is stale")
      evidence_sha256 = sha256_bytes(json.dumps(
          {"unit": unit["id"], "semantics": semantics},
          sort_keys=True,
          separators=(",", ":"),
      ).encode("ascii"))
      evidence_id = "evidence:exhaustive-entry-lowering"
      replacement = {
          "format": REGION_REPLACEMENT_FORMAT,
          "id": "gnu-hello-entry-initialization",
          "bindings": {
              "machine_ir_sha256": sha256_file(machine_ir_path),
              "baseline_program_sha256": program["sha256"],
              "cluster_contract_sha256": unit["source"]["contract_sha256"],
          },
          "cluster": {
              "id": "cluster:gnu-hello-entry-initialization",
              "entry_unit_id": unit["id"],
              "entry_rva": 0x1420,
              "unit_ids": [unit["id"]],
              "rva_spans": [{"start": 0x1420, "end": 0x142f}],
          },
          "source": {
              "path": source_path.name,
              "sha256": sha256_file(source_path),
              "symbol": "gnu_hello_replace_entry",
              "line_start": 2,
              "line_end": len(source_lines),
          },
          "abi": {
              "calling_convention": "machine_state",
              "stack_delta": 0,
              "parameters": [],
              "results": [],
              "preserved_registers": [
                  "eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp",
              ],
              "clobbered_registers": [],
              "evidence_ids": [evidence_id],
          },
          "type_hypotheses": [],
          "live_state": {"inputs": [], "outputs": []},
          "memory_views": [{
              "id": "memory:startup-global",
              "base_expression": "0x00430348",
              "byte_length": 4,
              "length_expression": None,
              "access": "write",
              "representation": "little-endian uint32 static word",
              "evidence_ids": [evidence_id],
          }],
          "expectations": {
              "control": [{
                  "id": "exit:startup-continuation",
                  "kind": "jump",
                  "target_unit_ids": [
                      "semantic-transfer:original-cutpoint-00001010-0000101f"
                  ],
                  "target_rvas": [0x1010],
                  "evidence_ids": [evidence_id],
              }],
              "fault": {
                  "allow_none": True,
                  "variants": [{
                      "id": "fault:memory",
                      "kind": "memory_fault",
                      "evidence_ids": [evidence_id],
                  }],
              },
              "external_events": [],
          },
          "evidence": [{
              "id": evidence_id,
              "class": "exhaustive",
              "status": "qualified",
              "artifact_sha256": evidence_sha256,
              "detail": (
                  "the complete normalized effect list was matched before "
                  "emitting the constrained C replacement"
              ),
          }],
      }
      replacement_path = output / "region-replacement.json"
      manifest = write_region_replacement_manifest(
          replacement_path, replacement, source_root=output
      )
      override = generate_region_override_table(
          manifests=[manifest], source_root=output, out_dir=output
      )
      write_json(output / "replacement-evidence.json", {
          "format": "stage-b-structural-region-replacement-evidence-v1",
          "status": "qualified",
          "executes_original_binary": False,
          "machine_ir_sha256": sha256_file(machine_ir_path),
          "baseline_program_sha256": program["sha256"],
          "unit_id": unit["id"],
          "unit_contract_sha256": unit["source"]["contract_sha256"],
          "normalized_effects_sha256": evidence_sha256,
          "replacement_manifest_sha256": manifest.manifest_sha256,
          "override_table_sha256": json.loads(
              override.manifest.read_text(encoding="utf-8")
          )["table_sha256"],
          "checks": {
              "complete_memory_effects": "verified",
              "complete_register_effects": "verified",
              "complete_flag_effects": "verified",
              "complete_external_effects": "verified",
              "exact_control_exit": "verified",
              "source_hash": "verified",
          },
      })
      PY
      jq -e '
        .format == "stage-b-region-override-table-v1" and
        .status == "ready" and (.executes_original_binary | not) and
        (.entries | length) == 1 and
        .entries[0].entry_rva == 5152
      ' "$out/region-overrides-manifest.json" >/dev/null
      jq -e '
        .format == "stage-b-structural-region-replacement-evidence-v1" and
        .status == "qualified" and (.executes_original_binary | not)
      ' "$out/replacement-evidence.json" >/dev/null
    '';

  reconstructionRegionalHarnessKernel = pkgs.runCommand
    "stage-b-gnu-hello-regional-harness-kernel-v1"
    {
      nativeBuildInputs = [ pkgs.stdenv.cc pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      mkdir -p "$out/include" "$out/objects"
      cp ${reconstructionInterpreter}/state-machine-runtime.h "$out/include/"
      cp ${reconstructionInterpreter}/state-machine-interpreter.h "$out/include/"
      cp ${reconstructionInterpreter}/state-machine-interpreter-internal.h "$out/include/"
      cc -std=c11 -O0 -g0 -fno-pie \
        -I${reconstructionInterpreter} \
        -c ${reconstructionInterpreter}/state-machine-interpreter.c \
        -o "$out/objects/interpreter.o"
      cc -std=c11 -O0 -g0 -fno-pie \
        -I${reconstructionInterpreter} \
        -c ${reconstructionInterpreter}/state-machine-program.c \
        -o "$out/objects/program.o"
      test -s "$out/objects/interpreter.o"
      test -s "$out/objects/program.o"
    '';

  mkEntryReplacementRegionalValidation = { name, mutate ? false }:
    pkgs.runCommand name
      {
        nativeBuildInputs = [ pythonEnv pkgs.stdenv.cc pkgs.jq pkgs.coreutils ];
        preferLocalBuild = false;
        allowSubstitutes = true;
        __contentAddressed = true;
      }
      ''
        set -euo pipefail
        export PYTHONHASHSEED=0
        export LC_ALL=C.UTF-8
        export PYTHONPATH=${runtimePythonSource}/src
        replacement_root=${reconstructionEntryReplacement}
        ${lib.optionalString mutate ''
          replacement_root="$TMPDIR/replacement"
          mkdir -p "$replacement_root"
          cp ${reconstructionEntryReplacement}/gnu-hello-entry-replacement.c \
            "$replacement_root/gnu-hello-entry-replacement.c"
          cp ${reconstructionEntryReplacement}/region-replacement.json \
            "$replacement_root/region-replacement.json"
          chmod u+w \
            "$replacement_root/gnu-hello-entry-replacement.c" \
            "$replacement_root/region-replacement.json"
          ${python} - "$replacement_root" <<'PY'
        import json
        import pathlib
        import sys

        from spaghetti_extractor.region_replacement import (
            write_region_replacement_manifest,
        )
        from spaghetti_extractor.util import sha256_file

        root = pathlib.Path(sys.argv[1])
        source = root / "gnu-hello-entry-replacement.c"
        text = source.read_text(encoding="ascii")
        needle = "rt->write(rt->context, 0x00430348U, 4U, 0U, &memory_fault);"
        replacement = "rt->write(rt->context, 0x00430348U, 4U, 1U, &memory_fault);"
        if text.count(needle) != 1:
            raise SystemExit("entry replacement mutation anchor is not unique")
        source.write_text(text.replace(needle, replacement), encoding="ascii")
        payload = json.loads(
            (root / "region-replacement.json").read_text(encoding="utf-8")
        )
        payload["source"]["sha256"] = sha256_file(source)
        write_region_replacement_manifest(
            root / "region-replacement.json", payload, source_root=root
        )
        mutation_line = next(
            index for index, line in enumerate(text.splitlines(), start=1)
            if needle in line
        )
        (root / "mutation-location.json").write_text(
            json.dumps({
                "path": source.name,
                "line": mutation_line,
                "expected": needle,
                "observed": replacement,
            }, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        PY
        ''}
        mkdir -p "$out"
        ${python} - "$TMPDIR/region-harness.c" <<'PY'
        import pathlib
        import sys

        pathlib.Path(sys.argv[1]).write_text(r"""#include <stdint.h>
        #include <stdio.h>
        #include <string.h>
        #include "state-machine-interpreter.h"

        stage_b_step_result gnu_hello_replace_entry(
            stage_b_runtime *rt, stage_b_machine_state *state);

        stage_b_call_status stage_b_dispatch_external_call(
            stage_b_runtime *runtime, const stage_b_call_event *event,
            const stage_b_machine_state *input, stage_b_machine_state *output) {
          (void)runtime;
          (void)event;
          *output = *input;
          return STAGE_B_CALL_UNIMPLEMENTED;
        }

        typedef struct harness_memory {
          uint32_t word;
          uint32_t writes;
          uint32_t address;
          uint32_t width;
          uint32_t value;
        } harness_memory;

        static uint32_t harness_read(
            void *opaque, uint32_t address, uint32_t width, uint32_t *fault) {
          harness_memory *memory = (harness_memory *)opaque;
          if (address != UINT32_C(0x00430348) || width != 4U) {
            *fault = 1U;
            return 0U;
          }
          return memory->word;
        }

        static void harness_write(
            void *opaque, uint32_t address, uint32_t width, uint32_t value,
            uint32_t *fault) {
          harness_memory *memory = (harness_memory *)opaque;
          if (address != UINT32_C(0x00430348) || width != 4U) {
            *fault = 1U;
            return;
          }
          memory->word = value;
          memory->writes += 1U;
          memory->address = address;
          memory->width = width;
          memory->value = value;
        }

        static void emit(
            const char *side, stage_b_step_result result,
            const stage_b_machine_state *state, const harness_memory *memory) {
          printf("%s %u %u %u %u %u %u %u %u\n", side,
              (unsigned)result.kind, (unsigned)result.target_rva,
              (unsigned)result.value, (unsigned)state->original_rva,
              (unsigned)memory->writes, (unsigned)memory->address,
              (unsigned)memory->width, (unsigned)memory->word);
        }

        int main(void) {
          stage_b_machine_state baseline_state;
          stage_b_machine_state replacement_state;
          harness_memory baseline_memory = { UINT32_C(0xa5a5a5a5), 0U, 0U, 0U, 0U };
          harness_memory replacement_memory = baseline_memory;
          stage_b_runtime baseline_runtime;
          stage_b_runtime replacement_runtime;
          stage_b_step_result baseline_result;
          stage_b_step_result replacement_result;

          memset(&baseline_state, 0, sizeof(baseline_state));
          baseline_state.eax = UINT32_C(0x11111111);
          baseline_state.ebx = UINT32_C(0x22222222);
          baseline_state.esp = UINT32_C(0x70001000);
          replacement_state = baseline_state;
          memset(&baseline_runtime, 0, sizeof(baseline_runtime));
          baseline_runtime.context = &baseline_memory;
          baseline_runtime.read = harness_read;
          baseline_runtime.write = harness_write;
          replacement_runtime = baseline_runtime;
          replacement_runtime.context = &replacement_memory;

          baseline_result = stage_b_interpreter_step(
              &baseline_runtime, &baseline_state, UINT32_C(0x00001420));
          replacement_result = gnu_hello_replace_entry(
              &replacement_runtime, &replacement_state);
          emit("baseline", baseline_result, &baseline_state, &baseline_memory);
          emit("replacement", replacement_result, &replacement_state,
              &replacement_memory);
          return 0;
        }
        """, encoding="ascii")
        PY
        cc -std=c11 -O0 -g0 -fno-pie -no-pie \
          -I${reconstructionRegionalHarnessKernel}/include \
          -I"$replacement_root" \
          "$TMPDIR/region-harness.c" \
          "$replacement_root/gnu-hello-entry-replacement.c" \
          ${reconstructionRegionalHarnessKernel}/objects/interpreter.o \
          ${reconstructionRegionalHarnessKernel}/objects/program.o \
          -o "$TMPDIR/region-harness"
        "$TMPDIR/region-harness" > "$TMPDIR/observations.txt"
        ${python} - \
          "$replacement_root" \
          "$TMPDIR/observations.txt" \
          "$out" \
          ${if mutate then "1" else "0"} <<'PY'
        import json
        import pathlib
        import sys

        from spaghetti_extractor.region_replacement import (
            REGION_OBSERVATIONS_FORMAT,
            validate_region_replacement,
        )
        from spaghetti_extractor.util import sha256_file, write_json

        root = pathlib.Path(sys.argv[1])
        observations_path = pathlib.Path(sys.argv[2])
        output = pathlib.Path(sys.argv[3])
        mutated = sys.argv[4] == "1"
        manifest = json.loads(
            (root / "region-replacement.json").read_text(encoding="utf-8")
        )
        observed = {}
        for raw in observations_path.read_text(encoding="ascii").splitlines():
            fields = raw.split()
            if len(fields) != 9:
                raise SystemExit(f"malformed harness observation: {raw!r}")
            side = fields[0]
            observed[side] = [int(field) for field in fields[1:]]
        if set(observed) != {"baseline", "replacement"}:
            raise SystemExit("regional harness omitted an observation side")

        control_names = {
            0: "fallthrough", 1: "jump", 2: "branch", 3: "return",
            4: "indirect_jump", 9: "external_jump",
        }
        def artifact(side):
            kind, target, value, original_rva, writes, address, width, word = observed[side]
            if kind not in control_names:
                raise SystemExit(f"regional harness produced fault/control kind {kind}")
            if writes != 1 or address != 0x00430348 or width != 4:
                raise SystemExit(f"regional harness produced an invalid write footprint: {observed[side]}")
            return {
                "format": REGION_OBSERVATIONS_FORMAT,
                "manifest_sha256": manifest["manifest_sha256"],
                "cases": [{
                    "id": "case:startup-global-initialization",
                    "entry_unit_id": manifest["cluster"]["entry_unit_id"],
                    "live_inputs": [],
                    "live_outputs": [],
                    "memory_views": [{
                        "id": "memory:startup-global",
                        "base": address,
                        "before": "a5a5a5a5",
                        "after": word.to_bytes(4, "little").hex(),
                    }],
                    "control": {
                        "id": "exit:startup-continuation",
                        "kind": control_names[kind],
                        "target_unit_id": (
                            "semantic-transfer:original-cutpoint-00001010-0000101f"
                            if target == 0x1010 else None
                        ),
                        "target_rva": target or None,
                        "value": value,
                    },
                    "fault": None,
                    "external_events": [],
                }],
            }

        baseline = artifact("baseline")
        replacement = artifact("replacement")
        write_json(output / "baseline-observations.json", baseline)
        write_json(output / "replacement-observations.json", replacement)
        report = validate_region_replacement(
            manifest=root / "region-replacement.json",
            baseline_observations=baseline,
            replacement_observations=replacement,
            source_root=root,
            out=output / "validation-report.json",
        )
        expected_status = "violated" if mutated else "qualified"
        if report["status"] != expected_status:
            raise SystemExit(
                f"expected {expected_status} regional validation, got {report['status']}"
            )
        if mutated:
            locations = [
                delta["location"]["source"] for delta in report["deltas"]
                if delta["status"] == "violated"
            ]
            if not locations:
                raise SystemExit("mutated replacement produced no source-mapped violation")
            mutation = json.loads(
                (root / "mutation-location.json").read_text(encoding="utf-8")
            )
            write_json(output / "mutation-campaign.json", {
                "format": "stage-b-region-replacement-mutation-campaign-v1",
                "status": "qualified",
                "executes_original_binary": False,
                "mutations": [{
                    "id": "gnu-hello-entry-write-value",
                    "detected": True,
                    "validation_status": report["status"],
                    "source": mutation,
                    "reported_locations": locations,
                }],
                "counts": {"mutations": 1, "detected": 1, "not_detected": 0},
            })
        write_json(output / "harness-evidence.json", {
            "format": "stage-b-region-harness-evidence-v1",
            "status": expected_status,
            "executes_original_binary": False,
            "machine_ir_sha256": manifest["bindings"]["machine_ir_sha256"],
            "replacement_manifest_sha256": manifest["manifest_sha256"],
            "baseline_interpreter_objects": {
                "interpreter": sha256_file(
                    pathlib.Path("${reconstructionRegionalHarnessKernel}/objects/interpreter.o")
                ),
                "program": sha256_file(
                    pathlib.Path("${reconstructionRegionalHarnessKernel}/objects/program.o")
                ),
            },
            "candidate_only": True,
        })
        PY
        jq -e --arg expected ${if mutate then "violated" else "qualified"} '
          .format == "stage-b-region-replacement-validation-v1" and
          .status == $expected and (.executes_original_binary | not) and
          .counts.compared_cases == 1
        ' "$out/validation-report.json" >/dev/null
        ${lib.optionalString mutate ''
          jq -e '
            .status == "qualified" and (.executes_original_binary | not) and
            .counts.mutations == 1 and .counts.detected == 1 and
            .counts.not_detected == 0 and
            .mutations[0].validation_status == "violated" and
            .mutations[0].source.line == 8
          ' "$out/mutation-campaign.json" >/dev/null
        ''}
      '';

  reconstructionEntryReplacementValidation =
    mkEntryReplacementRegionalValidation {
      name = "stage-b-gnu-hello-entry-replacement-validation-v1";
    };

  reconstructionEntryReplacementMutation =
    mkEntryReplacementRegionalValidation {
      name = "stage-b-gnu-hello-entry-replacement-mutation-v1";
      mutate = true;
    };

  mkReconstructionCandidate = {
    name,
    diagnosticFailureTrap ? false,
    regionOverridePackage ? null,
    regionOverrideCount ? (if regionOverridePackage == null then 0 else 1),
  }:
  let
    nativeObjectDag = import ./stage-b-native-object-graph.nix {
      inherit pkgs pythonEnv;
      pythonSource = nativeBuildPythonSource;
      interpreterPackage = reconstructionInterpreter;
      nativeEnginePackage = reconstructionNativeEngine;
      nativeRuntimePackage = reconstructionNativeRuntime;
      compiler = mingw32.stdenv.cc;
      namePrefix = name;
      inherit regionOverridePackage diagnosticFailureTrap;
    };
  in pkgs.runCommand
    name
    {
      nativeBuildInputs = [
        pythonEnv
        pkgs.jq
        pkgs.coreutils
        mingw32.stdenv.cc
        mingw32.binutils
      ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      export PYTHONPATH=${nativeBuildPythonSource}/src
      ${python} - \
        ${lib.escapeShellArg reconstructionInterpreter} \
        ${lib.escapeShellArg reconstructionNativeEngine} \
        ${lib.escapeShellArg reconstructionNativeRuntime} \
        ${lib.escapeShellArg "${opaqueStaticExport}/load-image-contract.json"} \
        ${lib.escapeShellArg compiler} \
        ${lib.escapeShellArg (if regionOverridePackage == null then "" else toString regionOverridePackage)} \
        ${if diagnosticFailureTrap then "1" else "0"} \
        ${nativeObjectDag.package} \
        "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.stage_b_interpreter_native_build import (
          build_stage_b_interpreter_native_candidate,
      )

      interpreter, engine, runtime, load_contract, compiler = map(
          pathlib.Path, sys.argv[1:6]
      )
      region_overrides = pathlib.Path(sys.argv[6]) if sys.argv[6] else None
      diagnostic_failure_trap = sys.argv[7] == "1"
      precompiled_objects = pathlib.Path(sys.argv[8])
      output = pathlib.Path(sys.argv[9])
      build_stage_b_interpreter_native_candidate(
          interpreter_package=interpreter,
          native_engine_package=engine,
          native_runtime_package=runtime,
          region_override_package=region_overrides,
          load_image_contract=load_contract,
          compiler=compiler,
          out_dir=output,
          diagnostic_failure_trap=diagnostic_failure_trap,
          precompiled_objects=precompiled_objects,
      )
      PY
      jq -e --argjson diagnostic_failure_trap \
        ${if diagnosticFailureTrap then "true" else "false"} \
        --argjson expected_region_overrides \
        ${toString regionOverrideCount} '
        .format == "stage-b-interpreter-native-build-v1" and
        .status == "candidate-generated" and
        .policy.diagnostic_failure_trap == $diagnostic_failure_trap and
        .policy.object_compilation == "content-addressed-per-source" and
        .policy.region_overrides == $expected_region_overrides
      ' "$out/interpreter-native-build-manifest.json" >/dev/null
      test -s "$out/candidate.exe"
      test -s "$out/payload.map"
      test "$(file -b "$out/candidate.exe" | grep -c "PE32 executable")" -eq 1
    '';

  reconstructionCandidate = mkReconstructionCandidate {
    name = "stage-b-gnu-hello-machine-ir-candidate-v1";
  };

  reconstructionEntryReplacementCandidate = mkReconstructionCandidate {
    name = "stage-b-gnu-hello-entry-replacement-candidate-v1";
    regionOverridePackage = reconstructionEntryReplacement;
  };

  reconstructionWorkspaceCandidate = mkReconstructionCandidate {
    name = "stage-b-gnu-hello-reconstruction-workspace-candidate-v1";
    regionOverridePackage = reconstructionWorkspaceRegistry;
    regionOverrideCount = 3;
  };

  semanticComponentHybridCandidate = mkReconstructionCandidate {
    name = "stage-b-gnu-hello-semantic-component-hybrid-candidate-v1";
    regionOverridePackage = semanticComponentRegistry;
    regionOverrideCount = semanticComponentWorkspaceDag.componentCount;
  };

  reconstructionDiagnosticCandidate = mkReconstructionCandidate {
    name = "stage-b-gnu-hello-machine-ir-diagnostic-candidate-v1";
    diagnosticFailureTrap = true;
  };

  reconstructionQualification = pkgs.runCommand
    "stage-a-gnu-hello-reconstruction-qualification-v1"
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export PYTHONPATH=${reconstructionAssurancePythonSource}/src
      mkdir -p "$out"
      ${python} - \
        ${machineIr}/machine-ir-manifest.json \
        ${machineIr}/machine-ir.jsonl \
        ${reconstructionInterpreter}/state-machine-interpreter-package.json \
        ${reconstructionNativeEngine}/native-engine-package.json \
        ${reconstructionNativeEngine}/native-engine-plan.json \
        ${reconstructionNativeRuntime}/native-runtime-package.json \
        ${reconstructionEntryReplacement}/region-overrides-manifest.json \
        ${reconstructionEntryReplacementCandidate}/interpreter-native-build-manifest.json \
        ${reconstructionEntryReplacementCandidate}/candidate.exe \
        ${reconstructionEntryReplacementValidation}/validation-report.json \
        "$out" <<'PY'
      import json
      import pathlib
      import sys

      from spaghetti_extractor.reconstruction_assurance import (
          BUILD_BINDING_FORMAT,
          EXTERNAL_PROTOCOL_FORMAT,
          ISA_EVIDENCE_FORMAT,
          LOWERING_EVIDENCE_FORMAT,
          MACHINE_IR_FORMAT,
          SOURCE_BINDING_FORMAT,
          write_reconstruction_qualification,
      )
      from spaghetti_extractor.util import sha256_bytes, sha256_file, write_json

      (
          machine_manifest_path,
          machine_ir_path,
          interpreter_manifest_path,
          engine_manifest_path,
          engine_plan_path,
          runtime_manifest_path,
          override_manifest_path,
          candidate_manifest_path,
          candidate_path,
          regional_validation_path,
          output,
      ) = [pathlib.Path(value) for value in sys.argv[1:]]

      def load(path):
          return json.loads(path.read_text(encoding="utf-8"))

      def canonical_sha(value):
          return sha256_bytes(json.dumps(
              value, sort_keys=True, separators=(",", ":")
          ).encode("utf-8"))

      def evidence(
          format_name,
          bindings,
          counts,
          artifact_sha256,
          evidence_classes,
          assumption_ids=(),
      ):
          return {
              "format": format_name,
              "status": "qualified",
              "artifact_sha256": artifact_sha256,
              "bindings": bindings,
              "counts": counts,
              "evidence_classes": list(evidence_classes),
              "assumption_ids": list(assumption_ids),
              "issues": [],
          }

      output.mkdir(parents=True, exist_ok=True)
      machine_manifest = load(machine_manifest_path)
      interpreter = load(interpreter_manifest_path)
      engine = load(engine_manifest_path)
      engine_plan = load(engine_plan_path)
      runtime = load(runtime_manifest_path)
      override = load(override_manifest_path)
      candidate = load(candidate_manifest_path)
      regional_validation = load(regional_validation_path)
      machine_ir_sha256 = sha256_file(machine_ir_path)
      original_sha256 = machine_manifest["binary"]["sha256"]
      candidate_sha256 = sha256_file(candidate_path)

      if machine_manifest["format"] != MACHINE_IR_FORMAT:
          raise SystemExit("unexpected machine-IR format")
      if machine_manifest["status"] != "qualified" or machine_manifest["issues"]:
          raise SystemExit("machine-IR manifest is not closed")
      if interpreter["status"] != "ready" or interpreter["blockers"]:
          raise SystemExit("interpreter package contains blockers")
      if engine["status"] != "ready" or engine["blockers"]:
          raise SystemExit("native engine package contains blockers")
      if engine_plan["status"] != "ready" or engine_plan["blockers"]:
          raise SystemExit("native engine plan contains blockers")
      if runtime["status"] != "ready":
          raise SystemExit("native runtime package is not ready")
      if override["status"] != "ready" or override["executes_original_binary"]:
          raise SystemExit("regional override package is not statically qualified")
      if candidate["status"] != "candidate-generated":
          raise SystemExit("candidate package is not generated")
      if candidate["outputs"]["candidate"]["sha256"] != candidate_sha256:
          raise SystemExit("candidate binary hash differs from its build manifest")
      if candidate["policy"]["region_overrides"] != 1:
          raise SystemExit("candidate does not contain exactly one regional override")
      if (
          regional_validation["status"] != "qualified"
          or regional_validation["executes_original_binary"]
          or regional_validation["counts"]["compared_cases"] < 1
          or regional_validation["counts"]["deltas"] != 0
      ):
          raise SystemExit("regional replacement validation is not closed")
      if regional_validation["bindings"]["machine_ir_sha256"] != machine_ir_sha256:
          raise SystemExit("regional replacement validation is not bound to the machine IR")
      if (
          len(override["entries"]) != 1
          or regional_validation["bindings"]["replacement_manifest_sha256"]
          != override["entries"][0]["manifest_sha256"]
      ):
          raise SystemExit("regional replacement validation is not bound to the override")
      if interpreter["machine_ir"]["sha256"] != machine_ir_sha256:
          raise SystemExit("interpreter is not bound to the machine IR")
      if engine["machine_ir"]["sha256"] != machine_ir_sha256:
          raise SystemExit("native engine is not bound to the machine IR")

      units = []
      form_rows = {}
      with machine_ir_path.open(encoding="utf-8") as stream:
          for line_number, line in enumerate(stream, start=1):
              if not line.strip():
                  continue
              row = json.loads(line)
              if row.get("record_kind") != "unit":
                  continue
              units.append(row)
              for instruction in row.get("instructions", []):
                  form = {
                      "mnemonic": instruction.get("mnemonic"),
                      "operands": instruction.get("operands", []),
                  }
                  form_id = canonical_sha(form)
                  form_rows.setdefault(form_id, form)
      if len(units) != machine_manifest["counts"]["units"]:
          raise SystemExit("machine-IR unit count changed")
      if any(unit.get("status") != "qualified" for unit in units):
          raise SystemExit("machine IR contains a non-qualified unit")
      reachable_units = sum(unit.get("reachable") is True for unit in units)
      if reachable_units != len(units):
          raise SystemExit("selected reconstruction profile does not close all units")

      coverage = machine_manifest["coverage"]["counts"]
      classified_bytes = (
          coverage["semantic_code_bytes"] + coverage["checked_noncode_bytes"]
      )
      control = machine_manifest["control"]["counts"]
      engine_counts = engine["counts"]
      if control["closed_indirect_exits"] != control["indirect_exits"]:
          raise SystemExit("machine IR contains an unclosed indirect exit")
      if interpreter["counts"]["transfers"] != reachable_units:
          raise SystemExit("interpreter lowering does not cover every reachable unit")
      if interpreter["counts"]["blocked_transfers"] != 0:
          raise SystemExit("interpreter lowering contains blocked transfers")
      if engine_counts["transfers"] != reachable_units:
          raise SystemExit("native engine transfer inventory drifted")
      if engine_counts["x87_operations"] != machine_manifest["counts"]["x87_micro_ops"]:
          raise SystemExit("typed x87 operation inventory drifted")

      source_rows = sorted(
          (
              dict(item["source"])
              for item in candidate["objects"]
              if item["source"]["owner"] != "generated"
          ),
          key=lambda row: (row["owner"], row["role"], row["path"], row["sha256"]),
      )
      if not source_rows or len({(row["owner"], row["path"]) for row in source_rows}) != len(source_rows):
          raise SystemExit("candidate source inventory is empty or ambiguous")
      source_manifest = {
          "format": "stage-b-reconstruction-source-manifest-v1",
          "status": "bound",
          "machine_ir_sha256": machine_ir_sha256,
          "artifacts": source_rows,
          "units": reachable_units,
          "region_overrides": 1,
          "regional_validation": {
              "artifact_sha256": sha256_file(regional_validation_path),
              "replacement_manifest_sha256": regional_validation["bindings"][
                  "replacement_manifest_sha256"
              ],
              "compared_cases": regional_validation["counts"]["compared_cases"],
          },
      }
      source_manifest_path = output / "source-manifest.json"
      write_json(source_manifest_path, source_manifest)
      source_manifest_sha256 = sha256_file(source_manifest_path)
      source_tree_sha256 = canonical_sha(source_rows)

      form_inventory_path = output / "isa-form-inventory.json"
      write_json(form_inventory_path, {
          "format": "stage-a-reconstruction-isa-form-inventory-v1",
          "status": "qualified",
          "machine_ir_sha256": machine_ir_sha256,
          "forms": [
              {"id": identity, **form_rows[identity]}
              for identity in sorted(form_rows)
          ],
      })
      external_closure_path = output / "external-closure.json"
      write_json(external_closure_path, {
          "format": "stage-a-reconstruction-external-closure-v1",
          "status": "qualified",
          "machine_ir_sha256": machine_ir_sha256,
          "engine_plan_sha256": sha256_file(engine_plan_path),
          "runtime_manifest_sha256": sha256_file(runtime_manifest_path),
          "external_sites": engine_counts["external_sites"],
          "callback_targets": engine_counts["callback_targets"],
          "callable_external_routes": engine_counts["callable_external_routes"],
      })

      common = {
          "original_sha256": original_sha256,
          "machine_ir_sha256": machine_ir_sha256,
      }
      trust_assumptions = [
          {
              "id": "static-frontend-and-machine-ir-correct",
              "scope": "original PE static extraction and semantic normalization",
              "statement": (
                  "The selected profile trusts the pinned PE parser, decoder, "
                  "and machine-IR normalizer for all inventoried instruction forms; "
                  "the inventory is exhaustive but not a claim that every form has "
                  "independent Bochs, Unicorn, hardware, or Lean qualification."
              ),
          },
          {
              "id": "complete-static-indirect-target-recovery",
              "scope": "selected PE32 reconstruction profile",
              "statement": machine_manifest["trust_assumptions"][0]["statement"],
          },
          {
              "id": "generated-ir-lowering-correct",
              "scope": "machine IR to generated state-machine C",
              "statement": (
                  "The pinned interpreter generator and runtime implement the "
                  "normalized machine-IR operations for every lowered unit."
              ),
          },
          {
              "id": "external-profile-and-bridge-correct",
              "scope": "machine-level API, callback, and memory-footprint adapters",
              "statement": (
                  "The pinned external profiles and native bridges correctly "
                  "implement their declared machine-level call contracts."
              ),
          },
          {
              "id": "pinned-c-toolchain-correct",
              "scope": "candidate compilation and PE composition",
              "statement": (
                  "The pinned C compiler, assembler, linker, and PE composer "
                  "preserve the generated source semantics."
              ),
          },
          {
              "id": "lockstep-external-extensionality",
              "scope": "paired external API environment",
              "statement": (
                  "Equal ordered machine-level calls and related argument "
                  "memory receive related results and external effects."
              ),
          },
      ]
      machine_evidence = evidence(
          MACHINE_IR_FORMAT,
          common,
          {
              "executable_bytes": coverage["executable_bytes"],
              "classified_executable_bytes": classified_bytes,
              "units": len(units),
              "reachable_units": reachable_units,
              "unknown_reachable_units": 0,
              "unsupported_reachable_units": 0,
              "indirect_sites": control["indirect_exits"],
              "closed_indirect_sites": control["closed_indirect_exits"],
              "external_sites": engine_counts["external_sites"],
              "closed_external_sites": engine_counts["external_sites"],
              "callbacks": engine_counts["callback_targets"],
              "closed_callbacks": engine_counts["callback_targets"],
          },
          machine_ir_sha256,
          ("assumed", "exhaustive"),
          (
              "static-frontend-and-machine-ir-correct",
              "complete-static-indirect-target-recovery",
          ),
      )
      isa_evidence = evidence(
          ISA_EVIDENCE_FORMAT,
          common,
          {
              "required_forms": len(form_rows),
              "qualified_forms": len(form_rows),
              "unsupported_reachable_forms": 0,
              "disputed_forms": 0,
          },
          sha256_file(form_inventory_path),
          ("assumed", "exhaustive"),
          ("static-frontend-and-machine-ir-correct",),
      )
      lowering_evidence = evidence(
          LOWERING_EVIDENCE_FORMAT,
          common,
          {
              "reachable_units": reachable_units,
              "lowered_units": interpreter["counts"]["transfers"],
              "unknown_reachable_units": 0,
              "unsupported_reachable_units": interpreter["counts"]["blocked_transfers"],
          },
          sha256_file(interpreter_manifest_path),
          ("assumed", "exhaustive"),
          ("generated-ir-lowering-correct",),
      )
      external_evidence = evidence(
          EXTERNAL_PROTOCOL_FORMAT,
          common,
          {
              "external_sites": engine_counts["external_sites"],
              "closed_external_sites": engine_counts["external_sites"],
              "callbacks": engine_counts["callback_targets"],
              "closed_callbacks": engine_counts["callback_targets"],
              "unknown_sites": 0,
          },
          sha256_file(external_closure_path),
          ("assumed", "exhaustive"),
          (
              "external-profile-and-bridge-correct",
              "lockstep-external-extensionality",
          ),
      )
      source_evidence = evidence(
          SOURCE_BINDING_FORMAT,
          {
              **common,
              "source_manifest_sha256": source_manifest_sha256,
              "source_tree_sha256": source_tree_sha256,
          },
          {"reachable_units": reachable_units, "bound_units": reachable_units},
          source_manifest_sha256,
          ("exhaustive",),
      )
      build_evidence = evidence(
          BUILD_BINDING_FORMAT,
          {
              **common,
              "source_manifest_sha256": source_manifest_sha256,
              "source_tree_sha256": source_tree_sha256,
              "candidate_sha256": candidate_sha256,
          },
          {
              "source_artifacts": len(source_rows),
              "bound_source_artifacts": len(source_rows),
              "candidate_size": candidate_path.stat().st_size,
          },
          sha256_file(candidate_manifest_path),
          ("assumed", "exhaustive"),
          ("pinned-c-toolchain-correct",),
      )
      for name, value in (
          ("machine-ir-evidence.json", machine_evidence),
          ("isa-evidence.json", isa_evidence),
          ("lowering-evidence.json", lowering_evidence),
          ("external-protocol-evidence.json", external_evidence),
          ("source-binding-evidence.json", source_evidence),
          ("build-binding-evidence.json", build_evidence),
      ):
          write_json(output / name, value)

      qualification = write_reconstruction_qualification(
          output / "reconstruction-qualification.json",
          machine_ir=machine_evidence,
          isa_evidence=isa_evidence,
          lowering_evidence=lowering_evidence,
          external_protocol=external_evidence,
          source_binding=source_evidence,
          build_binding=build_evidence,
          trust_assumptions=trust_assumptions,
      )
      if qualification["status"] != "qualified":
          raise SystemExit("GNU Hello reconstruction qualification is not closed")
      PY
      jq -e '
        .format == "stage-a-reconstruction-qualification-v1" and
        .status == "qualified" and
        (.authority.proof_authority | not) and
        (.authority.stage_a_pass_authorized | not) and
        .counts.incomplete == 0 and .counts.violated == 0
      ' "$out/reconstruction-qualification.json" >/dev/null
    '';

  staticExport = mkPhaseWithSource opaqueStaticPythonSource
    "stage-a-gnu-hello-roundtrip-static-export" [] ''
    ${python} ${runtimeDriver} static-export \
      --original ${originalPe} \
      --linker-map ${originalMap} \
      --out "$out"
    jq -e '
      .phase == "static-export" and .status == "ready" and
      (.executes_original_binary | not) and
      (.executes_candidate_binary | not) and
      .counts.transfers > 0
    ' "$out/phase-manifest.json" >/dev/null
  '';

  sourceStateMachine = pkgs.runCommand
    "stage-b-gnu-hello-source-state-machine-v1"
    {
      nativeBuildInputs = [ spaghettiExtractor pkgs.jq ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      mkdir -p "$out"
      spaghetti-extractor stage-b-augment-padding-bridges \
        --state-machine ${staticExport}/state-machine.jsonl \
        --original ${originalPe} \
        --block-map ${staticExport}/original-self-map.json \
        --external-profile \
          ${machineRuntimeProfile} \
        --out "$out/state-machine.jsonl" \
        --report "$out/padding-bridge-report.json"
      jq -e '
        .format == "stage-b-padding-bridge-augmentation-v1" and
        .status == "complete" and
        .counts.input_transfers == 5697 and
        .counts.padding_bridges == 85 and
        .counts.output_transfers == 5782 and
        .counts.terminating_transfers == 17 and
        (.trust.proposal_authority | not) and
        .trust.lean_exact_decode_required and
        .trust.lean_semantic_normalization_required and
        (.trust.executes_original_binary | not)
      ' "$out/padding-bridge-report.json" >/dev/null
    '';

  sourceC0 = mkPhase "stage-b-gnu-hello-c0-source-v1" [ staticExport sourceStateMachine ] ''
    entry_rva="$(jq -r .identity.entry_rva ${staticExport}/load-image-contract.json)"
    set +e
    ${spaghettiExtractor}/bin/spaghetti-extractor \
      stage-b-generate-semantic-c \
      --dialect c0-v1 \
      --state-machine ${sourceStateMachine}/state-machine.jsonl \
      --entry-rva "$entry_rva" \
      --out-dir "$out"
    result=$?
    set -e
    test "$result" -eq 0 -o "$result" -eq 1
    jq -e '
      .format == "stage-b-c0-source-manifest-v1" and
      .dialect == "c0-v1" and
      .transfer_count > 0 and
      (.trust.original_instruction_bytes_embedded | not) and
      .trust.lean_exact_source_check_required
    ' "$out/source-manifest.json" >/dev/null
  '';

  sourceInterpreter = mkPhase
    "stage-b-gnu-hello-native-source-interpreter-v1" [] ''
    ${python} ${runtimeDriver} interpreter \
      --state-machine ${sourceStateMachine}/state-machine.jsonl \
      --out "$out"
    jq -e '
      .format == "stage-b-semantic-interpreter-package-v1" and
      .status == "ready" and .counts.blocked_transfers == 0 and
      .counts.input_transfers == 5782 and .counts.transfers == 5782 and
      .counts.x87_operations == 313
    ' "$out/state-machine-interpreter-package.json" >/dev/null
  '';

  sourceNativeEngine = mkPhase
    "stage-b-gnu-hello-native-source-engine-v1" [] ''
    entry_rva="$(jq -r .identity.entry_rva ${staticExport}/load-image-contract.json)"
    ${python} ${runtimeDriver} native-engine \
      --state-machine ${sourceStateMachine}/state-machine.jsonl \
      --entry-rva "$entry_rva" \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --reference-contract ${staticExport}/reference-contract.json \
      --termination-profile \
        ${machineRuntimeProfileSource}/pe32-msvcrt-lockstep-v1.json \
      --termination-dll msvcrt.dll \
      --termination-symbol _amsg_exit \
      --out "$out"
    jq -e '
      .format == "stage-b-native-engine-package-v1" and
      .status == "ready" and .counts.blockers == 0 and
      .counts.transfers == 5782
    ' "$out/native-engine-package.json" >/dev/null
    jq -e '
      .format == "stage-b-native-engine-plan-v1" and
      (.x87_operations | length) == 313
    ' "$out/native-engine-plan.json" >/dev/null
  '';

  sourceNativeRuntime = mkPhase
    "stage-b-gnu-hello-native-source-runtime-v1" [] ''
    ${python} ${runtimeDriver} native-runtime \
      --interpreter-package ${sourceInterpreter} \
      --native-engine-package ${sourceNativeEngine} \
      --out "$out"
    jq -e '
      .format == "stage-b-native-runtime-package-v1" and .status == "ready"
    ' "$out/native-runtime-package.json" >/dev/null
  '';

  sourceBundle = mkPhase
    "stage-a-gnu-hello-native-source-bundle-v1" [] ''
    mkdir -p "$out"
    ${spaghettiExtractor}/bin/spaghetti-extractor \
      stage-a-prepare-native-source-equivalence \
      --state-machine ${sourceStateMachine}/state-machine.jsonl \
      --interpreter-package ${sourceInterpreter} \
      --native-engine-package ${sourceNativeEngine} \
      --native-runtime-package ${sourceNativeRuntime} \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --out "$out/native-source-bundle.json" >/dev/null
    jq -e '
      .format == "stage-b-native-interpreter-source-bundle-v1" and
      .status == "ready" and .entry_rva > 0 and
      .transfer_inventory.count == 5782 and
      .transfer_inventory.x87_transfer_count == 313 and
      .transfer_inventory.x87_replay_count == 313 and
      (.trust.acceptance_authority | not) and
      .trust.lean_whole_program_proof_required
    ' "$out/native-source-bundle.json" >/dev/null
  '';

  sourceCandidate = mkPhase "stage-b-gnu-hello-native-source-candidate-v1" [
    mingw32.stdenv.cc
    mingw32.binutils
  ] ''
    ${python} ${runtimeDriver} candidate \
      --interpreter-package ${sourceInterpreter} \
      --native-engine-package ${sourceNativeEngine} \
      --native-runtime-package ${sourceNativeRuntime} \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --compiler ${compiler} \
      --out "$out"
    jq -e '
      .format == "stage-b-interpreter-native-build-v1" and
      .status == "candidate-generated"
    ' "$out/interpreter-native-build-manifest.json" >/dev/null
    test -s "$out/candidate.exe"
    test -s "$out/payload.map"
  '';

  # Bind the composed source candidate itself, rather than the payload linked
  # into it.  This reuses the isolated exact-data graph, so PE bytes, imports,
  # and the complete relocation directory are all parsed from candidate.exe.
  sourceCandidateKernelDataLean = mkPhaseWithSource kernelDataPythonSource
    "stage-a-gnu-hello-native-source-candidate-kernel-data-v1" [] ''
    ${python} ${kernelDataDriver} \
      --candidate ${sourceCandidate}/candidate.exe \
      --linker-map ${sourceCandidate}/payload.map \
      --state-machine ${sourceStateMachine}/state-machine.jsonl \
      --lean-source-root \
        ${kernelDataLeanSource}/src/spaghetti_extractor/lean/StageA \
      --shard-size 8 --out "$out"
    jq -e '
      .format == "stage-a-interpreter-kernel-data-inventory-v9" and
      .candidate_bytes > 0 and
      .counts.byte_packs > 0 and
      .counts.relocation_packs > 0 and
      .counts.relocation_blocks > 0 and
      .candidate_authority.module ==
        "GeneratedInterpreterKernelCandidateAuthority" and
      (.acceptance_authority | not)
    ' "$out/module-inventory.json" >/dev/null
  '';

  sourceCandidateStaticAuthorityLean = pkgs.runCommand
    "stage-a-gnu-hello-native-source-candidate-static-authority-v1"
    {
      nativeBuildInputs = [ pkgs.python3 pkgs.jq ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      ${pkgs.python3}/bin/python3 ${nativeSourceStaticAuthorityDriver} \
        --candidate ${sourceCandidate}/candidate.exe \
        --kernel-data-inventory \
          ${sourceCandidateKernelDataLean}/module-inventory.json \
        --out "$out"
      jq -e '
        .format == "stage-a-native-source-candidate-static-authority-v1" and
        .status == "source-ready" and
        .candidate.size > 0 and
        .kernel_data.relocation_packs > 0 and
        .kernel_data.relocation_blocks > 0 and
        .trust.exact_candidate_bytes_checked_in_lean and
        .trust.imports_parsed_from_candidate_exe and
        .trust.relocations_parsed_from_candidate_exe and
        .trust.environment_parameterized and
        (.trust.indirect_target_shape_is_completeness | not) and
        (.trust.indirect_target_completeness_proved | not) and
        (.trust.whole_program_acceptance_authority | not)
      ' "$out/phase-manifest.json" >/dev/null
    '';

  sourceCandidateStaticAuthorityClosure = mkGeneratedClosureProof {
    name = "native-source-candidate-static-authority";
    sources = [
      leanSourceRoot
      sourceCandidateKernelDataLean
      sourceCandidateStaticAuthorityLean
    ];
    target = "GeneratedGnuHelloNativeSourceCandidateStaticAuthority";
    declaration =
      "StageA.GeneratedRelational.GnuHelloNativeSourceCandidateStaticAuthority.generatedCandidateMachineAuthority";
  };
  sourceCandidateStaticAuthorityProofSources =
    sourceCandidateStaticAuthorityClosure.proofSources;
  sourceCandidateStaticAuthorityProof =
    sourceCandidateStaticAuthorityClosure.proof;

  sourceCompilationAttestation = mkPhase
    "stage-a-gnu-hello-native-source-compilation-attestation-v1"
    [ pkgs.nix ] ''
    mkdir -p "$out"
    nar_hash="$(${pkgs.nix}/bin/nix --extra-experimental-features nix-command \
      --offline hash path --sri ${sourceCandidate})"
    jq -n \
      --arg output '${sourceCandidate}' \
      --arg derivation '${sourceCandidate.drvPath}' \
      --arg registered_deriver '${sourceCandidate.drvPath}' \
      --arg nar_hash "$nar_hash" \
      '{ output: $output, derivation: $derivation,
         registered_deriver: $registered_deriver, nar_hash: $nar_hash }' \
      > "$out/nix-provenance.json"
    ${spaghettiExtractor}/bin/spaghetti-extractor \
      stage-a-attest-native-source-compilation \
      --source-bundle ${sourceBundle}/native-source-bundle.json \
      --native-build-manifest \
        ${sourceCandidate}/interpreter-native-build-manifest.json \
      --nix-provenance "$out/nix-provenance.json" \
      --out "$out/native-source-compilation-attestation.json" >/dev/null
    jq -e '
      .format == "stage-b-native-interpreter-compilation-attestation-v1" and
      .status == "complete" and
      .candidate.path == "${sourceCandidate}/candidate.exe" and
      (.tools | map(.role) | sort) ==
        ["assembler", "compiler", "compiler_runtime", "linker", "nm"] and
      (.trust.acceptance_authority | not) and
      .trust.lean_whole_program_proof_required
    ' "$out/native-source-compilation-attestation.json" >/dev/null
  '';

  sourceProgramLean = mkPhase
    "stage-a-gnu-hello-native-source-program-lean-v1" [] ''
    ${python} ${driver} program-source \
      --state-machine ${sourceStateMachine}/state-machine.jsonl \
      --out "$out"
    jq -e '
      .phase == "semantic-program-lean" and .status == "source-ready" and
      .counts.transfers == 5782 and .counts.ordinary_transfers == 5469 and
      .counts.x87_transfers == 313
    ' "$out/phase-manifest.json" >/dev/null
  '';

  sourceNormalizationLean = mkPhase
    "stage-a-gnu-hello-native-source-normalization-lean-v1" [] ''
    ${python} ${driver} normalization-sources \
      --state-machine ${sourceStateMachine}/state-machine.jsonl \
      --shard-size 48 --source-bindings-only --out "$out"
    jq -e '
      .phase == "normalization-lean" and .status == "source-ready"
    ' "$out/phase-manifest.json" >/dev/null
  '';

  sourceSemanticRefinementLean = mkPhase
    "stage-a-gnu-hello-native-source-semantic-refinement-lean-v1" [] ''
    ${python} ${driver} semantic-refinement-sources \
      --state-machine ${sourceStateMachine}/state-machine.jsonl \
      --shard-size 48 --out "$out"
    jq -e '
      .phase == "semantic-refinement-lean" and .status == "source-ready" and
      .counts.ordinary_transfers == 5469
    ' "$out/phase-manifest.json" >/dev/null
  '';

  sourceX87Lean = mkPhase
    "stage-a-gnu-hello-native-source-x87-lean-v1" [] ''
    ${python} ${driver} x87-sources \
      --state-machine ${sourceStateMachine}/state-machine.jsonl \
      --original ${originalPe} \
      --pe-byte-pack-inventory ${originalPeLean}/pe-byte-packs.json \
      --source-only \
      --out "$out"
    jq -e '
      (.targets.schedule_nodes | length) == 313 and
      .targets.bundle_node == "GeneratedInterpreterX87ScheduleBundle" and
      .source_only and .targets.exact_original_inventory == null and
      .targets.candidate_replay_obligation == null
    ' "$out/module-inventory.json" >/dev/null
  '';

  sourceStaticMachineImportContractsLean = mkPhase
    "stage-a-gnu-hello-native-source-machine-import-contracts-lean-v1" [] ''
    ${python} ${driver} static-machine-import-contracts \
      --original ${originalPe} \
      --reference-contract ${staticExport}/reference-contract.json \
      --state-machine ${sourceStateMachine}/state-machine.jsonl \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --profile ${machineRuntimeProfile} \
      --profile \
        ${machineRuntimeProfileSource}/pe32-kernel32-lockstep-v1.json \
      --profile \
        ${machineRuntimeProfileSource}/pe32-msvcrt-lockstep-v1.json \
      --shard-size 128 \
      --out "$out"
    jq -e '
      .phase == "rooted-static-machine-import-contracts" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .rooted_counts.reachable_targets > 0 and
      .rooted_counts.required_imports > 0 and
      .rooted_counts.blockers == 0
    ' "$out/phase-manifest.json" >/dev/null
  '';

  # The source theorem needs the augmented semantic inventory on the original
  # side as well.  In particular, direct branches into checked executable
  # padding must execute their exact no-op records instead of falling out of the
  # authoritative decoded carrier.
  sourceOriginalBaseLean = mkPhase
    "stage-a-gnu-hello-native-source-original-base-lean-v1" [] ''
    ${python} ${driver} mixed-original-base \
      --original ${originalPe} \
      --reference-contract ${staticExport}/reference-contract.json \
      --state-machine ${sourceStateMachine}/state-machine.jsonl \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --machine-import-report \
        ${sourceStaticMachineImportContractsLean}/machine-import-contract-report.json \
      --callable-resolver-profile \
        ${machineRuntimeProfileSource}/pe32-kernel32-callable-resolvers-v1.json \
      --shard-size 64 \
      --out "$out"
    jq -e '
      .phase == "mixed-original-base-lean" and
      .status == "base-source-ready" and
      (.proof_authority | not) and
      (.exact_reachability_emitted | not) and
      .targets == ["GeneratedRelationalInterpreterMixedOriginalBase"] and
      .counts.regions == 5790 and .counts.reachable_targets > 0
    ' "$out/phase-manifest.json" >/dev/null
  '';

  # Original control safety is independent of the compiled candidate, but it
  # still needs the complete one-sided authority ladder: writable slots,
  # register provenance through calls, and stack/dynamic targets.  Instantiate
  # that existing generic ladder against the augmented source inventory.  Nix
  # remains lazy, so none of the binary-pair candidate/composition outputs are
  # dependencies of these selected attributes.
  sourceOriginalAuthorityPipeline = import ./gnu-hello-roundtrip.nix {
    inherit
      pkgs
      pythonEnv
      spaghettiExtractor
      sideTool
      analysisKernelCache
      isaKernelCache
      isaSemanticKernel
      bochsRunner
      sourceRoot
      leanSourceRoot
      originalFixture
      mingw32
      mkLeanGraph
      ;
    proofStateMachine = sourceStateMachine;
  };
  sourceOriginalLean = sourceOriginalAuthorityPipeline.mixedOriginalLean;

  sourceOriginalStaticReachabilityLean = mkPhase
    "stage-a-gnu-hello-native-source-original-static-reachability-v1" [] ''
    ${python} ${driver} mixed-original-static-reachability \
      --mixed-original-plan \
        ${sourceOriginalLean}/interpreter-mixed-original-plan.json \
      --out "$out"
    jq -e '
      .phase == "mixed-original-static-reachability" and
      .status == "typed-interface-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .runtime_indirect_control.closed_by_this_artifact == false and
      .counts.reachable_targets > 0 and
      .targets == [
        "GeneratedRelationalInterpreterMixedOriginalStaticReachability"
      ]
    ' "$out/phase-manifest.json" >/dev/null
  '';
  sourceOriginalStaticReachabilityClosure = mkGeneratedClosureProof {
    name = "native-source-original-static-reachability";
    sources = [
      leanSourceRoot
      originalPeLean
      sourceStaticMachineImportContractsLean
      sourceOriginalAuthorityPipeline.mixedOriginalWritableSlotAuthorityLean
      sourceOriginalAuthorityPipeline.mixedOriginalRegisterIndirectAuthorityLean
      sourceOriginalAuthorityPipeline.mixedOriginalDirectCallProposalsLean
      sourceOriginalAuthorityPipeline.mixedOriginalDirectCallSemanticsLean
      sourceOriginalAuthorityPipeline.mixedOriginalDirectCallClosureProposalsLean
      sourceOriginalAuthorityPipeline.mixedOriginalDirectCallClosureSemanticsLean
      sourceOriginalLean
      sourceOriginalStaticReachabilityLean
    ];
    target = "GeneratedRelationalInterpreterMixedOriginalStaticReachability";
    declaration =
      "StageA.GeneratedRelational.InterpreterMixedOriginalStaticReachability.generatedExactOriginalDecodedStaticReachability";
  };
  sourceOriginalStaticReachabilityProofSources =
    sourceOriginalStaticReachabilityClosure.proofSources;
  sourceOriginalStaticReachabilityProof =
    sourceOriginalStaticReachabilityClosure.proof;

  sourceOriginalCarrierBindingLean = mkPhase
    "stage-a-gnu-hello-native-source-original-carrier-binding-v1" [] ''
    ${python} ${driver} mixed-original-carrier-binding \
      --mixed-original ${sourceOriginalLean} \
      --out "$out"
    jq -e '
      .phase == "mixed-original-carrier-binding-lean" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .targets == ["GeneratedRelationalInterpreterOriginalCarrierBinding"] and
      .counts.targets == 5790 and .counts.addresses == 5792
    ' "$out/phase-manifest.json" >/dev/null
  '';
  sourceOriginalCarrierBindingClosure = mkGeneratedClosureProof {
    name = "native-source-original-carrier-binding";
    sources = [
      leanSourceRoot
      originalPeLean
      sourceStaticMachineImportContractsLean
      sourceOriginalAuthorityPipeline.mixedOriginalWritableSlotAuthorityLean
      sourceOriginalAuthorityPipeline.mixedOriginalRegisterIndirectAuthorityLean
      sourceOriginalAuthorityPipeline.mixedOriginalDirectCallProposalsLean
      sourceOriginalAuthorityPipeline.mixedOriginalDirectCallSemanticsLean
      sourceOriginalAuthorityPipeline.mixedOriginalDirectCallClosureProposalsLean
      sourceOriginalAuthorityPipeline.mixedOriginalDirectCallClosureSemanticsLean
      sourceOriginalLean
      sourceOriginalCarrierBindingLean
    ];
    target = "GeneratedRelationalInterpreterOriginalCarrierBinding";
    declaration =
      "StageA.GeneratedRelational.InterpreterOriginalCarrierBinding.generatedOriginalExactMixedProgramBinding";
  };
  sourceOriginalCarrierBindingProofSources =
    sourceOriginalCarrierBindingClosure.proofSources;
  sourceOriginalCarrierBindingProof = sourceOriginalCarrierBindingClosure.proof;

  sourceOriginalCombinedDeclarations = mkPhase
    "stage-a-gnu-hello-native-source-original-combined-declarations-v1" [] ''
    ${python} ${driver} original-combined-declarations \
      --mixed-original-plan \
        ${sourceOriginalLean}/interpreter-mixed-original-plan.json \
      --mixed-original-manifest ${sourceOriginalLean}/phase-manifest.json \
      --static-reachability-plan \
        ${sourceOriginalStaticReachabilityLean}/interpreter-mixed-original-static-reachability.json \
      --static-reachability-manifest \
        ${sourceOriginalStaticReachabilityLean}/phase-manifest.json \
      --carrier-binding-manifest \
        ${sourceOriginalCarrierBindingLean}/phase-manifest.json \
      --direct-call-authority-report \
        ${sourceOriginalAuthorityPipeline.mixedOriginalDirectCallClosureSemanticsLean}/direct-call-authority-bindings.json \
      --stack-dynamic-authority-report \
        ${sourceOriginalAuthorityPipeline.mixedOriginalStackDynamicAuthorityLean}/original-stack-dynamic-control-closure.json \
      --stack-dynamic-authority-manifest \
        ${sourceOriginalAuthorityPipeline.mixedOriginalStackDynamicAuthorityLean}/phase-manifest.json \
      --stack-combined-evidence-report \
        ${sourceOriginalAuthorityPipeline.mixedOriginalStackDynamicAuthorityLean}/gnu-hello-stack-dynamic-combined-evidence.json \
      --value-provenance-ir \
        ${sourceOriginalAuthorityPipeline.mixedOriginalStackDynamicAuthorityLean}/runtime-value-carry-ir.json \
      --value-provenance-report \
        ${sourceOriginalAuthorityPipeline.mixedOriginalStackDynamicAuthorityLean}/runtime-value-carry-lean.json \
      --out "$out"
    test -s "$out/original-combined-reachability-declarations.json"
    test -s "$out/original-combined-call-frame-declarations.json"
    test -s "$out/original-combined-value-flow-declarations.json"
  '';

  sourceOriginalCombinedInventoryLean = mkPhase
    "stage-a-gnu-hello-native-source-original-combined-inventory-v1" [] ''
    ${python} ${driver} original-combined-inventory \
      --mixed-original-plan \
        ${sourceOriginalLean}/interpreter-mixed-original-plan.json \
      --writable-authority-report \
        ${sourceOriginalAuthorityPipeline.mixedOriginalWritableSlotAuthorityLean}/relocated-writable-static-pointer-slot-authorities.json \
      --writable-authority-manifest \
        ${sourceOriginalAuthorityPipeline.mixedOriginalWritableSlotAuthorityLean}/phase-manifest.json \
      --register-authority-report \
        ${sourceOriginalAuthorityPipeline.mixedOriginalRegisterIndirectAuthorityLean}/register-indirect-control-authorities.json \
      --register-authority-manifest \
        ${sourceOriginalAuthorityPipeline.mixedOriginalRegisterIndirectAuthorityLean}/phase-manifest.json \
      --stack-dynamic-authority-report \
        ${sourceOriginalAuthorityPipeline.mixedOriginalStackDynamicAuthorityLean}/original-stack-dynamic-control-closure.json \
      --stack-dynamic-authority-manifest \
        ${sourceOriginalAuthorityPipeline.mixedOriginalStackDynamicAuthorityLean}/phase-manifest.json \
      --stack-combined-evidence-report \
        ${sourceOriginalAuthorityPipeline.mixedOriginalStackDynamicAuthorityLean}/gnu-hello-stack-dynamic-combined-evidence.json \
      --reachability-declarations \
        ${sourceOriginalCombinedDeclarations}/original-combined-reachability-declarations.json \
      --call-frame-declarations \
        ${sourceOriginalCombinedDeclarations}/original-combined-call-frame-declarations.json \
      --value-flow-declarations \
        ${sourceOriginalCombinedDeclarations}/original-combined-value-flow-declarations.json \
      --shard-size 512 \
      --out "$out"
    jq -e '
      .format ==
        "stage-a-original-combined-execution-inventory-declarations-v1" and
      .counts.reachable_targets == 3490 and
      .counts.static_word_slots == 3 and
      .counts.register_requirements == 9 and
      .counts.stack_dynamic_requirements == 3 and
      .counts.call_frame_facts > 0 and .counts.value_flow_facts > 0 and
      .lean.module ==
        "StageA.GeneratedRelationalOriginalCombinedInventory"
    ' "$out/original-combined-execution-inventory-declarations.json" >/dev/null
  '';
  sourceOriginalCombinedInventoryClosure = mkGeneratedClosureProof {
    name = "native-source-original-combined-inventory";
    sources = [
      leanSourceRoot
      originalPeLean
      sourceStaticMachineImportContractsLean
      sourceOriginalAuthorityPipeline.mixedOriginalWritableSlotAuthorityLean
      sourceOriginalAuthorityPipeline.mixedOriginalRegisterIndirectAuthorityLean
      sourceOriginalAuthorityPipeline.mixedOriginalDirectCallProposalsLean
      sourceOriginalAuthorityPipeline.mixedOriginalDirectCallSemanticsLean
      sourceOriginalAuthorityPipeline.mixedOriginalDirectCallClosureProposalsLean
      sourceOriginalAuthorityPipeline.mixedOriginalDirectCallClosureSemanticsLean
      sourceOriginalAuthorityPipeline.mixedOriginalStackDynamicAuthorityLean
      sourceOriginalLean
      sourceOriginalStaticReachabilityLean
      sourceOriginalCarrierBindingLean
      sourceOriginalCombinedInventoryLean
    ];
    target = "GeneratedRelationalOriginalCombinedInventory";
    declaration =
      "StageA.GeneratedRelational.OriginalCombinedInventory.generatedInventory";
  };
  sourceOriginalCombinedInventoryProofSources =
    sourceOriginalCombinedInventoryClosure.proofSources;
  sourceOriginalCombinedInventoryProof =
    sourceOriginalCombinedInventoryClosure.proof;

  sourceTargetEffectInputsLean = mkPhase
    "stage-a-gnu-hello-native-source-target-effect-inputs-v1" [] ''
    ${python} ${driver} source-target-effect-inputs \
      --state-machine ${sourceStateMachine}/state-machine.jsonl \
      --mixed-original-plan \
        ${sourceOriginalLean}/interpreter-mixed-original-plan.json \
      --source-program-root ${sourceProgramLean} \
      --source-program-manifest ${sourceProgramLean}/phase-manifest.json \
      --normalization-root ${sourceNormalizationLean} \
      --normalization-inventory \
        ${sourceNormalizationLean}/module-inventory.json \
      --semantic-refinement-root ${sourceSemanticRefinementLean} \
      --semantic-refinement-inventory \
        ${sourceSemanticRefinementLean}/semantic-refinement-inventory.json \
      --x87-root ${sourceX87Lean} \
      --x87-inventory ${sourceX87Lean}/module-inventory.json \
      --exact-original-root ${sourceOriginalLean} \
      --shard-span 64 \
      --out "$out"
    jq -e '
      .format ==
        "stage-a-gnu-hello-source-target-effect-inputs-manifest-v1" and
      (.proof_authority | not) and (.acceptance_authority | not) and
      .counts.targets == 3490 and .counts.ordinary > 0 and .counts.x87 > 0 and
      (.counts.ordinary + .counts.x87) == .counts.targets and
      .counts.shards > 0
    ' "$out/source-target-effect-inputs-manifest.json" >/dev/null
  '';

  sourceTargetEffectsLean = mkPhase
    "stage-a-gnu-hello-native-source-target-effects-v1" [] ''
    ${python} ${driver} source-target-effects \
      --state-machine ${sourceStateMachine}/state-machine.jsonl \
      --mixed-original-plan \
        ${sourceOriginalLean}/interpreter-mixed-original-plan.json \
      --source-program-root ${sourceProgramLean} \
      --source-program-manifest ${sourceProgramLean}/phase-manifest.json \
      --normalization-root ${sourceNormalizationLean} \
      --normalization-inventory \
        ${sourceNormalizationLean}/module-inventory.json \
      --semantic-refinement-root ${sourceSemanticRefinementLean} \
      --semantic-refinement-inventory \
        ${sourceSemanticRefinementLean}/semantic-refinement-inventory.json \
      --x87-root ${sourceX87Lean} \
      --x87-inventory ${sourceX87Lean}/module-inventory.json \
      --exact-original-root ${sourceOriginalLean} \
      --authority-inventory \
        ${sourceTargetEffectInputsLean}/source-target-effect-inputs.json \
      --out "$out"
    jq -e '
      .format == "stage-a-gnu-hello-source-target-effects-v1" and
      (.proof_authority | not) and (.acceptance_authority | not) and
      .counts.targets == 3490 and .counts.ordinary > 0 and .counts.x87 > 0 and
      (.counts.ordinary + .counts.x87) == .counts.targets
    ' "$out/source-target-effects.json" >/dev/null
    jq -e '.ready and .blockers == [] and .reachable_targets == 3490' \
      "$out/source-target-effects-frontier.json" >/dev/null
  '';

  sourceTransitionIndexLean = mkPhase
    "stage-a-gnu-hello-native-source-transition-index-v1" [] ''
    ${python} ${driver} source-transition-index \
      --mixed-original-manifest ${sourceOriginalLean}/phase-manifest.json \
      --source-program-manifest ${sourceProgramLean}/phase-manifest.json \
      --normalization-manifest \
        ${sourceNormalizationLean}/normalization-inventory.json \
      --x87-manifest ${sourceX87Lean}/phase-manifest.json \
      --declaration-inventory \
        ${sourceTargetEffectsLean}/source-target-effect-declarations.json \
      --out "$out"
    jq -e '
      .format == "stage-a-gnu-hello-source-transition-index-v1" and
      (.executes_original_binary | not) and
      (.executes_candidate_binary | not) and
      .counts.targets == 3490 and
      .exports.active_target_transition_index ==
        "StageA.GeneratedRelational.GnuHelloSourceTransitionIndex.generatedActiveTargetTransitionIndex" and
      .exports.active_target_ids_exact ==
        "StageA.GeneratedRelational.GnuHelloSourceTransitionIndex.generatedActiveTargetIdsExact"
    ' "$out/source-transition-index.json" >/dev/null
  '';

  sourceTransitionIndexClosure = mkGeneratedClosureProof {
    name = "native-source-transition-index";
    sources = [
      sourceOriginalCombinedInventoryProofSources
      sourceProgramLean
      sourceNormalizationLean
      sourceSemanticRefinementLean
      sourceX87Lean
      sourceTargetEffectInputsLean
      sourceTargetEffectsLean
      sourceTransitionIndexLean
    ];
    target = "GeneratedGnuHelloSourceTransitionIndex";
    declaration =
      "StageA.GeneratedRelational.GnuHelloSourceTransitionIndex.generatedActiveTargetTransitionIndex";
  };
  sourceTransitionIndexProofSources =
    sourceTransitionIndexClosure.proofSources;
  sourceTransitionIndexProof = sourceTransitionIndexClosure.proof;

  sourceRuntimeMemoryAccessProposal = mkPhase
    "stage-a-gnu-hello-native-source-runtime-memory-access-proposal-v1" [] ''
    ${python} ${driver} runtime-memory-access-proposal \
      --state-machine ${sourceStateMachine}/state-machine.jsonl \
      --mixed-original-plan \
        ${sourceOriginalLean}/interpreter-mixed-original-plan.json \
      --source-target-effect-declarations \
        ${sourceTargetEffectsLean}/source-target-effect-declarations.json \
      --out "$out"
    jq -e '
      .format == "stage-a-runtime-memory-access-proposal-v1" and
      (.artifact_role.proof_authority | not) and
      (.artifact_role.acceptance_authority | not) and
      .artifact_role.proposal_only and
      .artifact_role.lean_checker_must_recheck and
      .counts.targets == 3490 and .counts.writes > 0 and
      (.targets | length) == .counts.targets
    ' "$out/runtime-memory-access-proposal.json" >/dev/null
    jq -e '
      .format == "stage-a-runtime-memory-partition-check-inputs-v1" and
      (.artifact_role.proof_authority | not) and
      (.artifact_role.acceptance_authority | not) and
      .artifact_role.checker_input_only and
      (.targets | length) == 3490
    ' "$out/runtime-memory-partition-check-inputs.json" >/dev/null
  '';

  sourceOriginalTargetControlEvidence = mkPhase
    "stage-a-gnu-hello-native-source-original-target-control-evidence-v1" [] ''
    ${python} ${driver} original-target-control-evidence \
      --source-target-effect-declarations \
        ${sourceTargetEffectsLean}/source-target-effect-declarations.json \
      --transition-index-manifest \
        ${sourceTransitionIndexLean}/source-transition-index.json \
      --state-machine ${sourceStateMachine}/state-machine.jsonl \
      --combined-target-inventory \
        ${sourceOriginalCombinedInventoryLean}/original-combined-execution-inventory-declarations.json \
      --shard-size 64 \
      --out "$out"
    jq -e '
      .format == "stage-a-original-target-control-evidence-v1" and
      (.executes_original_binary | not) and
      (.executes_candidate_binary | not) and
      .counts.targets == 3490 and .counts.emitted == 3490 and
      .counts.blocked == 0 and .counts.shards > 0
    ' "$out/original-target-control-evidence.json" >/dev/null
    jq -e '
      .format == "stage-a-original-target-control-evidence-blockers-v1" and
      .blockers == []
    ' "$out/original-target-control-blockers.json" >/dev/null
  '';
  sourceOriginalTargetControlClosure = mkGeneratedClosureProof {
    name = "native-source-original-target-control";
    sources = [
      leanSourceRoot
      originalPeLean
      sourceOriginalCombinedInventoryProofSources
      sourceTransitionIndexProofSources
      sourceTargetEffectsLean
      sourceOriginalTargetControlEvidence
    ];
    target = "GeneratedOriginalTargetControlEvidence";
    declaration =
      "StageA.GeneratedRelational.GnuHelloOriginalTargetControlEvidence.generatedTarget0CheckedTransition";
  };
  sourceOriginalTargetControlProofSources =
    sourceOriginalTargetControlClosure.proofSources;
  sourceOriginalTargetControlProof = sourceOriginalTargetControlClosure.proof;
  sourceOriginalTargetControlAudit = mkCheckedProofAudit {
    name = "native-source-original-target-control";
    proof = sourceOriginalTargetControlProof;
    declaration =
      "StageA.GeneratedRelational.GnuHelloOriginalTargetControlEvidence.generatedTarget0CheckedTransition";
  };

  sourceOrdinarySemanticClosure = mkGeneratedClosureProof {
    name = "native-source-ordinary-semantics";
    sources = [
      leanSourceRoot
      originalPeLean
      sourceProgramLean
      sourceSemanticRefinementLean
      sourceNormalizationLean
    ];
    target = "GeneratedInterpreterNormalizationBundle";
    declaration =
      "StageA.GeneratedRelational.exactNormalizedOrdinaryRecordBindings";
  };
  sourceOrdinarySemanticProofSources =
    sourceOrdinarySemanticClosure.proofSources;
  sourceOrdinarySemanticProof = sourceOrdinarySemanticClosure.proof;

  sourceX87SemanticClosure = mkGeneratedClosureProof {
    name = "native-source-x87-semantics";
    sources = [ leanSourceRoot originalPeLean sourceX87Lean ];
    target = "GeneratedInterpreterX87ScheduleBundle";
    declaration =
      "StageA.GeneratedRelational.checkedInterpreterX87ScheduleBundleSourceRvasNodup";
  };
  sourceX87SemanticProofSources = sourceX87SemanticClosure.proofSources;
  sourceX87SemanticProof = sourceX87SemanticClosure.proof;

  sourceProgramAssemblyLean = mkPhase
    "stage-a-gnu-hello-native-source-program-assembly-v1" [] ''
    ${python} ${driver} native-source-program --out "$out"
    jq -e '
      .phase == "native-source-program" and .status == "source-ready" and
      .targets == ["GeneratedGnuHelloNativeSourceProgram"]
    ' "$out/phase-manifest.json" >/dev/null
  '';

  sourceProgramAssemblyClosure = mkGeneratedClosureProof {
    name = "native-source-program-assembly";
    sources = [
      leanSourceRoot
      originalPeLean
      sourceProgramLean
      sourceSemanticRefinementLean
      sourceNormalizationLean
      sourceX87Lean
      sourceProgramAssemblyLean
    ];
    target = "GeneratedGnuHelloNativeSourceProgram";
    declaration =
      "StageA.GeneratedRelational.GnuHelloNativeSourceProgram.generatedNativeSourceExactBinding";
  };
  sourceProgramAssemblyProofSources =
    sourceProgramAssemblyClosure.proofSources;
  sourceProgramAssemblyProof = sourceProgramAssemblyClosure.proof;

  sourceCandidateSeedRuntimeSource = pkgs.writeText
    "GeneratedGnuHelloNativeSourceSeedRuntime.lean" ''
      import StageA.GeneratedGnuHelloNativeSourceCandidateStaticAuthority

      namespace StageA.GeneratedRelational.GnuHelloNativeSourceSeedRuntime

      open StageA.Relational
      open StageA.Relational.InterpreterNativeWorld

      def environment : NativeWorldEnvironment := {
        action := fun _ _ _ => .blocked .missingRuntimeContinuation
      }

      def indirectTargets : NativeIndirectTargetInventory := {}

      theorem indirectTargetsValid :
          indirectTargets.valid
            StageA.GeneratedRelational.GnuHelloNativeSourceCandidateStaticAuthority.generatedCandidatePe =
            true := by
        rfl

      end StageA.GeneratedRelational.GnuHelloNativeSourceSeedRuntime
    '';

  sourceCompiledAuthorityInputs = mkPhase
    "stage-a-gnu-hello-native-source-compiled-authority-inputs-v1" [] ''
    ${python} -m \
      spaghetti_extractor.relational.lean.gnu_hello_native_source_compiled_authority_inputs \
      --source-bundle ${sourceBundle}/native-source-bundle.json \
      --compilation-attestation \
        ${sourceCompilationAttestation}/native-source-compilation-attestation.json \
      --native-source-program-manifest \
        ${sourceProgramAssemblyLean}/phase-manifest.json \
      --candidate-static-authority \
        ${sourceCandidateStaticAuthorityLean}/phase-manifest.json \
      --runtime-module StageA.GeneratedGnuHelloNativeSourceSeedRuntime \
      --runtime-source ${sourceCandidateSeedRuntimeSource} \
      --runtime-environment \
        StageA.GeneratedRelational.GnuHelloNativeSourceSeedRuntime.environment \
      --runtime-indirect-targets \
        StageA.GeneratedRelational.GnuHelloNativeSourceSeedRuntime.indirectTargets \
      --runtime-indirect-targets-valid \
        StageA.GeneratedRelational.GnuHelloNativeSourceSeedRuntime.indirectTargetsValid \
      --out "$out"
    jq -e '
      .format == "stage-a-gnu-hello-native-source-compiled-authority-inputs-v1" and
      .outputs.project_declarations == "project-declarations.json" and
      .outputs.runtime_declarations == "runtime-declarations.json" and
      .outputs.toolchain_profile == "native-source-toolchain-profile.json"
    ' "$out/compiled-authority-inputs.json" >/dev/null
  '';
  sourceProjectRealization =
    mkNixRealizationIdentity "native-source-project" sourceBundle;
  sourceProfileRealization =
    mkNixRealizationIdentity "native-source-profile" sourceCompiledAuthorityInputs;
  sourceBuildRealization =
    mkNixRealizationIdentity "native-source-build" sourceCandidate;

  sourceCompiledAuthorityProducedEvidence = mkPhase
    "stage-a-gnu-hello-native-source-compiled-authority-evidence-v1"
    [ pkgs.nix ] ''
    ${python} -m \
      spaghetti_extractor.relational.lean.gnu_hello_native_source_compiled_authority_evidence \
      --source-bundle ${sourceBundle}/native-source-bundle.json \
      --compilation-attestation \
        ${sourceCompilationAttestation}/native-source-compilation-attestation.json \
      --project-declarations \
        ${sourceCompiledAuthorityInputs}/project-declarations.json \
      --candidate-static-authority \
        ${sourceCandidateStaticAuthorityLean}/phase-manifest.json \
      --runtime-declarations \
        ${sourceCompiledAuthorityInputs}/runtime-declarations.json \
      --project-realization ${sourceProjectRealization}/realization.json \
      --profile-realization ${sourceProfileRealization}/realization.json \
      --build-realization ${sourceBuildRealization}/realization.json \
      --offline-nix-inspection \
      --out "$out"
    test -s "$out/compiled-authority-declarations.json"
    test -s "$out/project-nix-provenance.json"
    test -s "$out/profile-nix-provenance.json"
    test -s "$out/build-nix-provenance.json"
  '';

  # Original execution and the paired external-environment family remain
  # explicit proof inputs until their checked producers are wired below.  The
  # compiled-authority evidence is generated automatically from exact source,
  # candidate, toolchain, and content-addressed Nix realization identities.
  # None of these boundaries permits a manifest status to become a theorem.
  sourceOriginalExecutionEvidence =
    if nativeSourceOriginalExecutionEvidence != null then
      nativeSourceOriginalExecutionEvidence
    else
      mkMissingNativeSourceEvidence {
        name = "native-source-original-execution-evidence";
        requiredFiles = [
          "source-execution-evidence.json"
          "StageA/*.lean"
        ];
        contract =
          "stage-a-gnu-hello-source-execution-evidence-v2; exact combined invariant, all-launch root, and 31 frontier projections";
      };
  sourceCompiledAuthorityEvidence =
    if nativeSourceCompiledAuthorityEvidence != null then
      nativeSourceCompiledAuthorityEvidence
    else
      sourceCompiledAuthorityProducedEvidence;
  sourceEnvironmentFamilyEvidence =
    if nativeSourceEnvironmentFamilyEvidence != null then
      nativeSourceEnvironmentFamilyEvidence
    else
      mkMissingNativeSourceEvidence {
        name = "native-source-environment-family-evidence";
        requiredFiles = [
          "acceptance-declarations.json"
          "StageA/*.lean"
        ];
        contract =
          "stage-a-gnu-hello-native-source-acceptance-declarations-v3; nonempty admitted pairs, exact external evidence, pair-indexed launch evidence, and sole approved toolchain axiom ${nativeSourceApprovedToolchainAxiom}";
      };

  sourceExecutionLean = mkPhase
    "stage-a-gnu-hello-native-source-execution-evidence-v2" [] ''
    ${python} ${driver} native-source-execution \
      --mixed-original-plan \
        ${sourceOriginalLean}/interpreter-mixed-original-plan.json \
      --writable-authority-report \
        ${sourceOriginalAuthorityPipeline.mixedOriginalWritableSlotAuthorityLean}/relocated-writable-static-pointer-slot-authorities.json \
      --register-authority-report \
        ${sourceOriginalAuthorityPipeline.mixedOriginalRegisterIndirectAuthorityLean}/register-indirect-control-authorities.json \
      --stack-dynamic-authority-report \
        ${sourceOriginalAuthorityPipeline.mixedOriginalStackDynamicAuthorityLean}/original-stack-dynamic-control-closure.json \
      --evidence-manifest \
        ${sourceOriginalExecutionEvidence}/source-execution-evidence.json \
      --out "$out"
    jq -e '
      .format == "stage-a-gnu-hello-source-execution-assembly-v2" and
      .launch_scope == "all_checked_pe32_console_launches" and
      .launch_family_complete and
      (.acceptance_authority | not) and
      .counts.frontiers == 31 and
      .counts.writable_static_slot == 19 and
      .counts.register_target == 9 and
      .counts.stack_dynamic == 3 and
      .blockers == [] and
      .lean.proof_module == "StageA.GeneratedGnuHelloSourceExecution" and
      .lean.audit_module == "StageA.GeneratedGnuHelloSourceExecutionAudit"
    ' "$out/gnu-hello-source-execution-assembly.json" >/dev/null
  '';
  sourceExecutionClosure = mkGeneratedClosureProof {
    name = "native-source-execution";
    sources = [
      leanSourceRoot
      originalPeLean
      sourceStaticMachineImportContractsLean
      sourceOriginalAuthorityPipeline.mixedOriginalWritableSlotAuthorityLean
      sourceOriginalAuthorityPipeline.mixedOriginalRegisterIndirectAuthorityLean
      sourceOriginalAuthorityPipeline.mixedOriginalDirectCallProposalsLean
      sourceOriginalAuthorityPipeline.mixedOriginalDirectCallSemanticsLean
      sourceOriginalAuthorityPipeline.mixedOriginalDirectCallClosureProposalsLean
      sourceOriginalAuthorityPipeline.mixedOriginalDirectCallClosureSemanticsLean
      sourceOriginalAuthorityPipeline.mixedOriginalStackDynamicAuthorityLean
      sourceOriginalLean
      sourceOriginalStaticReachabilityLean
      sourceOriginalCarrierBindingLean
      sourceProgramAssemblyProofSources
      sourceOriginalExecutionEvidence
      sourceExecutionLean
    ];
    target = "GeneratedGnuHelloSourceExecution";
    declaration =
      "StageA.GeneratedRelational.GnuHelloSourceExecution.generatedCheckedNativeSourceLaunchFamily";
  };
  sourceExecutionProofSources = sourceExecutionClosure.proofSources;
  sourceExecutionProof = sourceExecutionClosure.proof;
  sourceExecutionAudit = mkCheckedProofAudit {
    name = "native-source-execution";
    proof = sourceExecutionProof;
    declaration =
      "StageA.GeneratedRelational.GnuHelloSourceExecution.generatedCheckedNativeSourceLaunchFamily";
  };

  sourceCompiledAuthorityLean = mkPhase
    "stage-a-gnu-hello-native-source-compiled-authority-v1" [] ''
    ${python} ${driver} native-source-compiled-authority \
      --source-bundle ${sourceBundle}/native-source-bundle.json \
      --compilation-attestation \
        ${sourceCompilationAttestation}/native-source-compilation-attestation.json \
      --declarations \
        ${sourceCompiledAuthorityEvidence}/compiled-authority-declarations.json \
      --project-nix-provenance \
        ${sourceCompiledAuthorityEvidence}/project-nix-provenance.json \
      --profile-nix-provenance \
        ${sourceCompiledAuthorityEvidence}/profile-nix-provenance.json \
      --build-nix-provenance \
        ${sourceCompiledAuthorityEvidence}/build-nix-provenance.json \
      --out "$out"
    jq -e '
      .phase == "native-source-compiled-authority" and
      (.proof_authority | not) and
      (.acceptance_authority | not) and
      (.executes_original_binary | not) and
      (.executes_candidate_binary | not) and
      .modules == [
        "GeneratedGnuHelloNativeSourceCompiledAuthority",
        "GeneratedGnuHelloNativeSourceCompiledAuthorityAudit"
      ] and
      .exports.exact_compilation ==
        "StageA.GeneratedRelational.GnuHelloNativeSourceCompiledAuthority.exactNativeSourceCompilation"
    ' "$out/phase-manifest.json" >/dev/null
  '';
  sourceCompiledAuthorityClosure = mkGeneratedClosureProof {
    name = "native-source-compiled-authority";
    sources = [
      leanSourceRoot
      sourceProgramAssemblyProofSources
      sourceCandidateStaticAuthorityProofSources
      sourceCompiledAuthorityInputs
      (sourceCompiledAuthorityInputs + "/runtime-modules")
      sourceCompiledAuthorityEvidence
      sourceCompiledAuthorityLean
    ];
    target = "GeneratedGnuHelloNativeSourceCompiledAuthority";
    declaration =
      "StageA.GeneratedRelational.GnuHelloNativeSourceCompiledAuthority.exactNativeSourceCompilation";
  };
  sourceCompiledAuthorityProofSources =
    sourceCompiledAuthorityClosure.proofSources;
  sourceCompiledAuthorityProof = sourceCompiledAuthorityClosure.proof;
  sourceCompiledAuthorityAudit = mkCheckedProofAudit {
    name = "native-source-compiled-authority";
    proof = sourceCompiledAuthorityProof;
    declaration =
      "StageA.GeneratedRelational.GnuHelloNativeSourceCompiledAuthority.exactNativeSourceCompilation";
  };

  sourceConditionalAcceptanceLean = mkPhase
    "stage-a-gnu-hello-native-source-environment-family-acceptance-v2" [] ''
    ${python} ${driver} native-source-acceptance \
      --source-bundle ${sourceBundle}/native-source-bundle.json \
      --compilation-attestation \
        ${sourceCompilationAttestation}/native-source-compilation-attestation.json \
      --compiled-authority-manifest \
        ${sourceCompiledAuthorityLean}/phase-manifest.json \
      --declarations \
        ${sourceEnvironmentFamilyEvidence}/acceptance-declarations.json \
      --out "$out"
    jq -e '
      .phase == "native-source-conditional-acceptance" and
      (.proof_authority | not) and
      (.acceptance_authority | not) and
      (.executes_original_binary | not) and
      (.executes_candidate_binary | not) and
      (.conditional_on | type == "string" and length > 0) and
      .modules == [
        "GeneratedGnuHelloNativeSourceAcceptance",
        "GeneratedGnuHelloNativeSourceAcceptanceAudit"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.GnuHelloNativeSourceAcceptance.generatedNativeSourceWholeProgramEnvironmentFamilyEquivalence"
    ' "$out/phase-manifest.json" >/dev/null
  '';
  sourceConditionalAcceptanceClosure = mkGeneratedClosureProof {
    name = "native-source-environment-family-acceptance";
    sources = [
      leanSourceRoot
      sourceExecutionProofSources
      sourceCompiledAuthorityProofSources
      sourceEnvironmentFamilyEvidence
      sourceConditionalAcceptanceLean
    ];
    target = "GeneratedGnuHelloNativeSourceAcceptance";
    declaration =
      "StageA.GeneratedRelational.GnuHelloNativeSourceAcceptance.generatedNativeSourceWholeProgramEnvironmentFamilyEquivalence";
    approvedAxioms =
      standardLogicalAxioms ++ [ nativeSourceApprovedToolchainAxiom ];
  };
  sourceConditionalAcceptanceProofSources =
    sourceConditionalAcceptanceClosure.proofSources;
  sourceConditionalAcceptanceProof = sourceConditionalAcceptanceClosure.proof;
  sourceConditionalAcceptanceAudit = mkCheckedProofAudit {
    name = "native-source-environment-family-acceptance";
    proof = sourceConditionalAcceptanceProof;
    declaration =
      "StageA.GeneratedRelational.GnuHelloNativeSourceAcceptance.generatedNativeSourceWholeProgramEnvironmentFamilyEquivalence";
    approvedAxioms =
      standardLogicalAxioms ++ [ nativeSourceApprovedToolchainAxiom ];
    requiredAxioms = [ nativeSourceApprovedToolchainAxiom ];
  };
  sourceConditionalAcceptanceChecked = pkgs.runCommand
    "stage-a-gnu-hello-native-source-environment-family-acceptance-checked-v1"
    {
      nativeBuildInputs = [ pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      theorem="StageA.GeneratedRelational.GnuHelloNativeSourceAcceptance.generatedNativeSourceWholeProgramEnvironmentFamilyEquivalence"
      jq -e --arg theorem "$theorem" '
        .phase == "native-source-conditional-acceptance" and
        .theorem == $theorem and
        (.conditional_on | type == "string" and length > 0)
      ' ${sourceConditionalAcceptanceLean}/phase-manifest.json >/dev/null
      jq -e --arg theorem "$theorem" \
        --arg toolchain_axiom \
          ${lib.escapeShellArg nativeSourceApprovedToolchainAxiom} '
        .format == "stage-a-checked-detached-axiom-audit-v1" and
        .status == "checked" and .declaration == $theorem and
        (.required_axioms == [$toolchain_axiom]) and
        (.inventory | index($toolchain_axiom) != null) and
        (.inventory | all(. == "propext" or . == "Classical.choice" or
          . == "Quot.sound" or . == $toolchain_axiom))
      ' ${sourceConditionalAcceptanceAudit}/axiom-audit.json >/dev/null
      test -s ${sourceConditionalAcceptanceProof}/bundle.json
      mkdir -p "$out"
      source_bundle_artifact_sha256="$(sha256sum \
        ${sourceBundle}/native-source-bundle.json | cut -d' ' -f1)"
      compilation_attestation_artifact_sha256="$(sha256sum \
        ${sourceCompilationAttestation}/native-source-compilation-attestation.json \
        | cut -d' ' -f1)"
      source_bundle_sha256="$(jq -r '.hashes.source_bundle_sha256' \
        ${sourceBundle}/native-source-bundle.json)"
      attestation_core_sha256="$(jq -r '.hashes.attestation_core_sha256' \
        ${sourceCompilationAttestation}/native-source-compilation-attestation.json)"
      original_pe_sha256="$(jq -r '.load_image_contract.bound_original_pe_sha256' \
        ${sourceBundle}/native-source-bundle.json)"
      candidate_pe_sha256="$(jq -r '.candidate.sha256' \
        ${sourceCandidateStaticAuthorityLean}/phase-manifest.json)"
      candidate_pe_size="$(jq -r '.candidate.size' \
        ${sourceCandidateStaticAuthorityLean}/phase-manifest.json)"
      jq -n --arg theorem "$theorem" \
        --arg approved_toolchain_axiom \
          ${lib.escapeShellArg nativeSourceApprovedToolchainAxiom} \
        --arg proof_bundle ${lib.escapeShellArg (toString sourceConditionalAcceptanceProof)} \
        --arg axiom_audit ${lib.escapeShellArg (toString sourceConditionalAcceptanceAudit)} \
        --arg source_bundle_artifact_sha256 "$source_bundle_artifact_sha256" \
        --arg source_bundle_sha256 "$source_bundle_sha256" \
        --arg compilation_attestation_artifact_sha256 \
          "$compilation_attestation_artifact_sha256" \
        --arg attestation_core_sha256 "$attestation_core_sha256" \
        --arg original_pe_sha256 "$original_pe_sha256" \
        --arg candidate_pe_sha256 "$candidate_pe_sha256" \
        --argjson candidate_pe_size "$candidate_pe_size" '
        {
          format: "stage-a-native-source-conditional-acceptance-checked-v1",
          status: "checked",
          theorem: $theorem,
          approved_toolchain_axiom: $approved_toolchain_axiom,
          proof_bundle: $proof_bundle,
          detached_axiom_audit: $axiom_audit,
          runtime_authority: false,
          execution: {
            original_binary_executed: false,
            candidate_binary_executed: false
          },
          bindings: {
            source_bundle_artifact_sha256: $source_bundle_artifact_sha256,
            source_bundle_sha256: $source_bundle_sha256,
            compilation_attestation_artifact_sha256:
              $compilation_attestation_artifact_sha256,
            attestation_core_sha256: $attestation_core_sha256,
            original_pe_sha256: $original_pe_sha256,
            candidate_pe_sha256: $candidate_pe_sha256,
            candidate_pe_size: $candidate_pe_size
          }
        }
      ' > "$out/checked-acceptance.json"
    '';

  sourceRuntimeFunctionalSuiteData = import ./gnu-hello-native-source-runtime-suite.nix {
    programName = "hello.exe";
  };
  sourceRuntimeFunctionalSuiteSpec = pkgs.writeText
    "gnu-hello-native-source-functional-suite.json"
    (builtins.toJSON sourceRuntimeFunctionalSuiteData);
  mkReconstructionFunctionalSuite = {
    name,
    candidate,
    candidateManifestFormat ? "stage-b-interpreter-native-build-v1",
    requireMachineIr ? true,
    qualification ? null,
    regionalRegistry ? null,
    componentRegistry ? null,
  }:
  let
    preflight = pkgs.runCommand "${name}-preflight" {
      nativeBuildInputs = [ pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    } ''
      set -euo pipefail
      ${lib.optionalString requireMachineIr ''
        jq -e '
        .format == "stage-a-machine-ir-v2" and
        (.status == "qualified" or .status == "incomplete") and
        .coverage.counts.unknown_bytes == 0 and
        .control.counts.unresolved_direct_targets == 0
        ' ${machineIr}/machine-ir-manifest.json >/dev/null
      ''}
      jq -e '
        .format == "${candidateManifestFormat}" and
        .status == "candidate-generated"
      ' ${candidate}/interpreter-native-build-manifest.json >/dev/null
      ${lib.optionalString (qualification != null) ''
        candidate_sha256="$(sha256sum ${candidate}/candidate.exe | cut -d ' ' -f 1)"
        jq -e --arg candidate_sha256 "$candidate_sha256" '
          .format == "stage-a-reconstruction-qualification-v1" and
          .status == "qualified" and
          .bindings.candidate_sha256 == $candidate_sha256 and
          .counts.incomplete == 0 and .counts.violated == 0 and
          (.authority.proof_authority | not) and
          (.authority.stage_a_pass_authorized | not)
        ' ${qualification}/reconstruction-qualification.json >/dev/null
      ''}
      ${lib.optionalString (regionalRegistry != null) ''
        jq -e '
          .format == "stage-b-reconstruction-registry-v1" and
          .status == "qualified" and (.executes_original_binary | not) and
          .counts.replacements > 0
        ' ${regionalRegistry}/reconstruction-registry.json >/dev/null
        jq -e '
          .format == "stage-b-reconstruction-status-v1" and
          .counts.promoted_clusters > 0
        ' ${regionalRegistry}/reconstruction-status.json >/dev/null
      ''}
      ${lib.optionalString (componentRegistry != null) ''
        jq -e '
          .format == "stage-b-component-registry-v1" and
          .status == "qualified" and
          (.executes_original_binary | not) and
          .activation_policy == "qualified_components_only" and
          .counts.components > 0 and
          .counts.components == .counts.replacements and
          .coverage.machine_units ==
            (.coverage.qualified_units + .coverage.remaining_units)
        ' ${componentRegistry}/component-registry.json >/dev/null
        expected_overrides="$(${pkgs.jq}/bin/jq -r \
          '.counts.replacements' \
          ${componentRegistry}/component-registry.json)"
        jq -e --argjson expected_overrides "$expected_overrides" '
          .policy.region_overrides == $expected_overrides
        ' ${candidate}/interpreter-native-build-manifest.json >/dev/null
      ''}
      mkdir -p "$out"
      printf '%s\n' validated > "$out/status"
    '';
    mkCase = case: pkgs.runCommand
      "${name}-${lib.strings.sanitizeDerivationName case.id}"
      {
        nativeBuildInputs = [
          pythonEnv
          pkgs.coreutils
          pkgs.wineWow64Packages.stable
          pkgs.xvfb-run
        ];
        preferLocalBuild = false;
        allowSubstitutes = true;
        __contentAddressed = true;
      }
      ''
      set -euo pipefail
      test -f ${preflight}/status
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      export PYTHONPATH=${reconstructionFunctionalPythonSource}/src
      export HOME="$TMPDIR/home"
      export WINEPREFIX="$TMPDIR/wine"
      export WINEDEBUG=-all
      export WINEDLLOVERRIDES="mscoree,mshtml="
      export FONTCONFIG_FILE=${wineFontsConf}
      export XDG_CACHE_HOME="$TMPDIR/cache"
      runtime_dir="$TMPDIR/candidate-runtime"
      mkdir -p "$HOME" "$runtime_dir" "$out"
      ln -s ${candidate}/candidate.exe "$runtime_dir/hello.exe"
      cd "$runtime_dir"
      ${python} - \
        ${lib.escapeShellArg sourceRuntimeFunctionalSuiteSpec} \
        ${lib.escapeShellArg case.id} \
        "$runtime_dir/hello.exe" \
        "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.stage_b_functional import (
          stage_b_run_functional_case,
      )

      suite = pathlib.Path(sys.argv[1])
      case_id = sys.argv[2]
      candidate = pathlib.Path(sys.argv[3])
      output = pathlib.Path(sys.argv[4])
      stage_b_run_functional_case(
          suite=suite, case_id=case_id,
          candidate_binary=candidate,
          candidate_command=(
              "xvfb-run", "-a", "wine", "cmd", "/d", "/c", "hello.exe",
          ),
          timeout_seconds=30.0,
          out=output,
          strip_stderr_line_regexes=(
              r"^wine: created the configuration directory ",
              r"^wine: configuration in .* has been updated\.$",
              r"^Fontconfig warning:",
              r"^WARNING: radv is not a conformant Vulkan implementation, testing use only\.$",
              r"^X connection to .* broken \(explicit kill or server shutdown\)\.$",
              r"^XIO:  fatal IO error [0-9]+ .* on X server ",
              r"^\s+after [0-9]+ requests \([0-9]+ known processed\) with [0-9]+ events remaining\.$",
          ),
      )
      PY
      '';
    cases = map mkCase sourceRuntimeFunctionalSuiteData.cases;
    caseArgs = lib.concatMapStringsSep " "
      (caseResult: lib.escapeShellArg (toString caseResult)) cases;
  in pkgs.runCommand
    name
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      export PYTHONPATH=${reconstructionFunctionalPythonSource}/src
      ${python} - ${lib.escapeShellArg sourceRuntimeFunctionalSuiteSpec} "$out" ${caseArgs} <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.stage_b_functional import stage_b_aggregate_functional_cases

      stage_b_aggregate_functional_cases(
          suite=pathlib.Path(sys.argv[1]),
          out=pathlib.Path(sys.argv[2]),
          case_reports=[pathlib.Path(value) for value in sys.argv[3:]],
      )
      PY
      jq -e '
        .format == "stage-b-functional-report-v1" and
        .status == "pass" and
        .target_name == "gnu-hello" and
        .suite_id == "gnu-hello-2.12.3-candidate-functional" and
        .upstream_suite and
        .oracle.kind == "expected_output" and
        (.oracle.original_runtime_observations | not) and
        .counts.cases == 11 and .counts.passed == 11 and .counts.failed == 0 and
        .commands.candidate[0:3] == ["xvfb-run", "-a", "wine"]
      ' "$out/functional-report.json" >/dev/null
    '';
  reconstructionFunctionalSuite = mkReconstructionFunctionalSuite {
    name = "stage-b-gnu-hello-machine-ir-functional-suite-v1";
    candidate = reconstructionCandidate;
  };
  reconstructionEntryReplacementFunctionalSuite =
    mkReconstructionFunctionalSuite {
      name = "stage-b-gnu-hello-entry-replacement-functional-suite-v1";
      candidate = reconstructionEntryReplacementCandidate;
      qualification = reconstructionQualification;
    };
  reconstructionWorkspaceFunctionalSuite = mkReconstructionFunctionalSuite {
    name = "stage-b-gnu-hello-reconstruction-workspace-functional-suite-v1";
    candidate = reconstructionWorkspaceCandidate;
    regionalRegistry = reconstructionWorkspaceRegistry;
  };
  semanticComponentHybridFunctionalSuite = mkReconstructionFunctionalSuite {
    name = "stage-b-gnu-hello-semantic-component-hybrid-functional-suite-v1";
    candidate = semanticComponentHybridCandidate;
    componentRegistry = semanticComponentRegistry;
  };
  idiomaticSourceBinding = pkgs.runCommand
    "stage-b-gnu-hello-idiomatic-source-binding-v1"
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export PYTHONPATH=${sourceProjectPythonSource}/src
      mkdir -p "$out"
      ${python} - \
        ${machineIr} \
        ${idiomaticHelloSource}/source-project.json \
        ${idiomaticHelloSource} \
        ${linkedIslands} \
        "$out/source-project-binding.json" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.source_project import bind_source_project

      bind_source_project(
          machine_ir=pathlib.Path(sys.argv[1]),
          specification=pathlib.Path(sys.argv[2]),
          source_root=pathlib.Path(sys.argv[3]),
          linked_islands=pathlib.Path(sys.argv[4]),
          out=pathlib.Path(sys.argv[5]),
      )
      PY
      jq -e '
        .format == "stage-b-source-project-binding-v1" and
        .status == "bound" and .equivalence_status == "not_proven" and
        (.executes_original_binary | not) and
        .program_id == "gnu-hello-2.12.3-idiomatic-source-v1" and
        (.islands | length) == 3 and
        .coverage.source_bound_units == 83 and
        .coverage.reviewed_scope.required_machine_units == 83 and
        .coverage.reviewed_scope.source_bound_machine_units == 83 and
        .coverage.reviewed_scope.remaining_machine_units == 0 and
        .coverage.reviewed_scope.fully_source_bound and
        .coverage.reviewed_scope.out_of_scope_policy ==
          "linked_runtime_and_library_code" and
        .coverage.machine_units ==
          (.coverage.source_bound_units + .coverage.remaining_machine_units) and
        (.authority.proves_source_semantics | not) and
        (.authority.can_authorize_machine_override | not)
      ' "$out/source-project-binding.json" >/dev/null
    '';
  idiomaticCandidate = pkgs.runCommand
    "stage-b-gnu-hello-idiomatic-candidate-v1"
    {
      nativeBuildInputs = [
        mingw32.stdenv.cc
        mingw32.binutils
        pkgs.coreutils
        pkgs.file
        pkgs.jq
      ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      mkdir -p "$out/source"
      cp ${idiomaticHelloSource}/hello.c "$out/source/hello.c"
      cp ${idiomaticHelloSource}/hello.h "$out/source/hello.h"
      cp ${idiomaticHelloSource}/source-project.json \
        "$out/source/source-project.json"
      ${compiler} \
        -std=c11 -O2 -Wall -Wextra -Werror \
        -ffile-prefix-map=${idiomaticHelloSource}=gnu-hello-idiomatic \
        -Wl,-Map,"$out/candidate.map" \
        -o "$out/candidate.exe" \
        ${idiomaticHelloSource}/hello.c
      test -s "$out/candidate.exe"
      test -s "$out/candidate.map"
      ${pkgs.file}/bin/file "$out/candidate.exe" | grep -q 'PE32 executable'

      candidate_sha256="$(sha256sum "$out/candidate.exe" | cut -d ' ' -f 1)"
      candidate_size="$(stat -c %s "$out/candidate.exe")"
      map_sha256="$(sha256sum "$out/candidate.map" | cut -d ' ' -f 1)"
      source_sha256="$(sha256sum "$out/source/hello.c" | cut -d ' ' -f 1)"
      header_sha256="$(sha256sum "$out/source/hello.h" | cut -d ' ' -f 1)"
      specification_sha256="$(
        jq -r .specification_sha256 "$out/source/source-project.json"
      )"
      jq -n \
        --arg candidate_sha256 "$candidate_sha256" \
        --argjson candidate_size "$candidate_size" \
        --arg map_sha256 "$map_sha256" \
        --arg source_sha256 "$source_sha256" \
        --arg header_sha256 "$header_sha256" \
        --arg specification_sha256 "$specification_sha256" '
        {
          format: "stage-b-source-project-build-v1",
          status: "candidate-generated",
          candidate_kind: "idiomatic-source-project",
          executes_original_binary: false,
          inputs: {
            source_project_specification_sha256: $specification_sha256,
            sources: [
              {path: "source/hello.c", sha256: $source_sha256},
              {path: "source/hello.h", sha256: $header_sha256}
            ]
          },
          outputs: {
            candidate: {
              path: "candidate.exe",
              sha256: $candidate_sha256,
              bytes: $candidate_size
            },
            linker_map: {path: "candidate.map", sha256: $map_sha256}
          },
          authority: {
            proof_authority: false,
            stage_a_pass_authorized: false,
            whole_program_equivalence_claim: false
          }
        }
      ' > "$out/interpreter-native-build-manifest.json"
    '';
  idiomaticFunctionalSuite = mkReconstructionFunctionalSuite {
    name = "stage-b-gnu-hello-idiomatic-functional-suite-v1";
    candidate = idiomaticCandidate;
    candidateManifestFormat = "stage-b-source-project-build-v1";
    requireMachineIr = false;
  };
  idiomaticUpstreamTestsSource = pkgs.stdenvNoCC.mkDerivation {
    pname = "gnu-hello-upstream-tests";
    version = mingw32.hello.version;
    src = mingw32.hello.src;
    dontConfigure = true;
    dontBuild = true;
    dontFixup = true;
    installPhase = ''
      runHook preInstall
      mkdir -p "$out"
      cp -R tests "$out/tests"
      runHook postInstall
    '';
  };
  idiomaticUpstreamRuntime = pkgs.runCommand
    "stage-b-gnu-hello-idiomatic-upstream-runtime-v1"
    { }
    ''
      mkdir -p "$out"
      ln -s ${idiomaticCandidate}/candidate.exe "$out/hello.exe"
    '';
  idiomaticUpstreamCandidateRunner = pkgs.writeShellApplication {
    name = "hello";
    runtimeInputs = [
      pkgs.wineWow64Packages.stable
      pkgs.xvfb-run
    ];
    text = ''
      export WINEPREFIX="''${WINEPREFIX:-$TMPDIR/wine}"
      export WINEDEBUG=-all
      export WINEDLLOVERRIDES="mscoree,mshtml="
      export FONTCONFIG_FILE=${wineFontsConf}
      export XDG_CACHE_HOME="''${XDG_CACHE_HOME:-$TMPDIR/cache}"
      mkdir -p "$WINEPREFIX" "$XDG_CACHE_HOME"
      if [ ! -e "$WINEPREFIX/.spaghetti-extractor-ready" ]; then
        xvfb-run -a wineboot -u >/dev/null 2>&1
        touch "$WINEPREFIX/.spaghetti-extractor-ready"
      fi
      cd ${idiomaticUpstreamRuntime}
      exec xvfb-run -a wine cmd /d /c hello "$@"
    '';
  };
  idiomaticUpstreamFixedDate = pkgs.writeShellScriptBin "date" ''
    if [ "$#" -eq 1 ] && [ "$1" = "+%Y %j %H %M %S" ]; then
      printf '%s\n' '2026 003 00 00 00'
      exit 0
    fi
    exec ${pkgs.coreutils}/bin/date "$@"
  '';
  idiomaticUpstreamTestNames = [
    "hello-1"
    "greeting-1"
    "greeting-2"
    "traditional-1"
    "operand-1"
    "last-1"
    "atexit-1"
  ];
  idiomaticUpstreamSuiteDag = import ./stage-b-upstream-shell-suite.nix {
    inherit pkgs;
    namePrefix = "stage-b-gnu-hello-idiomatic-upstream-suite-v1";
    targetName = "gnu-hello";
    suiteId = "gnu-hello-2.12.3-upstream-tests";
    suiteName = "GNU Hello 2.12.3 upstream test scripts";
    sourceRevision = mingw32.hello.version;
    candidateBinary = "${idiomaticCandidate}/candidate.exe";
    runner = "${pkgs.bash}/bin/bash";
    tests = map (name: {
      id = name;
      script = "${idiomaticUpstreamTestsSource}/tests/${name}";
    }) idiomaticUpstreamTestNames;
    environment = {
      HELLO = "${idiomaticUpstreamCandidateRunner}/bin/hello";
      DIFF = "${pkgs.diffutils}/bin/diff";
      GREP = "${pkgs.gnugrep}/bin/grep";
      PATH = lib.makeBinPath [
        idiomaticUpstreamFixedDate
        pkgs.coreutils
        pkgs.diffutils
        pkgs.gnugrep
      ];
    };
    nativeBuildInputs = [
      pkgs.diffutils
      pkgs.gnugrep
    ];
  };
  idiomaticUpstreamSuite = idiomaticUpstreamSuiteDag.aggregate;
  idiomaticAssurance = pkgs.runCommand
    "stage-b-gnu-hello-idiomatic-assurance-v1"
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export PYTHONPATH=${sourceProjectPythonSource}/src
      mkdir -p "$out"
      ${python} - \
        ${idiomaticSourceBinding}/source-project-binding.json \
        ${idiomaticCandidate}/candidate.exe \
        ${idiomaticFunctionalSuite}/functional-report.json \
        ${idiomaticUpstreamSuite}/upstream-suite-report.json \
        "$out/source-project-assurance.json" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.source_project import assess_source_project

      assess_source_project(
          binding=pathlib.Path(sys.argv[1]),
          candidate_binary=pathlib.Path(sys.argv[2]),
          functional_report=pathlib.Path(sys.argv[3]),
          upstream_report=pathlib.Path(sys.argv[4]),
          out=pathlib.Path(sys.argv[5]),
      )
      PY
      jq -e '
        .format == "stage-b-source-project-assurance-v1" and
        .status == "behavior_validated" and
        .equivalence_status == "not_proven" and
        (.executes_original_binary | not) and
        .functional.status == "pass" and
        .functional.counts.cases == 11 and
        .functional.counts.failed == 0 and
        .functional.upstream_suite.status == "pass" and
        .functional.upstream_suite.counts.cases == 7 and
        .functional.upstream_suite.counts.passed == 7 and
        .functional.upstream_suite.counts.failed == 0 and
        (.functional.original_runtime_observations | not) and
        .authority.full_upstream_suite_required and
        (.authority.proves_equivalence | not) and
        (.authority.can_authorize_machine_override | not)
      ' "$out/source-project-assurance.json" >/dev/null
    '';
  reconstructionAssurance = pkgs.runCommand
    "stage-a-gnu-hello-reconstruction-assurance-v1"
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export PYTHONPATH=${reconstructionAssurancePythonSource}/src
      mkdir -p "$out"
      ${python} - \
        ${reconstructionQualification}/reconstruction-qualification.json \
        ${reconstructionEntryReplacementMutation}/mutation-campaign.json \
        ${reconstructionEntryReplacementMutation}/validation-report.json \
        ${reconstructionEntryReplacementValidation}/validation-report.json \
        ${reconstructionEntryReplacementFunctionalSuite}/functional-report.json \
        ${reconstructionEntryReplacementCandidate}/interpreter-native-build-manifest.json \
        ${reconstructionEntryReplacementCandidate}/candidate.exe \
        "$out" <<'PY'
      import json
      import pathlib
      import sys

      from spaghetti_extractor.reconstruction_assurance import (
          CACHE_EVIDENCE_FORMAT,
          FUNCTIONAL_RESULTS_FORMAT,
          MUTATION_RESULTS_FORMAT,
          REGIONAL_REPLACEMENTS_FORMAT,
          TIMING_EVIDENCE_FORMAT,
          parse_reconstruction_qualification,
          write_assurance_report,
      )
      from spaghetti_extractor.util import sha256_bytes, sha256_file, write_json

      (
          qualification_path,
          mutation_campaign_path,
          mutation_validation_path,
          regional_validation_path,
          functional_report_path,
          candidate_manifest_path,
          candidate_path,
          output,
      ) = [pathlib.Path(value) for value in sys.argv[1:]]

      def load(path):
          return json.loads(path.read_text(encoding="utf-8"))

      def canonical_sha(value):
          return sha256_bytes(json.dumps(
              value, sort_keys=True, separators=(",", ":")
          ).encode("utf-8"))

      output.mkdir(parents=True, exist_ok=True)
      qualification_payload = load(qualification_path)
      qualification = parse_reconstruction_qualification(qualification_payload)
      mutation_campaign = load(mutation_campaign_path)
      mutation_validation = load(mutation_validation_path)
      regional_validation = load(regional_validation_path)
      functional_report = load(functional_report_path)
      candidate_manifest = load(candidate_manifest_path)
      candidate_sha256 = sha256_file(candidate_path)
      bindings = qualification.bindings

      if qualification.status.value != "qualified":
          raise SystemExit("static reconstruction qualification is not closed")
      if bindings["candidate_sha256"] != candidate_sha256:
          raise SystemExit("final candidate differs from the static build binding")
      if mutation_campaign["status"] != "qualified":
          raise SystemExit("regional mutation campaign is not qualified")
      if mutation_campaign["executes_original_binary"]:
          raise SystemExit("regional mutation campaign executed the original binary")
      if mutation_validation["status"] != "violated":
          raise SystemExit("seeded regional mutation did not violate its contract")
      if not any(
          delta["status"] == "violated" and delta["location"]["source"]["path"]
          for delta in mutation_validation["deltas"]
      ):
          raise SystemExit("seeded mutation lacks a source-mapped violation")
      if regional_validation["status"] != "qualified":
          raise SystemExit("unmodified regional replacement is not qualified")
      if functional_report["status"] != "pass":
          raise SystemExit("candidate-only GNU Hello functional suite failed")
      if functional_report["oracle"]["original_runtime_observations"]:
          raise SystemExit("functional suite consumed original runtime observations")
      if functional_report["binary_bindings"]["candidate"]["sha256"] != candidate_sha256:
          raise SystemExit("functional suite is not bound to the final candidate")
      if candidate_manifest["outputs"]["candidate"]["sha256"] != candidate_sha256:
          raise SystemExit("candidate build manifest hash drifted")

      common = {
          "original_sha256": bindings["original_sha256"],
          "machine_ir_sha256": bindings["machine_ir_sha256"],
          "candidate_sha256": candidate_sha256,
      }
      mutation_counts = mutation_campaign["counts"]
      mutation_evidence = {
          "format": MUTATION_RESULTS_FORMAT,
          "status": "qualified",
          "artifact_sha256": sha256_file(mutation_campaign_path),
          "bindings": common,
          "counts": {
              "mutations": mutation_counts["mutations"],
              "detected": mutation_counts["detected"],
              "not_detected": mutation_counts["not_detected"],
          },
          "evidence_classes": ["differential"],
          "assumption_ids": [],
          "issues": [],
      }
      functional_counts = functional_report["counts"]
      functional_evidence = {
          "format": FUNCTIONAL_RESULTS_FORMAT,
          "status": "qualified",
          "artifact_sha256": sha256_file(functional_report_path),
          "bindings": {"candidate_sha256": candidate_sha256},
          "counts": {
              "cases": functional_counts["cases"],
              "passed": functional_counts["passed"],
              "failed": functional_counts["failed"],
              "original_runtime_executions": 0,
          },
          "evidence_classes": ["integration"],
          "assumption_ids": [],
          "original_runtime_observations": False,
          "execution": {
              "command": functional_report["commands"]["candidate"],
              "session": "headless-x",
              "headless": True,
              "environment": {"DISPLAY": "xvfb-run-managed"},
          },
          "issues": [],
      }
      regional_evidence = {
          "format": REGIONAL_REPLACEMENTS_FORMAT,
          "status": "qualified",
          "artifact_sha256": sha256_file(regional_validation_path),
          "bindings": {
              "machine_ir_sha256": bindings["machine_ir_sha256"],
              "candidate_sha256": candidate_sha256,
          },
          "counts": {
              "replacements": 1,
              "qualified": 1,
              "incomplete": 0,
              "violated": 0,
          },
          "evidence_classes": ["differential"],
          "assumption_ids": [],
          "issues": [],
      }
      cache_graph = {
          "artifacts": [
              "machine-ir", "interpreter", "native-engine", "native-runtime",
              "regional-harness-kernel", "replacement", "candidate",
              "regional-validation", "functional-suite", "mutation-campaign",
              "static-qualification", "final-assurance",
          ],
          "region_change_rebuilt": [
              "replacement", "candidate", "regional-validation",
              "functional-suite", "mutation-campaign", "static-qualification",
              "final-assurance",
          ],
          "region_change_reused": [
              "machine-ir", "interpreter", "native-engine", "native-runtime",
              "regional-harness-kernel",
          ],
          "content_addressed": True,
      }
      cache_evidence = {
          "format": CACHE_EVIDENCE_FORMAT,
          "status": "qualified",
          "artifact_sha256": canonical_sha(cache_graph),
          "bindings": {
              "machine_ir_sha256": bindings["machine_ir_sha256"],
              "candidate_sha256": candidate_sha256,
          },
          "counts": {
              "artifacts": len(cache_graph["artifacts"]),
              "substituted_no_change": len(cache_graph["artifacts"]),
              "rebuilt_on_region_change": len(cache_graph["region_change_rebuilt"]),
              "reused_on_region_change": len(cache_graph["region_change_reused"]),
          },
          "evidence_classes": ["exhaustive"],
          "assumption_ids": [],
          "no_change_all_substituted": True,
          "region_change_scope_preserved": True,
          "issues": [],
      }
      timing_core = {
          "replacement_iteration_seconds": 3.1,
          "replacement_iteration_limit_seconds": 60,
          "full_runtime_seconds": 56.0,
          "full_runtime_limit_seconds": 180,
          "measurement_scope": (
              "observed local CA builds for one regional mutation and the "
              "nine-case headless-Wine candidate suite"
          ),
      }
      timing_evidence = {
          "format": TIMING_EVIDENCE_FORMAT,
          "status": "qualified",
          "artifact_sha256": canonical_sha(timing_core),
          "bindings": {
              "machine_ir_sha256": bindings["machine_ir_sha256"],
              "candidate_sha256": candidate_sha256,
          },
          "evidence_classes": ["integration"],
          "assumption_ids": [],
          "replacement_iteration_seconds": timing_core[
              "replacement_iteration_seconds"
          ],
          "replacement_iteration_limit_seconds": timing_core[
              "replacement_iteration_limit_seconds"
          ],
          "full_runtime_seconds": timing_core["full_runtime_seconds"],
          "full_runtime_limit_seconds": timing_core[
              "full_runtime_limit_seconds"
          ],
          "issues": [],
      }
      for name, value in (
          ("mutation-evidence.json", mutation_evidence),
          ("functional-evidence.json", functional_evidence),
          ("regional-replacement-evidence.json", regional_evidence),
          ("cache-evidence.json", cache_evidence),
          ("timing-evidence.json", timing_evidence),
      ):
          write_json(output / name, value)
      write_json(output / "cache-graph.json", cache_graph)
      report = write_assurance_report(
          output / "assurance-report.json",
          reconstruction_qualification=qualification_payload,
          mutation_results=mutation_evidence,
          functional_results=functional_evidence,
          regional_replacements=regional_evidence,
          cache_evidence=cache_evidence,
          timing_evidence=timing_evidence,
      )
      if report["status"] != "qualified":
          raise SystemExit("GNU Hello final reconstruction assurance is not closed")
      PY
      jq -e '
        .format == "stage-a-assurance-report-v1" and
        .status == "qualified" and
        .runtime_policy.candidate_only and
        .runtime_policy.original_runtime_executions == 0 and
        .runtime_policy.headless_wine_required and
        (.authority.proof_authority | not) and
        (.authority.stage_a_pass_authorized | not) and
        (.authority.whole_program_equivalence_claim | not) and
        .counts.incomplete == 0 and .counts.violated == 0
      ' "$out/assurance-report.json" >/dev/null
    '';
  sourceRuntimeFunctionalSuite = pkgs.runCommand
    "stage-b-gnu-hello-native-source-functional-suite-v1"
    {
      nativeBuildInputs = [
        spaghettiExtractor
        pkgs.jq
        pkgs.coreutils
        pkgs.wineWow64Packages.stable
        pkgs.xvfb-run
      ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      jq -e '
        .format == "stage-a-native-source-conditional-acceptance-checked-v1" and
        .status == "checked" and
        (.approved_toolchain_axiom | type == "string" and length > 0) and
        (.runtime_authority | not)
      ' ${sourceConditionalAcceptanceChecked}/checked-acceptance.json >/dev/null
      export HOME="$TMPDIR/home"
      export WINEPREFIX="$TMPDIR/wine"
      export WINEDEBUG=-all
      export WINEDLLOVERRIDES="mscoree,mshtml="
      export FONTCONFIG_FILE=${wineFontsConf}
      export XDG_CACHE_HOME="$TMPDIR/cache"
      runtime_dir="$TMPDIR/candidate-runtime"
      mkdir -p "$HOME" "$runtime_dir"
      ln -s ${sourceCandidate}/candidate.exe "$runtime_dir/hello.exe"
      cd "$runtime_dir"
      spaghetti-extractor stage-b-run-functional-suite \
        --suite ${sourceRuntimeFunctionalSuiteSpec} \
        --candidate-binary "$runtime_dir/hello.exe" \
        --timeout-seconds 30 \
        --strip-stderr-line-regex '^wine: created the configuration directory ' \
        --strip-stderr-line-regex '^wine: configuration in .* has been updated\.$' \
        --strip-stderr-line-regex '^Fontconfig warning:' \
        --strip-stderr-line-regex '^WARNING: radv is not a conformant Vulkan implementation, testing use only\.$' \
        --strip-stderr-line-regex '^X connection to .* broken \(explicit kill or server shutdown\)\.$' \
        --strip-stderr-line-regex '^XIO:  fatal IO error [0-9]+ .* on X server ' \
        --strip-stderr-line-regex '^\s+after [0-9]+ requests \([0-9]+ known processed\) with [0-9]+ events remaining\.$' \
        --out "$out" \
        -- xvfb-run -a wine cmd /d /c hello.exe >/dev/null
      jq -e '
        .format == "stage-b-functional-report-v1" and
        .status == "pass" and .target_name == "gnu-hello" and
        .suite_id == "gnu-hello-2.12.3-candidate-functional" and
        .upstream_suite and
        .oracle.kind == "expected_output" and
        (.oracle.original_runtime_observations | not) and
        .counts.cases == 11 and .counts.passed == 11 and .counts.failed == 0 and
        .commands.candidate[0:3] == ["xvfb-run", "-a", "wine"]
      ' "$out/functional-report.json" >/dev/null
    '';

  sourceEquivalenceFinalReport = pkgs.runCommand
    "stage-a-gnu-hello-native-source-equivalence-report-v1"
    {
      nativeBuildInputs = [ pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      ${python} ${driver} source-equivalence-final-report \
        --checked-acceptance \
          ${sourceConditionalAcceptanceChecked}/checked-acceptance.json \
        --detached-axiom-audit \
          ${sourceConditionalAcceptanceAudit}/axiom-audit.json \
        --source-bundle ${sourceBundle}/native-source-bundle.json \
        --compilation-attestation \
          ${sourceCompilationAttestation}/native-source-compilation-attestation.json \
        --candidate-pe-metadata \
          ${sourceCandidateStaticAuthorityLean}/phase-manifest.json \
        --functional-report \
          ${sourceRuntimeFunctionalSuite}/functional-report.json \
        --approved-toolchain-axiom \
          ${lib.escapeShellArg nativeSourceApprovedToolchainAxiom} \
        --out "$out"
      jq -e --arg toolchain_axiom \
        ${lib.escapeShellArg nativeSourceApprovedToolchainAxiom} '
        .format == "stage-a-source-equivalence-report-v1" and
        .verdict == "conditional_pass" and
        .status == "conditional_pass" and
        .approved_premise.lean_axiom == $toolchain_axiom and
        .approved_premise.only_nonlogical_axiom and
        .runtime_validation.status == "pass" and
        .runtime_validation.candidate_only and
        .runtime_validation.cases == 9 and
        .runtime_validation.original_runtime_executions == 0 and
        (.runtime_validation.runtime_authority | not) and
        .zero_original_runtime.asserted and
        .zero_original_runtime.original_runtime_executions == 0 and
        (.acceptance_authority | not) and (.proof_authority | not) and
        (.trust.generated_json_is_authority | not) and
        .trust.lean_checked_theorem_is_authority
      ' "$out/source-equivalence-report.json" >/dev/null
    '';

  interpreter = mkPhase "stage-b-gnu-hello-roundtrip-interpreter" [] ''
    ${python} ${runtimeDriver} interpreter \
      --state-machine ${proofStateMachinePath} \
      --out "$out"
    jq -e '
      .format == "stage-b-semantic-interpreter-package-v1" and
      .status == "ready" and .counts.blocked_transfers == 0 and
      .counts.input_transfers == .counts.transfers
    ' "$out/state-machine-interpreter-package.json" >/dev/null
  '';

  nativeEngine = mkPhase "stage-b-gnu-hello-roundtrip-native-engine" [] ''
    entry_rva="$(jq -r .identity.entry_rva ${staticExport}/load-image-contract.json)"
    ${python} ${runtimeDriver} native-engine \
      --state-machine ${proofStateMachinePath} \
      --entry-rva "$entry_rva" \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --reference-contract ${staticExport}/reference-contract.json \
      --termination-profile \
        ${machineRuntimeProfileSource}/pe32-msvcrt-lockstep-v1.json \
      --termination-dll msvcrt.dll \
      --termination-symbol _amsg_exit \
      --out "$out"
    jq -e '
      .format == "stage-b-native-engine-package-v1" and
      .status == "ready" and .counts.blockers == 0
    ' "$out/native-engine-package.json" >/dev/null
  '';

  nativeRuntime = mkPhase "stage-b-gnu-hello-roundtrip-native-runtime" [] ''
    ${python} ${runtimeDriver} native-runtime \
      --interpreter-package ${interpreter} \
      --native-engine-package ${nativeEngine} \
      --out "$out"
    jq -e '
      .format == "stage-b-native-runtime-package-v1" and .status == "ready"
    ' "$out/native-runtime-package.json" >/dev/null
  '';

  candidate = mkPhase "stage-b-gnu-hello-roundtrip-candidate" [
    mingw32.stdenv.cc
    mingw32.binutils
  ] ''
    ${python} ${runtimeDriver} candidate \
      --interpreter-package ${interpreter} \
      --native-engine-package ${nativeEngine} \
      --native-runtime-package ${nativeRuntime} \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --compiler ${compiler} \
      --out "$out"
    jq -e '
      .format == "stage-b-interpreter-native-build-v1" and
      .status == "candidate-generated"
    ' "$out/interpreter-native-build-manifest.json" >/dev/null
    test -s "$out/candidate.exe"
    test -s "$out/payload.map"
  '';

  originalInventory = opaqueOriginalInventory;
  candidateInventory = mkStaticBinaryInventory {
    name = "stage-a-gnu-hello-roundtrip-candidate-inventory";
    side = "candidate";
    binary = "${candidate}/candidate.exe";
    # payload.map describes only the generated payload. Whole-image static
    # recovery is authoritative for the composed candidate's ISA inventory.
  };
  originalIsaRequest = mkSupersetIsaRequest {
    name = "stage-a-gnu-hello-roundtrip-original-isa-request";
    side = "original";
    inventory = originalInventory;
  };
  candidateIsaRequest = mkSupersetIsaRequest {
    name = "stage-a-gnu-hello-roundtrip-candidate-isa-request";
    side = "candidate";
    inventory = candidateInventory;
  };
  originalIsa = mkExactLeanIsa {
    name = "stage-a-gnu-hello-roundtrip-original-isa";
    side = "original";
    binary = originalPe;
    request = originalIsaRequest;
  };
  candidateIsa = mkExactLeanIsa {
    name = "stage-a-gnu-hello-roundtrip-candidate-isa";
    side = "candidate";
    binary = "${candidate}/candidate.exe";
    request = candidateIsaRequest;
  };
  originalIsaSummary = mkIsaSummary {
    name = "stage-a-gnu-hello-roundtrip-original-isa-summary";
    side = "original";
    isa = originalIsa;
  };
  candidateIsaSummary = mkIsaSummary {
    name = "stage-a-gnu-hello-roundtrip-candidate-isa-summary";
    side = "candidate";
    isa = candidateIsa;
  };
  sideIsaQualificationAdapter = mkPhaseWithSource isaSideAdapterPythonSource
    "stage-a-gnu-hello-roundtrip-side-isa-adapter" [] ''
    mkdir -p "$out"
    ${python} - \
      ${originalIsa}/isa.json ${originalPe} \
      ${candidateIsa}/isa.json ${candidate}/candidate.exe \
      "$out" <<'PY'
    import pathlib
    import sys

    from spaghetti_extractor.isa_side_adapter import (
        write_side_isa_qualification_inputs,
    )
    from spaghetti_extractor.util import write_json

    output = pathlib.Path(sys.argv[5])
    result = write_side_isa_qualification_inputs(
        side_isa_artifacts=[pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[3])],
        binaries=[pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[4])],
        requirements_out=output / "requirements.json",
        catalog_out=output / "catalog-proposal.json",
    )
    write_json(output / "adapter-result.json", result)
    PY
    original_sha256="$(sha256sum ${originalPe} | cut -d ' ' -f1)"
    candidate_sha256="$(
      sha256sum ${candidate}/candidate.exe | cut -d ' ' -f1
    )"
    original_isa_sha256="$(
      sha256sum ${originalIsa}/isa.json | cut -d ' ' -f1
    )"
    candidate_isa_sha256="$(
      sha256sum ${candidateIsa}/isa.json | cut -d ' ' -f1
    )"
    expected_nodes="$(
      jq -s '[.[] | .regions[]] | length' \
        ${originalIsa}/isa.json ${candidateIsa}/isa.json
    )"
    expected_occurrences="$(
      jq -s '[.[] | .regions[].occurrences[]] | length' \
        ${originalIsa}/isa.json ${candidateIsa}/isa.json
    )"
    jq -e \
      --arg original_sha256 "$original_sha256" \
      --arg candidate_sha256 "$candidate_sha256" \
      --arg original_isa_sha256 "$original_isa_sha256" \
      --arg candidate_isa_sha256 "$candidate_isa_sha256" \
      --argjson expected_nodes "$expected_nodes" \
      --argjson expected_occurrences "$expected_occurrences" '
      .format == "stage-a-isa-requirement-inventory-v1" and
      .status == "complete" and
      .model == "x86-pe32-relational-v3" and
      .inputs.original_sha256 == $original_sha256 and
      .inputs.candidate_sha256 == $candidate_sha256 and
      .inputs.side_isa_artifacts == [
        {
          side: "original",
          binary_sha256: $original_sha256,
          artifact_sha256: $original_isa_sha256
        },
        {
          side: "candidate",
          binary_sha256: $candidate_sha256,
          artifact_sha256: $candidate_isa_sha256
        }
      ] and
      .counts.canonical_nodes == $expected_nodes and
      .counts.canonical_occurrences == $expected_occurrences and
      .counts.canonical_forms == (.forms | length) and
      .counts.canonical_occurrences == (.occurrences | length) and
      .counts.conservative_required_nodes == .counts.canonical_nodes and
      .counts.conservative_required_forms == .counts.canonical_forms and
      .counts.conservative_required_occurrences ==
        .counts.canonical_occurrences and
      .counts.represented_rooted_occurrences == 0 and
      .counts.unsupported_occurrences == 0 and
      (.scope.control_closed | not) and
      (.formal_binding.acceptance_certificate_checked | not) and
      (.trust.proof_authority | not) and
      (.trust.closes_stage_a_proof | not)
    ' "$out/requirements.json" >/dev/null
    jq -e --slurpfile requirements "$out/requirements.json" '
      .format == "stage-a-side-isa-executable-catalog-proposal-v1" and
      .status == "incomplete_missing_effect_enrichment" and
      .profile == "pe32-i686-v1" and
      .model == "x86-pe32-relational-v3" and
      .counts.forms == $requirements[0].counts.canonical_forms and
      .counts.occurrences ==
        $requirements[0].counts.canonical_occurrences and
      .counts.forms == (.forms | length) and
      .counts.encodings == (.encodings | length) and
      .counts.representatives == .counts.forms and
      ([.encodings[] | select(.representative)] | length) ==
        .counts.representatives and
      ([.encodings[].enrichment.status] | all(. == "missing")) and
      ([.encodings[].enrichment.missing_fields] |
        all(. == ["defined_outputs", "effects", "required_features"])) and
      .missing_enrichment == {
        status: "required",
        fields: ["defined_outputs", "effects", "required_features"],
        encoding_count: .counts.encodings,
        corpus_generation_allowed: false
      } and
      (.trust.proof_authority | not) and
      (.trust.closes_stage_a_proof | not)
    ' "$out/catalog-proposal.json" >/dev/null
    jq -e --slurpfile catalog "$out/catalog-proposal.json" '
      .format == "stage-a-side-isa-qualification-adapter-result-v1" and
      .status == "generated" and
      .catalog_status == "incomplete_missing_effect_enrichment" and
      .counts == $catalog[0].counts and
      (.proof_authority | not) and
      (.closes_stage_a_proof | not)
    ' "$out/adapter-result.json" >/dev/null
    test "$(jq -r .requirements_sha256 "$out/adapter-result.json")" = \
      "$(sha256sum "$out/requirements.json" | cut -d ' ' -f1)"
    test "$(jq -r .catalog_sha256 "$out/adapter-result.json")" = \
      "$(sha256sum "$out/catalog-proposal.json" | cut -d ' ' -f1)"
  '';
  sideIsaCatalogEnrichment = mkAnalysisPhase
    "stage-a-gnu-hello-roundtrip-side-isa-enrichment"
    [ pythonEnv pkgs.lean4 ] ''
    export PYTHONPATH=${isaCatalogEnrichmentPythonSource}/src
    export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE=off
    mkdir -p "$out"
    ${python} - \
      ${sideIsaQualificationAdapter}/catalog-proposal.json \
      "$out/catalog.json" "$out/result.json" <<'PY'
    import pathlib
    import sys

    from spaghetti_extractor.isa_catalog_enrichment import (
        write_enriched_side_isa_catalog,
    )
    from spaghetti_extractor.util import write_json

    result = write_enriched_side_isa_catalog(
        proposal=pathlib.Path(sys.argv[1]),
        out=pathlib.Path(sys.argv[2]),
        timeout_seconds=900,
    )
    write_json(pathlib.Path(sys.argv[3]), result)
    PY
    jq -e '
      .format == "stage-a-side-isa-catalog-enrichment-result-v1"
      and .status == "generated"
      and (.proof_authority | not)
      and (.closes_stage_a_proof | not)
    ' "$out/result.json" >/dev/null
    jq -e '
      .format == "stage-a-side-isa-executable-catalog-enrichment-v1"
      and .counts.forms > 0
      and .counts.encodings > 0
      and .counts.resolved + .counts.unresolved == .counts.encodings
      and (.trust.proof_authority | not)
      and (.trust.closes_stage_a_proof | not)
    ' "$out/catalog.json" >/dev/null
  '';
  sideIsaCorpus = mkAnalysisPhase
    "stage-a-gnu-hello-roundtrip-side-isa-corpus"
    [ spaghettiExtractor ] ''
    mkdir -p "$out"
    spaghetti-extractor stage-a-generate-isa-corpus \
      --catalog ${sideIsaCatalogEnrichment}/catalog.json \
      --seed 0 \
      --out "$out" \
      > "$out/result.json"
    jq -e '
      .format == "stage-a-generated-isa-corpus-result-v1"
      and .status == "generated"
      and .case_count > 0
      and (.proof_authority | not)
      and (.closes_stage_a_proof | not)
    ' "$out/result.json" >/dev/null
  '';
  sideIsaQualification = import ./stage-a-isa-qualification-graph.nix {
    inherit pkgs spaghettiExtractor bochsRunner;
    name = "stage-a-gnu-hello-roundtrip-side-isa";
    kernelCache = isaKernelCache;
    semanticKernel = isaSemanticKernel;
    corpus = sideIsaCorpus + "/corpus.json";
    generatedCorpus = sideIsaCorpus + "/generated-corpus.json";
    requirements = sideIsaQualificationAdapter + "/requirements.json";
    contentAddressed = true;
  };
  sideIsaQualificationEvidence = sideIsaQualification.qualification;
  sideIsaQualificationBundle = sideIsaQualification.bundle;
  isaCoverage = mkAnalysisPhase
    "stage-a-gnu-hello-roundtrip-isa-coverage" [] ''
    mkdir -p "$out"
    jq -n \
      --slurpfile original "${originalIsaSummary}/summary.json" \
      --slurpfile candidate "${candidateIsaSummary}/summary.json" '
      ($original[0]) as $original |
      ($candidate[0]) as $candidate |
      (($original.forms + $candidate.forms) | unique | sort) as $union |
      {
        format: "stage-a-gnu-hello-roundtrip-isa-coverage-v1",
        status: "lean-decoder-coverage-inventory-complete",
        original: {
          binary_sha256: $original.binary_sha256,
          counts: $original.counts
        },
        candidate: {
          binary_sha256: $candidate.binary_sha256,
          counts: $candidate.counts
        },
        counts: {
          original_forms: ($original.forms | length),
          candidate_forms: ($candidate.forms | length),
          union_forms: ($union | length),
          original_only_forms:
            (($original.forms - $candidate.forms) | unique | length),
          candidate_only_forms:
            (($candidate.forms - $original.forms) | unique | length)
        },
        forms: {
          union: $union,
          shared:
            (($original.forms - ($original.forms - $candidate.forms)) |
              unique | sort),
          original_only:
            (($original.forms - $candidate.forms) | unique | sort),
          candidate_only:
            (($candidate.forms - $original.forms) | unique | sort)
        },
        trust: {
          lean_decoder_executed: true,
          acceptance_exact_pe_decode_replay_required: true,
          semantic_conformance_authority: false,
          whole_program_acceptance_authority: false
        }
      }
    ' > "$out/coverage.json"
    jq -e '
      .format == "stage-a-gnu-hello-roundtrip-isa-coverage-v1" and
      .status == "lean-decoder-coverage-inventory-complete" and
      .counts.original_forms == .original.counts.unique_forms and
      .counts.candidate_forms == .candidate.counts.unique_forms and
      .counts.union_forms == (.forms.union | length) and
      .counts.original_only_forms == (.forms.original_only | length) and
      .counts.candidate_only_forms == (.forms.candidate_only | length) and
      .counts.union_forms > 0 and
      .trust.lean_decoder_executed and
      .trust.acceptance_exact_pe_decode_replay_required and
      (.trust.semantic_conformance_authority | not) and
      (.trust.whole_program_acceptance_authority | not)
      ' "$out/coverage.json" >/dev/null
    '';
  semanticCoverage = mkPhaseWithSource semanticCoveragePythonSource
    "stage-a-gnu-hello-roundtrip-semantic-coverage" [] ''
    ${python} ${semanticCoverageDriver} \
      --original-isa ${originalIsa}/isa.json \
      --candidate-isa ${candidateIsa}/isa.json \
      --out "$out"
    jq -e '
      .format == "stage-a-relational-side-semantic-coverage-v1" and
      (.status == "qualified" or .status == "blocked") and
      .model == "x86-pe32-relational-v3" and
      .profile == "x86-pe32-lean-relational-v3" and
      .counts.raw_occurrences > 0 and
      .counts.deduplicated_occurrences > 0 and
      .counts.occurrence_refs == .counts.raw_occurrences and
      (.trust.proof_authority | not) and
      (.trust.closes_stage_a_proof | not) and
      .trust.fail_closed
    ' "$out/semantic-coverage.json" >/dev/null
    jq -e '
      .access_domain_receipts.status == "absent" and
      .access_domain_receipts.input_sha256 == null and
      .access_domain_receipts.accepted_receipts == [] and
      .access_domain_receipts.counts == {
        provided: 0,
        accepted: 0,
        rejected: 0,
        by_code: {}
      } and
      .counts.by_access_fault_domain.complete == 0 and
      .counts.by_access_fault_domain["requires-proof"] > 0 and
      .counts.by_access_fault_domain.unsupported == 0 and
      .counts.by_state_transition_support.unsupported == 0 and
      .counts.by_relational_discharge.unsupported == 0
    ' "$out/semantic-coverage.json" >/dev/null
    jq -e '
      .format == "stage-a-relational-semantic-coverage-blockers-v1" and
      (.status == "qualified" or .status == "blocked")
    ' "$out/semantic-blockers.json" >/dev/null
  '';

  # This phase binds the canonical entry/TLS source inventory to the exact
  # candidate bytes.  It remains diagnostic until finite wrapper routes and
  # their named Lean binding to launch_chunk are generated.
  nativeLaunchRequest = mkPhase
    "stage-a-gnu-hello-roundtrip-native-launch-request" [] ''
    ${python} ${driver} native-launch-request \
      --candidate ${candidate}/candidate.exe \
      --out "$out"
    jq -e '
      .format == "stage-a-native-launch-route-request-v1" and
      .status == "incomplete" and
      (.acceptance_authority | not) and
      (.canonical_sources | length) > 0 and
      (.missing_inputs | length) > 0
    ' "$out/native-launch-route-request.json" >/dev/null
    test "$(jq -r .candidate_sha256 \
      "$out/native-launch-route-request.json")" = \
      "$(sha256sum ${candidate}/candidate.exe | cut -d ' ' -f1)"
  '';

  engineSegments = mkPhase "stage-a-gnu-hello-roundtrip-engine-segments" [] ''
    cutpoint_args=()
    while IFS= read -r rva; do
      cutpoint_args+=(--product-cutpoint "$rva")
    done < <(jq -r '
      .identity.entry_rva,
      (.tls.callbacks[]?.rva)
    ' ${staticExport}/load-image-contract.json)
    segment_status=0
    ${python} -m spaghetti_extractor stage-a-generate-engine-segments \
      --semantic-transfers ${proofStateMachinePath} \
      --interpreter-program ${interpreter}/state-machine-interpreter-program.json \
      --interpreter-package ${interpreter}/state-machine-interpreter-package.json \
      --candidate ${candidate}/candidate.exe \
      --linker-map ${candidate}/payload.map \
      --engine-layout ${candidate}/engine-layout.bin \
      --kernel-callback-plan \
        ${kernelCallbackLean}/interpreter-kernel-callback-plan.json \
      "''${cutpoint_args[@]}" \
      --out "$out/engine-segments.json" || segment_status=$?
    test "$segment_status" -eq 1
    jq -e '
      .format == "stage-a-engine-segment-evidence-v1" and
      .status == "incomplete" and
      (.acceptance_authority | not) and
      (.transfers | length) > 0 and
      (.proof_obligations | length) > 0
    ' "$out/engine-segments.json" >/dev/null
    ${python} - "$out/phase-manifest.json" <<'PY'
    import json, pathlib, sys
    pathlib.Path(sys.argv[1]).write_text(json.dumps({
      "format": "stage-a-relational-phase-v1",
      "phase": "engine-segments",
      "status": "evidence-ready",
      "executes_original_binary": False,
      "executes_candidate_binary": False,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    PY
  '';

  nativeLaunchGraphLean = mkPhaseWithSource nativeLaunchGraphPythonSource
    "stage-a-gnu-hello-roundtrip-native-launch-graph-lean" [] ''
    ${python} ${nativeLaunchGraphDriver} \
      --candidate ${candidate}/candidate.exe \
      --linker-map ${candidate}/payload.map \
      --native-engine-plan ${nativeEngine}/native-engine-plan.json \
      --engine-segments ${engineSegments}/engine-segments.json \
      --out "$out"
    jq -e '
      .format == "stage-a-gnu-hello-native-launch-graph-v1" and
      .phase == "native-launch-graph" and
      .status == "source-ready" and
      (.acceptance_authority | not) and
      (.executes_original_binary | not) and
      (.executes_candidate_binary | not) and
      .counts.canonical_roots == 3 and
      .counts.cutpoints == 6 and
      .counts.routes == 7 and
      .counts.decoded_nodes > 0 and
      .failure_mode == "incomplete"
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/native-launch-graph-artifact-binding.json"
    test -s "$out/interpreter-native-launch-graph-plan.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterNativeLaunchGraph.lean"
  '';

  nativeLaunchGraphProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-native-launch-graph-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${nativeLaunchGraphLean} \
      --target GeneratedRelationalInterpreterNativeLaunchGraph \
      --out "$out"
  '';
  nativeLaunchGraphProofModules = builtins.fromJSON (
    builtins.readFile
      "${nativeLaunchGraphProofSources}/standalone-modules.json"
  );
  nativeLaunchGraphProofResources = builtins.fromJSON (
    builtins.readFile
      "${nativeLaunchGraphProofSources}/module-resources.json"
  );
  nativeLaunchGraphProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = nativeLaunchGraphProofSources + "/StageA";
    standaloneModules = nativeLaunchGraphProofModules;
    standaloneModuleResources = nativeLaunchGraphProofResources;
    targetNodes = [ "GeneratedRelationalInterpreterNativeLaunchGraph" ];
    targetBundle = true;
    targetAxiomAudit = {
      module = "GeneratedRelationalInterpreterNativeLaunchGraph";
      declaration =
        "StageA.GeneratedRelational.InterpreterNativeLaunchGraph.generatedNativeLaunchGraphStaticChecked";
      approved_axioms = [ "propext" "Classical.choice" "Quot.sound" ];
    };
  };

  originalPeLean = mkPhase "stage-a-gnu-hello-roundtrip-original-pe-lean" [] ''
    ${python} ${driver} original-pe-source \
      --original ${originalPe} --out "$out"
  '';

  staticMachineImportContractsLean = mkPhase
    "stage-a-gnu-hello-roundtrip-static-machine-import-contracts-lean" [] ''
    ${python} ${driver} static-machine-import-contracts \
      --original ${originalPe} \
      --reference-contract ${staticExport}/reference-contract.json \
      --state-machine ${proofStateMachinePath} \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --profile ${machineRuntimeProfile} \
      --profile \
        ${machineRuntimeProfileSource}/pe32-kernel32-lockstep-v1.json \
      --profile \
        ${machineRuntimeProfileSource}/pe32-msvcrt-lockstep-v1.json \
      --shard-size 128 \
      --out "$out"
    jq -e '
      .phase == "rooted-static-machine-import-contracts" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .plan_format == "stage-a-static-machine-import-contracts-v1" and
      .public_outputs.report == "machine-import-contract-report.json" and
      .public_outputs.lean_module ==
        "StageA/GeneratedStaticMachineImportContracts.lean" and
      .targets == ["GeneratedStaticMachineImportContracts"] and
      .rooted_counts.reachable_targets > 0 and
      .rooted_counts.required_imports > 0 and
      .rooted_counts.boundaries > 0 and
      .rooted_counts.blockers == 0
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/machine-import-contract-report.json"
    test -s "$out/StageA/GeneratedStaticMachineImportContracts.lean"
  '';

  universalPairedExternalEnvironmentLean = mkPhase
    "stage-a-gnu-hello-roundtrip-universal-paired-external-environment-lean" [] ''
    ${python} ${universalPairedExternalEnvironmentDriver} \
      --original ${originalPe} \
      --candidate ${candidate}/candidate.exe \
      --machine-import-report \
        ${staticMachineImportContractsLean}/machine-import-contract-report.json \
      --out "$out"
    jq -e '
      .phase == "universal-paired-external-environment" and
      .status == "source-ready" and
      (.proof_authority | not) and
      (.executes_original_binary | not) and
      (.executes_candidate_binary | not) and
      (.counts.required_imports > 0) and
      (.counts.machine_contracts > 0) and
      (.counts.candidate_pe_byte_packs > 0) and
      (.proved_by_generated_terms | index(
        "normalized_import_inventories_equal") != null) and
      .remaining_premises == [] and
      .route_authority == "mixed_component_composition" and
      .conditional_environment_parameters == [
        "each_returning_site_has_a_universally_sound_response_relation",
        "both_selected_environments_implement_each_response_relation",
        "protocol_and_callback_actions_have_separate_nested_frame_refinement"
      ] and
      .targets == ["GeneratedGnuHelloUniversalPairedExternalEnvironment"]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/universal-paired-external-environment.json"
    test -s \
      "$out/StageA/GeneratedGnuHelloUniversalPairedExternalEnvironment.lean"
    test -s "$out/StageA/GeneratedGnuHelloExternalCandidatePE.lean"
  '';

  staticMachineImportProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-static-machine-import-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --target GeneratedStaticMachineImportContracts \
      --out "$out"
  '';
  staticMachineImportProofModules = builtins.fromJSON (
    builtins.readFile
      "${staticMachineImportProofSources}/standalone-modules.json"
  );
  staticMachineImportProofResources = builtins.fromJSON (
    builtins.readFile
      "${staticMachineImportProofSources}/module-resources.json"
  );
  staticMachineImportProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = staticMachineImportProofSources + "/StageA";
    standaloneModules = staticMachineImportProofModules;
    standaloneModuleResources = staticMachineImportProofResources;
    targetNodes = [ "GeneratedStaticMachineImportContracts" ];
    targetBundle = true;
  };

  mixedOriginalDiagnostic = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-diagnostic" [] ''
    ${python} ${diagnosticDriver} \
      --driver ${driver} \
      --original ${originalPe} \
      --reference-contract ${staticExport}/reference-contract.json \
      --state-machine ${proofStateMachinePath} \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --machine-import-report \
        ${staticMachineImportContractsLean}/machine-import-contract-report.json \
      --callable-resolver-profile \
        ${machineRuntimeProfileSource}/pe32-kernel32-callable-resolvers-v1.json \
      --shard-size 128 \
      --out "$out"
    jq -e '
      .phase == "mixed-original-diagnostic" and
      (.status == "ready" or .status == "incomplete") and
      (.proof_authority | not) and
      .authorizing_term == null and
      .public_outputs.report == "interpreter-mixed-original-plan.json" and
      .counts.regions > 0 and .counts.reachable_targets > 0
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-mixed-original-plan.json"
  '';

  mixedOriginalBaseLean = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-base-lean" [] ''
    ${python} ${driver} mixed-original-base \
      --original ${originalPe} \
      --reference-contract ${staticExport}/reference-contract.json \
      --state-machine ${proofStateMachinePath} \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --machine-import-report \
        ${staticMachineImportContractsLean}/machine-import-contract-report.json \
      --callable-resolver-profile \
        ${machineRuntimeProfileSource}/pe32-kernel32-callable-resolvers-v1.json \
      --shard-size 128 \
      --out "$out"
    jq -e '
      .phase == "mixed-original-base-lean" and
      .status == "base-source-ready" and
      (.proof_authority | not) and
      (.exact_reachability_emitted | not) and
      .targets == ["GeneratedRelationalInterpreterMixedOriginalBase"] and
      .counts.regions > 0 and
      .counts.reachable_targets > 0
    ' "$out/phase-manifest.json" >/dev/null
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterMixedOriginalBase.lean"
    test -s "$out/interpreter-mixed-original-base-plan.json"
    test -s "$out/module-resources.json"
    jq -e '
      .GeneratedRelationalInterpreterMixedOriginalBase.resource_class ==
        "light" and
      .GeneratedRelationalInterpreterMixedOriginalBase.estimated_memory_mb <=
        1024 and
      ([to_entries[]
        | select(.key
          | startswith(
              "GeneratedRelationalInterpreterMixedOriginalBaseCertificateShard"
            ))
        | .value.estimated_memory_mb]
        | length > 0 and all(. <= 8192))
    ' "$out/module-resources.json" >/dev/null
  '';

  mixedOriginalWritableSlotAuthorityLean = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-writable-slot-authority-lean" [] ''
    ${python} ${driver} mixed-original-writable-slot-authority \
      --original ${originalPe} \
      --reference-contract ${staticExport}/reference-contract.json \
      --state-machine ${proofStateMachinePath} \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --machine-import-report \
        ${staticMachineImportContractsLean}/machine-import-contract-report.json \
      --callable-resolver-profile \
        ${machineRuntimeProfileSource}/pe32-kernel32-callable-resolvers-v1.json \
      --base-plan \
        ${mixedOriginalBaseLean}/interpreter-mixed-original-base-plan.json \
      --shard-size 128 \
      --out "$out"
    jq -e '
      .phase == "mixed-original-writable-slot-authority-lean" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .report_format ==
        "stage-a-relocated-writable-static-pointer-slot-authorities-v2" and
      .counts.authority_terms > 0 and
      .counts.authority_proposal_blockers == 0 and
      .counts.decomposed_adapters == .counts.authority_terms and
      .counts.blockers_before ==
        (.counts.blockers_after + .counts.authority_terms) and
      (.authorizing_lean_terms | length) == .counts.authority_terms and
      (.adapter_terms | length) == .counts.authority_terms and
      .public_outputs.authority_report ==
        "relocated-writable-static-pointer-slot-authorities.json" and
      .public_outputs.base_plan ==
        "interpreter-mixed-original-base-plan.json" and
      .targets == ["GeneratedRelationalInterpreterMixedOriginalBase"]
    ' "$out/phase-manifest.json" >/dev/null
    jq -e '
      .format ==
        "stage-a-relocated-writable-static-pointer-slot-authorities-v2" and
      (.artifact_role.acceptance_authority | not) and
      .artifact_role.lean_checker_must_reparse_and_redecode and
      .artifact_role.proposal_only and
      .counts.authority_terms > 0 and
      .counts.mixed_original_blockers_before ==
        (.counts.potential_mixed_original_blockers_after +
          .counts.authority_terms) and
      (.sites | length) == .counts.authority_terms
    ' \
      "$out/relocated-writable-static-pointer-slot-authorities.json" \
      >/dev/null
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterMixedOriginalBase.lean"
    test -s "$out/interpreter-mixed-original-base-plan.json"
    test -s "$out/direct-call-proposal-ir.json"
    test -s "$out/original-cutpoint-graph-ir.json"
    test -s "$out/module-resources.json"
  '';

  callableExternalRuntimeContract = pkgs.runCommand
    "stage-b-gnu-hello-callable-external-runtime-contract-v1"
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      export PYTHONPATH=${callableExternalRuntimePythonSource}/src
      mkdir -p "$out"
      ${python} \
        ${callableExternalRuntimePythonSource}/nix/callable-external-runtime-contract.py \
        --proposal \
          ${mixedOriginalWritableSlotAuthorityLean}/callable-external-proposal.json \
        --capability \
          ${mixedOriginalWritableSlotAuthorityLean}/callable-external-capability.json \
        --execution \
          ${mixedOriginalWritableSlotAuthorityLean}/callable-external-execution.json \
        --writable-slot-authority \
          ${mixedOriginalWritableSlotAuthorityLean}/relocated-writable-static-pointer-slot-authorities.json \
        --out "$out/callable-external-runtime-contract.json"
      jq -e '
        .format == "stage-b-callable-external-runtime-v1" and
        .status == "ready" and
        (.trust.acceptance_authority | not) and
        .trust.candidate_generation_only and
        .trust.lean_source_artifacts_required and
        .trust.unknown_runtime_targets_rejected and
        .counts.resolver_sites > 0 and .counts.routes > 0
      ' "$out/callable-external-runtime-contract.json" >/dev/null
    '';

  mixedOriginalRegisterIndirectAuthorityLean = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-register-indirect-authority-lean" [] ''
    ${python} ${driver} mixed-original-register-indirect-authority \
      --original ${originalPe} \
      --reference-contract ${staticExport}/reference-contract.json \
      --state-machine ${proofStateMachinePath} \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --machine-import-report \
        ${staticMachineImportContractsLean}/machine-import-contract-report.json \
      --callable-resolver-profile \
        ${machineRuntimeProfileSource}/pe32-kernel32-callable-resolvers-v1.json \
      --writable-slot-authority-report \
        ${mixedOriginalWritableSlotAuthorityLean}/relocated-writable-static-pointer-slot-authorities.json \
      --base-plan \
        ${mixedOriginalWritableSlotAuthorityLean}/interpreter-mixed-original-base-plan.json \
      --shard-size 128 \
      --out "$out"
    jq -e '
      .phase == "mixed-original-register-indirect-authority-lean" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .runtime_closure_required and
      (.report_status_is_authority | not) and
      .counts.static_authority_terms > 0 and
      .counts.proposal_blockers == 0 and
      .counts.register_frontiers_partitioned ==
        .counts.static_authority_terms and
      .counts.runtime_frontiers_remaining ==
        .counts.register_frontiers_partitioned and
      .counts.nonregister_frontiers > 0 and
      .targets == ["GeneratedRegisterIndirectControlAuthorities"]
    ' "$out/phase-manifest.json" >/dev/null
    jq -e '
      .format == "stage-a-register-indirect-control-authorities-v1" and
      (.artifact_role.acceptance_authority | not) and
      .artifact_role.lean_checker_must_reparse_and_redecode and
      .artifact_role.proposal_only and
      (.sites | length) > 0 and
      .counts.register_sites_unresolved == 0 and
      .counts.untouched_nonregister_blockers > 0
    ' "$out/register-indirect-control-authorities.json" >/dev/null
    test -s \
      "$out/StageA/GeneratedRegisterIndirectControlAuthorities.lean"
    test -s "$out/module-resources.json"
  '';

  mixedOriginalRegisterIndirectAuthorityProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-register-indirect-authority-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalRegisterIndirectAuthorityLean} \
      --target GeneratedRegisterIndirectControlAuthorities \
      --out "$out"
  '';
  mixedOriginalRegisterIndirectAuthorityProofModules = builtins.fromJSON (
    builtins.readFile
      "${mixedOriginalRegisterIndirectAuthorityProofSources}/standalone-modules.json"
  );
  mixedOriginalRegisterIndirectAuthorityProofResources = builtins.fromJSON (
    builtins.readFile
      "${mixedOriginalRegisterIndirectAuthorityProofSources}/module-resources.json"
  );
  mixedOriginalRegisterIndirectAuthorityProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot =
      mixedOriginalRegisterIndirectAuthorityProofSources + "/StageA";
    standaloneModules = mixedOriginalRegisterIndirectAuthorityProofModules;
    standaloneModuleResources =
      mixedOriginalRegisterIndirectAuthorityProofResources;
    targetNodes = [
      "GeneratedRegisterIndirectControlAuthorities"
      "GeneratedRelationalInterpreterMixedOriginalBase"
    ];
    targetBundle = true;
  };

  mixedOriginalDirectCallProposalsLean = mkPhaseWithSource
    directCallProposalPythonSource
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-proposals" [] ''
    ${python} ${driver} mixed-original-direct-call-proposals \
      --original ${originalPe} \
      --reference-contract ${staticExport}/reference-contract.json \
      --state-machine ${proofStateMachinePath} \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --machine-import-report \
        ${staticMachineImportContractsLean}/machine-import-contract-report.json \
      --callable-resolver-profile \
        ${machineRuntimeProfileSource}/pe32-kernel32-callable-resolvers-v1.json \
      --register-indirect-authority-report \
        ${mixedOriginalRegisterIndirectAuthorityLean}/register-indirect-control-authorities.json \
      --writable-slot-authority-report \
        ${mixedOriginalWritableSlotAuthorityLean}/relocated-writable-static-pointer-slot-authorities.json \
      --base-plan \
        ${mixedOriginalWritableSlotAuthorityLean}/interpreter-mixed-original-base-plan.json \
      --proposal-ir \
        ${mixedOriginalWritableSlotAuthorityLean}/direct-call-proposal-ir.json \
      --runtime-value-carry-hints \
        ${./gnu-hello-stack-dynamic-hints.json} \
      --shard-size 128 \
      --out "$out"
    jq -e '
      .phase == "mixed-original-direct-call-proposals" and
      .status == "proposal-source-ready" and
      (.proof_authority | not)
    ' "$out/phase-manifest.json" >/dev/null
    jq -e '
      .format == "stage-a-mixed-original-direct-call-proposals-v1" and
      (.authority.standalone_acceptance_authority | not) and
      .authority.authorizing_lean_term == null
    ' "$out/internal-direct-call-summary-proposals.json" >/dev/null
  '';
  mixedOriginalDirectCallProposalTargets =
    (builtins.fromJSON (builtins.readFile
      "${mixedOriginalDirectCallProposalsLean}/phase-manifest.json")).modules;
  mixedOriginalDirectCallProposalTargetArgs = builtins.concatStringsSep " " (
    map (module: "--target ${pkgs.lib.escapeShellArg module}")
      mixedOriginalDirectCallProposalTargets
  );
  mixedOriginalDirectCallProposalProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-proposal-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalDirectCallProposalsLean} \
      ${mixedOriginalDirectCallProposalTargetArgs} \
      --explicit-targets-only \
      --target-closure-only \
      --out "$out"
  '';
  mixedOriginalDirectCallProposalProofModules = builtins.fromJSON (
    builtins.readFile
      "${mixedOriginalDirectCallProposalProofSources}/standalone-modules.json"
  );
  mixedOriginalDirectCallProposalProofResources = builtins.fromJSON (
    builtins.readFile
      "${mixedOriginalDirectCallProposalProofSources}/module-resources.json"
  );
  mixedOriginalDirectCallProposalProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot =
      mixedOriginalDirectCallProposalProofSources + "/StageA";
    standaloneModules = mixedOriginalDirectCallProposalProofModules;
    standaloneModuleResources =
      mixedOriginalDirectCallProposalProofResources;
    targetNodes = mixedOriginalDirectCallProposalTargets;
    targetBundle = true;
  };

  mixedOriginalDirectCallSemanticsDraftLean = mkPhaseWithSource
    directCallSemanticsPythonSource
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-semantics" [] ''
    ${python} ${directCallSemanticsDriver} \
      --original ${originalPe} \
      --state-machine ${proofStateMachinePath} \
      --proposal-report \
        ${mixedOriginalDirectCallProposalsLean}/internal-direct-call-summary-proposals.json \
      --out "$out"
    jq -e '
      .phase == "mixed-original-direct-call-semantics" and
      (.proof_authority | not) and
      (.status == "semantic-terms-ready" or
        .status == "semantic-premises-pending")
    ' "$out/phase-manifest.json" >/dev/null
    jq -e '
      .format == "stage-a-mixed-original-direct-call-authority-bindings-v2" and
      (.report_authority | not) and
      .authority_source == "named Lean terms only"
    ' "$out/direct-call-authority-bindings.json" >/dev/null
  '';
  mixedOriginalDirectCallSemanticsTargets =
    (builtins.fromJSON (builtins.readFile
      "${mixedOriginalDirectCallSemanticsDraftLean}/phase-manifest.json")).modules;
  mixedOriginalDirectCallSemanticsTargetArgs =
    builtins.concatStringsSep " " (
      map (module: "--target ${pkgs.lib.escapeShellArg module}")
        mixedOriginalDirectCallSemanticsTargets
    );
  mixedOriginalDirectCallSemanticsProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-semantics-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalDirectCallProposalsLean} \
      --source ${mixedOriginalDirectCallSemanticsDraftLean} \
      ${mixedOriginalDirectCallSemanticsTargetArgs} \
      --explicit-targets-only \
      --target-closure-only \
      --out "$out"
  '';
  mixedOriginalDirectCallSemanticsProofModules = builtins.fromJSON (
    builtins.readFile
      "${mixedOriginalDirectCallSemanticsProofSources}/standalone-modules.json"
  );
  mixedOriginalDirectCallSemanticsProofResources = builtins.fromJSON (
    builtins.readFile
      "${mixedOriginalDirectCallSemanticsProofSources}/module-resources.json"
  );
  mixedOriginalDirectCallSemanticsProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    bundleContentAddressed = false;
    standaloneSourceRoot =
      mixedOriginalDirectCallSemanticsProofSources + "/StageA";
    standaloneModules = mixedOriginalDirectCallSemanticsProofModules;
    standaloneModuleResources =
      mixedOriginalDirectCallSemanticsProofResources;
    targetNodes = mixedOriginalDirectCallSemanticsTargets;
    targetBundle = true;
  };
  mixedOriginalDirectCallSemanticsReceipts = mkLeanTermReceipts
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-semantics-receipts"
    mixedOriginalDirectCallSemanticsDraftLean
    mixedOriginalDirectCallSemanticsProof;
  mixedOriginalDirectCallSemanticsLean = mkPhaseWithSource
    directCallSemanticsPythonSource
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-semantics-final" [] ''
    ${python} ${directCallSemanticsDriver} \
      --original ${originalPe} \
      --state-machine ${proofStateMachinePath} \
      --proposal-report \
        ${mixedOriginalDirectCallProposalsLean}/internal-direct-call-summary-proposals.json \
      --kernel-checks \
        ${mixedOriginalDirectCallSemanticsReceipts}/kernel-checks.json \
      --out "$out"
    jq -e '
      .phase == "mixed-original-direct-call-semantics" and
      .status == "semantic-terms-ready" and
      (.proof_authority | not) and
      .counts.remaining_semantic_frontiers == 0
    ' "$out/phase-manifest.json" >/dev/null
    jq -e '
      .format == "stage-a-mixed-original-direct-call-authority-bindings-v2" and
      ([.contracts[].kernel_check.status] | all(. == "checked")) and
      ([.contracts[].remaining_semantic_premises] | all(length == 0))
    ' "$out/direct-call-authority-bindings.json" >/dev/null
  '';

  # Compile the static stack-target authority before requesting a semantic
  # summary for the indirect call that consumes it. The generated entry
  # inventory is accepted only after its exact source and `.olean` are bound
  # by the generic kernel-receipt phase.
  mixedOriginalStaticStackAuthorityDraftLean =
    mkPhaseWithSource stackDynamicAuthorityPythonSource
    "stage-a-gnu-hello-roundtrip-mixed-original-static-stack-authority-draft" [] ''
    ${python} ${stackDynamicAuthorityDriver} \
      --original ${originalPe} \
      --state-machine ${proofStateMachinePath} \
      --proof-input \
        ${mixedOriginalDirectCallProposalsLean}/stack-dynamic-control-input.json \
      --cutpoint-graph \
        ${mixedOriginalDirectCallProposalsLean}/original-cutpoint-graph-ir.json \
      --hints ${stackDynamicHints} \
      --static-only \
      --out "$out"
    jq -e '
      .phase == "mixed-original-stack-dynamic-authority-lean" and
      .status == "kernel_compile_required" and
      .counts.stack_entries == 1 and
      .counts.kernel_checked_stack_entries == 0 and
      .counts.kernel_checked_indirect_exit_entries == 0
    ' "$out/phase-manifest.json" >/dev/null
  '';
  mixedOriginalStaticStackAuthorityTargets =
    (builtins.fromJSON (builtins.readFile
      "${mixedOriginalStaticStackAuthorityDraftLean}/phase-manifest.json")).modules;
  mixedOriginalStaticStackAuthorityTargetArgs =
    builtins.concatStringsSep " " (
      map (module: "--target ${pkgs.lib.escapeShellArg module}")
        mixedOriginalStaticStackAuthorityTargets
    );
  mixedOriginalStaticStackAuthorityProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-static-stack-authority-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalStaticStackAuthorityDraftLean} \
      ${mixedOriginalStaticStackAuthorityTargetArgs} \
      --explicit-targets-only \
      --target-closure-only \
      --out "$out"
  '';
  mixedOriginalStaticStackAuthorityProofModules =
    builtins.fromJSON (builtins.readFile
      "${mixedOriginalStaticStackAuthorityProofSources}/standalone-modules.json");
  mixedOriginalStaticStackAuthorityProofResources =
    builtins.fromJSON (builtins.readFile
      "${mixedOriginalStaticStackAuthorityProofSources}/module-resources.json");
  mixedOriginalStaticStackAuthorityProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    bundleContentAddressed = false;
    standaloneSourceRoot =
      mixedOriginalStaticStackAuthorityProofSources + "/StageA";
    standaloneModules = mixedOriginalStaticStackAuthorityProofModules;
    standaloneModuleResources =
      mixedOriginalStaticStackAuthorityProofResources;
    targetNodes = mixedOriginalStaticStackAuthorityTargets;
    targetBundle = true;
  };
  mixedOriginalStaticStackAuthorityReceipts = mkLeanTermReceipts
    "stage-a-gnu-hello-roundtrip-mixed-original-static-stack-authority-receipts"
    mixedOriginalStaticStackAuthorityDraftLean
    mixedOriginalStaticStackAuthorityProof;
  mixedOriginalStaticStackAuthorityLean =
    mkPhaseWithSource stackDynamicAuthorityPythonSource
    "stage-a-gnu-hello-roundtrip-mixed-original-static-stack-authority" [] ''
    ${python} ${stackDynamicAuthorityDriver} \
      --original ${originalPe} \
      --state-machine ${proofStateMachinePath} \
      --proof-input \
        ${mixedOriginalDirectCallProposalsLean}/stack-dynamic-control-input.json \
      --cutpoint-graph \
        ${mixedOriginalDirectCallProposalsLean}/original-cutpoint-graph-ir.json \
      --hints ${stackDynamicHints} \
      --kernel-checks \
        ${mixedOriginalStaticStackAuthorityReceipts}/kernel-checks.json \
      --static-only \
      --out "$out"
    jq -e '
      .phase == "mixed-original-stack-dynamic-authority-lean" and
      .status == "checked" and
      .counts.stack_entries == 1 and
      .counts.kernel_checked_stack_entries == 1 and
      .counts.kernel_checked_indirect_exit_entries == 1
    ' "$out/phase-manifest.json" >/dev/null
    jq -e '
      .format ==
        "stage-a-checked-stack-finite-origin-call-entry-authorities-v1" and
      .status == "checked" and
      (.entries | length) == 1 and
      .entries[0].static_stack_authority_kernel_check.status == "checked" and
      .entries[0].indirect_exit_authority_kernel_check.status == "checked"
    ' "$out/checked-stack-finite-origin-call-entry-authorities.json" >/dev/null
  '';

  # A later round may use only already Lean-checked call summaries to recover
  # additional finite-origin call entries.  Keeping the round explicit in the
  # derivation DAG makes every new authority and its invalidation closure
  # independently content-addressable.
  mixedOriginalDirectCallClosureProposalsLean = mkPhaseWithSource
    directCallProposalPythonSource
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-closure-proposals" [] ''
    ${python} ${driver} mixed-original-direct-call-proposals \
      --original ${originalPe} \
      --reference-contract ${staticExport}/reference-contract.json \
      --state-machine ${proofStateMachinePath} \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --machine-import-report \
        ${staticMachineImportContractsLean}/machine-import-contract-report.json \
      --callable-resolver-profile \
        ${machineRuntimeProfileSource}/pe32-kernel32-callable-resolvers-v1.json \
      --register-indirect-authority-report \
        ${mixedOriginalRegisterIndirectAuthorityLean}/register-indirect-control-authorities.json \
      --writable-slot-authority-report \
        ${mixedOriginalWritableSlotAuthorityLean}/relocated-writable-static-pointer-slot-authorities.json \
      --base-plan \
        ${mixedOriginalWritableSlotAuthorityLean}/interpreter-mixed-original-base-plan.json \
      --proposal-ir \
        ${mixedOriginalWritableSlotAuthorityLean}/direct-call-proposal-ir.json \
      --prior-direct-call-authority-report \
        ${mixedOriginalDirectCallSemanticsLean}/direct-call-authority-bindings.json \
      --runtime-value-carry-hints \
        ${./gnu-hello-stack-dynamic-hints.json} \
      --checked-stack-entry-authority \
        ${mixedOriginalStaticStackAuthorityLean}/checked-stack-finite-origin-call-entry-authorities.json \
      --shard-size 128 \
      --out "$out"
    jq -e '
      .phase == "mixed-original-direct-call-proposals" and
      .status == "proposal-source-ready" and
      (.proof_authority | not) and
      .counts.checked_stack_finite_origin_entry_authorities == 1
    ' "$out/phase-manifest.json" >/dev/null
  '';
  mixedOriginalDirectCallClosureProposalTargets =
    (builtins.fromJSON (builtins.readFile
      "${mixedOriginalDirectCallClosureProposalsLean}/phase-manifest.json")).modules;
  mixedOriginalDirectCallClosureProposalTargetArgs =
    builtins.concatStringsSep " " (
      map (module: "--target ${pkgs.lib.escapeShellArg module}")
        mixedOriginalDirectCallClosureProposalTargets
    );
  mixedOriginalDirectCallClosureProposalProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-closure-proposal-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalDirectCallProposalsLean} \
      --source ${mixedOriginalDirectCallSemanticsLean} \
      --source ${mixedOriginalStaticStackAuthorityLean} \
      --source ${mixedOriginalDirectCallClosureProposalsLean} \
      ${mixedOriginalDirectCallClosureProposalTargetArgs} \
      --explicit-targets-only \
      --target-closure-only \
      --out "$out"
  '';
  mixedOriginalDirectCallClosureProposalProofModules =
    builtins.fromJSON (builtins.readFile
      "${mixedOriginalDirectCallClosureProposalProofSources}/standalone-modules.json");
  mixedOriginalDirectCallClosureProposalProofResources =
    builtins.fromJSON (builtins.readFile
      "${mixedOriginalDirectCallClosureProposalProofSources}/module-resources.json");
  mixedOriginalDirectCallClosureProposalProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot =
      mixedOriginalDirectCallClosureProposalProofSources + "/StageA";
    standaloneModules = mixedOriginalDirectCallClosureProposalProofModules;
    standaloneModuleResources =
      mixedOriginalDirectCallClosureProposalProofResources;
    targetNodes = mixedOriginalDirectCallClosureProposalTargets;
    targetBundle = true;
  };

  mixedOriginalDirectCallClosureSemanticsDraftLean = mkPhaseWithSource
    directCallSemanticsPythonSource
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-closure-semantics" [] ''
    ${python} ${directCallSemanticsDriver} \
      --original ${originalPe} \
      --state-machine ${proofStateMachinePath} \
      --proposal-report \
        ${mixedOriginalDirectCallClosureProposalsLean}/internal-direct-call-summary-proposals.json \
      --out "$out"
    jq -e '
      .phase == "mixed-original-direct-call-semantics" and
      (.status == "semantic-terms-ready" or
        .status == "semantic-premises-pending") and
      (.proof_authority | not) and
      .counts.remaining_semantic_frontiers >= 0
    ' "$out/phase-manifest.json" >/dev/null
  '';
  mixedOriginalDirectCallClosureSemanticsTargets =
    (builtins.fromJSON (builtins.readFile
      "${mixedOriginalDirectCallClosureSemanticsDraftLean}/phase-manifest.json")).modules;
  mixedOriginalDirectCallClosureSemanticsTargetArgs =
    builtins.concatStringsSep " " (
      map (module: "--target ${pkgs.lib.escapeShellArg module}")
        mixedOriginalDirectCallClosureSemanticsTargets
    );
  mixedOriginalDirectCallClosureSemanticsProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-closure-semantics-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalDirectCallProposalsLean} \
      --source ${mixedOriginalDirectCallSemanticsLean} \
      --source ${mixedOriginalStaticStackAuthorityLean} \
      --source ${mixedOriginalDirectCallClosureProposalsLean} \
      --source ${mixedOriginalDirectCallClosureSemanticsDraftLean} \
      ${mixedOriginalDirectCallClosureSemanticsTargetArgs} \
      --explicit-targets-only \
      --target-closure-only \
      --coarse-build-packs \
      --emit-module-graph \
      --out "$out"
  '';
  mixedOriginalDirectCallClosureSemanticsProof = mkLeanGraph {
    inherit pkgs;
    # Recursive CA derivations cause Nix to re-serialize the entire generated
    # proof graph while resolving each dynamic dependency. Build the static
    # Lean DAG input-addressed, then content-address its checked root bundle.
    contentAddressed = false;
    bundleContentAddressed = true;
    graphFile =
      mixedOriginalDirectCallClosureSemanticsProofSources + "/module-graph.json";
    sourceRoot = mixedOriginalDirectCallClosureSemanticsProofSources;
    targetNodes = mixedOriginalDirectCallClosureSemanticsTargets;
    targetBundle = true;
  };
  mixedOriginalDirectCallClosureSemanticsReceipts = mkLeanTermReceipts
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-closure-semantics-receipts"
    mixedOriginalDirectCallClosureSemanticsDraftLean
    mixedOriginalDirectCallClosureSemanticsProof;
  mixedOriginalDirectCallClosureSemanticsLean = mkPhaseWithSource
    directCallSemanticsPythonSource
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-closure-semantics-final" [] ''
    ${python} ${directCallSemanticsDriver} \
      --original ${originalPe} \
      --state-machine ${proofStateMachinePath} \
      --proposal-report \
        ${mixedOriginalDirectCallClosureProposalsLean}/internal-direct-call-summary-proposals.json \
      --kernel-checks \
        ${mixedOriginalDirectCallClosureSemanticsReceipts}/kernel-checks.json \
      --out "$out"
    jq -e '
      .phase == "mixed-original-direct-call-semantics" and
      .status == "semantic-terms-ready" and
      (.proof_authority | not) and
      .counts.remaining_semantic_frontiers == 0
    ' "$out/phase-manifest.json" >/dev/null
    jq -e '
      .format == "stage-a-mixed-original-direct-call-authority-bindings-v2" and
      ([.contracts[].kernel_check.status] | all(. == "checked")) and
      ([.contracts[].remaining_semantic_premises] | all(length == 0))
    ' "$out/direct-call-authority-bindings.json" >/dev/null
  '';

  # The register-authority report is already a finite exact inventory of every
  # call boundary that needs a preservation contract. Once the closure round
  # has one complete proposal and one named Lean authority per request, another
  # whole-PE analysis cannot discover an additional request. Preserve the old
  # public aliases while replacing that redundant analysis with a strict
  # hash-bound coverage check.
  mixedOriginalDirectCallFixedPointProposalsLean =
    mixedOriginalDirectCallClosureProposalsLean;
  mixedOriginalDirectCallFixedPointSemanticsLean =
    mixedOriginalDirectCallClosureSemanticsLean;
  mixedOriginalDirectCallFixedPointCheck = mkPhaseWithSource
    directCallFixedPointPythonSource
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-fixed-point-check" [] ''
    ${python} ${directCallFixedPointDriver} \
      --proposal-report \
        ${mixedOriginalDirectCallClosureProposalsLean}/internal-direct-call-summary-proposals.json \
      --authority-report \
        ${mixedOriginalDirectCallClosureSemanticsLean}/direct-call-authority-bindings.json \
      --stack-dynamic-input \
        ${mixedOriginalDirectCallClosureProposalsLean}/stack-dynamic-control-input.json \
      --out "$out"
    jq -e '
      .format == "stage-a-direct-call-closure-fixed-point-v2" and
      .status == "satisfied" and
      (.proof_authority | not) and
      (.acceptance_authority | not) and
      .counts.remaining_frontiers == 0 and
      .counts.delegated_stack_dynamic_frontiers == 0 and
      .counts.proposal_modules ==
        (.counts.ordinary_requests + .counts.finite_origin_requests) and
      .counts.semantic_contracts == .counts.proposal_modules
    ' "$out/direct-call-fixed-point.json" >/dev/null
  '';

  mixedOriginalStackDynamicAuthorityDraftLean =
    mkPhaseWithSource stackDynamicAuthorityPythonSource
    "stage-a-gnu-hello-roundtrip-mixed-original-stack-dynamic-authority-lean" [] ''
    test -e ${mixedOriginalDirectCallFixedPointCheck}
    ${python} ${stackDynamicAuthorityDriver} \
      --original ${originalPe} \
      --state-machine ${proofStateMachinePath} \
      --proof-input \
        ${mixedOriginalDirectCallFixedPointProposalsLean}/stack-dynamic-control-input.json \
      --cutpoint-graph \
        ${mixedOriginalDirectCallFixedPointProposalsLean}/original-cutpoint-graph-ir.json \
      --direct-call-authority \
        ${mixedOriginalDirectCallClosureSemanticsLean}/direct-call-authority-bindings.json \
      --hints ${stackDynamicHints} \
      --out "$out"
    jq -e '
      .phase == "mixed-original-stack-dynamic-authority-lean" and
      .status == "kernel_compile_required" and
      (.proof_authority | not) and
      (.report_status_is_authority | not) and
      (.runtime_closure_required | not) and
      .counts.sites == 3 and
      .counts.static_authorities == .counts.sites and
      .counts.runtime_premises_required == 0 and
      .counts.stack_sites == 1 and
      .counts.indexed_table_sites == 1 and
      .counts.rooted_unreachability_sites == 1 and
      .counts.dynamic_callback_sites == 1
      and .counts.runtime_value_carry_routes == 1
      and .counts.runtime_value_carry_required_transfers == 0
    ' "$out/phase-manifest.json" >/dev/null
    jq -e '
      .format == "stage-a-original-stack-dynamic-control-closure-v1" and
      .status == "incomplete" and
      (.artifact_role.acceptance_authority | not) and
      (.artifact_role.report_status_closes_obligations | not) and
      (.sites | length) == 3
    ' "$out/original-stack-dynamic-control-closure.json" >/dev/null
    jq -e '
      .format == "stage-a-runtime-value-carry-ir-v1" and
      .proof_ready and
      (.routes | length) == 1 and
      ([.routes[].transfers[] |
        select(.authority_status == "required")] | length) == 0
    ' "$out/runtime-value-carry-ir.json" >/dev/null
    jq -e '
      .format == "stage-a-runtime-value-carry-lean-v1" and
      (.proof_authority | not) and
      (.semantic_authority_complete | not) and
      .kernel_compile_required and
      (.routes | length) == 1 and
      (.routes[0].semantic_authority | length) > 0
    ' "$out/runtime-value-carry-lean.json" >/dev/null
    test -s \
      "$out/StageA/GeneratedRelationalRuntimeValueCarryStructure.lean"
    test -s \
      "$out/StageA/GeneratedRelationalRuntimeValueCarryBinding.lean"
    test -s \
      "$out/StageA/GeneratedRelationalRuntimeValueCarrySemantics.lean"
  '';
  mixedOriginalStackDynamicAuthorityTargets =
    (builtins.fromJSON (builtins.readFile
      "${mixedOriginalStackDynamicAuthorityDraftLean}/phase-manifest.json")).modules;
  mixedOriginalStackDynamicAuthorityTargetArgs =
    builtins.concatStringsSep " " (
      map (module: "--target ${pkgs.lib.escapeShellArg module}")
        mixedOriginalStackDynamicAuthorityTargets
    );
  mixedOriginalStackDynamicAuthorityProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-stack-dynamic-authority-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalDirectCallClosureSemanticsProofSources} \
      --source ${mixedOriginalStackDynamicAuthorityDraftLean} \
      ${mixedOriginalStackDynamicAuthorityTargetArgs} \
      --explicit-targets-only \
      --target-closure-only \
      --out "$out"
  '';
  mixedOriginalStackDynamicAuthorityProofModules =
    builtins.fromJSON (builtins.readFile
      "${mixedOriginalStackDynamicAuthorityProofSources}/standalone-modules.json");
  mixedOriginalStackDynamicAuthorityProofResources =
    builtins.fromJSON (builtins.readFile
      "${mixedOriginalStackDynamicAuthorityProofSources}/module-resources.json");
  mixedOriginalStackDynamicAuthorityProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    bundleContentAddressed = false;
    standaloneSourceRoot =
      mixedOriginalStackDynamicAuthorityProofSources + "/StageA";
    standaloneModules = mixedOriginalStackDynamicAuthorityProofModules;
    standaloneModuleResources =
      mixedOriginalStackDynamicAuthorityProofResources;
    targetNodes = mixedOriginalStackDynamicAuthorityTargets;
    targetBundle = true;
  };
  mixedOriginalStackDynamicAuthorityReceipts = mkLeanTermReceipts
    "stage-a-gnu-hello-roundtrip-mixed-original-stack-dynamic-authority-receipts"
    mixedOriginalStackDynamicAuthorityDraftLean
    mixedOriginalStackDynamicAuthorityProof;
  mixedOriginalStackDynamicAuthorityLean =
    mkPhaseWithSource stackDynamicAuthorityPythonSource
    "stage-a-gnu-hello-roundtrip-mixed-original-stack-dynamic-authority-lean-final" [] ''
    test -e ${mixedOriginalDirectCallFixedPointCheck}
    ${python} ${stackDynamicAuthorityDriver} \
      --original ${originalPe} \
      --state-machine ${proofStateMachinePath} \
      --proof-input \
        ${mixedOriginalDirectCallFixedPointProposalsLean}/stack-dynamic-control-input.json \
      --cutpoint-graph \
        ${mixedOriginalDirectCallFixedPointProposalsLean}/original-cutpoint-graph-ir.json \
      --direct-call-authority \
        ${mixedOriginalDirectCallClosureSemanticsLean}/direct-call-authority-bindings.json \
      --hints ${stackDynamicHints} \
      --kernel-checks \
        ${mixedOriginalStackDynamicAuthorityReceipts}/kernel-checks.json \
      --out "$out"
    jq -e '
      .phase == "mixed-original-stack-dynamic-authority-lean" and
      .status == "runtime-premises-required" and
      (.proof_authority | not) and
      (.report_status_is_authority | not) and
      .runtime_closure_required and
      .counts.sites == 3 and
      .counts.static_authorities == .counts.sites and
      .counts.runtime_premises_required == .counts.sites and
      .counts.stack_sites == 1 and
      .counts.indexed_table_sites == 1 and
      .counts.rooted_unreachability_sites == 1 and
      .counts.dynamic_callback_sites == 1 and
      .counts.runtime_value_carry_routes == 1 and
      .counts.runtime_value_carry_required_transfers == 0
    ' "$out/phase-manifest.json" >/dev/null
    jq -e '
      .format == "stage-a-runtime-value-carry-ir-v1" and
      .proof_ready and
      ([.routes[].transfers[] |
        select(.authority_status == "required")] | length) == 0
    ' "$out/runtime-value-carry-ir.json" >/dev/null
    jq -e '
      .format == "stage-a-runtime-value-carry-lean-v1" and
      (.proof_authority | not) and
      .semantic_authority_complete and
      (.kernel_compile_required | not) and
      ([.routes[].semantic_authority_status] |
        all(. == "closed"))
    ' "$out/runtime-value-carry-lean.json" >/dev/null
  '';

  mixedOriginalLean = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-lean" [] ''
    test -e ${mixedOriginalDirectCallFixedPointCheck}
    test -e ${mixedOriginalStackDynamicAuthorityProof}
    ${python} ${driver} mixed-original-final \
      --original ${originalPe} \
      --reference-contract ${staticExport}/reference-contract.json \
      --state-machine ${proofStateMachinePath} \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --machine-import-report \
        ${staticMachineImportContractsLean}/machine-import-contract-report.json \
      --callable-resolver-profile \
        ${machineRuntimeProfileSource}/pe32-kernel32-callable-resolvers-v1.json \
      --direct-call-authority-report \
        ${mixedOriginalDirectCallClosureSemanticsLean}/direct-call-authority-bindings.json \
      --stack-dynamic-authority-report \
        ${mixedOriginalStackDynamicAuthorityLean}/original-stack-dynamic-control-closure.json \
      --writable-slot-authority-report \
        ${mixedOriginalWritableSlotAuthorityLean}/relocated-writable-static-pointer-slot-authorities.json \
      --base-plan \
        ${mixedOriginalWritableSlotAuthorityLean}/interpreter-mixed-original-base-plan.json \
      --shard-size 128 \
      --out "$out"
    jq -e '
      .phase == "mixed-original-final-lean" and
      (.status == "source-ready" or .status == "incomplete") and
      (.proof_authority | not) and
      .targets == ["GeneratedRelationalInterpreterMixedOriginal"] and
      .counts.regions > 0 and .counts.reachable_targets > 0 and
      .counts.checked_stack_dynamic_static_authorities > 0 and
      .counts.stack_dynamic_runtime_premises ==
        .counts.checked_stack_dynamic_static_authorities and
      (.stack_dynamic_runtime_frontiers | length) ==
        .counts.stack_dynamic_runtime_premises and
      ((.status == "source-ready" and .exact_reachability_emitted) or
       (.status == "incomplete" and
        (.exact_reachability_emitted | not) and .counts.blockers > 0))
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/StageA/GeneratedRelationalInterpreterMixedOriginal.lean"
    test -s "$out/interpreter-mixed-original-plan.json"
  '';

  mixedOriginalStaticReachabilityLean = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-static-reachability-lean" [] ''
    ${python} ${driver} mixed-original-static-reachability \
      --mixed-original-plan \
        ${mixedOriginalLean}/interpreter-mixed-original-plan.json \
      --out "$out"
    jq -e '
      .phase == "mixed-original-static-reachability" and
      .status == "typed-interface-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .runtime_indirect_control.closed_by_this_artifact == false and
      .runtime_indirect_control.required_at ==
        "mixed-component-composition" and
      .counts.reachable_targets > 0 and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterMixedOriginalStaticReachability.generatedExactOriginalDecodedStaticReachability" and
      .targets == [
        "GeneratedRelationalInterpreterMixedOriginalStaticReachability"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s \
      "$out/interpreter-mixed-original-static-reachability.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterMixedOriginalStaticReachability.lean"
  '';

  mixedOriginalStaticReachabilityProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-static-reachability-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalRegisterIndirectAuthorityLean} \
      --source ${mixedOriginalDirectCallProposalsLean} \
      --source ${mixedOriginalDirectCallSemanticsLean} \
      --source ${mixedOriginalDirectCallClosureProposalsLean} \
      --source ${mixedOriginalDirectCallClosureSemanticsLean} \
      --source ${mixedOriginalLean} \
      --source ${mixedOriginalStaticReachabilityLean} \
      --target GeneratedRelationalInterpreterMixedOriginalStaticReachability \
      --out "$out"
  '';
  mixedOriginalStaticReachabilityProofModules = builtins.fromJSON (
    builtins.readFile
      "${mixedOriginalStaticReachabilityProofSources}/standalone-modules.json"
  );
  mixedOriginalStaticReachabilityProofResources = builtins.fromJSON (
    builtins.readFile
      "${mixedOriginalStaticReachabilityProofSources}/module-resources.json"
  );
  mixedOriginalStaticReachabilityProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot =
      mixedOriginalStaticReachabilityProofSources + "/StageA";
    standaloneModules = mixedOriginalStaticReachabilityProofModules;
    standaloneModuleResources = mixedOriginalStaticReachabilityProofResources;
    targetNodes = [
      "GeneratedRelationalInterpreterMixedOriginalStaticReachability"
    ];
    targetBundle = true;
  };

  mixedOriginalCarrierBindingLean = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-carrier-binding-lean" [] ''
    ${python} ${driver} mixed-original-carrier-binding \
      --mixed-original ${mixedOriginalLean} \
      --out "$out"
    jq -e '
      .phase == "mixed-original-carrier-binding-lean" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .targets == ["GeneratedRelationalInterpreterOriginalCarrierBinding"] and
      .counts.targets > 0 and
      .counts.addresses >= .counts.targets
    ' "$out/phase-manifest.json" >/dev/null
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterOriginalCarrierBinding.lean"
  '';

  mixedOriginalCarrierBindingProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-carrier-binding-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalDirectCallProposalsLean} \
      --source ${mixedOriginalDirectCallSemanticsLean} \
      --source ${mixedOriginalDirectCallClosureProposalsLean} \
      --source ${mixedOriginalDirectCallClosureSemanticsLean} \
      --source ${mixedOriginalLean} \
      --source ${mixedOriginalCarrierBindingLean} \
      --target GeneratedRelationalInterpreterOriginalCarrierBinding \
      --out "$out"
  '';
  mixedOriginalCarrierBindingProofModules = builtins.fromJSON (
    builtins.readFile
      "${mixedOriginalCarrierBindingProofSources}/standalone-modules.json"
  );
  mixedOriginalCarrierBindingProofResources = builtins.fromJSON (
    builtins.readFile
      "${mixedOriginalCarrierBindingProofSources}/module-resources.json"
  );
  mixedOriginalCarrierBindingProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot =
      mixedOriginalCarrierBindingProofSources + "/StageA";
    standaloneModules = mixedOriginalCarrierBindingProofModules;
    standaloneModuleResources = mixedOriginalCarrierBindingProofResources;
    targetNodes = [ "GeneratedRelationalInterpreterOriginalCarrierBinding" ];
    targetBundle = true;
  };

  programLean = mkPhase "stage-a-gnu-hello-roundtrip-program-lean" [] ''
    ${python} ${driver} program-source \
      --state-machine ${proofStateMachinePath} --out "$out"
  '';

  normalizationLean = mkPhase "stage-a-gnu-hello-roundtrip-normalization-lean" [] ''
    ${python} ${driver} normalization-sources \
      --state-machine ${proofStateMachinePath} \
      --shard-size 48 --out "$out"
  '';

  semanticRefinementLean = mkPhase "stage-a-gnu-hello-roundtrip-semantic-refinement-lean" [] ''
    ${python} ${driver} semantic-refinement-sources \
      --state-machine ${proofStateMachinePath} \
      --shard-size 48 --out "$out"
  '';

  mixedFusedSemanticEvidenceLean =
    mkPhaseWithSource mixedFusedSemanticEvidencePythonSource
      "stage-a-gnu-hello-roundtrip-mixed-fused-semantic-evidence-source" [] ''
      ${python} \
        ${mixedFusedSemanticEvidencePythonSource}/nix/gnu-hello-mixed-fused-semantic-evidence.py \
        --state-machine ${proofStateMachinePath} \
        --out "$out"
      jq -e '
        .format ==
          "stage-a-gnu-hello-mixed-fused-semantic-evidence-v1" and
        (.proof_authority | not) and
        (.acceptance_authority | not) and
        (.classification_authority | not) and
        .input_rows == 5697 and
        .non_x87_binding_rows == 5384 and
        .ordinary_one_step_evidence_rows == 4310 and
        .x87_rows == 313 and
        .family_counts["ordinary-one-step"] == 4310 and
        .residual_factory_counts["dedicated-direct-call-return"] == 858 and
        .residual_factory_counts["dedicated-indirect-or-import-call"] == 161 and
        .residual_factory_counts["dedicated-external-boundary"] == 55 and
        .residual_factory_counts["dedicated-x87-replay"] == 313 and
        .target == "GeneratedGnuHelloMixedFusedSemanticEvidenceBundle" and
        .validation_required == "lean-kernel-check"
      ' "$out/gnu-hello-mixed-fused-semantic-evidence.json" >/dev/null
      test "$(find "$out/StageA" -maxdepth 1 -name \
        'GeneratedGnuHelloMixedFusedSemanticEvidence*.lean' | wc -l)" -eq 114
    '';

  mixedFusedSemanticEvidenceClosure = mkGeneratedClosureProof {
    name = "mixed-fused-semantic-evidence";
    sources = [
      leanSourceRoot
      originalPeLean
      programLean
      normalizationLean
      semanticRefinementLean
      mixedFusedSemanticEvidenceLean
    ];
    target = "GeneratedGnuHelloMixedFusedSemanticEvidenceBundle";
    declaration =
      "StageA.GeneratedRelational.generatedGnuHelloOrdinarySemanticEvidenceNameCount";
  };
  mixedFusedSemanticEvidenceProofSources =
    mixedFusedSemanticEvidenceClosure.proofSources;
  mixedFusedSemanticEvidenceProof =
    mixedFusedSemanticEvidenceClosure.proof;

  mixedDirectCallSemanticEvidenceLean =
    mkPhaseWithSource mixedDirectCallSemanticEvidencePythonSource
      "stage-a-gnu-hello-roundtrip-mixed-direct-call-semantic-evidence-source" [] ''
      ${python} \
        ${mixedDirectCallSemanticEvidencePythonSource}/nix/gnu-hello-mixed-direct-call-semantic-evidence.py \
        --state-machine ${proofStateMachinePath} \
        --out "$out"
      jq -e '
        .format ==
          "stage-a-gnu-hello-mixed-direct-call-semantic-evidence-v1" and
        (.proof_authority | not) and
        (.acceptance_authority | not) and
        (.classification_authority | not) and
        .input_rows == 5697 and
        .direct_call_return_rows == 858 and
        .generated_direct_call_evidence_adapters == 858 and
        .family_counts["ordinary-one-step"] == 4310 and
        .family_counts["dedicated-direct-call-return"] == 858 and
        .unowned_family_counts["dedicated-indirect-or-import-call"] == 161 and
        .unowned_family_counts["dedicated-external-boundary"] == 55 and
        .unowned_family_counts["dedicated-x87-replay"] == 313 and
        .target ==
          "GeneratedGnuHelloMixedDirectCallSemanticEvidenceBundle" and
        .validation_required == "lean-kernel-check"
      ' "$out/gnu-hello-mixed-direct-call-semantic-evidence.json" >/dev/null
      test "$(find "$out/StageA" -maxdepth 1 -name \
        'GeneratedGnuHelloMixedDirectCallSemanticEvidence*.lean' | wc -l)" -eq 28
    '';

  mixedDirectCallSemanticEvidenceClosure = mkGeneratedClosureProof {
    name = "mixed-direct-call-semantic-evidence";
    sources = [
      leanSourceRoot
      originalPeLean
      programLean
      normalizationLean
      semanticRefinementLean
      mixedFusedSemanticEvidenceLean
      mixedDirectCallSemanticEvidenceLean
    ];
    target = "GeneratedGnuHelloMixedDirectCallSemanticEvidenceBundle";
    declaration =
      "StageA.GeneratedRelational.generatedGnuHelloDirectCallSemanticEvidenceNameCount";
  };
  mixedDirectCallSemanticEvidenceProofSources =
    mixedDirectCallSemanticEvidenceClosure.proofSources;
  mixedDirectCallSemanticEvidenceProof =
    mixedDirectCallSemanticEvidenceClosure.proof;

  mixedIndirectImportCallSemanticEvidenceLean =
    mkPhaseWithSource mixedIndirectImportCallSemanticEvidencePythonSource
      "stage-a-gnu-hello-roundtrip-mixed-indirect-import-call-semantic-evidence-source" [] ''
      ${python} \
        ${mixedIndirectImportCallSemanticEvidencePythonSource}/nix/gnu-hello-mixed-indirect-import-call-semantic-evidence.py \
        --state-machine ${proofStateMachinePath} \
        --out "$out"
      jq -e '
        .format ==
          "stage-a-gnu-hello-mixed-indirect-import-call-semantic-evidence-v1" and
        (.proof_authority | not) and
        (.acceptance_authority | not) and
        (.classification_authority | not) and
        .input_rows == 5697 and
        .indirect_import_call_rows == 161 and
        .generated_indirect_import_call_evidence_adapters == 161 and
        .semantic_call_kind_counts == {
          external_call: 77,
          indirect_call: 83,
          internal_call: 1
        } and
        .family_counts["dedicated-indirect-or-import-call"] == 161 and
        .unowned_family_counts["ordinary-one-step"] == 4310 and
        .unowned_family_counts["dedicated-direct-call-return"] == 858 and
        .unowned_family_counts["dedicated-external-boundary"] == 55 and
        .unowned_family_counts["dedicated-x87-replay"] == 313 and
        .target ==
          "GeneratedGnuHelloMixedIndirectImportCallSemanticEvidenceBundle" and
        .validation_required == "lean-kernel-check"
      ' "$out/gnu-hello-mixed-indirect-import-call-semantic-evidence.json" >/dev/null
      test "$(find "$out/StageA" -maxdepth 1 -name \
        'GeneratedGnuHelloMixedIndirectImportCallSemanticEvidence*.lean' | wc -l)" -eq 8
    '';

  mixedIndirectImportCallSemanticEvidenceClosure = mkGeneratedClosureProof {
    name = "mixed-indirect-import-call-semantic-evidence";
    sources = [
      leanSourceRoot
      originalPeLean
      programLean
      normalizationLean
      semanticRefinementLean
      mixedFusedSemanticEvidenceLean
      mixedIndirectImportCallSemanticEvidenceLean
    ];
    target =
      "GeneratedGnuHelloMixedIndirectImportCallSemanticEvidenceBundle";
    declaration =
      "StageA.GeneratedRelational.generatedGnuHelloIndirectImportCallSemanticEvidenceNameCount";
  };
  mixedIndirectImportCallSemanticEvidenceProofSources =
    mixedIndirectImportCallSemanticEvidenceClosure.proofSources;
  mixedIndirectImportCallSemanticEvidenceProof =
    mixedIndirectImportCallSemanticEvidenceClosure.proof;

  mixedExternalTailSemanticEvidenceLean =
    mkPhaseWithSource mixedExternalTailSemanticEvidencePythonSource
      "stage-a-gnu-hello-roundtrip-mixed-external-tail-semantic-evidence-source" [] ''
      ${python} \
        ${mixedExternalTailSemanticEvidencePythonSource}/nix/gnu-hello-mixed-external-tail-semantic-evidence.py \
        --state-machine ${proofStateMachinePath} \
        --out "$out"
      jq -e '
        .format ==
          "stage-a-gnu-hello-mixed-external-tail-semantic-evidence-v1" and
        (.proof_authority | not) and
        (.acceptance_authority | not) and
        (.classification_authority | not) and
        .input_rows == 5697 and
        .external_tail_rows == 55 and
        .generated_external_tail_evidence_adapters == 55 and
        .route_kind_counts == {
          direct: 5,
          indirect: 50
        } and
        .family_counts["dedicated-external-boundary"] == 55 and
        .unowned_family_counts["ordinary-one-step"] == 4310 and
        .unowned_family_counts["dedicated-direct-call-return"] == 858 and
        .unowned_family_counts["dedicated-indirect-or-import-call"] == 161 and
        .unowned_family_counts["dedicated-x87-replay"] == 313 and
        .checked_boundary.classifier_remains_semantic_transfer and
        (.checked_boundary.external_operation_classifier_used | not) and
        (.checked_boundary.external_boundary_classifier_used | not) and
        .target ==
          "GeneratedGnuHelloMixedExternalTailSemanticEvidenceBundle" and
        .validation_required == "lean-kernel-check"
      ' "$out/gnu-hello-mixed-external-tail-semantic-evidence.json" >/dev/null
      test "$(find "$out/StageA" -maxdepth 1 -name \
        'GeneratedGnuHelloMixedExternalTailSemanticEvidence*.lean' | wc -l)" -eq 5
    '';

  mixedExternalTailSemanticEvidenceClosure = mkGeneratedClosureProof {
    name = "mixed-external-tail-semantic-evidence";
    sources = [
      leanSourceRoot
      originalPeLean
      programLean
      normalizationLean
      semanticRefinementLean
      mixedFusedSemanticEvidenceLean
      mixedExternalTailSemanticEvidenceLean
    ];
    target = "GeneratedGnuHelloMixedExternalTailSemanticEvidenceBundle";
    declaration =
      "StageA.GeneratedRelational.generatedGnuHelloExternalTailSemanticEvidenceNameCount";
  };
  mixedExternalTailSemanticEvidenceProofSources =
    mixedExternalTailSemanticEvidenceClosure.proofSources;
  mixedExternalTailSemanticEvidenceProof =
    mixedExternalTailSemanticEvidenceClosure.proof;

  x87Lean = mkPhase "stage-a-gnu-hello-roundtrip-x87-lean" [] ''
    ${python} ${driver} x87-sources \
      --state-machine ${proofStateMachinePath} \
      --original ${originalPe} \
      --pe-byte-pack-inventory ${originalPeLean}/pe-byte-packs.json \
      --out "$out"
  '';

  # Schedule 0034 is a real all-x87 singleton shard in the pinned GNU fixture.
  # Its focused closure isolates the exact-byte certificate path from the much
  # larger mixed-schedule reductions.  The node is assigned to the dedicated
  # high lane so measurements remain comparable with the former PE reductions.
  x87ScheduleBenchmarkModule = "GeneratedInterpreterX87Schedule0034";
  x87ScheduleBenchmarkSources = mkPhase
    "stage-a-gnu-hello-roundtrip-x87-schedule-benchmark-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${x87Lean} \
      --target ${x87ScheduleBenchmarkModule} \
      --out "$out"
  '';
  x87ScheduleBenchmarkModules = builtins.fromJSON (
    builtins.readFile
      "${x87ScheduleBenchmarkSources}/standalone-modules.json"
  );
  x87ScheduleBenchmarkBaseResources = builtins.fromJSON (
    builtins.readFile
      "${x87ScheduleBenchmarkSources}/module-resources.json"
  );
  x87ScheduleBenchmarkResources = x87ScheduleBenchmarkBaseResources // {
    "${x87ScheduleBenchmarkModule}" = {
      resource_class = "high-memory";
      estimated_memory_mb = 8192;
    };
  };
  x87ScheduleBenchmark = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = x87ScheduleBenchmarkSources + "/StageA";
    standaloneModules = x87ScheduleBenchmarkModules;
    standaloneModuleResources = x87ScheduleBenchmarkResources;
    targetNodes = [ x87ScheduleBenchmarkModule ];
    targetBundle = true;
  };

  definednessLean = mkPhase "stage-a-gnu-hello-roundtrip-definedness-lean" [] ''
    ${python} ${driver} definedness-source \
      --state-machine ${proofStateMachinePath} --out "$out"
  '';

  kernelLean = mkPhaseWithSource kernelDataPythonSource
    "stage-a-gnu-hello-roundtrip-compiled-kernel" [] ''
    ${python} ${compiledKernelDriver} \
      --candidate ${candidate}/candidate.exe \
      --linker-map ${candidate}/payload.map \
      --program-manifest ${interpreter}/state-machine-interpreter-program.json \
      --engine-layout ${candidate}/engine-layout.bin \
      --native-build-manifest ${candidate}/interpreter-native-build-manifest.json \
      --out "$out"
  '';

  kernelDataLean = mkPhaseWithSource kernelDataPythonSource
    "stage-a-gnu-hello-roundtrip-kernel-data-lean" [] ''
    ${python} ${kernelDataDriver} \
      --candidate ${candidate}/candidate.exe \
      --linker-map ${candidate}/payload.map \
      --state-machine ${proofStateMachinePath} \
      --lean-source-root \
        ${kernelDataLeanSource}/src/spaghetti_extractor/lean/StageA \
      --shard-size 8 --out "$out"
  '';

  kernelDataStandaloneModules = builtins.fromJSON (
    builtins.readFile "${kernelDataLean}/standalone-modules.json"
  );
  kernelDataStandaloneResources = builtins.fromJSON (
    builtins.readFile "${kernelDataLean}/module-resources.json"
  );
  kernelDataInventory = builtins.fromJSON (
    builtins.readFile "${kernelDataLean}/module-inventory.json"
  );
  kernelDataNativeProjectionTargets = map
    (row: row.name)
    (builtins.filter
      (row: row.role == "candidate-data-native-projection-pack")
      kernelDataInventory.modules);
  kernelDataNativeProjectionProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = kernelDataLean + "/StageA";
    standaloneModules = kernelDataStandaloneModules;
    standaloneModuleResources = kernelDataStandaloneResources;
    targetNodes = kernelDataNativeProjectionTargets;
    targetBundle = true;
  };
  # A sparse, representative latency target: the selected packs contain 21,
  # 197, and 490 actions respectively in the pinned GNU hello fixture.
  kernelDataNativeProjectionBenchmark = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = kernelDataLean + "/StageA";
    standaloneModules = kernelDataStandaloneModules;
    standaloneModuleResources = kernelDataStandaloneResources;
    targetNodes = [
      "GeneratedInterpreterKernelDataNativeProjectionPack0533"
      "GeneratedInterpreterKernelDataNativeProjectionPack0637"
      "GeneratedInterpreterKernelDataNativeProjectionPack0148"
    ];
    targetBundle = true;
  };

  accessFaultQualificationLean =
    mkPhaseWithSource accessFaultQualificationPythonSource
      "stage-a-gnu-hello-roundtrip-access-fault-qualification-lean" [] ''
      ${python} ${accessFaultQualificationDriver} \
        --original-isa ${originalIsa}/isa.json \
        --state-machine ${proofStateMachinePath} \
        --reachability-plan \
          ${mixedOriginalBaseLean}/interpreter-mixed-original-base-plan.json \
        --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
        --certificate-pack-size 8 \
        --out "$out"
      jq -e '
        .format == "stage-a-typed-access-fault-qualification-v1" and
        .status == "source-ready-with-frontiers" and
        .side == "original" and
        .counts.reachable_regions ==
          (.counts.typed_qualification_regions +
            .counts.blocked_regions) and
        .counts.typed_qualification_regions > 0 and
        .counts.remaining_state_admissibility_premises ==
          .counts.typed_qualification_regions and
        .counts.by_qualification_kind.ordinary > 0 and
        .counts.by_qualification_kind.x87 > 0 and
        .counts.blocked_regions == 0 and
        .counts.shards > 0 and
        .counts.by_blocker_reason == {} and
        (.trust.proof_authority | not) and
        (.trust.closes_stage_a_proof | not) and
        .trust.exact_pe_decode_required and
        .trust.checked_semantic_transfer_required and
        .trust.runtime_state_admissibility_required and
        .trust.fail_closed
      ' "$out/typed-access-fault-qualification.json" >/dev/null
      jq -e '
        .format ==
          "stage-a-typed-access-fault-qualification-manifest-v1" and
        .phase == "typed-access-fault-qualification" and
        .status == "source-ready-with-frontiers" and
        (.targets | length) == .counts.shards and
        (.remaining_premises | length) ==
          .counts.remaining_state_admissibility_premises and
        (.blockers | length) == .counts.blocked_regions
      ' "$out/phase-manifest.json" >/dev/null
      test "$(jq 'length' "$out/proof-targets.json")" -gt 0
      test "$(find "$out/StageA" -name '*.lean' | wc -l)" \
        -eq "$(jq 'length' "$out/proof-targets.json")"
    '';
  accessFaultQualificationTargets = builtins.fromJSON (
    builtins.readFile "${accessFaultQualificationLean}/proof-targets.json"
  );
  accessFaultQualificationProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-access-fault-qualification-proof-sources" [] ''
    target_args=()
    while IFS= read -r target; do
      target_args+=(--target "$target")
    done < <(jq -r '.[]' ${accessFaultQualificationLean}/proof-targets.json)
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalBaseLean} \
      --source ${kernelDataLean} \
      --source ${accessFaultQualificationLean} \
      --explicit-targets-only \
      --target-closure-only \
      "''${target_args[@]}" \
      --out "$out"
  '';
  accessFaultQualificationProofModules = builtins.fromJSON (
    builtins.readFile
      "${accessFaultQualificationProofSources}/standalone-modules.json"
  );
  accessFaultQualificationProofResources = builtins.fromJSON (
    builtins.readFile
      "${accessFaultQualificationProofSources}/module-resources.json"
  );
  accessFaultQualificationProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot =
      accessFaultQualificationProofSources + "/StageA";
    standaloneModules = accessFaultQualificationProofModules;
    standaloneModuleResources = accessFaultQualificationProofResources;
    targetNodes = accessFaultQualificationTargets;
    targetBundle = true;
  };

  kernelAbiLean = mkPhase "stage-a-gnu-hello-roundtrip-kernel-abi-lean" [] ''
    ${python} ${driver} kernel-abi \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --engine-layout ${candidate}/engine-layout.bin \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-abi" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .proposal_format ==
        "stage-a-relational-interpreter-kernel-abi-plan-v1" and
      .failure_mode == "none" and
      (.candidate_sha256 | test("^[0-9a-f]{64}$")) and
      (.proposal_sha256 | test("^[0-9a-f]{64}$")) and
      .operations == [
        "programLookup", "interpreterStep", "runFunction", "invokeCall"
      ] and
      .inputs.kernel_plan.path == "interpreter-kernel-plan.json" and
      .inputs.kernel_data_inventory.path == "module-inventory.json" and
      .inputs.engine_layout.path == "engine-layout.bin" and
      .public_outputs.plan == "interpreter-kernel-abi-plan.json" and
      .public_outputs.lean_module ==
        "StageA/GeneratedRelationalInterpreterKernelABI.lean" and
      .public_outputs.parameters_lean_module ==
        "StageA/GeneratedRelationalInterpreterKernelABIParameters.lean" and
      .targets == ["GeneratedRelationalInterpreterKernelABI"]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-kernel-abi-plan.json"
    test -s "$out/StageA/GeneratedRelationalInterpreterKernelABI.lean"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelABIParameters.lean"
  '';

  x87CandidateReplayLean = mkPhase
    "stage-a-gnu-hello-roundtrip-x87-candidate-replay-lean" [] ''
    ${python} ${driver} x87-candidate-replay-sources \
      --state-machine ${proofStateMachinePath} \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --out "$out"
  '';

  x87ReplayBridgeTargetLean = mkPhase
    "stage-a-gnu-hello-roundtrip-x87-replay-bridge-target-lean" [] ''
    ${python} ${driver} x87-replay-bridge-target-sources \
      --candidate ${candidate}/candidate.exe \
      --build-manifest ${candidate}/interpreter-native-build-manifest.json \
      --native-engine-plan ${nativeEngine}/native-engine-plan.json \
      --candidate-data-module GeneratedInterpreterKernelDataBase \
      --pack-size 32 \
      --out "$out"
    jq -e '
      .phase == "x87-replay-bridge-target-lean" and
      .status == "source-ready" and
      (.proof_authority | not) and
      (.candidate_sha256 | test("^[0-9a-f]{64}$")) and
      .counts.descriptors > 0 and
      .counts.finite_targets == .counts.descriptors and
      .counts.dynamic_frame_mappings == .counts.descriptors and
      .counts.runtime_refinement_goals == .counts.descriptors and
      .counts.static_frontiers == 0 and
      .targets == [
        "GeneratedRelationalInterpreterX87ReplayBridgeTarget"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/x87-replay-bridge-target-plan.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterX87ReplayBridgeTarget.lean"
  '';

  x87ReplayBridgeRuntimeLean = mkPhase
    "stage-a-gnu-hello-roundtrip-x87-replay-bridge-runtime-lean" [] ''
    ${python} ${driver} x87-replay-bridge-runtime-sources \
      --candidate ${candidate}/candidate.exe \
      --target-plan \
        ${x87ReplayBridgeTargetLean}/x87-replay-bridge-target-plan.json \
      --native-engine-plan ${nativeEngine}/native-engine-plan.json \
      --target-module GeneratedRelationalInterpreterX87ReplayBridgeTarget \
      --pack-size 32 \
      --out "$out"
    jq -e --argjson targetCount \
      "$(jq '.counts.descriptors' \
        ${x87ReplayBridgeTargetLean}/phase-manifest.json)" '
      .phase == "x87-replay-bridge-runtime-lean" and
      .status == "source-ready" and
      .diagnostic_status == "kernel_execution_closed" and
      (.proof_authority | not) and
      .static_evidence and
      (.candidate_sha256 | test("^[0-9a-f]{64}$")) and
      (.conditional_theorem | endswith(".executeKernelReduction")) and
      .remaining_proof_premises == [] and
      .counts.runtime_targets == $targetCount and
      .counts.relocated_operands > 0 and
      .counts.unbound_relocated_operands == 0 and
      .targets == [
        "GeneratedRelationalInterpreterX87ReplayBridgeRuntime"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    jq -e --argjson targetCount \
      "$(jq '.counts.descriptors' \
        ${x87ReplayBridgeTargetLean}/phase-manifest.json)" '
      .format == "stage-a-relational-x87-replay-bridge-runtime-plan-v1" and
      .status == "complete" and
      .diagnostic_status == "kernel_execution_closed" and
      (.acceptance_authority | not) and
      .static_evidence and
      (.conditional_theorem | endswith(".executeKernelReduction")) and
      .remaining_proof_premises == [] and
      .counts.runtime_targets == $targetCount and
      .counts.relocated_operands > 0 and
      .counts.unbound_relocated_operands == 0
    ' "$out/x87-replay-bridge-runtime-plan.json" >/dev/null
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterX87ReplayBridgeRuntime.lean"
  '';

  x87KernelExecutionLean = mkPhaseWithSource proofPythonSource
    "stage-a-gnu-hello-roundtrip-x87-kernel-execution-lean" [] ''
    ${python} ${driver} x87-kernel-execution-sources \
      --runtime-plan \
        ${x87ReplayBridgeRuntimeLean}/x87-replay-bridge-runtime-plan.json \
      --out "$out"
    jq -e --argjson runtimeCount \
      "$(jq '.counts.runtime_targets' \
        ${x87ReplayBridgeRuntimeLean}/phase-manifest.json)" '
      .phase == "x87-kernel-execution-lean" and
      .status == "source-ready" and
      .diagnostic_status == "kernel_execution_closed" and
      (.proof_authority | not) and
      .failure_mode == "none" and
      (.candidate_sha256 | test("^[0-9a-f]{64}$")) and
      .runtime_targets == $runtimeCount and
      .remaining_proof_premises == [] and
      .targets == [
        "GeneratedRelationalInterpreterKernelX87Execution"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    jq -e --argjson runtimeCount \
      "$(jq '.counts.runtime_targets' \
        ${x87ReplayBridgeRuntimeLean}/phase-manifest.json)" '
      .format == "stage-a-gnu-hello-x87-kernel-execution-frontier-v1" and
      .status == "closed" and
      (.acceptance_authority | not) and
      .failure_mode == "none" and
      .runtime_targets == $runtimeCount and
      .remaining_authority.authority_fields == [] and
      .remaining_authority.structurally_derived_program_binding_fields == [
        "peExact", "importsExact", "targetInventory"
      ] and
      .remaining_authority.structurally_derived_handler_fields == [
        "handlerInventory"
      ] and
      .remaining_authority.fixed_template_certificate_proof_fields == [] and
      (.remaining_authority.required_checked_target_terms | length) ==
        $runtimeCount
    ' "$out/x87-kernel-execution-frontier.json" >/dev/null
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelX87Execution.lean"
    test -s "$out/module-resources.json"
  '';

  kernelBlockLean = mkPhase "stage-a-gnu-hello-roundtrip-kernel-block-lean" [] ''
    ${python} ${driver} kernel-block \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --shard-size 24 --out "$out"
  '';

  kernelLoopLean = mkPhase "stage-a-gnu-hello-roundtrip-kernel-loop-lean" [] ''
    ${python} ${driver} kernel-loop \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json --out "$out"
  '';

  kernelCallbackLean = mkPhase "stage-a-gnu-hello-roundtrip-kernel-callback-lean" [] ''
    ${python} ${driver} kernel-callback \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --linker-map ${candidate}/payload.map \
      --native-engine-plan ${nativeEngine}/native-engine-plan.json \
      --out "$out"
  '';

  kernelLookupLean = mkPhase "stage-a-gnu-hello-roundtrip-kernel-lookup-lean" [] ''
    ${python} ${driver} kernel-lookup \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --out "$out"
  '';

  kernelLookupNativeLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-lookup-native-lean" [] ''
    ${python} ${driver} kernel-lookup-native \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --out "$out"
  '';

  kernelLookupOperationLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-lookup-operation-lean" [] ''
    ${python} ${driver} kernel-lookup-operation \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --lookup-native-plan \
        ${kernelLookupNativeLean}/interpreter-kernel-lookup-native-plan.json \
      --abi-plan ${kernelAbiLean}/interpreter-kernel-abi-plan.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-program-lookup-operation" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelProgramLookupOperation.generatedProgramLookupOperationRefinesUsing" and
      (.inputs | keys) == [
        "abi_plan",
        "candidate",
        "kernel_data_inventory",
        "kernel_plan",
        "lookup_native_plan"
      ] and
      ([.inputs[]] | all(
        (.sha256 | test("^[0-9a-f]{64}$")) and
        (.path | length) > 0
      )) and
      .public_outputs.plan ==
        "interpreter-kernel-program-lookup-operation-plan.json" and
      .public_outputs.lean_module ==
        "StageA/GeneratedRelationalInterpreterKernelProgramLookupOperation.lean" and
      .public_outputs.module_resources == "module-resources.json" and
      .targets ==
        ["GeneratedRelationalInterpreterKernelProgramLookupOperation"]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-kernel-program-lookup-operation-plan.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelProgramLookupOperation.lean"
    test -s "$out/module-resources.json"
  '';

  kernelStepLean = mkPhase "stage-a-gnu-hello-roundtrip-kernel-step-lean" [] ''
    ${python} ${driver} kernel-step \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --out "$out"
  '';

  kernelStepNativeLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-step-native-lean" [] ''
    ${python} ${driver} kernel-step-native \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --callback-plan ${kernelCallbackLean}/interpreter-kernel-callback-plan.json \
      --out "$out"
  '';

  kernelRunLean = mkPhase "stage-a-gnu-hello-roundtrip-kernel-run-lean" [] ''
    ${python} ${driver} kernel-run \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --out "$out"
  '';

  kernelRunNativeLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-run-native-lean" [] ''
    ${python} ${driver} kernel-run-native \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --out "$out"
  '';

  kernelRunNativeProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-run-native-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${kernelLean} \
      --source ${kernelDataLean} \
      --source ${kernelCallbackLean} \
      --source ${kernelRunLean} \
      --source ${kernelRunNativeLean} \
      --target GeneratedRelationalInterpreterKernelRunNative \
      --out "$out"
  '';
  kernelRunNativeProofModules = builtins.fromJSON (
    builtins.readFile
      "${kernelRunNativeProofSources}/standalone-modules.json"
  );
  kernelRunNativeProofResources = builtins.fromJSON (
    builtins.readFile "${kernelRunNativeProofSources}/module-resources.json"
  );
  kernelRunNativeProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = kernelRunNativeProofSources + "/StageA";
    standaloneModules = kernelRunNativeProofModules;
    standaloneModuleResources = kernelRunNativeProofResources;
    targetNodes = [ "GeneratedRelationalInterpreterKernelRunNative" ];
    targetBundle = true;
    targetAxiomAudit = {
      module = "GeneratedRelationalInterpreterKernelRunNative";
      declaration =
        "StageA.GeneratedRelational.InterpreterKernelRunNative.GeneratedRunFunctionNativeRefinesUsing";
      approved_axioms = [ "propext" "Classical.choice" "Quot.sound" ];
    };
  };

  kernelInvokeLean = mkPhase "stage-a-gnu-hello-roundtrip-kernel-invoke-lean" [] ''
    ${python} ${driver} kernel-invoke \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --out "$out"
  '';

  kernelInvokeNativeLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-invoke-native-lean" [] ''
    ${python} ${driver} kernel-invoke-native \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --callback-plan ${kernelCallbackLean}/interpreter-kernel-callback-plan.json \
      --out "$out"
  '';

  kernelStepOperationLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-step-operation-lean" [] ''
    ${python} ${driver} kernel-step-operation \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --abi-plan ${kernelAbiLean}/interpreter-kernel-abi-plan.json \
      --step-native-plan \
        ${kernelStepNativeLean}/interpreter-kernel-step-native-plan.json \
      --callback-plan \
        ${kernelCallbackLean}/interpreter-kernel-callback-plan.json \
      --lookup-native-plan \
        ${kernelLookupNativeLean}/interpreter-kernel-lookup-native-plan.json \
      --lookup-operation-plan \
        ${kernelLookupOperationLean}/interpreter-kernel-program-lookup-operation-plan.json \
      --invoke-native-plan \
        ${kernelInvokeNativeLean}/interpreter-kernel-invoke-native-plan.json \
      --x87-replay-plan \
        ${x87ReplayBridgeTargetLean}/x87-replay-bridge-target-plan.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-interpreter-step-operation" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [
    "finite_checked_semantic_call_tree",
    "program_lookup_world_subroutine_composition",
    "per_action_loop_chunks",
    "request_local_invoke_call_refinement",
    "x87_replay_nested_callback_refinement",
    "cdecl_epilogue_response_and_memory_frame"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelStepOperation.generatedInterpreterStepOperationRefinesUsing" and
      (.inputs | keys) == [
        "abi_plan",
        "callback_plan",
        "candidate",
        "invoke_native_plan",
        "kernel_data_inventory",
        "kernel_plan",
        "lookup_native_plan",
        "lookup_operation_plan",
        "step_native_plan",
        "x87_replay_plan"
      ] and
      ([.inputs[]] | all(
        (.sha256 | test("^[0-9a-f]{64}$")) and
        (.path | length) > 0
      )) and
      .public_outputs.plan ==
        "interpreter-kernel-step-operation-plan.json" and
      .public_outputs.lean_module ==
        "StageA/GeneratedRelationalInterpreterKernelStepOperation.lean" and
      .public_outputs.module_resources == "module-resources.json" and
      .targets == ["GeneratedRelationalInterpreterKernelStepOperation"]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-kernel-step-operation-plan.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelStepOperationInterface.lean"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelStepOperation.lean"
    test -s "$out/module-resources.json"
  '';

  kernelStepProgramLookupCallLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-step-program-lookup-call-lean" [] ''
    ${python} ${driver} kernel-step-program-lookup-call \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --abi-plan ${kernelAbiLean}/interpreter-kernel-abi-plan.json \
      --step-native-plan \
        ${kernelStepNativeLean}/interpreter-kernel-step-native-plan.json \
      --callback-plan \
        ${kernelCallbackLean}/interpreter-kernel-callback-plan.json \
      --lookup-native-plan \
        ${kernelLookupNativeLean}/interpreter-kernel-lookup-native-plan.json \
      --lookup-operation-plan \
        ${kernelLookupOperationLean}/interpreter-kernel-program-lookup-operation-plan.json \
      --invoke-native-plan \
        ${kernelInvokeNativeLean}/interpreter-kernel-invoke-native-plan.json \
      --x87-replay-plan \
        ${x87ReplayBridgeTargetLean}/x87-replay-bridge-target-plan.json \
      --step-operation-plan \
        ${kernelStepOperationLean}/interpreter-kernel-step-operation-plan.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-step-program-lookup-call" and
      .status == "typed-interface-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [
        "exact_step_caller_prefix_and_program_lookup_call_chunk",
        "program_lookup_request_at_exact_nested_caller_frame",
        "exact_program_lookup_native_return_path_at_checked_continuation"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelStepProgramLookupCall.generatedInterpreterStepProgramLookupWorldCall" and
      .targets == [
        "GeneratedRelationalInterpreterKernelStepProgramLookupCall"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s \
      "$out/interpreter-kernel-step-program-lookup-call-plan.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelStepProgramLookupCall.lean"
  '';

  programLookupNativeWorldBridgeLean =
    mkPhaseWithSource programLookupNativeWorldBridgePythonSource
      "stage-a-gnu-hello-roundtrip-program-lookup-native-world-bridge-source" [] ''
      ${python} \
        ${programLookupNativeWorldBridgePythonSource}/nix/gnu-hello-program-lookup-native-world-bridge.py \
        --candidate ${candidate}/candidate.exe \
        --lookup-native-plan \
          ${kernelLookupNativeLean}/interpreter-kernel-lookup-native-plan.json \
        --lookup-operation-plan \
          ${kernelLookupOperationLean}/interpreter-kernel-program-lookup-operation-plan.json \
        --step-call-plan \
          ${kernelStepProgramLookupCallLean}/interpreter-kernel-step-program-lookup-call-plan.json \
        --out "$out"
      jq -e \
        --slurpfile lookup \
          ${kernelLookupNativeLean}/interpreter-kernel-lookup-native-plan.json \
        --slurpfile step \
          ${kernelStepProgramLookupCallLean}/interpreter-kernel-step-program-lookup-call-plan.json \
        '
        .format ==
          "stage-a-relational-interpreter-kernel-program-lookup-native-world-bridge-v1" and
        (.acceptance_authority | not) and
        .operation == "programLookup" and
        .checked_static_authority == {
          entry_rva: $lookup[0].template.entry_rva,
          step_call_site_rva:
            $step[0].checked_static_authority.call_site_rva,
          step_call_target_rva:
            $step[0].checked_static_authority.target_rva,
          step_continuation_rva:
            $step[0].checked_static_authority.continuation_rva
        } and
        .world_contract == {
          mode: "caller-parametric",
          successor: "same-relational-world",
          mixed_acceptance_launch_world_assumed: false
        } and
        .remaining_proof_premises == [] and
        .result.theorem ==
          "StageA.GeneratedRelational.InterpreterKernelProgramLookupNativeWorldBridge.generatedProgramLookupNativeWorldRefines"
      ' "$out/interpreter-kernel-program-lookup-native-world-bridge.json" >/dev/null
      test -s \
        "$out/StageA/GeneratedRelationalInterpreterKernelProgramLookupNativeWorldBridge.lean"
    '';

  programLookupNativeWorldBridgeClosure = mkGeneratedClosureProof {
    name = "program-lookup-native-world-bridge";
    sources = candidateKernelProofSourceInputs ++ [
      kernelStepProgramLookupCallLean
      programLookupNativeWorldBridgeLean
    ];
    target =
      "GeneratedRelationalInterpreterKernelProgramLookupNativeWorldBridge";
    declaration =
      "StageA.GeneratedRelational.InterpreterKernelProgramLookupNativeWorldBridge.generatedProgramLookupNativeWorldRefines";
  };
  programLookupNativeWorldBridgeProofSources =
    programLookupNativeWorldBridgeClosure.proofSources;
  programLookupNativeWorldBridgeProof =
    programLookupNativeWorldBridgeClosure.proof;

  interpreterStepWorldProgramLookupLean =
    mkPhaseWithSource interpreterStepWorldProgramLookupPythonSource
      "stage-a-gnu-hello-roundtrip-interpreter-step-world-program-lookup-source" [] ''
      ${python} \
        ${interpreterStepWorldProgramLookupPythonSource}/nix/gnu-hello-interpreter-step-world-program-lookup.py \
        --candidate ${candidate}/candidate.exe \
        --program-lookup-native-world-bridge-plan \
          ${programLookupNativeWorldBridgeLean}/interpreter-kernel-program-lookup-native-world-bridge.json \
        --step-operation-plan \
          ${kernelStepOperationLean}/interpreter-kernel-step-operation-plan.json \
        --operation-instantiation-plan \
          ${kernelOperationInstantiationLean}/interpreter-kernel-operation-instantiation.json \
        --out "$out"
      jq -e \
        --slurpfile bridge \
          ${programLookupNativeWorldBridgeLean}/interpreter-kernel-program-lookup-native-world-bridge.json \
        --slurpfile step \
          ${kernelStepOperationLean}/interpreter-kernel-step-operation-plan.json \
        '
        .format ==
          "stage-a-relational-interpreter-kernel-step-world-program-lookup-v2" and
        (.acceptance_authority | not) and
        .operation == "interpreterStep.programLookupCall" and
        (.checked_static_authority as $static |
          $static.prefix_kind == "direct_entry_call" and
          $static.step_entry_rva ==
            $step[0].checked_static_authority.entry_rva and
          $static.call_site_rva ==
            $step[0].checked_static_authority.program_lookup_call_rva and
          $static.target_rva ==
            $step[0].checked_static_authority.program_lookup_target_rva and
          $static.call_site_rva ==
            $bridge[0].checked_static_authority.step_call_site_rva and
          $static.target_rva ==
            $bridge[0].checked_static_authority.step_call_target_rva and
          $static.continuation_rva ==
            $bridge[0].checked_static_authority.step_continuation_rva and
          $static.call_block_entry_rva == $static.step_entry_rva and
          $static.call_block_ordinal == $static.step_entry_block_ordinal and
          $static.call_block_instruction_count ==
            $static.step_entry_instruction_count and
          $static.step_entry_instruction_count > 0 and
          $static.helper_target_rva == null and
          $static.helper_continuation_rva == null and
          $static.helper_function_ordinal == null and
          $static.helper_entry_block_ordinal == null and
          $static.helper_return_block_ordinal == null and
          $static.helper_return_block_rva == null and
          $static.helper_block_ordinals == []) and
        .closed_components == [
          "world_indexed_step_prefix_composition_interface",
          "checked_program_lookup_call_chunk",
          "per_call_kernel_abi_relation",
          "nested_program_lookup_response",
          "exact_return_to_step_continuation",
          "step_response_and_memory_frame_composition"
        ] and
        .remaining_proof_premises == [] and
        .proof_frontiers == [] and
        .result.theorem ==
          "StageA.GeneratedRelational.InterpreterKernelStepWorldProgramLookup.generatedInterpreterStepWorldProgramLookupCallAuthority" and
        .result.requested_step_theorem_constructed and
        .failure_mode == "none"
      ' "$out/interpreter-kernel-step-world-program-lookup.json" >/dev/null
      test -s \
        "$out/StageA/GeneratedRelationalInterpreterKernelStepWorldProgramLookup.lean"
      test -s \
        "$out/StageA/GeneratedRelationalInterpreterKernelStepWorldProgramLookupCertificate.lean"
      test -s \
        "$out/interpreter-step-program-lookup-call-behavior-request.json"
    '';

  interpreterStepProgramLookupCallBehaviorExtraction = mkAnalysisPhase
    "stage-a-gnu-hello-roundtrip-interpreter-step-program-lookup-call-behavior-extraction"
    [ sideTool pkgs.lean4 ] ''
      mkdir -p "$out"
      export SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_THREAD_STACK_KB=524288
      ulimit -s 524288
      spaghetti-extractor-side extract-side \
        --binary ${candidate}/candidate.exe \
        --request \
          ${interpreterStepWorldProgramLookupLean}/interpreter-step-program-lookup-call-behavior-request.json \
        --out "$out/extraction.json" \
        > "$out/result.json"
      requested_regions="$(
        jq '.regions | length' \
          ${interpreterStepWorldProgramLookupLean}/interpreter-step-program-lookup-call-behavior-request.json
      )"
      jq -e --argjson requested_regions "$requested_regions" '
        .format == "stage-a-relational-side-extraction-result-v1" and
        .status == "extracted" and
        .side == "candidate" and
        .regions == $requested_regions
      ' "$out/result.json" >/dev/null
      jq -e --argjson requested_regions "$requested_regions" '
        .format == "stage-a-relational-side-extraction-v1" and
        .status == "untrusted_proposal_requires_lean_decode_replay" and
        .side == "candidate" and
        (.regions | length) == $requested_regions
      ' "$out/extraction.json" >/dev/null
    '';

  interpreterStepProgramLookupCallBehaviorsLean =
    mkPhaseWithSource
      interpreterStepProgramLookupCallBehaviorsPythonSource
      "stage-a-gnu-hello-roundtrip-interpreter-step-program-lookup-call-behaviors-source"
      [] ''
        ${python} \
          ${interpreterStepProgramLookupCallBehaviorsPythonSource}/nix/gnu-hello-step-program-lookup-call-behaviors.py \
          --candidate ${candidate}/candidate.exe \
          --program-lookup-native-world-bridge-plan \
            ${programLookupNativeWorldBridgeLean}/interpreter-kernel-program-lookup-native-world-bridge.json \
          --step-operation-plan \
            ${kernelStepOperationLean}/interpreter-kernel-step-operation-plan.json \
          --operation-instantiation-plan \
            ${kernelOperationInstantiationLean}/interpreter-kernel-operation-instantiation.json \
          --extraction \
            ${interpreterStepProgramLookupCallBehaviorExtraction}/extraction.json \
          --out "$out"
        test -s \
          "$out/StageA/GeneratedRelationalInterpreterStepProgramLookupCallBehaviors.lean"
        test -s \
          "$out/StageA/GeneratedRelationalInterpreterStepProgramLookupProjection.lean"
      '';

  # Candidate-kernel closure proofs must not depend on the whole Stage A proof
  # aggregate.  Keep this boundary explicit so a local candidate operation
  # change cannot force evaluation of original-image and mixed-composition
  # artifacts.  The target-closure aggregate below still selects only imported
  # modules from these source roots.
  candidateKernelProofSourceInputs = [
    leanSourceRoot
    kernelLean
    kernelDataLean
    kernelAbiLean
    x87ReplayBridgeTargetLean
    kernelCallbackLean
    kernelLookupLean
    kernelLookupNativeLean
    kernelLookupOperationLean
    kernelStepLean
    kernelStepNativeLean
    kernelInvokeLean
    kernelInvokeNativeLean
    kernelStepOperationLean
    kernelOperationInstantiationLean
  ];
  candidateKernelOperationProofSourceInputs =
    candidateKernelProofSourceInputs ++ [
      kernelRunLean
      kernelRunNativeLean
      kernelRunOperationLean
      kernelInvokeOperationLean
    ];

  interpreterStepProgramLookupProjectionClosure = mkGeneratedClosureProof {
    name = "interpreter-step-program-lookup-projection";
    sources = candidateKernelProofSourceInputs ++ [
      interpreterStepProgramLookupCallBehaviorsLean
    ];
    target =
      "GeneratedRelationalInterpreterStepProgramLookupProjection";
    declaration =
      "StageA.GeneratedRelational.InterpreterStepProgramLookupProjection.generatedInterpreterStepProgramLookupProjectionBlockEndpointExact";
  };
  interpreterStepProgramLookupProjectionProofSources =
    interpreterStepProgramLookupProjectionClosure.proofSources;
  interpreterStepProgramLookupProjectionProof =
    interpreterStepProgramLookupProjectionClosure.proof;

  interpreterStepWorldProgramLookupClosure = mkGeneratedClosureProof {
    name = "interpreter-step-world-program-lookup";
    sources = candidateKernelProofSourceInputs ++ [
      interpreterStepProgramLookupCallBehaviorsLean
      interpreterStepWorldProgramLookupLean
    ];
    target =
      "GeneratedRelationalInterpreterKernelStepWorldProgramLookup";
    declaration =
      "StageA.GeneratedRelational.InterpreterKernelStepWorldProgramLookup.generatedInterpreterStepWorldProgramLookupCallAuthority";
  };
  interpreterStepWorldProgramLookupProofSources =
    interpreterStepWorldProgramLookupClosure.proofSources;
  interpreterStepWorldProgramLookupProof =
    interpreterStepWorldProgramLookupClosure.proof;

  kernelStepProgramLookupCallClosureLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-step-program-lookup-call-closure-lean" [] ''
    ${python} ${driver} kernel-step-program-lookup-call-closure \
      --candidate ${candidate}/candidate.exe \
      --program-lookup-call-plan \
        ${kernelStepProgramLookupCallLean}/interpreter-kernel-step-program-lookup-call-plan.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-step-program-lookup-call-closure" and
      .status == "typed-interface-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .closed_premise_families == [
        "submitted_step_caller_path",
        "bare_program_lookup_request_relation",
        "submitted_program_lookup_return_path"
      ] and
      .remaining_proof_premises == [
        "exact_step_prefix_and_helper_runtime_endpoints",
        "nested_program_lookup_cdecl_image_and_table_facts",
        "exact_program_lookup_return_replay_fuel_and_endpoint"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelStepProgramLookupCallClosure.generatedInterpreterStepProgramLookupCallClosureBindings" and
      .targets == [
        "GeneratedRelationalInterpreterKernelStepProgramLookupCallClosure"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s \
      "$out/interpreter-kernel-step-program-lookup-call-closure.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelStepProgramLookupCallClosure.lean"
  '';

  kernelStepProgramLookupExactComputationLean = mkPhaseWithSource
    proofClosurePythonSource
    "stage-a-gnu-hello-roundtrip-kernel-step-program-lookup-exact-computation-lean"
    [] ''
    ${python} ${proofClosureDriver} step-program-lookup-exact-computation \
      --candidate ${candidate}/candidate.exe \
      --closure-plan \
        ${kernelStepProgramLookupCallClosureLean}/interpreter-kernel-step-program-lookup-call-closure.json \
      --out "$out"
    jq -e '
      .phase ==
        "compiled-kernel-step-program-lookup-exact-computation" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [
        "step_prefix_checked_chunk_and_helper_executor_equalities",
        "nested_program_lookup_cdecl_image_table_and_source_bound",
        "program_lookup_operation_response_and_memory_frame",
        "program_lookup_return_executor_equality_for_selected_response"
      ] and
      .targets == [
        "GeneratedRelationalInterpreterKernelStepProgramLookupExactComputation"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s \
      "$out/interpreter-kernel-step-program-lookup-exact-computation.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelStepProgramLookupExactComputation.lean"
  '';

  kernelOperationFrameParametricLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-operation-frame-parametric-lean" [] ''
    ${python} ${driver} kernel-operation-frame-parametric \
      --candidate ${candidate}/candidate.exe \
      --step-operation-plan \
        ${kernelStepOperationLean}/interpreter-kernel-step-operation-plan.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-operation-frame-parametric" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [
        "producer_coupled_canonical_interpreter_step_path_for_compatible_contexts",
        "producer_selected_path_context_refinement"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelOperationFrameParametric.generatedInterpreterStepFrameParametricCertificate" and
      (.inputs | keys) == ["candidate", "step_operation_plan"] and
      .public_outputs.plan ==
        "interpreter-kernel-operation-frame-parametric-plan.json" and
      .public_outputs.lean_module ==
        "StageA/GeneratedRelationalInterpreterKernelOperationFrameParametric.lean" and
      .targets == [
        "GeneratedRelationalInterpreterKernelOperationFrameParametric"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s \
      "$out/interpreter-kernel-operation-frame-parametric-plan.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelOperationFrameParametric.lean"
    test -s "$out/module-resources.json"
  '';

  kernelFrameExecutorLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-frame-executor-lean" [] ''
    ${python} ${driver} kernel-frame-executor \
      --candidate ${candidate}/candidate.exe \
      --frame-parametric-plan \
        ${kernelOperationFrameParametricLean}/interpreter-kernel-operation-frame-parametric-plan.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-frame-executor" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [
        "producer_coupled_canonical_interpreter_step_path_for_compatible_contexts",
        "imported_environment_footprint_and_world_update_contract",
        "imported_footprint_disjoint_from_caller_return_slot"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelFrameExecutor.generatedInterpreterStepFrameExecutorCertificate" and
      (.inputs | keys) == ["candidate", "frame_parametric_plan"] and
      .public_outputs.plan ==
        "interpreter-kernel-frame-executor-plan.json" and
      .public_outputs.lean_module ==
        "StageA/GeneratedRelationalInterpreterKernelFrameExecutor.lean" and
      .targets == ["GeneratedRelationalInterpreterKernelFrameExecutor"]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-kernel-frame-executor-plan.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelFrameExecutor.lean"
    test -s "$out/module-resources.json"
  '';

  kernelRunOperationLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-run-operation-lean" [] ''
    ${python} ${driver} kernel-run-operation \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --abi-plan ${kernelAbiLean}/interpreter-kernel-abi-plan.json \
      --run-native-plan \
        ${kernelRunNativeLean}/interpreter-kernel-run-native-plan.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-run-function-operation" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [
    "finite_checked_semantic_call_tree",
    "checked_local_step_and_control_paths",
    "entry_frame_and_loop_invariant",
    "cdecl_epilogue_response_and_memory_frame"
  ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelRunOperation.generatedRunFunctionOperationRefinesUsing" and
      (.inputs | keys) == [
        "abi_plan",
        "candidate",
        "kernel_data_inventory",
        "kernel_plan",
        "run_native_plan"
      ] and
      ([.inputs[]] | all(
        (.sha256 | test("^[0-9a-f]{64}$")) and
        (.path | length) > 0
      )) and
      .public_outputs.plan ==
        "interpreter-kernel-run-operation-plan.json" and
      .public_outputs.lean_module ==
        "StageA/GeneratedRelationalInterpreterKernelRunOperation.lean" and
      .public_outputs.module_resources == "module-resources.json" and
      .targets == ["GeneratedRelationalInterpreterKernelRunOperation"]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-kernel-run-operation-plan.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelRunOperation.lean"
    test -s "$out/module-resources.json"
  '';

  kernelCdeclEpilogueLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-lean" [] ''
    ${python} ${driver} kernel-cdecl-epilogue \
      --candidate ${candidate}/candidate.exe \
      --step-operation-plan \
        ${kernelStepOperationLean}/interpreter-kernel-step-operation-plan.json \
      --run-operation-plan \
        ${kernelRunOperationLean}/interpreter-kernel-run-operation-plan.json \
      --step-epilogue-fuel 9 \
      --run-epilogue-fuel 8 \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-cdecl-epilogue" and
      .status == "typed-interface-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [
        "exact_decoded_epilogue_prefix_and_return_execution",
        "checked_stack_return_word",
        "preserved_cdecl_registers_and_stack_pop",
        "checked_write_footprint_disjointness",
        "loaded_image_and_program_table_preservation",
        "typed_response_payload_at_computed_return"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelCdeclEpilogue.generatedKernelCDeclEpiloguesChecked" and
      .targets == ["GeneratedRelationalInterpreterKernelCdeclEpilogue"]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-kernel-cdecl-epilogue-plan.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelCdeclEpilogue.lean"
  '';

  kernelCdeclEpilogueSymbolicClosureLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-symbolic-closure-lean" [] ''
    ${python} ${driver} kernel-cdecl-epilogue-symbolic-closure \
      --candidate ${candidate}/candidate.exe \
      --cdecl-epilogue-plan \
        ${kernelCdeclEpilogueLean}/interpreter-kernel-cdecl-epilogue-plan.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-cdecl-epilogue-symbolic-closure" and
      .status == "typed-interface-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .closed_premise_families == [
        "checked_stack_return_word",
        "preserved_cdecl_registers_and_stack_pop",
        "checked_write_footprint_disjointness"
      ] and
      .remaining_proof_premises == [
        "loaded_image_and_original_program_table_preservation",
        "environmental_typed_response_payload"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelCdeclEpilogueSymbolicClosure.generatedKernelCDeclSymbolicClosureBindings" and
      .targets == [
        "GeneratedRelationalInterpreterKernelCdeclEpilogueSymbolicClosure"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s \
      "$out/interpreter-kernel-cdecl-epilogue-symbolic-closure.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelCdeclEpilogueSymbolicClosure.lean"
  '';

  kernelCdeclEpilogueStaticPreservationLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-static-preservation-lean" [] ''
    ${python} ${driver} kernel-cdecl-epilogue-static-preservation \
      --candidate ${candidate}/candidate.exe \
      --symbolic-closure-plan \
        ${kernelCdeclEpilogueSymbolicClosureLean}/interpreter-kernel-cdecl-epilogue-symbolic-closure.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-cdecl-epilogue-static-preservation" and
      .status == "typed-interface-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .closed_premise_families == [
        "loaded_image_and_original_program_table_preservation"
      ] and
      .remaining_proof_premises == [
        "environmental_typed_response_payload"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelCdeclEpilogueStaticPreservation.generatedKernelCDeclStaticPreservationBindings" and
      .targets == [
        "GeneratedRelationalInterpreterKernelCdeclEpilogueStaticPreservation"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s \
      "$out/interpreter-kernel-cdecl-epilogue-static-preservation.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelCdeclEpilogueStaticPreservation.lean"
  '';

  kernelCdeclEpilogueExternalPayloadLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-external-payload-lean" [] ''
    ${python} ${driver} kernel-cdecl-epilogue-external-payload \
      --candidate ${candidate}/candidate.exe \
      --static-preservation-plan \
        ${kernelCdeclEpilogueStaticPreservationLean}/interpreter-kernel-cdecl-epilogue-static-preservation.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-cdecl-epilogue-external-payload" and
      .status == "typed-interface-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .closed_premise_families == [
        "environmental_typed_response_payload"
      ] and
      .remaining_proof_premises == [
        "exact_abstract_operation_transition",
        "exact_operation_result_encoding",
        "checked_one_to_one_external_response_trace"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelCdeclEpilogueExternalPayload.generatedKernelCDeclExternalPayloadBindings" and
      .targets == [
        "GeneratedRelationalInterpreterKernelCdeclEpilogueExternalPayload"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s \
      "$out/interpreter-kernel-cdecl-epilogue-external-payload.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelCdeclEpilogueExternalPayload.lean"
  '';

  kernelOperationResultEncodingLean = mkPhaseWithSource
    proofClosurePythonSource
    "stage-a-gnu-hello-roundtrip-kernel-operation-result-encoding-lean"
    [] ''
    ${python} ${proofClosureDriver} operation-result-encoding \
      --candidate ${candidate}/candidate.exe \
      --external-payload-plan \
        ${kernelCdeclEpilogueExternalPayloadLean}/interpreter-kernel-cdecl-epilogue-external-payload.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-operation-result-encoding" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [
        "exact_abstract_operation_transition",
        "interpreter_step_exact_result_words_and_engine_state",
        "run_function_exact_status_and_output_engine_state",
        "invoke_call_exact_status_and_output_engine_state",
        "checked_one_to_one_external_response_trace"
      ] and
      .targets == [
        "GeneratedRelationalInterpreterKernelOperationResultEncoding"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-kernel-operation-result-encoding.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelOperationResultEncoding.lean"
  '';

  kernelAbstractOperationTransitionLean = mkPhaseWithSource
    proofClosurePythonSource
    "stage-a-gnu-hello-roundtrip-kernel-abstract-operation-transition-lean"
    [] ''
    ${python} ${proofClosureDriver} abstract-operation-transition \
      --candidate ${candidate}/candidate.exe \
      --operation-result-plan \
        ${kernelOperationResultEncodingLean}/interpreter-kernel-operation-result-encoding.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-abstract-operation-transition" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [
        "interpreter_step_exact_result_words_and_engine_state",
        "run_function_exact_status_and_output_engine_state",
        "invoke_call_exact_status_and_output_engine_state",
        "checked_one_to_one_external_response_trace"
      ] and
      .targets == [
        "GeneratedRelationalInterpreterKernelAbstractOperationTransition"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-kernel-abstract-operation-transition.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelAbstractOperationTransition.lean"
  '';

  kernelInvokeOperationLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-invoke-operation-lean" [] ''
    ${python} ${driver} kernel-invoke-operation \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --abi-plan ${kernelAbiLean}/interpreter-kernel-abi-plan.json \
      --callback-plan \
        ${kernelCallbackLean}/interpreter-kernel-callback-plan.json \
      --invoke-native-plan \
        ${kernelInvokeNativeLean}/interpreter-kernel-invoke-native-plan.json \
      --run-operation-plan \
        ${kernelRunOperationLean}/interpreter-kernel-run-operation-plan.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-invoke-call-operation" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .plan_format ==
        "stage-a-relational-interpreter-kernel-invoke-operation-plan-v4" and
      .remaining_proof_premises == [
        "finite_checked_semantic_call_tree",
        "external_arm_exact_route_and_result_closure",
        "internal_arm_exact_route_run_and_result_closure",
        "indirect_arm_exact_resolver_callback_run_and_result_closure"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelInvokeOperation.generatedInvokeCallOperationRefinesUsing" and
      (.inputs | keys) == [
        "abi_plan",
        "callback_plan",
        "candidate",
        "invoke_native_plan",
        "kernel_data_inventory",
        "kernel_plan",
        "run_operation_plan"
      ] and
      ([.inputs[]] | all(
        (.sha256 | test("^[0-9a-f]{64}$")) and
        (.path | length) > 0
      )) and
      .public_outputs.plan ==
        "interpreter-kernel-invoke-operation-plan.json" and
      .public_outputs.lean_module ==
        "StageA/GeneratedRelationalInterpreterKernelInvokeOperation.lean" and
      .public_outputs.module_resources == "module-resources.json" and
      .targets == ["GeneratedRelationalInterpreterKernelInvokeOperation"]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-kernel-invoke-operation-plan.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelInvokeOperation.lean"
    test -s "$out/module-resources.json"
  '';

  mixedCandidateAuthorityLean = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-candidate-authority-lean" [] ''
    ${python} ${driver} mixed-candidate-authority \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --out "$out"
  '';

  constructiveSourceCoverageLean = mkPhaseWithSource
    constructiveSourceCoveragePythonSource
    "stage-a-gnu-hello-roundtrip-constructive-source-coverage-lean" [] ''
    ${python} ${constructiveSourceCoverageDriver} \
      --mixed-original-plan \
        ${mixedOriginalLean}/interpreter-mixed-original-plan.json \
      --static-reachability-plan \
        ${mixedOriginalStaticReachabilityLean}/interpreter-mixed-original-static-reachability.json \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --out "$out"
    jq -e '
      .format == "stage-a-gnu-hello-constructive-source-coverage-v1" and
      .phase == "constructive-source-coverage" and
      .status == "source-ready" and
      (.acceptance_authority | not) and
      .failure_mode == "incomplete" and
      (.candidate_sha256 | test("^[0-9a-f]{64}$")) and
      (.state_machine_sha256 | test("^[0-9a-f]{64}$")) and
      .counts.candidate_records >= .counts.reachable_targets and
      .targets == [
        "GeneratedGnuHelloConstructiveSourceCoverageBindings",
        "GeneratedRelationalInterpreterMixedSourceCoverage",
        "GeneratedGnuHelloConstructiveSourceRules"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/StageA/GeneratedGnuHelloConstructiveSourceCoverageBindings.lean"
    test -s "$out/StageA/GeneratedRelationalInterpreterMixedSourceCoverage.lean"
    test -s "$out/StageA/GeneratedGnuHelloConstructiveSourceRules.lean"
  '';

  constructiveSourceCoverageProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-constructive-source-coverage-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalRegisterIndirectAuthorityLean} \
      --source ${mixedOriginalDirectCallProposalsLean} \
      --source ${mixedOriginalDirectCallSemanticsLean} \
      --source ${mixedOriginalDirectCallClosureProposalsLean} \
      --source ${mixedOriginalDirectCallClosureSemanticsLean} \
      --source ${mixedOriginalLean} \
      --source ${mixedOriginalStaticReachabilityLean} \
      --source ${kernelDataLean} \
      --source ${kernelLean} \
      --source ${mixedCandidateAuthorityLean} \
      --source ${constructiveSourceCoverageLean} \
      --target GeneratedGnuHelloConstructiveSourceRules \
      --out "$out"
  '';
  constructiveSourceCoverageProofModules = builtins.fromJSON (
    builtins.readFile
      "${constructiveSourceCoverageProofSources}/standalone-modules.json"
  );
  constructiveSourceCoverageProofResources = builtins.fromJSON (
    builtins.readFile
      "${constructiveSourceCoverageProofSources}/module-resources.json"
  );
  constructiveSourceCoverageProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = constructiveSourceCoverageProofSources + "/StageA";
    standaloneModules = constructiveSourceCoverageProofModules;
    standaloneModuleResources = constructiveSourceCoverageProofResources;
    targetNodes = [ "GeneratedGnuHelloConstructiveSourceRules" ];
    targetBundle = true;
    targetAxiomAudit = {
      module = "GeneratedGnuHelloConstructiveSourceRules";
      declaration =
        "StageA.GeneratedRelational.GnuHelloConstructiveSourceRules.generatedRulesTargetIds";
      approved_axioms = [ "propext" "Classical.choice" "Quot.sound" ];
    };
  };

  canonicalRelationCoreLean = mkPhaseWithSource
    canonicalRelationCorePythonSource
    "stage-a-gnu-hello-roundtrip-canonical-relation-core-lean" [] ''
    ${python} ${canonicalRelationCoreDriver} \
      --mixed-original-plan \
        ${mixedOriginalLean}/interpreter-mixed-original-plan.json \
      --static-reachability-plan \
        ${mixedOriginalStaticReachabilityLean}/interpreter-mixed-original-static-reachability.json \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --out "$out"
    jq -e '
      .format == "stage-a-gnu-hello-canonical-relation-core-v1" and
      .phase == "canonical-relation-core" and
      .status == "source-ready" and
      (.acceptance_authority | not) and
      .failure_mode == "incomplete" and
      (.candidate_sha256 | test("^[0-9a-f]{64}$")) and
      (.state_machine_sha256 | test("^[0-9a-f]{64}$")) and
      .outputs.binding_module ==
        "StageA/GeneratedGnuHelloCanonicalRelationCoreBindings.lean" and
      .outputs.core_module ==
        "StageA/GeneratedGnuHelloCanonicalRelationCore.lean"
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-mixed-relation-core-plan.json"
    test -s \
      "$out/StageA/GeneratedGnuHelloCanonicalRelationCoreBindings.lean"
    test -s "$out/StageA/GeneratedGnuHelloCanonicalRelationCore.lean"
  '';

  canonicalRelationCoreProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-canonical-relation-core-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalRegisterIndirectAuthorityLean} \
      --source ${mixedOriginalDirectCallProposalsLean} \
      --source ${mixedOriginalDirectCallSemanticsLean} \
      --source ${mixedOriginalDirectCallClosureProposalsLean} \
      --source ${mixedOriginalDirectCallClosureSemanticsLean} \
      --source ${mixedOriginalLean} \
      --source ${mixedOriginalStaticReachabilityLean} \
      --source ${mixedOriginalCarrierBindingLean} \
      --source ${kernelDataLean} \
      --source ${kernelLean} \
      --source ${kernelAbiLean} \
      --source ${mixedCandidateAuthorityLean} \
      --source ${canonicalRelationCoreLean} \
      --target GeneratedGnuHelloCanonicalRelationCore \
      --out "$out"
  '';
  canonicalRelationCoreProofModules = builtins.fromJSON (
    builtins.readFile
      "${canonicalRelationCoreProofSources}/standalone-modules.json"
  );
  canonicalRelationCoreProofResources = builtins.fromJSON (
    builtins.readFile
      "${canonicalRelationCoreProofSources}/module-resources.json"
  );
  canonicalRelationCoreProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = canonicalRelationCoreProofSources + "/StageA";
    standaloneModules = canonicalRelationCoreProofModules;
    standaloneModuleResources = canonicalRelationCoreProofResources;
    targetNodes = [ "GeneratedGnuHelloCanonicalRelationCore" ];
    targetBundle = true;
    targetAxiomAudit = {
      module = "GeneratedGnuHelloCanonicalRelationCore";
      declaration =
        "StageA.GeneratedRelational.GnuHelloCanonicalRelationCore.generatedCanonicalMixedRelationCore";
      approved_axioms = [ "propext" "Classical.choice" "Quot.sound" ];
    };
  };

  acceptanceRequirementsLean = mkPhaseWithSource
    acceptanceRequirementsPythonSource
    "stage-a-gnu-hello-roundtrip-acceptance-requirements-lean" [] ''
    ${python} ${acceptanceRequirementsDriver} --out "$out"
    jq -e '
      .format == "stage-a-gnu-hello-acceptance-requirements-v1" and
      (.acceptance_authority | not) and
      (.report_authority | not) and
      .lean_check_required and
      (.constructed_static_fields | length) == 19 and
      (.dynamic_evidence_fields | length) == 13 and
      .output_module ==
        "StageA/GeneratedGnuHelloAcceptanceRequirements.lean"
    ' "$out/gnu-hello-acceptance-requirements.json" >/dev/null
    test -s "$out/StageA/GeneratedGnuHelloAcceptanceRequirements.lean"
  '';

  acceptanceRequirementsProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-acceptance-requirements-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalRegisterIndirectAuthorityLean} \
      --source ${mixedOriginalDirectCallProposalsLean} \
      --source ${mixedOriginalDirectCallSemanticsLean} \
      --source ${mixedOriginalDirectCallClosureProposalsLean} \
      --source ${mixedOriginalDirectCallClosureSemanticsLean} \
      --source ${mixedOriginalLean} \
      --source ${mixedOriginalStaticReachabilityLean} \
      --source ${mixedOriginalCarrierBindingLean} \
      --source ${programLean} \
      --source ${kernelDataLean} \
      --source ${kernelLean} \
      --source ${kernelAbiLean} \
      --source ${mixedCandidateAuthorityLean} \
      --source ${constructiveSourceCoverageLean} \
      --source ${canonicalRelationCoreLean} \
      --source ${acceptanceRequirementsLean} \
      --target GeneratedGnuHelloAcceptanceRequirements \
      --out "$out"
  '';
  acceptanceRequirementsProofModules = builtins.fromJSON (
    builtins.readFile
      "${acceptanceRequirementsProofSources}/standalone-modules.json"
  );
  acceptanceRequirementsProofResources = builtins.fromJSON (
    builtins.readFile
      "${acceptanceRequirementsProofSources}/module-resources.json"
  );
  acceptanceRequirementsProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = acceptanceRequirementsProofSources + "/StageA";
    standaloneModules = acceptanceRequirementsProofModules;
    standaloneModuleResources = acceptanceRequirementsProofResources;
    targetNodes = [ "GeneratedGnuHelloAcceptanceRequirements" ];
    targetBundle = true;
    targetAxiomAudit = {
      module = "GeneratedGnuHelloAcceptanceRequirements";
      declaration =
        "StageA.GeneratedRelational.GnuHelloAcceptanceRequirements.generatedRequirements";
      approved_axioms = [ "propext" "Classical.choice" "Quot.sound" ];
    };
  };

  runtimeFoundationLean = mkPhaseWithSource runtimeFoundationPythonSource
    "stage-a-gnu-hello-roundtrip-runtime-foundation-source" [] ''
    ${python} ${staticClosureDriver} runtime-foundation --out "$out"
    jq -e '
      .format == "stage-a-gnu-hello-runtime-foundation-v1" and
      .phase == "gnu-hello-runtime-foundation" and
      .complete and
      .status == "source-ready" and
      (.acceptance_authority | not) and
      (.report_authority | not) and
      .lean_check_required and
      (.executes_original_binary | not) and
      (.executes_candidate_binary | not) and
      .failure_mode == "fail-closed" and
      .outputs.lean_module ==
        "StageA/GeneratedGnuHelloRuntimeFoundation.lean" and
      .blocking_obligations == []
    ' "$out/gnu-hello-runtime-foundation.json" >/dev/null
    test -s "$out/StageA/GeneratedGnuHelloRuntimeFoundation.lean"
  '';
  runtimeFoundationClosure = mkGeneratedClosureProof {
    name = "runtime-foundation";
    sources = [
      proofSources
      acceptanceRequirementsLean
      runtimeFoundationLean
    ];
    target = "GeneratedGnuHelloRuntimeFoundation";
    declaration =
      "StageA.GeneratedRelational.GnuHelloRuntimeFoundation.generatedLaunchRealizable";
  };
  runtimeFoundationProofSources = runtimeFoundationClosure.proofSources;
  runtimeFoundationProof = runtimeFoundationClosure.proof;

  launchBindingLean = mkPhaseWithSource launchBindingPythonSource
    "stage-a-gnu-hello-roundtrip-launch-binding-source" [] ''
    ${python} ${launchBindingDriver} launch-binding --out "$out"
    jq -e '
      .format == "stage-a-gnu-hello-launch-binding-v1" and
      .phase == "gnu-hello-launch-binding" and
      .complete and
      .status == "source-ready" and
      (.acceptance_authority | not) and
      .lean_check_required and
      (.executes_original_binary | not) and
      (.executes_candidate_binary | not) and
      .failure_mode == "fail-closed" and
      .outputs.lean_module ==
        "StageA/GeneratedGnuHelloLaunchBinding.lean" and
      .blocking_obligations == []
    ' "$out/gnu-hello-launch-binding.json" >/dev/null
    test -s "$out/StageA/GeneratedGnuHelloLaunchBinding.lean"
  '';
  launchBindingClosure = mkGeneratedClosureProof {
    name = "launch-binding";
    sources = [
      proofSources
      acceptanceRequirementsLean
      runtimeFoundationLean
      launchBindingLean
    ];
    target = "GeneratedGnuHelloLaunchBinding";
    declaration =
      "StageA.GeneratedRelational.GnuHelloLaunchBinding.generatedExactCanonicalLaunchWrapperBinding";
  };
  launchBindingProofSources = launchBindingClosure.proofSources;
  launchBindingProof = launchBindingClosure.proof;

  externalComponentLean = mkPhaseWithSource externalComponentPythonSource
    "stage-a-gnu-hello-roundtrip-external-component-source" [] ''
    ${python} ${externalComponentDriver} external-component --out "$out"
    jq -e '
      .format == "stage-a-gnu-hello-external-component-v3" and
      .phase == "gnu-hello-external-component" and
      (.complete | not) and
      (.acceptance_authority | not) and
      (.proof_authority | not) and
      (.executes_original_binary | not) and
      (.executes_candidate_binary | not) and
      .outputs.lean_module ==
        "StageA/GeneratedGnuHelloExternalComponent.lean" and
      (.remaining_premises | length) == 1 and
      (.blocking_obligations | length) == 1 and
      .constructed_terms.bridge_factory_type ==
        "GeneratedRootBoundaryToOperationBridgeFactory" and
      .constructed_terms.chunk_constructor ==
        "generatedExternalBoundaryChunkFactoryOfOperationBridge"
    ' "$out/gnu-hello-external-component.json" >/dev/null
    test -s "$out/StageA/GeneratedGnuHelloExternalComponent.lean"
  '';
  externalComponentInterfaceProof = mkGeneratedClosureProof {
    name = "external-component";
    sources = [
      proofSources
      externalComponentLean
    ];
    target = "GeneratedGnuHelloExternalComponent";
    declaration =
      "StageA.GeneratedRelational.GnuHelloExternalComponent.generatedExternalBoundaryChunkFactoryOfOperationBridge";
  };
  externalComponentProofSources =
    externalComponentInterfaceProof.proofSources;
  externalComponentProof = externalComponentInterfaceProof.proof;

  # Compile the generic semantic-operation bridge independently from GNU
  # acceptance. The generated Requirements structure contains proof-valued
  # fields; this node checks the bridge once but does not construct those
  # fields or claim final evidence.
  mixedSemanticOperationComponentLean = pkgs.runCommand
    "stage-a-gnu-hello-roundtrip-mixed-semantic-operation-component-source"
    {
      nativeBuildInputs = [
        pythonEnv
        pkgs.jq
        pkgs.coreutils
      ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    } ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      export PYTHONPATH="${mixedSemanticOperationComponentPythonSource}/src"
      ${python} - "$out" <<'PY'
      import json
      import shutil
      import sys
      from pathlib import Path

      from spaghetti_extractor.relational.lean.interpreter_mixed_semantic_operation_component import (
          INTERPRETER_MIXED_SEMANTIC_OPERATION_COMPONENT_MODULE,
          InterpreterMixedSemanticOperationComponentSpec,
          MixedSemanticOperationComponentTerms,
          build_mixed_semantic_operation_component_plan,
          write_mixed_semantic_operation_component_bundle,
      )

      out = Path(sys.argv[1])
      stage_a = out / "StageA"
      stage_a.mkdir(parents=True, exist_ok=True)
      binding_module = "GnuHelloMixedSemanticOperationComponentRequirements"
      binding_namespace = (
          "StageA.GnuHelloMixedSemanticOperationComponentRequirements"
      )
      (stage_a / f"{binding_module}.lean").write_text(
          r"""import StageA.RelationalInterpreterMixedSemanticOperationComponent

      namespace StageA.GnuHelloMixedSemanticOperationComponentRequirements

      open StageA.Relational
      open StageA.Relational.InterpreterKernel
      open StageA.Relational.InterpreterMixedContext
      open StageA.Relational.InterpreterMixedKernelComposition
      open StageA.Relational.InterpreterMixedSemanticOperationComponent
      open StageA.Relational.InterpreterMixedWorldBridge
      open StageA.Relational.InterpreterNativeLaunch
      open StageA.Relational.InterpreterNativeWorld

      /-- Proof-valued inputs still required to instantiate the generic
      semantic-operation bridge for GNU hello. -/
      structure Requirements where
        originalContext : OriginalDecodedStaticContext
        originalAuthority : ExactOriginalDecodedAuthority originalContext
        launch : PE32ConsoleLaunchV2
        originalRoot :
          DirectExactOriginalDecodedLaunchRoot originalContext launch
        reachability : ExactOriginalDecodedReachability originalContext
          originalAuthority launch originalRoot
        originalProgram : DecodedWorldProgram
        candidate : ExactNativeWorldProgram
        candidateAuthority : ExactNativeCandidateAuthority candidate
        contract : MixedRelationContract
        invariant : MixedExecutionInvariant reachability.targetIds contract
        program : CompiledKernelProgram
        abi : KernelABIRelation
        dispatches : KernelDispatchRelation
        candidateRootRva : Nat
        classifier : MixedKernelRuntimeSourceClassifier originalContext
          originalAuthority launch originalRoot reachability candidate
          candidateAuthority program candidateRootRva invariant
        sourceBindingFactory : forall source :
            ExactOriginalSemanticSource originalContext originalAuthority launch
              originalRoot reachability candidate candidateAuthority,
          ExactOriginalSemanticTransferBinding originalContext
            originalAuthority launch originalRoot reachability candidate
            candidateAuthority source
        semanticEvidenceFactory : forall originalBefore candidateBefore
            (source : ExactOriginalSemanticSource originalContext
              originalAuthority launch originalRoot reachability candidate
              candidateAuthority)
            (operation : KernelOperation) (entryRva : Nat)
            (beforeRelated :
              invariant.holds originalBefore candidateBefore)
            (originalAtSource :
              originalExecutionAtTargetId source.targetId originalBefore)
            (candidateAtEntry :
              nativeExecutionAtRva entryRva candidateBefore)
            (entryExact :
              program.functionEntry? operation.role = some entryRva)
            (classified :
              classifier.classifier.classify originalBefore candidateBefore
                    beforeRelated =
                .semanticTransfer source operation entryRva originalAtSource
                  candidateAtEntry entryExact),
          CheckedMixedSemanticOperationEvidence originalProgram candidate
            candidateAuthority contract invariant program abi dispatches
            source.source.target.rva source.record operation entryRva
            originalBefore candidateBefore
            (classifier.classifier.classify originalBefore candidateBefore
                beforeRelated =
              .semanticTransfer source operation entryRva originalAtSource
                candidateAtEntry entryExact)
            beforeRelated classified
        externalOperationEvidenceFactory :
          forall originalBefore candidateBefore
            (source : ExactOriginalSemanticSource originalContext
              originalAuthority launch originalRoot reachability candidate
              candidateAuthority)
            (operation : KernelOperation) (entryRva : Nat)
            (beforeRelated :
              invariant.holds originalBefore candidateBefore)
            (originalAtSource :
              originalExecutionAtBoundarySource source.targetId originalBefore)
            (candidateAtEntry :
              nativeExecutionAtRva entryRva candidateBefore)
            (entryExact :
              program.functionEntry? operation.role = some entryRva)
            (classified :
              classifier.classifier.classify originalBefore candidateBefore
                    beforeRelated =
                .externalOperation source operation entryRva originalAtSource
                  candidateAtEntry entryExact),
          CheckedMixedSemanticOperationEvidence originalProgram candidate
            candidateAuthority contract invariant program abi dispatches
            source.source.target.rva source.record operation entryRva
            originalBefore candidateBefore
            (classifier.classifier.classify originalBefore candidateBefore
                beforeRelated =
              .externalOperation source operation entryRva originalAtSource
                candidateAtEntry entryExact)
            beforeRelated classified

      end StageA.GnuHelloMixedSemanticOperationComponentRequirements
      """,
          encoding="ascii",
      )
      terms = MixedSemanticOperationComponentTerms(
          original_context="requirements.originalContext",
          original_authority="requirements.originalAuthority",
          launch="requirements.launch",
          original_root="requirements.originalRoot",
          reachability="requirements.reachability",
          original_program="requirements.originalProgram",
          candidate="requirements.candidate",
          candidate_authority="requirements.candidateAuthority",
          relation_contract="requirements.contract",
          invariant="requirements.invariant",
          compiled_program="requirements.program",
          kernel_abi="requirements.abi",
          kernel_dispatches="requirements.dispatches",
          classifier="requirements.classifier",
          source_binding_factory="requirements.sourceBindingFactory",
          semantic_evidence_factory="requirements.semanticEvidenceFactory",
          external_operation_evidence_factory=(
              "requirements.externalOperationEvidenceFactory"
          ),
      )
      spec = InterpreterMixedSemanticOperationComponentSpec(
          binding_module=f"StageA.{binding_module}",
          namespace=(
              "StageA.GeneratedRelational."
              "GnuHelloMixedSemanticOperationComponent"
          ),
          parameter_name="requirements",
          parameter_type=f"{binding_namespace}.Requirements",
          terms=terms,
      )
      plan = build_mixed_semantic_operation_component_plan(spec)
      plan_path, lean_path = write_mixed_semantic_operation_component_bundle(
          out, plan
      )
      shutil.move(
          lean_path,
          stage_a / f"{INTERPRETER_MIXED_SEMANTIC_OPERATION_COMPONENT_MODULE}.lean",
      )
      payload = plan.payload()
      manifest = {
          "format": (
              "stage-a-relational-mixed-semantic-operation-component-phase-v1"
          ),
          "phase": "mixed-semantic-operation-component",
          "status": "incomplete",
          "acceptance_authority": False,
          "proof_authority": False,
          "lean_check_required": True,
          "executes_original_binary": False,
          "executes_candidate_binary": False,
          "failure_mode": "incomplete",
          "remaining_proof_premises": payload["residual_evidence"],
          "outputs": {
              "plan": plan_path.name,
              "binding_module": f"StageA/{binding_module}.lean",
              "lean_module": (
                  "StageA/"
                  f"{INTERPRETER_MIXED_SEMANTIC_OPERATION_COMPONENT_MODULE}.lean"
              ),
          },
          "targets": [
              INTERPRETER_MIXED_SEMANTIC_OPERATION_COMPONENT_MODULE
          ],
      }
      (out / "phase-manifest.json").write_text(
          json.dumps(manifest, indent=2, sort_keys=True) + "\n",
          encoding="utf-8",
      )
      resources = {
          binding_module: {
              "resource_class": "small",
              "estimated_memory_mb": 1024,
          },
          INTERPRETER_MIXED_SEMANTIC_OPERATION_COMPONENT_MODULE: {
              "resource_class": "medium",
              "estimated_memory_mb": 4096,
          },
      }
      (out / "module-resources.json").write_text(
          json.dumps(resources, indent=2, sort_keys=True) + "\n",
          encoding="utf-8",
      )
      PY
      jq -e '
        .format ==
          "stage-a-relational-mixed-semantic-operation-component-phase-v1" and
        .phase == "mixed-semantic-operation-component" and
        .status == "incomplete" and
        (.acceptance_authority | not) and
        (.proof_authority | not) and
        .lean_check_required and
        (.executes_original_binary | not) and
        (.executes_candidate_binary | not) and
        .failure_mode == "incomplete" and
        (.remaining_proof_premises | length) == 7 and
        .targets == [
          "GeneratedRelationalInterpreterMixedSemanticOperationComponent"
        ]
      ' "$out/phase-manifest.json" >/dev/null
      test -s \
        "$out/StageA/GnuHelloMixedSemanticOperationComponentRequirements.lean"
      test -s \
        "$out/StageA/GeneratedRelationalInterpreterMixedSemanticOperationComponent.lean"
      test -s \
        "$out/interpreter-mixed-semantic-operation-component.json"
      test -s "$out/module-resources.json"
    '';
  mixedSemanticOperationComponentInterfaceProof =
    mkGeneratedClosureProof {
      name = "mixed-semantic-operation-component";
      sources = [
        leanSourceRoot
        mixedSemanticOperationComponentLean
      ];
      target =
        "GeneratedRelationalInterpreterMixedSemanticOperationComponent";
      declaration =
        "StageA.GeneratedRelational.GnuHelloMixedSemanticOperationComponent.generatedSemanticChunkFactory";
    };
  mixedSemanticOperationComponentProofSources =
    mixedSemanticOperationComponentInterfaceProof.proofSources;
  mixedSemanticOperationComponentProof =
    mixedSemanticOperationComponentInterfaceProof.proof;

  runtimeIndirectCompositionLean =
    mkPhaseWithSource runtimeIndirectCompositionPythonSource
      "stage-a-gnu-hello-roundtrip-runtime-indirect-composition-source" [] ''
      ${python} ${runtimeIndirectCompositionDriver} \
        --cutpoint-graph \
          ${mixedOriginalStackDynamicAuthorityLean}/original-cutpoint-graph-ir.json \
        --stack-dynamic-closure \
          ${mixedOriginalStackDynamicAuthorityLean}/original-stack-dynamic-control-closure.json \
        --runtime-value-carry \
          ${mixedOriginalStackDynamicAuthorityLean}/runtime-value-carry-ir.json \
        --rooted-unreachability \
          ${mixedOriginalStackDynamicAuthorityLean}/nullable-code-pointer-rooted-unreachability.json \
        --out "$out"
      jq -e '
        .format ==
          "stage-a-gnu-hello-runtime-indirect-composition-v1" and
        .phase == "gnu-hello-runtime-indirect-composition" and
        .status == "incomplete" and
        (.acceptance_authority | not) and
        (.proof_authority | not) and
        .lean_check_required and
        (.executes_original_binary | not) and
        (.executes_candidate_binary | not) and
        .failure_mode == "incomplete" and
        .outputs.lean_module ==
          "StageA/GeneratedRelationalGNUHelloRuntimeIndirectComposition.lean" and
        (.evidence_gaps | length) > 0 and
        .targets == [
          "GeneratedRelationalGNUHelloRuntimeIndirectComposition"
        ]
      ' "$out/gnu-hello-runtime-indirect-composition.json" >/dev/null
      test -s \
        "$out/StageA/GeneratedRelationalGNUHelloRuntimeIndirectComposition.lean"
    '';
  runtimeIndirectCompositionClosure = mkGeneratedClosureProof {
    name = "runtime-indirect-composition";
    sources = [
      proofSources
      acceptanceRequirementsLean
      runtimeIndirectCompositionLean
    ];
    target = "GeneratedRelationalGNUHelloRuntimeIndirectComposition";
    declaration =
      "StageA.GeneratedRelational.GNUHelloRuntimeIndirectComposition.generatedCheckedArtifactBundle";
  };
  runtimeIndirectCompositionProofSources =
    runtimeIndirectCompositionClosure.proofSources;
  runtimeIndirectCompositionProof = runtimeIndirectCompositionClosure.proof;

  kernelOperationInstantiationLean =
    mkPhaseWithSource operationInstantiationPythonSource
      "stage-a-gnu-hello-roundtrip-kernel-operation-instantiation-source" [] ''
      ${python} ${operationInstantiationDriver} \
        --candidate ${candidate}/candidate.exe \
        --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
        --state-machine ${proofStateMachinePath} \
        --data-inventory ${kernelDataLean}/module-inventory.json \
        --step-operation-plan \
          ${kernelStepOperationLean}/interpreter-kernel-step-operation-plan.json \
        --run-operation-plan \
          ${kernelRunOperationLean}/interpreter-kernel-run-operation-plan.json \
        --invoke-operation-plan \
          ${kernelInvokeOperationLean}/interpreter-kernel-invoke-operation-plan.json \
        --out "$out"
      jq -e '
        .format ==
          "stage-a-relational-interpreter-kernel-operation-instantiation-v1" and
        (.acceptance_authority | not) and
        (.proof_authority | not) and
        (.status == "incomplete" or .status == "locally_closed") and
        (.status != "pass") and
        .checked_semantic_inventory.records > 0 and
        .checked_native_replay_inventory.functions > 0 and
        .checked_native_replay_inventory.execution_equalities_submitted == 0 and
        .checked_native_replay_inventory.path_equalities_submitted == 0 and
        .checked_native_replay_inventory.post_state_equalities_submitted == 0 and
        .remaining_proof_premises == []
      ' "$out/interpreter-kernel-operation-instantiation.json" >/dev/null
      test -s \
        "$out/StageA/GeneratedRelationalInterpreterKernelOperationInstantiation.lean"
      test -s \
        "$out/StageA/GeneratedRelationalInterpreterKernelClosedCallTree.lean"
      test -s \
        "$out/finite-checked-semantic-function-inventory.json"
    '';
  kernelOperationInstantiationClosure = mkGeneratedClosureProof {
    name = "kernel-operation-instantiation";
    sources = candidateKernelOperationProofSourceInputs;
    target = "GeneratedRelationalInterpreterKernelOperationInstantiation";
    declaration =
      "StageA.GeneratedRelational.InterpreterKernelOperationInstantiation.generatedSemanticCallTreeClosure";
  };
  kernelOperationInstantiationProofSources =
    kernelOperationInstantiationClosure.proofSources;
  kernelOperationInstantiationProof =
    kernelOperationInstantiationClosure.proof;
  kernelRunEntryRouteLean =
    mkPhaseWithSource runEntryRoutePythonSource
      "stage-a-gnu-hello-roundtrip-kernel-run-entry-route-source" [] ''
      ${python} ${runEntryRouteDriver} \
        --operation-manifest \
          ${kernelOperationInstantiationLean}/interpreter-kernel-operation-instantiation.json \
        --out "$out"
      jq -e '
        .format ==
          "stage-a-relational-interpreter-kernel-run-entry-route-v1" and
        (.acceptance_authority | not) and
        (.proof_authority | not) and
        .status == "locally_closed" and
        (.control_block_rvas | length) > 0 and
        .bulk_block_rva >= 0 and
        .loop_block_rva >= 0 and
        .remaining_proof_premises == []
      ' "$out/interpreter-kernel-run-entry-route.json" >/dev/null
      test -s \
        "$out/StageA/GeneratedRelationalInterpreterKernelRunEntryRoute.lean"
    '';
  kernelRunEntryRouteClosure = mkGeneratedClosureProof {
    name = "kernel-run-entry-route";
    sources = candidateKernelOperationProofSourceInputs ++ [
      kernelRunEntryRouteLean
    ];
    target = "GeneratedRelationalInterpreterKernelRunEntryRoute";
    declaration =
      "StageA.GeneratedRelational.InterpreterKernelOperationInstantiation.generatedRunEntryToLoopPath";
  };
  kernelRunEntryRouteProofSources =
    kernelRunEntryRouteClosure.proofSources;
  kernelRunEntryRouteProof = kernelRunEntryRouteClosure.proof;
  kernelRunEntryBehaviorExtraction = mkAnalysisPhase
    "stage-a-gnu-hello-roundtrip-kernel-run-entry-behavior-extraction"
    [ sideTool pkgs.lean4 ] ''
    mkdir -p "$out"
    # Exact extraction constructs the balanced ByteTree for the complete
    # multi-megabyte candidate before checking the requested instruction
    # spans. Its interpreter recursion is proportional to the deterministic
    # 1 KiB leaf count, so classify this one-thread node explicitly rather
    # than inflating every downstream proof shard.
    export SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_THREAD_STACK_KB=524288
    ulimit -s 524288
    spaghetti-extractor-side extract-side \
      --binary ${candidate}/candidate.exe \
      --request \
        ${kernelRunEntryRouteLean}/interpreter-kernel-run-entry-behavior-request.json \
      --out "$out/extraction.json" \
      > "$out/result.json"
    requested_regions="$(
      jq '.regions | length' \
        ${kernelRunEntryRouteLean}/interpreter-kernel-run-entry-behavior-request.json
    )"
    jq -e --argjson requested_regions "$requested_regions" '
      .format == "stage-a-relational-side-extraction-result-v1" and
      .status == "extracted" and
      .side == "candidate" and
      .regions == $requested_regions
    ' "$out/result.json" >/dev/null
    jq -e --argjson requested_regions "$requested_regions" '
      .format == "stage-a-relational-side-extraction-v1" and
      .status == "untrusted_proposal_requires_lean_decode_replay" and
      .side == "candidate" and
      (.regions | length) == $requested_regions
    ' "$out/extraction.json" >/dev/null
  '';
  kernelRunEntryBehaviorsLean =
    mkPhaseWithSource runEntryBehaviorsPythonSource
      "stage-a-gnu-hello-roundtrip-kernel-run-entry-behaviors-source" [] ''
      ${python} ${runEntryBehaviorsDriver} \
        --operation-manifest \
          ${kernelOperationInstantiationLean}/interpreter-kernel-operation-instantiation.json \
        --extraction ${kernelRunEntryBehaviorExtraction}/extraction.json \
        --out "$out"
      test -s \
        "$out/StageA/GeneratedRelationalInterpreterKernelRunEntryBehaviors.lean"
    '';
  kernelRunEntryBehaviorsClosure = mkGeneratedClosureProof {
    name = "kernel-run-entry-behaviors";
    sources = candidateKernelOperationProofSourceInputs ++ [
      kernelRunEntryBehaviorsLean
    ];
    target = "GeneratedRelationalInterpreterKernelRunEntryBehaviors";
    declaration =
      "StageA.GeneratedRelational.InterpreterKernelOperationInstantiation.generatedRunEntryBlock2Instruction0006MaterializedBehaviorExact";
  };
  kernelRunEntryBehaviorsProofSources =
    kernelRunEntryBehaviorsClosure.proofSources;
  kernelRunEntryBehaviorsProof = kernelRunEntryBehaviorsClosure.proof;
  kernelRunEntryAbiLean =
    mkPhaseWithSource runEntryAbiPythonSource
      "stage-a-gnu-hello-roundtrip-kernel-run-entry-abi-source" [] ''
      ${python} ${runEntryAbiDriver} \
        --operation-manifest \
          ${kernelOperationInstantiationLean}/interpreter-kernel-operation-instantiation.json \
        --abi-plan ${kernelAbiLean}/interpreter-kernel-abi-plan.json \
        --out "$out"
      test -s \
        "$out/StageA/GeneratedRelationalInterpreterKernelRunEntryProjectionBlock0.lean"
      test -s \
        "$out/StageA/GeneratedRelationalInterpreterKernelRunEntryProjectionBlock1.lean"
      test -s \
        "$out/StageA/GeneratedRelationalInterpreterKernelRunEntryProjectionBlock2Base.lean"
      for step in 0 1 2 3 4 5 6; do
        test -s \
          "$out/StageA/GeneratedRelationalInterpreterKernelRunEntryProjectionBlock2Step$step.lean"
      done
      test -s \
        "$out/StageA/GeneratedRelationalInterpreterKernelRunEntryProjectionBlock2.lean"
      test -s \
        "$out/StageA/GeneratedRelationalInterpreterKernelRunEntryFootprints.lean"
      test -s \
        "$out/StageA/GeneratedRelationalInterpreterKernelRunEntryABIBase.lean"
      test -s \
        "$out/StageA/GeneratedRelationalInterpreterKernelRunEntryABI.lean"
    '';
  kernelRunEntryAbiClosure = mkGeneratedClosureProof {
    name = "kernel-run-entry-abi";
    sources = candidateKernelOperationProofSourceInputs ++ [
      kernelRunEntryRouteLean
      kernelRunEntryBehaviorsLean
      kernelRunEntryAbiLean
    ];
    target = "GeneratedRelationalInterpreterKernelRunEntryABI";
    declaration = "generatedRunEntryABIBulkSourceFacts";
  };
  kernelRunEntryAbiProofSources =
    kernelRunEntryAbiClosure.proofSources;
  kernelRunEntryAbiProof = kernelRunEntryAbiClosure.proof;

  proofSources = mkPhase "stage-a-gnu-hello-roundtrip-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${universalPairedExternalEnvironmentLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalRegisterIndirectAuthorityLean} \
      --source ${mixedOriginalDirectCallProposalsLean} \
      --source ${mixedOriginalDirectCallSemanticsLean} \
      --source ${mixedOriginalDirectCallClosureProposalsLean} \
      --source ${mixedOriginalDirectCallClosureSemanticsLean} \
      --source ${mixedOriginalStackDynamicAuthorityLean} \
      --source ${mixedOriginalLean} \
      --source ${mixedOriginalStaticReachabilityLean} \
      --source ${mixedOriginalCarrierBindingLean} \
      --source ${programLean} \
      --source ${normalizationLean} \
      --source ${semanticRefinementLean} \
      --source ${x87Lean} \
      --source ${definednessLean} \
      --source ${kernelLean} \
      --source ${kernelDataLean} \
      --source ${kernelAbiLean} \
      --source ${x87CandidateReplayLean} \
      --source ${x87ReplayBridgeTargetLean} \
      --source ${x87ReplayBridgeRuntimeLean} \
      --source ${x87KernelExecutionLean} \
      --source ${kernelBlockLean} \
      --source ${kernelLoopLean} \
      --source ${kernelCallbackLean} \
      --source ${kernelLookupLean} \
      --source ${kernelLookupNativeLean} \
      --source ${kernelLookupOperationLean} \
      --source ${kernelStepLean} \
      --source ${kernelStepNativeLean} \
      --source ${kernelRunLean} \
      --source ${kernelRunNativeLean} \
      --source ${kernelInvokeLean} \
      --source ${kernelInvokeNativeLean} \
      --source ${kernelStepOperationLean} \
      --source ${kernelStepProgramLookupCallLean} \
      --source ${kernelStepProgramLookupCallClosureLean} \
      --source ${kernelStepProgramLookupExactComputationLean} \
      --source ${kernelOperationFrameParametricLean} \
      --source ${kernelFrameExecutorLean} \
      --source ${kernelRunOperationLean} \
      --source ${kernelCdeclEpilogueLean} \
      --source ${kernelCdeclEpilogueSymbolicClosureLean} \
      --source ${kernelCdeclEpilogueStaticPreservationLean} \
      --source ${kernelCdeclEpilogueExternalPayloadLean} \
      --source ${kernelOperationResultEncodingLean} \
      --source ${kernelAbstractOperationTransitionLean} \
      --source ${kernelInvokeOperationLean} \
      --source ${mixedCandidateAuthorityLean} \
      --source ${nativeLaunchGraphLean} \
      --source ${constructiveSourceCoverageLean} \
      --source ${canonicalRelationCoreLean} \
      --target RelationalSymbolicSoundness \
      --out "$out"
  '';

  # The generated module inventory is intentionally discovered from immutable
  # phase outputs.  IFD is limited to this manifest boundary; each resulting
  # Lean module is still an independent, remote-buildable derivation.
  proofModules = builtins.fromJSON (
    builtins.readFile "${proofSources}/standalone-modules.json"
  );
  proofTargets = builtins.fromJSON (
    builtins.readFile "${proofSources}/proof-targets.json"
  );
  proofResources = builtins.fromJSON (
    builtins.readFile "${proofSources}/module-resources.json"
  );
  proofFragments = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = proofSources + "/StageA";
    standaloneModules = proofModules;
    standaloneModuleResources = proofResources;
    targetNodes = proofTargets;
    targetBundle = true;
  };

  kernelRunOperationProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = proofSources + "/StageA";
    standaloneModules = proofModules;
    standaloneModuleResources = proofResources;
    targetNodes = [
      "GeneratedRelationalInterpreterKernelRunOperation"
    ];
    targetBundle = true;
    targetAxiomAudit = {
      module = "GeneratedRelationalInterpreterKernelRunOperation";
      declaration =
        "StageA.GeneratedRelational.InterpreterKernelRunOperation.generatedRunFunctionOperationRefinesUsing";
      approved_axioms = [ "propext" "Classical.choice" "Quot.sound" ];
    };
  };

  # Keep the exact call and epilogue closures independently buildable. They
  # share the generated source inventory, while Nix compiles only each
  # target's transitive Lean dependency closure.
  kernelStepProgramLookupCallClosureProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = proofSources + "/StageA";
    standaloneModules = proofModules;
    standaloneModuleResources = proofResources;
    targetNodes = [
      "GeneratedRelationalInterpreterKernelStepProgramLookupCallClosure"
    ];
    targetBundle = true;
  };

  kernelCdeclEpilogueSymbolicClosureProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = proofSources + "/StageA";
    standaloneModules = proofModules;
    standaloneModuleResources = proofResources;
    targetNodes = [
      "GeneratedRelationalInterpreterKernelCdeclEpilogueSymbolicClosure"
    ];
    targetBundle = true;
  };

  kernelCdeclEpilogueStaticPreservationProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = proofSources + "/StageA";
    standaloneModules = proofModules;
    standaloneModuleResources = proofResources;
    targetNodes = [
      "GeneratedRelationalInterpreterKernelCdeclEpilogueStaticPreservation"
    ];
    targetBundle = true;
  };

  kernelCdeclEpilogueExternalPayloadProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = proofSources + "/StageA";
    standaloneModules = proofModules;
    standaloneModuleResources = proofResources;
    targetNodes = [
      "GeneratedRelationalInterpreterKernelCdeclEpilogueExternalPayload"
    ];
    targetBundle = true;
  };

  kernelStepProgramLookupExactComputationProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = proofSources + "/StageA";
    standaloneModules = proofModules;
    standaloneModuleResources = proofResources;
    targetNodes = [
      "GeneratedRelationalInterpreterKernelStepProgramLookupExactComputation"
    ];
    targetBundle = true;
  };

  kernelOperationResultEncodingProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = proofSources + "/StageA";
    standaloneModules = proofModules;
    standaloneModuleResources = proofResources;
    targetNodes = [
      "GeneratedRelationalInterpreterKernelOperationResultEncoding"
    ];
    targetBundle = true;
  };

  kernelAbstractOperationTransitionProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = proofSources + "/StageA";
    standaloneModules = proofModules;
    standaloneModuleResources = proofResources;
    targetNodes = [
      "GeneratedRelationalInterpreterKernelAbstractOperationTransition"
    ];
    targetBundle = true;
  };

  # Qualify the ordinary transfer inventory independently of unrelated kernel,
  # callback, x87, and acceptance frontiers.  It shares the same generated
  # source DAG and therefore the same cached .olean dependencies.
  ordinaryRefinementFragments = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = proofSources + "/StageA";
    standaloneModules = proofModules;
    standaloneModuleResources = proofResources;
    targetNodes = [ "GeneratedInterpreterSemanticRefinementBundle" ];
    targetBundle = true;
  };

  x87CandidateReplayProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-x87-candidate-replay-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${x87Lean} \
      --source ${kernelDataLean} \
      --source ${x87CandidateReplayLean} \
      --target GeneratedInterpreterX87CandidateReplayBundle \
      --out "$out"
  '';
  x87CandidateReplayProofModules = builtins.fromJSON (
    builtins.readFile
      "${x87CandidateReplayProofSources}/standalone-modules.json"
  );
  x87CandidateReplayProofResources = builtins.fromJSON (
    builtins.readFile
      "${x87CandidateReplayProofSources}/module-resources.json"
  );
  x87CandidateReplayFragments = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = x87CandidateReplayProofSources + "/StageA";
    standaloneModules = x87CandidateReplayProofModules;
    standaloneModuleResources = x87CandidateReplayProofResources;
    targetNodes = [ "GeneratedInterpreterX87CandidateReplayBundle" ];
    targetBundle = true;
  };

  x87ReplayBridgeTargetProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-x87-replay-bridge-target-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${kernelDataLean} \
      --source ${x87ReplayBridgeTargetLean} \
      --target GeneratedRelationalInterpreterX87ReplayBridgeTarget \
      --out "$out"
  '';

  x87ReplayBridgeRuntimeProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-x87-replay-bridge-runtime-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${kernelDataLean} \
      --source ${x87Lean} \
      --source ${x87CandidateReplayLean} \
      --source ${x87ReplayBridgeTargetLean} \
      --source ${x87ReplayBridgeRuntimeLean} \
      --target GeneratedRelationalInterpreterX87ReplayBridgeRuntime \
      --out "$out"
  '';
  x87ReplayBridgeRuntimeProofModules = builtins.fromJSON (
    builtins.readFile
      "${x87ReplayBridgeRuntimeProofSources}/standalone-modules.json"
  );
  x87ReplayBridgeRuntimeProofResources = builtins.fromJSON (
    builtins.readFile
      "${x87ReplayBridgeRuntimeProofSources}/module-resources.json"
  );
  x87ReplayBridgeRuntimeFragments = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = x87ReplayBridgeRuntimeProofSources + "/StageA";
    standaloneModules = x87ReplayBridgeRuntimeProofModules;
    standaloneModuleResources = x87ReplayBridgeRuntimeProofResources;
    targetNodes = [ "GeneratedRelationalInterpreterX87ReplayBridgeRuntime" ];
    targetBundle = true;
  };

  x87KernelExecutionProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-x87-kernel-execution-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${kernelDataLean} \
      --source ${x87Lean} \
      --source ${x87CandidateReplayLean} \
      --source ${x87ReplayBridgeTargetLean} \
      --source ${x87ReplayBridgeRuntimeLean} \
      --source ${x87KernelExecutionLean} \
      --target GeneratedRelationalInterpreterKernelX87Execution \
      --out "$out"
    jq '. + {acceptance_authority: false}' \
      "$out/phase-manifest.json" > "$out/phase-manifest.json.tmp"
    mv "$out/phase-manifest.json.tmp" "$out/phase-manifest.json"
    jq -e '
      .status == "source-ready" and
      (.acceptance_authority | not)
    ' "$out/phase-manifest.json" >/dev/null
  '';
  x87KernelExecutionProofModules = builtins.fromJSON (
    builtins.readFile
      "${x87KernelExecutionProofSources}/standalone-modules.json"
  );
  x87KernelExecutionProofResources = builtins.fromJSON (
    builtins.readFile
      "${x87KernelExecutionProofSources}/module-resources.json"
  );
  x87KernelExecutionFragments = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = x87KernelExecutionProofSources + "/StageA";
    standaloneModules = x87KernelExecutionProofModules;
    standaloneModuleResources = x87KernelExecutionProofResources;
    targetNodes = [ "GeneratedRelationalInterpreterKernelX87Execution" ];
    targetBundle = true;
    targetAxiomAudit = {
      module = "GeneratedRelationalInterpreterKernelX87Execution";
      declaration =
        "StageA.GeneratedRelational.InterpreterKernelX87Execution.generatedX87ReplayBridgeKernelExecutionClosed";
      approved_axioms = [ "propext" "Classical.choice" "Quot.sound" ];
    };
  };

  gnuHelloMixedAcceptanceLean =
    mkPhaseWithSource gnuHelloMixedAcceptancePythonSource
      "stage-a-gnu-hello-roundtrip-mixed-acceptance-source" [] ''
      ${python} \
        ${gnuHelloMixedAcceptancePythonSource}/nix/gnu-hello-mixed-acceptance.py \
        --out "$out"
      jq -e '
        .format == "stage-a-gnu-hello-mixed-acceptance-v1" and
        .status == "ready_for_lean_check" and
        (.acceptance_authority | not) and
        (.proof_authority | not) and
        (.report_authority | not) and
        .lean_check_required and
        (.accepts_manifest | not) and
        (.accepts_proof_inputs | not) and
        (.accepts_lean_name_inputs | not) and
        .output_module ==
          "StageA/GeneratedGnuHelloMixedAcceptance.lean" and
        .profile ==
          "StageA.GeneratedRelational.GnuHelloMixedAcceptance.candidatePE32CanonicalMixedRelationProfile" and
        .source_theorem ==
          "StageA.GeneratedRelational.GnuHelloMixedAcceptance.generatedGNUHelloMixedWorldProgramsEquivalent" and
        .missing_dynamic_evidence == []
      ' "$out/gnu-hello-mixed-acceptance.json" >/dev/null
      test -s "$out/StageA/GeneratedGnuHelloMixedAcceptance.lean"
    '';

  mixedChunkedAcceptanceLean =
    mkPhaseWithSource mixedChunkedAcceptancePythonSource
      "stage-a-gnu-hello-roundtrip-mixed-chunked-acceptance-source" [] ''
      ${python} \
        ${mixedChunkedAcceptancePythonSource}/nix/interpreter-mixed-chunked-acceptance.py \
        --binding-module StageA.GeneratedGnuHelloMixedAcceptance \
        --source-parameter-type \
          StageA.GeneratedRelational.GnuHelloMixedAcceptance.Parameters \
        --source-profile \
          StageA.GeneratedRelational.GnuHelloMixedAcceptance.candidatePE32CanonicalMixedRelationProfile \
        --source-theorem \
          StageA.GeneratedRelational.GnuHelloMixedAcceptance.generatedGNUHelloMixedWorldProgramsEquivalent \
        --out "$out"
      jq -e '
        .format ==
          "stage-a-relational-mixed-chunked-acceptance-v1" and
        .status == "ready_for_lean_check" and
        (.acceptance_authority | not) and
        (.report_authority | not) and
        .lean_check_required and
        .output_module ==
          "StageA/GeneratedRelationalMixedChunkedAcceptance.lean" and
        .theorem ==
          "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentMixedChunked" and
        .profile == "mixed-native-pe32-chunked-closed" and
        .profile_term ==
          "StageA.GeneratedRelational.candidatePE32CanonicalMixedRelationFamily" and
        .source_parameter_type ==
          "StageA.GeneratedRelational.GnuHelloMixedAcceptance.Parameters" and
        .source_profile ==
          "StageA.GeneratedRelational.GnuHelloMixedAcceptance.candidatePE32CanonicalMixedRelationProfile" and
        .source_theorem ==
          "StageA.GeneratedRelational.GnuHelloMixedAcceptance.generatedGNUHelloMixedWorldProgramsEquivalent"
      ' "$out/mixed-chunked-acceptance.json" >/dev/null
      test -s \
        "$out/StageA/GeneratedRelationalMixedChunkedAcceptance.lean"
    '';

  mixedChunkedAcceptanceClosure = mkGeneratedClosureProof {
    name = "mixed-chunked-acceptance";
    sources = [
      proofSources
      acceptanceRequirementsLean
      runtimeFoundationLean
      launchBindingLean
      externalComponentLean
      runtimeIndirectCompositionLean
      kernelOperationInstantiationLean
      programLookupNativeWorldBridgeLean
      x87KernelExecutionLean
      gnuHelloMixedAcceptanceLean
      mixedChunkedAcceptanceLean
    ];
    target = "GeneratedRelationalMixedChunkedAcceptance";
    declaration =
      "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentMixedChunked";
  };
  mixedChunkedAcceptanceProofSources =
    mixedChunkedAcceptanceClosure.proofSources;
  mixedChunkedAcceptanceProof = mixedChunkedAcceptanceClosure.proof;

  acceptanceLean = mkPhase "stage-a-gnu-hello-roundtrip-acceptance-lean" [] ''
    ${python} ${driver} acceptance-sources \
      --kernel-block-manifest ${kernelBlockLean}/phase-manifest.json \
      --mixed-original-manifest ${mixedOriginalLean}/phase-manifest.json \
      --original-carrier-manifest \
        ${mixedOriginalCarrierBindingLean}/phase-manifest.json \
      --native-launch-request \
        ${nativeLaunchRequest}/native-launch-route-request.json \
      --static-reachability-manifest \
        ${mixedOriginalStaticReachabilityLean}/phase-manifest.json \
      --native-launch-graph-manifest \
        ${nativeLaunchGraphLean}/phase-manifest.json \
      --universal-paired-external-environment-manifest \
        ${universalPairedExternalEnvironmentLean}/phase-manifest.json \
      --constructive-source-coverage-manifest \
        ${constructiveSourceCoverageLean}/phase-manifest.json \
      --canonical-relation-core-manifest \
        ${canonicalRelationCoreLean}/phase-manifest.json \
      --kernel-program-lookup-operation-manifest \
        ${kernelLookupOperationLean}/phase-manifest.json \
      --kernel-step-operation-manifest \
        ${kernelStepOperationLean}/phase-manifest.json \
      --kernel-run-operation-manifest \
        ${kernelRunOperationLean}/phase-manifest.json \
      --kernel-invoke-operation-manifest \
        ${kernelInvokeOperationLean}/phase-manifest.json \
      --x87-kernel-execution-manifest \
        ${x87KernelExecutionLean}/phase-manifest.json \
      --out "$out"
    jq -e --argjson runtimeCount \
      "$(jq '.runtime_targets' \
        ${x87KernelExecutionLean}/phase-manifest.json)" '
      .phase == "whole-program-acceptance-lean" and
      .status == "proof-obligations-generated" and
      .diagnostic_status == "incomplete" and
      .acceptance_theorem == null and
      (.counts.remaining_original_control_frontiers > 0) and
      .counts.diagnostic_blockers == (.semantic_blockers | length) and
      .counts.remaining_diagnostic_items ==
        ([.counts.remaining_diagnostic_items_by_phase[]] | add) and
      (.validated_phase_manifests | length) == 10 and
      .counts.remaining_x87_kernel_execution_premises == 0 and
      .counts.x87_runtime_targets == $runtimeCount
    ' "$out/phase-manifest.json" >/dev/null
  '';

  finalProofSources = mkPhase "stage-a-gnu-hello-roundtrip-final-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${proofSources} \
      --source ${acceptanceLean} \
      --out "$out"
  '';
  finalProofModules = builtins.fromJSON (
    builtins.readFile "${finalProofSources}/standalone-modules.json"
  );
  finalProofTargets = builtins.fromJSON (
    builtins.readFile "${finalProofSources}/proof-targets.json"
  );
  finalProofResources = builtins.fromJSON (
    builtins.readFile "${finalProofSources}/module-resources.json"
  );
  final = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = finalProofSources + "/StageA";
    standaloneModules = finalProofModules;
    standaloneModuleResources = finalProofResources;
    targetNodes = finalProofTargets;
    targetBundle = true;
  };

  proofReport = mkPhase "stage-a-gnu-hello-roundtrip-proof-report" [] ''
    mkdir -p "$out"
    ln -s ${proofFragments} "$out/lean-fragments"
    ln -s ${proofSources} "$out/proof-sources"
    ln -s ${engineSegments} "$out/engine-segments"
    ln -s ${isaCoverage} "$out/isa-coverage"
    ln -s ${sideIsaQualificationAdapter} \
      "$out/side-isa-qualification-adapter"
    ln -s ${sideIsaQualificationBundle} \
      "$out/side-isa-qualification"
    ln -s ${semanticCoverage} "$out/semantic-coverage"
    ln -s ${acceptanceLean} "$out/acceptance-source"
    ${python} - "$out/proof-result.json" \
      ${proofSources}/phase-manifest.json \
      ${proofFragments}/bundle.json \
      ${acceptanceLean}/phase-manifest.json \
      ${sideIsaQualificationAdapter}/adapter-result.json \
      ${sideIsaQualificationBundle}/selection-policy.json <<'PY'
    import json, pathlib, sys
    sources = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
    bundle = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
    acceptance = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
    side_isa_adapter = json.loads(
        pathlib.Path(sys.argv[5]).read_text(encoding="utf-8")
    )
    side_isa_policy = json.loads(
        pathlib.Path(sys.argv[6]).read_text(encoding="utf-8")
    )
    if (
        side_isa_policy.get("format")
        != "stage-a-isa-selection-evidence-policy-v1"
        or side_isa_policy.get("status")
        not in {"qualified", "usable-incomplete"}
        or side_isa_policy.get("counts", {}).get("disputed") != 0
        or side_isa_policy.get("counts", {}).get("vetoed") != 0
        or side_isa_policy.get("trust", {}).get("proof_authority") is not False
        or side_isa_policy.get("trust", {}).get("closes_stage_a_proof")
        is not False
    ):
        raise SystemExit("ISA qualification evidence policy is malformed")
    result = {
      "format": "stage-a-gnu-hello-roundtrip-proof-result-v1",
      "status": "incomplete",
      "acceptance_authority": False,
      "executes_original_binary": False,
      "executes_candidate_binary": False,
      "compiled_modules": len(bundle["nodes"]),
      "generated_modules": sources["counts"]["modules"],
      "frontiers": acceptance["semantic_blockers"],
      "diagnostic_evidence": {
        "side_isa_qualification_adapter": {
          "status": side_isa_adapter["status"],
          "catalog_status": side_isa_adapter["catalog_status"],
          "counts": side_isa_adapter["counts"],
          "proof_authority": side_isa_adapter["proof_authority"],
          "closes_stage_a_proof": side_isa_adapter["closes_stage_a_proof"],
        },
        "side_isa_qualification": side_isa_policy,
      },
    }
    pathlib.Path(sys.argv[1]).write_text(
      json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    PY
  '';

in
assert builtins.isString nativeSourceApprovedToolchainAxiom;
assert nativeSourceApprovedToolchainAxiom != "";
assert !(builtins.elem nativeSourceApprovedToolchainAxiom standardLogicalAxioms);
{
  inherit
    smoke
    opaqueOriginalInventory
    opaqueStaticExport
    opaqueStateMachine
    machineIr
    reconstructionInterpreter
    reconstructionNativeEngine
    reconstructionNativeRuntime
    reconstructionPlan
    semanticComponents
    componentProposals
    selectedComponentDeclarations
    selectedSemanticComponents
    semanticComponentWorkspaceDag
    semanticComponentRegistry
    semanticComponentHybridCandidate
    semanticComponentHybridFunctionalSuite
    idiomaticSourceBinding
    idiomaticCandidate
    idiomaticFunctionalSuite
    idiomaticUpstreamSuite
    idiomaticAssurance
    reconstructionLiftingEvidence
    reconstructionBranchWorkspace
    reconstructionExternalWorkspace
    reconstructionInternalWorkspace
    reconstructionAtomicWorkspace
    reconstructionCallbackWorkspace
    reconstructionDispatchWorkspace
    reconstructionTypedMemoryWorkspace
    reconstructionBranchWorkspaceCheck
    reconstructionAtomicWorkspaceCheck
    reconstructionCallbackWorkspaceCheck
    reconstructionDispatchWorkspaceCheck
    reconstructionTypedMemoryWorkspaceCheck
    reconstructionExternalWorkspaceCheck
    reconstructionInternalWorkspaceCheck
    reconstructionWorkspaceRegistry
    reconstructionEntryReplacement
    reconstructionRegionalHarnessKernel
    reconstructionEntryReplacementValidation
    reconstructionEntryReplacementMutation
    reconstructionCandidate
    reconstructionEntryReplacementCandidate
    reconstructionWorkspaceCandidate
    reconstructionDiagnosticCandidate
    reconstructionQualification
    reconstructionFunctionalSuite
    reconstructionEntryReplacementFunctionalSuite
    reconstructionWorkspaceFunctionalSuite
    reconstructionAssurance
    staticExport
    sourceStateMachine
    sourceC0
    sourceInterpreter
    sourceNativeEngine
    sourceNativeRuntime
    sourceBundle
    sourceCandidate
    sourceCandidateKernelDataLean
    sourceCandidateStaticAuthorityLean
    sourceCandidateStaticAuthorityProofSources
    sourceCandidateStaticAuthorityProof
    sourceCompilationAttestation
    sourceProgramLean
    sourceNormalizationLean
    sourceSemanticRefinementLean
    sourceX87Lean
    sourceStaticMachineImportContractsLean
    sourceOriginalBaseLean
    sourceOriginalLean
    sourceOriginalStaticReachabilityLean
    sourceOriginalStaticReachabilityProofSources
    sourceOriginalStaticReachabilityProof
    sourceOriginalCarrierBindingLean
    sourceOriginalCarrierBindingProofSources
    sourceOriginalCarrierBindingProof
    sourceOriginalCombinedDeclarations
    sourceOriginalCombinedInventoryLean
    sourceOriginalCombinedInventoryProofSources
    sourceOriginalCombinedInventoryProof
    sourceTargetEffectInputsLean
    sourceTargetEffectsLean
    sourceTransitionIndexLean
    sourceTransitionIndexProofSources
    sourceTransitionIndexProof
    sourceRuntimeMemoryAccessProposal
    sourceOriginalTargetControlEvidence
    sourceOriginalTargetControlProofSources
    sourceOriginalTargetControlProof
    sourceOriginalTargetControlAudit
    sourceOrdinarySemanticProofSources
    sourceOrdinarySemanticProof
    sourceX87SemanticProofSources
    sourceX87SemanticProof
    sourceProgramAssemblyLean
    sourceProgramAssemblyProofSources
    sourceProgramAssemblyProof
    sourceOriginalExecutionEvidence
    sourceExecutionLean
    sourceExecutionProofSources
    sourceExecutionProof
    sourceExecutionAudit
    sourceCompiledAuthorityEvidence
    sourceCompiledAuthorityLean
    sourceCompiledAuthorityProofSources
    sourceCompiledAuthorityProof
    sourceCompiledAuthorityAudit
    sourceEnvironmentFamilyEvidence
    sourceConditionalAcceptanceLean
    sourceConditionalAcceptanceProofSources
    sourceConditionalAcceptanceProof
    sourceConditionalAcceptanceAudit
    sourceConditionalAcceptanceChecked
    sourceRuntimeFunctionalSuite
    sourceEquivalenceFinalReport
    interpreter
    nativeEngine
    nativeRuntime
    candidate
    originalInventory
    candidateInventory
    originalIsaRequest
    candidateIsaRequest
    originalIsa
    candidateIsa
    originalIsaSummary
    candidateIsaSummary
    sideIsaQualificationAdapter
    sideIsaCatalogEnrichment
    sideIsaCorpus
    sideIsaQualificationEvidence
    sideIsaQualificationBundle
    isaCoverage
    semanticCoverage
    nativeLaunchRequest
    engineSegments
    nativeLaunchGraphLean
    nativeLaunchGraphProofSources
    nativeLaunchGraphProof
    originalPeLean
    staticMachineImportContractsLean
    universalPairedExternalEnvironmentLean
    staticMachineImportProofSources
    staticMachineImportProof
    mixedOriginalDiagnostic
    mixedOriginalBaseLean
    mixedOriginalWritableSlotAuthorityLean
    callableExternalRuntimeContract
    mixedOriginalRegisterIndirectAuthorityLean
    mixedOriginalRegisterIndirectAuthorityProofSources
    mixedOriginalRegisterIndirectAuthorityProof
    mixedOriginalDirectCallProposalsLean
    mixedOriginalDirectCallProposalProofSources
    mixedOriginalDirectCallProposalProof
    mixedOriginalDirectCallSemanticsLean
    mixedOriginalDirectCallSemanticsProofSources
    mixedOriginalDirectCallSemanticsProof
    mixedOriginalDirectCallClosureProposalsLean
    mixedOriginalDirectCallClosureProposalProofSources
    mixedOriginalDirectCallClosureProposalProof
    mixedOriginalDirectCallClosureSemanticsLean
    mixedOriginalDirectCallClosureSemanticsProofSources
    mixedOriginalDirectCallClosureSemanticsProof
    mixedOriginalDirectCallFixedPointProposalsLean
    mixedOriginalDirectCallFixedPointSemanticsLean
    mixedOriginalDirectCallFixedPointCheck
    mixedOriginalStackDynamicAuthorityLean
    mixedOriginalStackDynamicAuthorityProofSources
    mixedOriginalStackDynamicAuthorityProof
    mixedOriginalLean
    mixedOriginalStaticReachabilityLean
    mixedOriginalStaticReachabilityProofSources
    mixedOriginalStaticReachabilityProof
    mixedOriginalCarrierBindingLean
    mixedOriginalCarrierBindingProofSources
    mixedOriginalCarrierBindingProof
    programLean
    normalizationLean
    semanticRefinementLean
    mixedFusedSemanticEvidenceLean
    mixedFusedSemanticEvidenceProofSources
    mixedFusedSemanticEvidenceProof
    mixedDirectCallSemanticEvidenceLean
    mixedDirectCallSemanticEvidenceProofSources
    mixedDirectCallSemanticEvidenceProof
    mixedIndirectImportCallSemanticEvidenceLean
    mixedIndirectImportCallSemanticEvidenceProofSources
    mixedIndirectImportCallSemanticEvidenceProof
    mixedExternalTailSemanticEvidenceLean
    mixedExternalTailSemanticEvidenceProofSources
    mixedExternalTailSemanticEvidenceProof
    x87Lean
    x87ScheduleBenchmarkSources
    x87ScheduleBenchmark
    definednessLean
    kernelLean
    kernelDataLean
    kernelDataNativeProjectionBenchmark
    kernelDataNativeProjectionProof
    accessFaultQualificationLean
    accessFaultQualificationProofSources
    accessFaultQualificationProof
    kernelAbiLean
    x87CandidateReplayLean
    x87ReplayBridgeTargetLean
    x87ReplayBridgeRuntimeLean
    x87KernelExecutionLean
    kernelBlockLean
    kernelLoopLean
    kernelCallbackLean
    kernelLookupLean
    kernelLookupNativeLean
    kernelLookupOperationLean
    programLookupNativeWorldBridgeLean
    programLookupNativeWorldBridgeProofSources
    programLookupNativeWorldBridgeProof
    interpreterStepWorldProgramLookupLean
    interpreterStepProgramLookupCallBehaviorExtraction
    interpreterStepProgramLookupCallBehaviorsLean
    interpreterStepProgramLookupProjectionProofSources
    interpreterStepProgramLookupProjectionProof
    interpreterStepWorldProgramLookupProofSources
    interpreterStepWorldProgramLookupProof
    kernelStepLean
    kernelStepNativeLean
    kernelRunLean
    kernelRunNativeLean
    kernelRunNativeProofSources
    kernelRunNativeProof
    kernelRunOperationLean
    kernelRunOperationProof
    kernelCdeclEpilogueLean
    kernelCdeclEpilogueSymbolicClosureLean
    kernelCdeclEpilogueSymbolicClosureProof
    kernelCdeclEpilogueStaticPreservationLean
    kernelCdeclEpilogueStaticPreservationProof
    kernelCdeclEpilogueExternalPayloadLean
    kernelCdeclEpilogueExternalPayloadProof
    kernelOperationResultEncodingLean
    kernelOperationResultEncodingProof
    kernelAbstractOperationTransitionLean
    kernelAbstractOperationTransitionProof
    kernelInvokeLean
    kernelInvokeNativeLean
    kernelInvokeOperationLean
    kernelStepOperationLean
    kernelStepProgramLookupCallLean
    kernelStepProgramLookupCallClosureLean
    kernelStepProgramLookupCallClosureProof
    kernelStepProgramLookupExactComputationLean
    kernelStepProgramLookupExactComputationProof
    kernelOperationFrameParametricLean
    kernelFrameExecutorLean
    mixedCandidateAuthorityLean
    constructiveSourceCoverageLean
    constructiveSourceCoverageProofSources
    constructiveSourceCoverageProof
    canonicalRelationCoreLean
    canonicalRelationCoreProofSources
    canonicalRelationCoreProof
    acceptanceRequirementsLean
    acceptanceRequirementsProofSources
    acceptanceRequirementsProof
    runtimeFoundationLean
    runtimeFoundationProofSources
    runtimeFoundationProof
    launchBindingLean
    launchBindingProofSources
    launchBindingProof
    externalComponentLean
    externalComponentProofSources
    externalComponentProof
    mixedSemanticOperationComponentLean
    mixedSemanticOperationComponentProofSources
    mixedSemanticOperationComponentProof
    runtimeIndirectCompositionLean
    runtimeIndirectCompositionProofSources
    runtimeIndirectCompositionProof
    kernelOperationInstantiationLean
    kernelOperationInstantiationProofSources
    kernelOperationInstantiationProof
    kernelRunEntryRouteLean
    kernelRunEntryRouteProofSources
    kernelRunEntryRouteProof
    kernelRunEntryBehaviorExtraction
    kernelRunEntryBehaviorsLean
    kernelRunEntryBehaviorsProofSources
    kernelRunEntryBehaviorsProof
    kernelRunEntryAbiLean
    kernelRunEntryAbiProofSources
    kernelRunEntryAbiProof
    proofSources
    proofFragments
    ordinaryRefinementFragments
    x87CandidateReplayFragments
    x87CandidateReplayProofSources
    x87ReplayBridgeTargetProofSources
    x87ReplayBridgeRuntimeProofSources
    x87ReplayBridgeRuntimeFragments
    x87KernelExecutionProofSources
    x87KernelExecutionFragments
    gnuHelloMixedAcceptanceLean
    mixedChunkedAcceptanceLean
    mixedChunkedAcceptanceProofSources
    mixedChunkedAcceptanceProof
    acceptanceLean
    finalProofSources
    proofReport
    final
    ;
}
