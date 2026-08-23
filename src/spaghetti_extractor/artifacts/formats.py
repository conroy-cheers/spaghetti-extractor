"""Canonical identifiers for artifacts shared across pipeline boundaries.

Keep this module dependency-free.  Producers and consumers in static analysis,
round-trip qualification, and candidate reconstruction must agree on these values without
importing one another's implementation modules.
"""

SEMANTIC_IR_FORMAT = "spaghetti-extractor-static-semantic-ir-v1"
SEMANTIC_TRANSFER_CONTRACT_FORMAT = (
    "spaghetti-extractor-static-transfer-v1"
)
INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT = (
    "spaghetti-extractor-static-instruction-effects-v1"
)
INTERPRETER_NATIVE_BUILD_FORMAT = "spaghetti-extractor-interpreter-native-build-v1"
SPX_INTERPRETER_PROGRAM_FORMAT = "spaghetti-extractor-semantic-interpreter-program-v1"
SPX_INTERPRETER_PACKAGE_FORMAT = "spaghetti-extractor-semantic-interpreter-package-v1"
BEHAVIORAL_C_LAYOUT_INTENT_FORMAT = "spaghetti-extractor-behavioral-c-layout-intent-v1"
BEHAVIORAL_C_PLAN_FORMAT = "spaghetti-extractor-behavioral-c-plan-v1"
BEHAVIORAL_C_PACKAGE_FORMAT = "spaghetti-extractor-behavioral-c-package-v1"
BEHAVIORAL_C_LOWERING_FORMAT = "spaghetti-extractor-behavioral-c-lowering-v1"
BEHAVIORAL_C_COVERAGE_FORMAT = "spaghetti-extractor-behavioral-c-coverage-v1"
BEHAVIORAL_C_RUNTIME_QUALIFICATION_FORMAT = (
    "spaghetti-extractor-behavioral-c-runtime-qualification-v1"
)
BEHAVIORAL_C_COMPLETION_FORMAT = "spaghetti-extractor-behavioral-c-completion-v1"
PE32_MODULE_INTERFACE_FORMAT = "spaghetti-extractor-pe32-module-interface-v2"
NATIVE_INGRESS_PLAN_FORMAT = "spaghetti-extractor-native-ingress-plan-v1"
CHECKED_BOUNDARY_OUTCOME_PROTOCOL_FORMAT = (
    "spaghetti-extractor-checked-boundary-outcome-protocol-v1"
)
CHECKED_SEH_PROTOCOL_FORMAT = "spaghetti-extractor-checked-seh-protocol-v1"
NATIVE_INGRESS_LINK_RECEIPT_FORMAT = (
    "spaghetti-extractor-native-ingress-link-receipt-v1"
)
PE32_MODULE_DEPLOYMENT_FORMAT = "spaghetti-extractor-pe32-module-deployment-v1"
PE32_LOADER_SURFACE_RECEIPT_FORMAT = (
    "spaghetti-extractor-pe32-loader-surface-receipt-v1"
)
PE32_PROJECT_INTENT_FORMAT = "spaghetti-extractor-pe32-project-intent-v1"
PE32_PROJECT_LOAD_PLAN_FORMAT = "spaghetti-extractor-pe32-project-load-plan-v1"
PE32_LOAD_OBSERVATION_FORMAT = "spaghetti-extractor-pe32-load-observation-v1"
PE32_OBSERVED_LOAD_GRAPH_FORMAT = "spaghetti-extractor-pe32-observed-load-graph-v1"
PE32_PROJECT_COMPLETION_FORMAT = "spaghetti-extractor-pe32-project-completion-v2"
NATIVE_ENGINE_PLAN_FORMAT = "spaghetti-extractor-native-engine-plan-v1"
NATIVE_ENGINE_PACKAGE_FORMAT = "spaghetti-extractor-native-engine-package-v1"
NATIVE_RUNTIME_PACKAGE_FORMAT = "spaghetti-extractor-native-runtime-package-v1"
MACHINE_IR_V2_FORMAT = "spaghetti-extractor-machine-ir-v2"
MACHINE_IR_FORMAT = "spaghetti-extractor-machine-ir-v3"
MACHINE_MEMORY_ACTION_GRAPH_FORMAT = (
    "spaghetti-extractor-machine-memory-action-graph-v1"
)
CONCURRENCY_SIGNATURE_FORMAT = (
    "spaghetti-extractor-concurrency-signature-v1"
)
MEMORY_MODEL_RECEIPT_FORMAT = (
    "spaghetti-extractor-memory-model-receipt-v1"
)
PE32_WB_TSO_PROFILE_ID = "x86-pe32-user-wb-tso-v1"
STATIC_ANALYSIS_PROFILE_ID = "x86-pe32-static-reconstruction-v1"
STATIC_PROGRAM_CONTRACT_FORMAT = "spaghetti-extractor-static-program-contract-v2"
STATIC_PROGRAM_SEMANTIC_BINDING_FORMAT = (
    "spaghetti-extractor-static-program-semantic-binding-v2"
)
FALLBACK_CAPABILITY_ANALYSIS_FORMAT = (
    "spaghetti-extractor-fallback-capability-analysis-v1"
)
STRUCTURAL_EXECUTABLE_FORMAT = "spaghetti-extractor-structural-executable-v1"
RELEASE_ACCEPTANCE_FORMAT = "spaghetti-extractor-release-acceptance-v1"
CALLER_MEMORY_FRAME_MODEL = "pe32-declared-pointer-arguments-v1"
SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL = "same-library-call-through-v1"
LAUNCH_ASSUMPTION_TEMPLATE_FORMAT = (
    "spaghetti-extractor-pe32-launch-assumption-template-v1"
)
NATIVE_X87_REPLAY_FORMAT = "spaghetti-extractor-native-exact-x87-command-replay-obligation-v1"
ISA_ENCODING_PROPOSAL_FORMAT = (
    "spaghetti-extractor-side-isa-executable-encoding-proposal-v1"
)
STATIC_MACHINE_IMPORT_PROFILE_FORMAT = "spaghetti-extractor-static-machine-import-profile-v1"
AUTHORITY_DIAGNOSTICS_V3_FORMAT = (
    "spaghetti-extractor-authority-diagnostics-v3"
)
IMPLEMENTATION_DISPATCH_RECEIPT_FORMAT = (
    "spaghetti-extractor-native-implementation-dispatch-receipt-v3"
)
TARGET_HINTS_ARTIFACT_KIND = "target-hints-v3"
EXTERNAL_OPERATION_PROFILE_FORMAT = "spaghetti-extractor-external-operation-profile-v2"
EXTERNAL_OPERATION_CONTRACT_FORMAT = "spaghetti-extractor-external-operation-contract-v1"
SOURCE_OPERATION_CATALOG_FORMAT = "spaghetti-extractor-source-operation-catalog-v1"
SOURCE_OPERATION_RENDERING_FORMAT = "spaghetti-extractor-source-operation-rendering-v1"
PAYLOAD_RELOCATION_INVENTORY_FORMAT = (
    "spaghetti-extractor-pe-payload-relocation-inventory-v1"
)
PE_COMPOSITION_MANIFEST_FORMAT = "spaghetti-extractor-pe-composition-manifest-v1"
REGION_REPLACEMENT_BUNDLE_FORMAT = "spaghetti-extractor-region-replacement-v2"
RECONSTRUCTION_PLAN_FORMAT = "spaghetti-extractor-reconstruction-plan-v1"
RECONSTRUCTION_CONTRACT_ANALYSIS_FORMAT = (
    "spaghetti-extractor-reconstruction-contract-analysis-v1"
)
SEMANTIC_COMPONENT_DECLARATIONS_FORMAT = (
    "spaghetti-extractor-semantic-component-declarations-v1"
)
SEMANTIC_COMPONENT_CATALOG_FORMAT = "spaghetti-extractor-semantic-component-catalog-v1"
COMPONENT_INTERFACE_SPEC_FORMAT = "spaghetti-extractor-component-interface-spec-v1"
COMPONENT_INTERFACE_REFINEMENT_FORMAT = (
    "spaghetti-extractor-component-interface-refinement-v1"
)
COMPONENT_QUALIFICATION_FORMAT = "spaghetti-extractor-component-qualification-v1"
LIBRARY_ARTIFACT_INPUTS_FORMAT = "spaghetti-extractor-library-artifact-inputs-v1"
LIBRARY_ARTIFACT_INDEX_FORMAT = "spaghetti-extractor-library-artifact-index-v1"
LIBRARY_ARTIFACT_INPUTS_V2_FORMAT = "spaghetti-extractor-library-artifact-inputs-v2"
LIBRARY_ARTIFACT_INDEX_V2_FORMAT = "spaghetti-extractor-library-artifact-index-v2"
LIBRARY_CATALOG_LOCK_FORMAT = "spaghetti-extractor-library-catalog-lock-v1"
LIBRARY_MATCH_EVIDENCE_FORMAT = "spaghetti-extractor-library-match-evidence-v1"
LIBRARY_HYPOTHESIS_SET_FORMAT = "spaghetti-extractor-library-hypothesis-set-v1"
DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT = (
    "spaghetti-extractor-dynamic-library-requirements-v1"
)
LIBRARY_INTERFACE_CATALOG_FORMAT = "spaghetti-extractor-interface-contract-catalog-v1"
LINKED_ISLAND_REVIEW_FORMAT = "spaghetti-extractor-linked-island-review-v1"
LINKED_ISLAND_MANIFEST_FORMAT = "spaghetti-extractor-linked-island-manifest-v1"
LINKED_ISLAND_MANIFEST_V2_FORMAT = "spaghetti-extractor-linked-island-manifest-v2"
LINKED_INTERFACE_ASSIGNMENTS_FORMAT = "spaghetti-extractor-linked-interface-assignments-v1"
LINKED_INTERFACE_QUALIFICATION_FORMAT = (
    "spaghetti-extractor-linked-interface-qualification-v1"
)
LIBRARY_REPLACEMENT_PLAN_FORMAT = "spaghetti-extractor-library-replacement-plan-v1"
LIBRARY_ABI_CATALOG_V3_FORMAT = "spaghetti-extractor-library-abi-catalog-v3"
LIBRARY_TARGET_SIGNATURE_GRAPH_V3_FORMAT = (
    "spaghetti-extractor-library-target-signature-graph-v3"
)
LIBRARY_CATALOG_SEARCH_INDEX_V3_FORMAT = (
    "spaghetti-extractor-library-catalog-search-index-v3"
)
LIBRARY_CONSTELLATION_HYPOTHESES_V3_FORMAT = (
    "spaghetti-extractor-library-constellation-hypotheses-v3"
)
LIBRARY_PROCEDURE_CANDIDATES_V3_FORMAT = (
    "spaghetti-extractor-library-procedure-candidates-v3"
)
LIBRARY_STATUS_V4_FORMAT = "spaghetti-extractor-library-status-v4"
LIBRARY_RELEASE_HYPOTHESES_V4_FORMAT = (
    "spaghetti-extractor-library-release-hypotheses-v4"
)
LIBRARY_RELEASE_HYPOTHESES_SET_V4_FORMAT = (
    "spaghetti-extractor-library-release-hypotheses-set-v4"
)
CHECKED_LIBRARY_ISLAND_V1_FORMAT = "spaghetti-extractor-checked-library-island-v1"
REUSABLE_LIBRARY_IMPLEMENTATION_V1_FORMAT = (
    "spaghetti-extractor-reusable-library-implementation-v1"
)
REUSABLE_LIBRARY_BEHAVIOR_PACK_V1_FORMAT = (
    "spaghetti-extractor-reusable-library-behavior-pack-v1"
)
REUSABLE_LIBRARY_BEHAVIOR_PACK_V2_FORMAT = (
    "spaghetti-extractor-reusable-library-behavior-pack-v2"
)
LIBRARY_BEHAVIOR_CONTRACT_V2_FORMAT = (
    "spaghetti-extractor-library-behavior-contract-v2"
)
GENERATED_LIBRARY_COMPONENT_V1_FORMAT = (
    "spaghetti-extractor-generated-library-component-v1"
)
LIBRARY_ADOPTION_INTENT_V1_FORMAT = "spaghetti-extractor-library-adoption-intent-v1"
CANONICAL_EXTERNAL_SITE_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-canonical-external-site-record-v3"
)
CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3 = "canonical-external-sites-v3"
CANDIDATE_TEST_SUITE_FORMAT = "spaghetti-extractor-candidate-test-suite-v1"
CANDIDATE_TEST_CASE_REPORT_FORMAT = (
    "spaghetti-extractor-candidate-test-case-report-v1"
)
CANDIDATE_TEST_REPORT_FORMAT = "spaghetti-extractor-candidate-test-report-v1"
ABI_EVIDENCE_FORMAT = "spaghetti-extractor-abi-evidence-v1"
ABI_FACT_SET_FORMAT = "spaghetti-extractor-abi-fact-set-v1"
ABI_CONSTRAINT_RESULT_FORMAT = "spaghetti-extractor-abi-constraint-result-v1"
PHYSICAL_ABI_CERTIFICATE_FORMAT = (
    "spaghetti-extractor-physical-abi-certificate-v1"
)
PORTABLE_PROTOTYPE_FORMAT = "spaghetti-extractor-portable-prototype-v1"
BOUNDARY_EFFECTS_FORMAT = "spaghetti-extractor-boundary-effects-v1"
REVIEWED_ABI_ASSUMPTION_FORMAT = "spaghetti-extractor-reviewed-abi-assumption-v1"
ABI_ANALYSIS_BUNDLE_FORMAT = "spaghetti-extractor-abi-analysis-bundle-v1"
PHYSICAL_ABI_CATALOG_FORMAT = "spaghetti-extractor-physical-abi-catalog-v1"
ABI_MATCH_RESOLUTION_FORMAT = "spaghetti-extractor-abi-match-resolution-v1"
CATALOG_CALL_CONTRACT_SET_FORMAT = (
    "spaghetti-extractor-catalog-call-contract-set-v1"
)
PHYSICAL_ABI_DECLARATIONS_FORMAT = (
    "spaghetti-extractor-physical-abi-declarations-v1"
)
PHYSICAL_ABI_DECLARATION_SPEC_FORMAT = (
    "spaghetti-extractor-physical-abi-declaration-spec-v1"
)
ABI_DECLARATION_INGESTION_FORMAT = (
    "spaghetti-extractor-abi-declaration-ingestion-v1"
)
PORTABLE_TYPE_GRAPH_V1_FORMAT = "spaghetti-extractor-portable-type-graph-v1"
SOURCE_NAMING_V1_FORMAT = "spaghetti-extractor-source-naming-v1"
TARGET_LAYOUT_SET_V1_FORMAT = "spaghetti-extractor-target-layout-set-v1"
PHYSICAL_CALL_FRAME_V2_FORMAT = "spaghetti-extractor-physical-call-frame-v2"
PHYSICAL_CALL_FRAME_V3_FORMAT = "spaghetti-extractor-physical-call-frame-v3"
CALL_FRAME_RELATION_V1_FORMAT = "spaghetti-extractor-call-frame-relation-v1"
CALL_FRAME_RELATION_RECEIPT_V1_FORMAT = (
    "spaghetti-extractor-call-frame-relation-receipt-v1"
)
CALL_LIFECYCLE_V1_FORMAT = "spaghetti-extractor-call-lifecycle-v1"
CALL_LIFECYCLE_RECEIPT_V1_FORMAT = (
    "spaghetti-extractor-call-lifecycle-receipt-v1"
)
CHECKED_CALL_PROTOCOL_V1_FORMAT = "spaghetti-extractor-checked-call-protocol-v1"
CHECKED_CALL_PROTOCOL_V2_FORMAT = "spaghetti-extractor-checked-call-protocol-v2"
IDIOMATIC_CALL_VIEW_V1_FORMAT = "spaghetti-extractor-idiomatic-call-view-v1"
CALL_PROTOCOL_PROPOSAL_V1_FORMAT = (
    "spaghetti-extractor-call-protocol-proposal-v1"
)
CALL_PROTOCOL_INTENT_V1_FORMAT = "spaghetti-extractor-call-protocol-intent-v1"
IA32_DIALECT_RECEIPT_V1_FORMAT = "spaghetti-extractor-ia32-dialect-receipt-v1"
CALLBACK_PROTOCOL_V2_FORMAT = "spaghetti-extractor-callback-protocol-v2"
CALLBACK_PROTOCOL_V3_FORMAT = "spaghetti-extractor-callback-protocol-v3"
CALL_PROTOCOL_COMPATIBILITY_V1_FORMAT = (
    "spaghetti-extractor-call-protocol-compatibility-v1"
)
MACHINE_CALL_EVIDENCE_V1_FORMAT = "spaghetti-extractor-machine-call-evidence-v1"
BOUNDARY_SCHEMA_V1_FORMAT = "spaghetti-extractor-boundary-schema-v1"
TARGET_DATA_LAYOUT_V1_FORMAT = "spaghetti-extractor-target-data-layout-v1"
BOUNDARY_FACT_SET_V1_FORMAT = "spaghetti-extractor-boundary-fact-set-v1"
BOUNDARY_EVIDENCE_RECEIPT_V1_FORMAT = (
    "spaghetti-extractor-boundary-evidence-receipt-v1"
)
BOUNDARY_LIFECYCLE_V1_FORMAT = "spaghetti-extractor-boundary-lifecycle-v1"
BOUNDARY_LIFECYCLE_RECEIPT_V1_FORMAT = (
    "spaghetti-extractor-boundary-lifecycle-receipt-v1"
)
BOUNDARY_PROJECTION_V1_FORMAT = "spaghetti-extractor-boundary-projection-v1"
BOUNDARY_PROJECTION_RECEIPT_V1_FORMAT = (
    "spaghetti-extractor-boundary-projection-receipt-v1"
)
__all__ = [
    "BEHAVIORAL_C_COMPLETION_FORMAT",
    "BEHAVIORAL_C_COVERAGE_FORMAT",
    "BEHAVIORAL_C_LAYOUT_INTENT_FORMAT",
    "BEHAVIORAL_C_LOWERING_FORMAT",
    "BEHAVIORAL_C_PACKAGE_FORMAT",
    "BEHAVIORAL_C_PLAN_FORMAT",
    "BEHAVIORAL_C_RUNTIME_QUALIFICATION_FORMAT",
    "CHECKED_BOUNDARY_OUTCOME_PROTOCOL_FORMAT",
    "CHECKED_SEH_PROTOCOL_FORMAT",
    "NATIVE_INGRESS_LINK_RECEIPT_FORMAT",
    "NATIVE_INGRESS_PLAN_FORMAT",
    "PE32_MODULE_DEPLOYMENT_FORMAT",
    "PE32_LOADER_SURFACE_RECEIPT_FORMAT",
    "PE32_MODULE_INTERFACE_FORMAT",
    "PE32_PROJECT_INTENT_FORMAT",
    "PE32_PROJECT_LOAD_PLAN_FORMAT",
    "PE32_LOAD_OBSERVATION_FORMAT",
    "PE32_OBSERVED_LOAD_GRAPH_FORMAT",
    "PE32_PROJECT_COMPLETION_FORMAT",
    "ABI_ANALYSIS_BUNDLE_FORMAT",
    "ABI_CONSTRAINT_RESULT_FORMAT",
    "ABI_EVIDENCE_FORMAT",
    "ABI_FACT_SET_FORMAT",
    "ABI_MATCH_RESOLUTION_FORMAT",
    "CATALOG_CALL_CONTRACT_SET_FORMAT",
    "AUTHORITY_DIAGNOSTICS_V3_FORMAT",
    "CANONICAL_EXTERNAL_SITE_RECORD_V3_SCHEMA",
    "CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3",
    "CANDIDATE_TEST_SUITE_FORMAT",
    "CANDIDATE_TEST_CASE_REPORT_FORMAT",
    "CANDIDATE_TEST_REPORT_FORMAT",
    "BOUNDARY_EFFECTS_FORMAT",
    "COMPONENT_INTERFACE_REFINEMENT_FORMAT",
    "COMPONENT_INTERFACE_SPEC_FORMAT",
    "COMPONENT_QUALIFICATION_FORMAT",
    "INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT",
    "CALLER_MEMORY_FRAME_MODEL",
    "IMPLEMENTATION_DISPATCH_RECEIPT_FORMAT",
    "ISA_ENCODING_PROPOSAL_FORMAT",
    "INTERPRETER_NATIVE_BUILD_FORMAT",
    "SPX_INTERPRETER_PACKAGE_FORMAT",
    "SPX_INTERPRETER_PROGRAM_FORMAT",
    "LIBRARY_ARTIFACT_INDEX_FORMAT",
    "LIBRARY_ARTIFACT_INDEX_V2_FORMAT",
    "LIBRARY_ARTIFACT_INPUTS_FORMAT",
    "LIBRARY_ARTIFACT_INPUTS_V2_FORMAT",
    "LIBRARY_ADOPTION_INTENT_V1_FORMAT",
    "LIBRARY_CATALOG_LOCK_FORMAT",
    "LIBRARY_HYPOTHESIS_SET_FORMAT",
    "LIBRARY_INTERFACE_CATALOG_FORMAT",
    "LIBRARY_MATCH_EVIDENCE_FORMAT",
    "LIBRARY_REPLACEMENT_PLAN_FORMAT",
    "LIBRARY_ABI_CATALOG_V3_FORMAT",
    "LIBRARY_CATALOG_SEARCH_INDEX_V3_FORMAT",
    "LIBRARY_CONSTELLATION_HYPOTHESES_V3_FORMAT",
    "LIBRARY_PROCEDURE_CANDIDATES_V3_FORMAT",
    "LIBRARY_RELEASE_HYPOTHESES_V4_FORMAT",
    "LIBRARY_RELEASE_HYPOTHESES_SET_V4_FORMAT",
    "LIBRARY_STATUS_V4_FORMAT",
    "LIBRARY_TARGET_SIGNATURE_GRAPH_V3_FORMAT",
    "CHECKED_LIBRARY_ISLAND_V1_FORMAT",
    "REUSABLE_LIBRARY_IMPLEMENTATION_V1_FORMAT",
    "REUSABLE_LIBRARY_BEHAVIOR_PACK_V1_FORMAT",
    "REUSABLE_LIBRARY_BEHAVIOR_PACK_V2_FORMAT",
    "LIBRARY_BEHAVIOR_CONTRACT_V2_FORMAT",
    "GENERATED_LIBRARY_COMPONENT_V1_FORMAT",
    "DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT",
    "EXTERNAL_OPERATION_CONTRACT_FORMAT",
    "EXTERNAL_OPERATION_PROFILE_FORMAT",
    "LINKED_INTERFACE_ASSIGNMENTS_FORMAT",
    "LINKED_INTERFACE_QUALIFICATION_FORMAT",
    "LINKED_ISLAND_MANIFEST_FORMAT",
    "LINKED_ISLAND_MANIFEST_V2_FORMAT",
    "LINKED_ISLAND_REVIEW_FORMAT",
    "MACHINE_IR_FORMAT",
    "MACHINE_IR_V2_FORMAT",
    "MACHINE_MEMORY_ACTION_GRAPH_FORMAT",
    "CONCURRENCY_SIGNATURE_FORMAT",
    "MEMORY_MODEL_RECEIPT_FORMAT",
    "PE32_WB_TSO_PROFILE_ID",
    "LAUNCH_ASSUMPTION_TEMPLATE_FORMAT",
    "NATIVE_ENGINE_PACKAGE_FORMAT",
    "NATIVE_ENGINE_PLAN_FORMAT",
    "NATIVE_RUNTIME_PACKAGE_FORMAT",
    "NATIVE_X87_REPLAY_FORMAT",
    "PAYLOAD_RELOCATION_INVENTORY_FORMAT",
    "PE_COMPOSITION_MANIFEST_FORMAT",
    "REGION_REPLACEMENT_BUNDLE_FORMAT",
    "RECONSTRUCTION_PLAN_FORMAT",
    "RECONSTRUCTION_CONTRACT_ANALYSIS_FORMAT",
    "SEMANTIC_COMPONENT_CATALOG_FORMAT",
    "SEMANTIC_COMPONENT_DECLARATIONS_FORMAT",
    "SEMANTIC_IR_FORMAT",
    "SEMANTIC_TRANSFER_CONTRACT_FORMAT",
    "SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL",
    "SOURCE_OPERATION_CATALOG_FORMAT",
    "SOURCE_OPERATION_RENDERING_FORMAT",
    "STATIC_ANALYSIS_PROFILE_ID",
    "STRUCTURAL_EXECUTABLE_FORMAT",
    "STATIC_PROGRAM_CONTRACT_FORMAT",
    "STATIC_PROGRAM_SEMANTIC_BINDING_FORMAT",
    "FALLBACK_CAPABILITY_ANALYSIS_FORMAT",
    "STATIC_MACHINE_IMPORT_PROFILE_FORMAT",
    "TARGET_HINTS_ARTIFACT_KIND",
    "RELEASE_ACCEPTANCE_FORMAT",
    "PHYSICAL_ABI_CERTIFICATE_FORMAT",
    "PHYSICAL_ABI_DECLARATIONS_FORMAT",
    "PHYSICAL_ABI_DECLARATION_SPEC_FORMAT",
    "PHYSICAL_ABI_CATALOG_FORMAT",
    "ABI_DECLARATION_INGESTION_FORMAT",
    "PORTABLE_TYPE_GRAPH_V1_FORMAT",
    "SOURCE_NAMING_V1_FORMAT",
    "TARGET_LAYOUT_SET_V1_FORMAT",
    "PHYSICAL_CALL_FRAME_V2_FORMAT",
    "PHYSICAL_CALL_FRAME_V3_FORMAT",
    "CALL_FRAME_RELATION_V1_FORMAT",
    "CALL_FRAME_RELATION_RECEIPT_V1_FORMAT",
    "CALL_LIFECYCLE_V1_FORMAT",
    "CHECKED_CALL_PROTOCOL_V1_FORMAT",
    "CHECKED_CALL_PROTOCOL_V2_FORMAT",
    "IDIOMATIC_CALL_VIEW_V1_FORMAT",
    "CALL_PROTOCOL_PROPOSAL_V1_FORMAT",
    "CALL_PROTOCOL_INTENT_V1_FORMAT",
    "IA32_DIALECT_RECEIPT_V1_FORMAT",
    "CALLBACK_PROTOCOL_V2_FORMAT",
    "CALLBACK_PROTOCOL_V3_FORMAT",
    "CALL_PROTOCOL_COMPATIBILITY_V1_FORMAT",
    "MACHINE_CALL_EVIDENCE_V1_FORMAT",
    "BOUNDARY_SCHEMA_V1_FORMAT",
    "TARGET_DATA_LAYOUT_V1_FORMAT",
    "BOUNDARY_FACT_SET_V1_FORMAT",
    "BOUNDARY_EVIDENCE_RECEIPT_V1_FORMAT",
    "BOUNDARY_LIFECYCLE_V1_FORMAT",
    "BOUNDARY_LIFECYCLE_RECEIPT_V1_FORMAT",
    "BOUNDARY_PROJECTION_V1_FORMAT",
    "BOUNDARY_PROJECTION_RECEIPT_V1_FORMAT",
    "PORTABLE_PROTOTYPE_FORMAT",
    "REVIEWED_ABI_ASSUMPTION_FORMAT",
]
