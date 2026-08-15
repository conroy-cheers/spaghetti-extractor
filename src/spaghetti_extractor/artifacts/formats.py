"""Canonical identifiers for artifacts shared across pipeline boundaries.

Keep this module dependency-free.  Producers and consumers in Stage A,
round-trip qualification, and Stage B must agree on these values without
importing one another's implementation modules.
"""

SEMANTIC_IR_FORMAT = "stage-a-semantic-ir-v1"
SEMANTIC_TRANSFER_CONTRACT_FORMAT = (
    "stage-a-semantic-transfer-contract-v1"
)
INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT = (
    "stage-a-instruction-ordered-effect-schedule-v1"
)
INTERPRETER_NATIVE_BUILD_FORMAT = "stage-b-interpreter-native-build-v1"
STAGE_B_INTERPRETER_PROGRAM_FORMAT = "stage-b-semantic-interpreter-program-v1"
STAGE_B_INTERPRETER_PACKAGE_FORMAT = "stage-b-semantic-interpreter-package-v1"
NATIVE_ENGINE_PLAN_FORMAT = "stage-b-native-engine-plan-v1"
NATIVE_ENGINE_PACKAGE_FORMAT = "stage-b-native-engine-package-v1"
NATIVE_RUNTIME_PACKAGE_FORMAT = "stage-b-native-runtime-package-v1"
MACHINE_IR_FORMAT = "stage-a-machine-ir-v2"
STATIC_ANALYSIS_PROFILE_ID = "x86-pe32-static-reconstruction-v1"
CALLER_MEMORY_FRAME_MODEL = "pe32-declared-pointer-arguments-v1"
SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL = "same-library-call-through-v1"
LAUNCH_ASSUMPTION_TEMPLATE_FORMAT = (
    "spaghetti-extractor-pe32-launch-assumption-template-v1"
)
NATIVE_X87_REPLAY_FORMAT = "stage-a-native-exact-x87-command-replay-obligation-v1"
NATIVE_X87_REPLAY_PROGRAM_FORMAT = (
    "stage-b-native-exact-x87-command-replay-program-v1"
)
ISA_ENCODING_PROPOSAL_FORMAT = (
    "stage-a-side-isa-executable-encoding-proposal-v1"
)
STATIC_MACHINE_IMPORT_PROFILE_FORMAT = "stage-a-static-machine-import-profile-v1"
CALLBACK_ADAPTER_RECEIPT_FORMAT = "stage-b-native-callback-adapter-receipt-v1"
IMPLEMENTATION_DISPATCH_RECEIPT_FORMAT = (
    "stage-b-native-implementation-dispatch-receipt-v3"
)
TARGET_HINTS_ARTIFACT_KIND = "target-hints-v3"
EXTERNAL_OPERATION_PROFILE_FORMAT = "stage-a-external-operation-profile-v2"
EXTERNAL_OPERATION_CONTRACT_FORMAT = "stage-a-external-operation-contract-v1"
SOURCE_OPERATION_CATALOG_FORMAT = "stage-b-source-operation-catalog-v1"
SOURCE_OPERATION_RENDERING_FORMAT = "stage-b-source-operation-rendering-v1"
PAYLOAD_RELOCATION_INVENTORY_FORMAT = (
    "stage-b-pe-payload-relocation-inventory-v1"
)
PE_COMPOSITION_MANIFEST_FORMAT = "stage-b-pe-composition-manifest-v1"
REGION_REPLACEMENT_BUNDLE_FORMAT = "stage-b-region-replacement-v2"
RECONSTRUCTION_PLAN_FORMAT = "stage-b-reconstruction-plan-v1"
RECONSTRUCTION_CONTRACT_ANALYSIS_FORMAT = (
    "stage-a-reconstruction-contract-analysis-v1"
)
SEMANTIC_COMPONENT_DECLARATIONS_FORMAT = (
    "stage-b-semantic-component-declarations-v1"
)
SEMANTIC_COMPONENT_CATALOG_FORMAT = "stage-b-semantic-component-catalog-v1"
COMPONENT_INTERFACE_SPEC_FORMAT = "stage-b-component-interface-spec-v1"
COMPONENT_INTERFACE_REFINEMENT_FORMAT = (
    "stage-b-component-interface-refinement-v1"
)
COMPONENT_QUALIFICATION_FORMAT = "stage-b-component-qualification-v1"
LIBRARY_ARTIFACT_INPUTS_FORMAT = "stage-b-library-artifact-inputs-v1"
LIBRARY_ARTIFACT_INDEX_FORMAT = "stage-b-library-artifact-index-v1"
LIBRARY_ARTIFACT_INPUTS_V2_FORMAT = "stage-b-library-artifact-inputs-v2"
LIBRARY_ARTIFACT_INDEX_V2_FORMAT = "stage-b-library-artifact-index-v2"
LIBRARY_CATALOG_LOCK_FORMAT = "stage-b-library-catalog-lock-v1"
LIBRARY_MATCH_EVIDENCE_FORMAT = "stage-b-library-match-evidence-v1"
LIBRARY_HYPOTHESIS_SET_FORMAT = "stage-b-library-hypothesis-set-v1"
DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT = (
    "stage-b-dynamic-library-requirements-v1"
)
LIBRARY_INTERFACE_CATALOG_FORMAT = "stage-b-interface-contract-catalog-v1"
LINKED_ISLAND_REVIEW_FORMAT = "stage-b-linked-island-review-v1"
LINKED_ISLAND_MANIFEST_FORMAT = "stage-b-linked-island-manifest-v1"
LINKED_ISLAND_MANIFEST_V2_FORMAT = "stage-b-linked-island-manifest-v2"
LINKED_INTERFACE_ASSIGNMENTS_FORMAT = "stage-b-linked-interface-assignments-v1"
LINKED_INTERFACE_QUALIFICATION_FORMAT = (
    "stage-b-linked-interface-qualification-v1"
)
LIBRARY_REPLACEMENT_PLAN_FORMAT = "stage-b-library-replacement-plan-v1"
CANONICAL_EXTERNAL_SITE_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-canonical-external-site-record-v3"
)
CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3 = "canonical-external-sites-v3"
__all__ = [
    "CANONICAL_EXTERNAL_SITE_RECORD_V3_SCHEMA",
    "CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3",
    "COMPONENT_INTERFACE_REFINEMENT_FORMAT",
    "COMPONENT_INTERFACE_SPEC_FORMAT",
    "COMPONENT_QUALIFICATION_FORMAT",
    "INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT",
    "CALLBACK_ADAPTER_RECEIPT_FORMAT",
    "CALLER_MEMORY_FRAME_MODEL",
    "IMPLEMENTATION_DISPATCH_RECEIPT_FORMAT",
    "ISA_ENCODING_PROPOSAL_FORMAT",
    "INTERPRETER_NATIVE_BUILD_FORMAT",
    "STAGE_B_INTERPRETER_PACKAGE_FORMAT",
    "STAGE_B_INTERPRETER_PROGRAM_FORMAT",
    "LIBRARY_ARTIFACT_INDEX_FORMAT",
    "LIBRARY_ARTIFACT_INDEX_V2_FORMAT",
    "LIBRARY_ARTIFACT_INPUTS_FORMAT",
    "LIBRARY_ARTIFACT_INPUTS_V2_FORMAT",
    "LIBRARY_CATALOG_LOCK_FORMAT",
    "LIBRARY_HYPOTHESIS_SET_FORMAT",
    "LIBRARY_INTERFACE_CATALOG_FORMAT",
    "LIBRARY_MATCH_EVIDENCE_FORMAT",
    "LIBRARY_REPLACEMENT_PLAN_FORMAT",
    "DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT",
    "EXTERNAL_OPERATION_CONTRACT_FORMAT",
    "EXTERNAL_OPERATION_PROFILE_FORMAT",
    "LINKED_INTERFACE_ASSIGNMENTS_FORMAT",
    "LINKED_INTERFACE_QUALIFICATION_FORMAT",
    "LINKED_ISLAND_MANIFEST_FORMAT",
    "LINKED_ISLAND_MANIFEST_V2_FORMAT",
    "LINKED_ISLAND_REVIEW_FORMAT",
    "MACHINE_IR_FORMAT",
    "LAUNCH_ASSUMPTION_TEMPLATE_FORMAT",
    "NATIVE_ENGINE_PACKAGE_FORMAT",
    "NATIVE_ENGINE_PLAN_FORMAT",
    "NATIVE_RUNTIME_PACKAGE_FORMAT",
    "NATIVE_X87_REPLAY_FORMAT",
    "NATIVE_X87_REPLAY_PROGRAM_FORMAT",
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
    "STATIC_MACHINE_IMPORT_PROFILE_FORMAT",
    "TARGET_HINTS_ARTIFACT_KIND",
]
