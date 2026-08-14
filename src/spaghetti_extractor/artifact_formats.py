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
NATIVE_ENGINE_PLAN_FORMAT = "stage-b-native-engine-plan-v1"
NATIVE_ENGINE_PACKAGE_FORMAT = "stage-b-native-engine-package-v1"
NATIVE_RUNTIME_PACKAGE_FORMAT = "stage-b-native-runtime-package-v1"
MACHINE_IR_FORMAT = "stage-a-machine-ir-v2"
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
COMPONENT_PROPOSAL_SET_FORMAT = "stage-b-component-proposal-set-v1"
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
__all__ = [
    "COMPONENT_INTERFACE_REFINEMENT_FORMAT",
    "COMPONENT_INTERFACE_SPEC_FORMAT",
    "COMPONENT_PROPOSAL_SET_FORMAT",
    "COMPONENT_QUALIFICATION_FORMAT",
    "INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT",
    "INTERPRETER_NATIVE_BUILD_FORMAT",
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
    "NATIVE_ENGINE_PACKAGE_FORMAT",
    "NATIVE_ENGINE_PLAN_FORMAT",
    "NATIVE_RUNTIME_PACKAGE_FORMAT",
    "PAYLOAD_RELOCATION_INVENTORY_FORMAT",
    "PE_COMPOSITION_MANIFEST_FORMAT",
    "REGION_REPLACEMENT_BUNDLE_FORMAT",
    "RECONSTRUCTION_PLAN_FORMAT",
    "RECONSTRUCTION_CONTRACT_ANALYSIS_FORMAT",
    "SEMANTIC_COMPONENT_CATALOG_FORMAT",
    "SEMANTIC_COMPONENT_DECLARATIONS_FORMAT",
    "SEMANTIC_IR_FORMAT",
    "SEMANTIC_TRANSFER_CONTRACT_FORMAT",
    "SOURCE_OPERATION_CATALOG_FORMAT",
    "SOURCE_OPERATION_RENDERING_FORMAT",
]
