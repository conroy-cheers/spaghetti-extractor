"""Versioned artifact identifiers owned by the component framework."""

from ..artifacts.format_spec import FormatSpecV1

COMPONENT_DISCOVERY_RESULT_V2_FORMAT = (
    "spaghetti-extractor-component-discovery-result-v2"
)
COMPONENT_PROPOSAL_PACKAGE_V2_FORMAT = (
    "spaghetti-extractor-component-proposal-package-v2"
)
COMPONENT_PROPOSAL_INDEX_V2_FORMAT = (
    "spaghetti-extractor-component-proposal-index-v2"
)
COMPONENT_UNIT_BINDING_INDEX_V2_FORMAT = (
    "spaghetti-extractor-component-unit-binding-index-v2"
)
COMPONENT_PROPOSAL_RECORD_V2_KIND = "component-proposal-v2"
COMPONENT_EXTERNAL_SITE_SLICE_V1_FORMAT = (
    "spaghetti-extractor-component-external-site-slice-v1"
)

_OWNER = __name__

FORMAT_SPECS = (
    FormatSpecV1(
        literal="spaghetti-extractor-component-lifting-intent-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.components.lifting_intent",
        role="intent",
        state="active",
        symbol="COMPONENT_LIFTING_INTENT_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-interface-intent-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.components.interface_package_v5",
        role="intent",
        state="active",
        symbol="COMPONENT_INTERFACE_INTENT_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-machine-binding-intent-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.components.binding_intent",
        role="intent",
        state="active",
        symbol="COMPONENT_MACHINE_BINDING_INTENT_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-unit-inventory-v1",
        version=1,
        owner=_OWNER,
        codec=_OWNER,
        role="inventory",
        state="retired",
        symbol="RETIRED_COMPONENT_UNIT_INVENTORY_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-portable-component-interface-v5",
        version=5,
        owner=_OWNER,
        codec="spaghetti_extractor.components.interface_v5",
        role="interface",
        state="active",
        symbol="PORTABLE_COMPONENT_INTERFACE_V5_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-source-package-v3",
        version=3,
        owner=_OWNER,
        codec="spaghetti_extractor.components.source",
        role="source_package",
        state="active",
        symbol="COMPONENT_SOURCE_PACKAGE_V3_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-contract-v4",
        version=4,
        owner=_OWNER,
        codec=_OWNER,
        role="contract",
        state="retired",
        symbol="RETIRED_COMPONENT_CONTRACT_V4_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-machine-binding-v5",
        version=5,
        owner=_OWNER,
        codec=_OWNER,
        role="binding",
        state="retired",
        symbol="RETIRED_COMPONENT_MACHINE_BINDING_V5_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-implementation-v4",
        version=4,
        owner=_OWNER,
        codec=_OWNER,
        role="implementation",
        state="retired",
        symbol="RETIRED_COMPONENT_IMPLEMENTATION_V4_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-dependency-graph-v4",
        version=4,
        owner=_OWNER,
        codec=_OWNER,
        role="graph",
        state="retired",
        symbol="RETIRED_COMPONENT_DEPENDENCY_GRAPH_V4_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-activation-plan-v4",
        version=4,
        owner=_OWNER,
        codec=_OWNER,
        role="plan",
        state="retired",
        symbol="RETIRED_COMPONENT_ACTIVATION_PLAN_V4_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-work-package-v5",
        version=5,
        owner=_OWNER,
        codec=_OWNER,
        role="work_package",
        state="retired",
        symbol="RETIRED_COMPONENT_WORK_PACKAGE_V5_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-implementation-facet-receipt-v1",
        version=1,
        owner=_OWNER,
        codec=_OWNER,
        role="receipt",
        state="retired",
        symbol="RETIRED_COMPONENT_IMPLEMENTATION_FACET_RECEIPT_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-interface-index-v5",
        version=5,
        owner=_OWNER,
        codec="spaghetti_extractor.components.indexes_v5",
        role="intent",
        state="active",
        symbol="COMPONENT_INTERFACE_INDEX_V5_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-machine-binding-index-v5",
        version=5,
        owner=_OWNER,
        codec="spaghetti_extractor.components.indexes_v5",
        role="intent",
        state="active",
        symbol="COMPONENT_MACHINE_BINDING_INDEX_V5_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-relation-intent-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.components.relation_v5",
        role="intent",
        state="active",
        symbol="COMPONENT_RELATION_INTENT_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-interaction-contract-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.components.interaction_contract",
        role="contract",
        state="active",
        symbol="INTERACTION_CONTRACT_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-interaction-contract-catalog-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.components.interaction_contract",
        role="catalog",
        state="active",
        symbol="INTERACTION_CONTRACT_CATALOG_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-interaction-contract-receipt-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.components.interaction_contract",
        role="receipt",
        state="active",
        symbol="INTERACTION_CONTRACT_RECEIPT_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-work-package-v6",
        version=6,
        owner=_OWNER,
        codec="spaghetti_extractor.components.work_package_v6",
        role="work_package",
        state="active",
        symbol="COMPONENT_WORK_PACKAGE_V6_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-adoption-intent-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.components.formats",
        role="intent",
        state="retired",
        symbol="RETIRED_COMPONENT_ADOPTION_INTENT_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-work-package-inspection-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.boundary.work_status",
        role="view",
        state="retired",
        symbol="RETIRED_COMPONENT_WORK_PACKAGE_INSPECTION_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-proposal-inspection-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.commands.workflows",
        role="view",
        state="active",
        symbol="COMPONENT_PROPOSAL_INSPECTION_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-bisimulation-intent-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.components.bisimulation",
        role="intent",
        state="active",
        symbol="COMPONENT_BISIMULATION_INTENT_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-proof-plan-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.components.bisimulation",
        role="plan",
        state="active",
        symbol="COMPONENT_PROOF_PLAN_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-contextual-refinement-v2",
        version=2,
        owner=_OWNER,
        codec="spaghetti_extractor.components.contextual_bisimulation",
        role="receipt",
        state="active",
        symbol="CONTEXTUAL_REFINEMENT_V2_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-exact-c-slice-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.components.component_exact_c_slice",
        role="source_package",
        state="active",
        symbol="COMPONENT_EXACT_C_SLICE_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-trusted-adapter-lowering-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.components.contextual_bisimulation",
        role="receipt",
        state="active",
        symbol="TRUSTED_ADAPTER_LOWERING_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-conditional-contextual-check-v1",
        version=1,
        owner=__name__,
        codec="spaghetti_extractor.components.conditional_check_result",
        role="proof_diagnostic",
        state="active",
        symbol="CONDITIONAL_CONTEXTUAL_CHECK_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-conditional-contextual-refinement-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.components.contextual_bisimulation",
        role="receipt",
        state="active",
        symbol="CONDITIONAL_CONTEXTUAL_REFINEMENT_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-comparison-plan-v1",
        version=1, owner=_OWNER,
        codec="spaghetti_extractor.components.comparison_package",
        role="plan", state="active", symbol="COMPONENT_COMPARISON_PLAN_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-comparison-result-v1",
        version=1, owner=_OWNER,
        codec="spaghetti_extractor.components.comparison_run",
        role="receipt", state="active", symbol="COMPONENT_COMPARISON_RESULT_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-component-partition-intent-v1",
        version=1, owner=_OWNER,
        codec="spaghetti_extractor.components.partition_inventory",
        role="intent", state="active", symbol="COMPONENT_PARTITION_INTENT_V1_FORMAT",
    ),
)

COMPONENT_LIFTING_INTENT_V1_FORMAT = FORMAT_SPECS[0].literal
COMPONENT_INTERFACE_INTENT_V1_FORMAT = FORMAT_SPECS[1].literal
COMPONENT_MACHINE_BINDING_INTENT_V1_FORMAT = FORMAT_SPECS[2].literal
RETIRED_COMPONENT_UNIT_INVENTORY_V1_FORMAT = FORMAT_SPECS[3].literal
PORTABLE_COMPONENT_INTERFACE_V5_FORMAT = FORMAT_SPECS[4].literal
COMPONENT_SOURCE_PACKAGE_V3_FORMAT = FORMAT_SPECS[5].literal
RETIRED_COMPONENT_CONTRACT_V4_FORMAT = FORMAT_SPECS[6].literal
RETIRED_COMPONENT_MACHINE_BINDING_V5_FORMAT = FORMAT_SPECS[7].literal
RETIRED_COMPONENT_IMPLEMENTATION_V4_FORMAT = FORMAT_SPECS[8].literal
RETIRED_COMPONENT_DEPENDENCY_GRAPH_V4_FORMAT = FORMAT_SPECS[9].literal
RETIRED_COMPONENT_ACTIVATION_PLAN_V4_FORMAT = FORMAT_SPECS[10].literal
RETIRED_COMPONENT_WORK_PACKAGE_V5_FORMAT = FORMAT_SPECS[11].literal
RETIRED_COMPONENT_IMPLEMENTATION_FACET_RECEIPT_V1_FORMAT = FORMAT_SPECS[12].literal
COMPONENT_INTERFACE_INDEX_V5_FORMAT = FORMAT_SPECS[13].literal
COMPONENT_MACHINE_BINDING_INDEX_V5_FORMAT = FORMAT_SPECS[14].literal
COMPONENT_RELATION_INTENT_V1_FORMAT = FORMAT_SPECS[15].literal
INTERACTION_CONTRACT_V1_FORMAT = FORMAT_SPECS[16].literal
INTERACTION_CONTRACT_CATALOG_V1_FORMAT = FORMAT_SPECS[17].literal
INTERACTION_CONTRACT_RECEIPT_V1_FORMAT = FORMAT_SPECS[18].literal
COMPONENT_WORK_PACKAGE_V6_FORMAT = FORMAT_SPECS[19].literal
RETIRED_COMPONENT_ADOPTION_INTENT_V1_FORMAT = FORMAT_SPECS[20].literal
RETIRED_COMPONENT_WORK_PACKAGE_INSPECTION_V1_FORMAT = FORMAT_SPECS[21].literal
COMPONENT_PROPOSAL_INSPECTION_V1_FORMAT = FORMAT_SPECS[22].literal
COMPONENT_BISIMULATION_INTENT_V1_FORMAT = FORMAT_SPECS[23].literal
COMPONENT_PROOF_PLAN_V1_FORMAT = FORMAT_SPECS[24].literal
CONTEXTUAL_REFINEMENT_V2_FORMAT = FORMAT_SPECS[25].literal
COMPONENT_EXACT_C_SLICE_V1_FORMAT = FORMAT_SPECS[26].literal
TRUSTED_ADAPTER_LOWERING_V1_FORMAT = FORMAT_SPECS[27].literal
CONDITIONAL_CONTEXTUAL_CHECK_V1_FORMAT = FORMAT_SPECS[28].literal
CONDITIONAL_CONTEXTUAL_REFINEMENT_V1_FORMAT = FORMAT_SPECS[29].literal
COMPONENT_COMPARISON_PLAN_V1_FORMAT = FORMAT_SPECS[30].literal
COMPONENT_COMPARISON_RESULT_V1_FORMAT = FORMAT_SPECS[31].literal
COMPONENT_PARTITION_INTENT_V1_FORMAT = FORMAT_SPECS[32].literal


__all__ = [
    "COMPONENT_PARTITION_INTENT_V1_FORMAT",
    "FORMAT_SPECS",
    "COMPONENT_COMPARISON_PLAN_V1_FORMAT",
    "COMPONENT_COMPARISON_RESULT_V1_FORMAT",
    "CONDITIONAL_CONTEXTUAL_CHECK_V1_FORMAT",
    "CONDITIONAL_CONTEXTUAL_REFINEMENT_V1_FORMAT",
    "RETIRED_COMPONENT_ACTIVATION_PLAN_V4_FORMAT",
    "RETIRED_COMPONENT_CONTRACT_V4_FORMAT",
    "RETIRED_COMPONENT_DEPENDENCY_GRAPH_V4_FORMAT",
    "COMPONENT_DISCOVERY_RESULT_V2_FORMAT",
    "COMPONENT_PROPOSAL_INDEX_V2_FORMAT",
    "COMPONENT_PROPOSAL_PACKAGE_V2_FORMAT",
    "COMPONENT_PROPOSAL_RECORD_V2_KIND",
    "COMPONENT_UNIT_BINDING_INDEX_V2_FORMAT",
    "COMPONENT_EXTERNAL_SITE_SLICE_V1_FORMAT",
    "COMPONENT_INTERFACE_INTENT_V1_FORMAT",
    "COMPONENT_INTERFACE_INDEX_V5_FORMAT",
    "PORTABLE_COMPONENT_INTERFACE_V5_FORMAT",
    "INTERACTION_CONTRACT_V1_FORMAT",
    "INTERACTION_CONTRACT_CATALOG_V1_FORMAT",
    "INTERACTION_CONTRACT_RECEIPT_V1_FORMAT",
    "RETIRED_COMPONENT_IMPLEMENTATION_V4_FORMAT",
    "RETIRED_COMPONENT_IMPLEMENTATION_FACET_RECEIPT_V1_FORMAT",
    "COMPONENT_MACHINE_BINDING_INTENT_V1_FORMAT",
    "COMPONENT_MACHINE_BINDING_INDEX_V5_FORMAT",
    "RETIRED_COMPONENT_MACHINE_BINDING_V5_FORMAT",
    "COMPONENT_RELATION_INTENT_V1_FORMAT",
    "COMPONENT_SOURCE_PACKAGE_V3_FORMAT",
    "RETIRED_COMPONENT_WORK_PACKAGE_V5_FORMAT",
    "COMPONENT_WORK_PACKAGE_V6_FORMAT",
    "RETIRED_COMPONENT_ADOPTION_INTENT_V1_FORMAT",
    "RETIRED_COMPONENT_WORK_PACKAGE_INSPECTION_V1_FORMAT",
    "COMPONENT_PROPOSAL_INSPECTION_V1_FORMAT",
    "COMPONENT_BISIMULATION_INTENT_V1_FORMAT",
    "COMPONENT_PROOF_PLAN_V1_FORMAT",
    "CONTEXTUAL_REFINEMENT_V2_FORMAT",
    "COMPONENT_EXACT_C_SLICE_V1_FORMAT",
    "TRUSTED_ADAPTER_LOWERING_V1_FORMAT",
]
