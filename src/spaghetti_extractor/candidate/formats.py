"""Artifact formats owned by behavioral-C and native-ingress construction."""

from __future__ import annotations

from ..artifacts.format_spec import FormatSpecV1


_OWNER = __name__
SPX_RUNTIME_STATE_LAYOUT_FORMAT = (
    "spaghetti-extractor-runtime-state-layout-table-v1"
)

FORMAT_SPECS = (
    FormatSpecV1(
        literal="spaghetti-extractor-behavioral-c-layout-intent-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.behavioral_c_package",
        role="intent",
        state="active",
        symbol="BEHAVIORAL_C_LAYOUT_INTENT_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-behavioral-c-plan-v2",
        version=2,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.behavioral_c_package",
        role="plan",
        state="active",
        symbol="BEHAVIORAL_C_PLAN_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-behavioral-c-package-v2",
        version=2,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.behavioral_c_package",
        role="package",
        state="active",
        symbol="BEHAVIORAL_C_PACKAGE_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-behavioral-c-lowering-v2",
        version=2,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.behavioral_c_package",
        role="receipt",
        state="active",
        symbol="BEHAVIORAL_C_LOWERING_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-behavioral-c-coverage-v2",
        version=2,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.behavioral_c_package",
        role="receipt",
        state="active",
        symbol="BEHAVIORAL_C_COVERAGE_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-behavioral-c-runtime-qualification-v2",
        version=2,
        owner=_OWNER,
        codec=_OWNER,
        role="qualification",
        state="retired",
        symbol="RETIRED_BEHAVIORAL_C_RUNTIME_QUALIFICATION_V2_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-behavioral-c-completion-v2",
        version=2,
        owner=_OWNER,
        codec=_OWNER,
        role="completion",
        state="retired",
        symbol="RETIRED_BEHAVIORAL_C_COMPLETION_V2_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-native-ingress-plan-v2",
        version=2,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.native_ingress_plan",
        role="plan",
        state="active",
        symbol="NATIVE_INGRESS_PLAN_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-checked-boundary-outcome-protocol-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.outcomes",
        role="protocol",
        state="active",
        symbol="CHECKED_BOUNDARY_OUTCOME_PROTOCOL_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-checked-seh-protocol-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.outcomes",
        role="protocol",
        state="active",
        symbol="CHECKED_SEH_PROTOCOL_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-pinned-code-layout-authority-v2",
        version=2,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.outcomes",
        role="authority",
        state="active",
        symbol="PINNED_CODE_LAYOUT_AUTHORITY_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-behavioral-c-source-map-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.behavioral_c_package",
        role="source_map",
        state="active",
        symbol="BEHAVIORAL_C_SOURCE_MAP_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-behavioral-c-build-manifest-v2",
        version=2,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.behavioral_c_package",
        role="build_manifest",
        state="active",
        symbol="BEHAVIORAL_C_BUILD_MANIFEST_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-native-module-build-plan-v2",
        version=2,
        owner=_OWNER,
        codec=_OWNER,
        role="plan",
        state="retired",
        symbol="RETIRED_NATIVE_MODULE_BUILD_PLAN_V2_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-native-module-link-receipt-v2",
        version=2,
        owner=_OWNER,
        codec=_OWNER,
        role="receipt",
        state="retired",
        symbol="RETIRED_NATIVE_MODULE_LINK_RECEIPT_V2_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-native-realization-build-manifest-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.build_workflow",
        role="internal_link_manifest",
        state="active",
        symbol="NATIVE_REALIZATION_BUILD_MANIFEST_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-module-runtime-core-package-v1",
        version=1,
        owner=_OWNER,
        codec=_OWNER,
        role="runtime_source_package",
        state="retired",
        symbol="RETIRED_MODULE_RUNTIME_CORE_PACKAGE_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-shared-module-runtime-package-v2",
        version=2,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.runtime",
        role="runtime_source_package",
        state="active",
        symbol="SHARED_MODULE_RUNTIME_PACKAGE_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-behavioral-c-differential-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.behavioral_c_differential",
        role="diagnostic_receipt",
        state="active",
        symbol="BEHAVIORAL_C_DIFFERENTIAL_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-module-runtime-core-plan-v1",
        version=1,
        owner=_OWNER,
        codec=_OWNER,
        role="runtime_plan",
        state="retired",
        symbol="RETIRED_MODULE_RUNTIME_CORE_PLAN_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-module-runtime-plan-v2",
        version=2,
        owner=_OWNER,
        codec=_OWNER,
        role="runtime_plan",
        state="retired",
        symbol="RETIRED_MODULE_RUNTIME_PLAN_V2_FORMAT",
    ),
    FormatSpecV1(
        literal=SPX_RUNTIME_STATE_LAYOUT_FORMAT,
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.module_runtime_layout",
        role="linked_runtime_metadata",
        state="active",
        symbol="SPX_RUNTIME_STATE_LAYOUT_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-native-module-build-plan-v1",
        version=1,
        owner=_OWNER,
        codec=_OWNER,
        role="plan",
        state="retired",
        symbol="RETIRED_NATIVE_MODULE_BUILD_PLAN_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-native-module-link-receipt-v1",
        version=1,
        owner=_OWNER,
        codec=_OWNER,
        role="receipt",
        state="retired",
        symbol="RETIRED_NATIVE_MODULE_LINK_RECEIPT_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-native-linked-skeleton-v1",
        version=1,
        owner=_OWNER,
        codec=_OWNER,
        role="internal_link_manifest",
        state="retired",
        symbol="RETIRED_NATIVE_LINKED_SKELETON_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-behavioral-c-plan-v1",
        version=1,
        owner=_OWNER,
        codec=_OWNER,
        role="plan",
        state="retired",
        symbol="RETIRED_BEHAVIORAL_C_PLAN_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-behavioral-c-package-v1",
        version=1,
        owner=_OWNER,
        codec=_OWNER,
        role="package",
        state="retired",
        symbol="RETIRED_BEHAVIORAL_C_PACKAGE_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-behavioral-c-lowering-v1",
        version=1,
        owner=_OWNER,
        codec=_OWNER,
        role="receipt",
        state="retired",
        symbol="RETIRED_BEHAVIORAL_C_LOWERING_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-behavioral-c-coverage-v1",
        version=1,
        owner=_OWNER,
        codec=_OWNER,
        role="receipt",
        state="retired",
        symbol="RETIRED_BEHAVIORAL_C_COVERAGE_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-behavioral-c-runtime-qualification-v1",
        version=1,
        owner=_OWNER,
        codec=_OWNER,
        role="qualification",
        state="retired",
        symbol="RETIRED_BEHAVIORAL_C_RUNTIME_QUALIFICATION_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-behavioral-c-completion-v1",
        version=1,
        owner=_OWNER,
        codec=_OWNER,
        role="completion",
        state="retired",
        symbol="RETIRED_BEHAVIORAL_C_COMPLETION_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-behavioral-c-build-manifest-v1",
        version=1,
        owner=_OWNER,
        codec=_OWNER,
        role="build_manifest",
        state="retired",
        symbol="RETIRED_BEHAVIORAL_C_BUILD_MANIFEST_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-module-runtime-plan-v3",
        version=3,
        owner=_OWNER,
        codec=_OWNER,
        role="runtime_plan",
        state="retired",
        symbol="RETIRED_MODULE_RUNTIME_PLAN_V3_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-module-runtime-plan-v4",
        version=4,
        owner=_OWNER,
        codec=_OWNER,
        role="runtime_plan",
        state="retired",
        symbol="RETIRED_MODULE_RUNTIME_PLAN_V4_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-module-runtime-plan-v5",
        version=5,
        owner=_OWNER,
        codec=_OWNER,
        role="runtime_plan",
        state="retired",
        symbol="RETIRED_MODULE_RUNTIME_PLAN_V5_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-module-runtime-plan-v6",
        version=6,
        owner=_OWNER,
        codec=_OWNER,
        role="runtime_plan",
        state="retired",
        symbol="RETIRED_MODULE_RUNTIME_PLAN_V6_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-module-runtime-plan-v8",
        version=8,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.module_runtime_plan",
        role="runtime_plan",
        state="active",
        symbol="MODULE_RUNTIME_PLAN_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-pinned-code-layout-authority-v1",
        version=1,
        owner=_OWNER,
        codec=_OWNER,
        role="authority",
        state="retired",
        symbol="RETIRED_PINNED_CODE_LAYOUT_AUTHORITY_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-module-runtime-plan-v7",
        version=7,
        owner=_OWNER,
        codec=_OWNER,
        role="runtime_plan",
        state="retired",
        symbol="RETIRED_MODULE_RUNTIME_PLAN_V7_FORMAT",
    ),
)

BEHAVIORAL_C_LAYOUT_INTENT_FORMAT = FORMAT_SPECS[0].literal
BEHAVIORAL_C_PLAN_FORMAT = FORMAT_SPECS[1].literal
BEHAVIORAL_C_PACKAGE_FORMAT = FORMAT_SPECS[2].literal
BEHAVIORAL_C_LOWERING_FORMAT = FORMAT_SPECS[3].literal
BEHAVIORAL_C_COVERAGE_FORMAT = FORMAT_SPECS[4].literal
RETIRED_BEHAVIORAL_C_RUNTIME_QUALIFICATION_V2_FORMAT = FORMAT_SPECS[5].literal
RETIRED_BEHAVIORAL_C_COMPLETION_V2_FORMAT = FORMAT_SPECS[6].literal
NATIVE_INGRESS_PLAN_FORMAT = FORMAT_SPECS[7].literal
CHECKED_BOUNDARY_OUTCOME_PROTOCOL_FORMAT = FORMAT_SPECS[8].literal
CHECKED_SEH_PROTOCOL_FORMAT = FORMAT_SPECS[9].literal
PINNED_CODE_LAYOUT_AUTHORITY_FORMAT = FORMAT_SPECS[10].literal
BEHAVIORAL_C_SOURCE_MAP_FORMAT = FORMAT_SPECS[11].literal
BEHAVIORAL_C_BUILD_MANIFEST_FORMAT = FORMAT_SPECS[12].literal
RETIRED_NATIVE_MODULE_BUILD_PLAN_V2_FORMAT = FORMAT_SPECS[13].literal
RETIRED_NATIVE_MODULE_LINK_RECEIPT_V2_FORMAT = FORMAT_SPECS[14].literal
NATIVE_REALIZATION_BUILD_MANIFEST_FORMAT = FORMAT_SPECS[15].literal
RETIRED_MODULE_RUNTIME_CORE_PACKAGE_FORMAT = FORMAT_SPECS[16].literal
SHARED_MODULE_RUNTIME_PACKAGE_FORMAT = FORMAT_SPECS[17].literal
BEHAVIORAL_C_DIFFERENTIAL_FORMAT = FORMAT_SPECS[18].literal
RETIRED_MODULE_RUNTIME_CORE_PLAN_FORMAT = FORMAT_SPECS[19].literal
RETIRED_MODULE_RUNTIME_PLAN_V2_FORMAT = FORMAT_SPECS[20].literal
RETIRED_NATIVE_MODULE_BUILD_PLAN_V1_FORMAT = FORMAT_SPECS[22].literal
RETIRED_NATIVE_MODULE_LINK_RECEIPT_V1_FORMAT = FORMAT_SPECS[23].literal
RETIRED_NATIVE_LINKED_SKELETON_V1_FORMAT = FORMAT_SPECS[24].literal
RETIRED_BEHAVIORAL_C_PLAN_V1_FORMAT = FORMAT_SPECS[25].literal
RETIRED_BEHAVIORAL_C_PACKAGE_V1_FORMAT = FORMAT_SPECS[26].literal
RETIRED_BEHAVIORAL_C_LOWERING_V1_FORMAT = FORMAT_SPECS[27].literal
RETIRED_BEHAVIORAL_C_COVERAGE_V1_FORMAT = FORMAT_SPECS[28].literal
RETIRED_BEHAVIORAL_C_RUNTIME_QUALIFICATION_V1_FORMAT = FORMAT_SPECS[29].literal
RETIRED_BEHAVIORAL_C_COMPLETION_V1_FORMAT = FORMAT_SPECS[30].literal
RETIRED_BEHAVIORAL_C_BUILD_MANIFEST_V1_FORMAT = FORMAT_SPECS[31].literal
RETIRED_MODULE_RUNTIME_PLAN_V3_FORMAT = FORMAT_SPECS[32].literal
RETIRED_MODULE_RUNTIME_PLAN_V4_FORMAT = FORMAT_SPECS[33].literal
RETIRED_MODULE_RUNTIME_PLAN_V5_FORMAT = FORMAT_SPECS[34].literal
RETIRED_MODULE_RUNTIME_PLAN_V6_FORMAT = FORMAT_SPECS[35].literal
MODULE_RUNTIME_PLAN_FORMAT = FORMAT_SPECS[36].literal
RETIRED_PINNED_CODE_LAYOUT_AUTHORITY_V1_FORMAT = FORMAT_SPECS[37].literal
RETIRED_MODULE_RUNTIME_PLAN_V7_FORMAT = FORMAT_SPECS[38].literal

__all__ = [spec.symbol for spec in FORMAT_SPECS] + ["FORMAT_SPECS"]
