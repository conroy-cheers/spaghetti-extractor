"""Artifact formats owned by PE32 module and project deployment."""

from __future__ import annotations

from ..artifacts.format_spec import FormatSpecV1


_OWNER = __name__

FORMAT_SPECS = (
    FormatSpecV1(
        literal="spaghetti-extractor-pe32-module-interface-v2",
        version=2,
        owner=_OWNER,
        codec="spaghetti_extractor.pe32.module_interface",
        role="interface",
        state="active",
        symbol="PE32_MODULE_INTERFACE_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-pe32-module-deployment-v3",
        version=3,
        owner=_OWNER,
        codec=_OWNER,
        role="completion",
        state="retired",
        symbol="RETIRED_PE32_MODULE_DEPLOYMENT_V3_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-pe32-loader-surface-receipt-v2",
        version=2,
        owner=_OWNER,
        codec=_OWNER,
        role="receipt",
        state="retired",
        symbol="RETIRED_PE32_LOADER_SURFACE_RECEIPT_V2_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-pe32-project-intent-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.project_load_plan",
        role="intent",
        state="active",
        symbol="PE32_PROJECT_INTENT_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-pe32-project-load-plan-v2",
        version=2,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.project",
        role="plan",
        state="active",
        symbol="PE32_PROJECT_LOAD_PLAN_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-pe32-load-observation-v2",
        version=2,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.project",
        role="observation",
        state="active",
        symbol="PE32_LOAD_OBSERVATION_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-pe32-observed-load-graph-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.project",
        role="observation",
        state="active",
        symbol="PE32_OBSERVED_LOAD_GRAPH_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-pe32-project-completion-v3",
        version=3,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.project",
        role="completion",
        state="active",
        symbol="PE32_PROJECT_COMPLETION_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-pe32-module-deployment-v2",
        version=2,
        owner=_OWNER,
        codec=_OWNER,
        role="completion",
        state="retired",
        symbol="RETIRED_PE32_MODULE_DEPLOYMENT_V2_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-pe32-project-load-plan-v1",
        version=1,
        owner=_OWNER,
        codec=_OWNER,
        role="plan",
        state="retired",
        symbol="RETIRED_PE32_PROJECT_LOAD_PLAN_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-pe32-project-completion-v2",
        version=2,
        owner=_OWNER,
        codec=_OWNER,
        role="completion",
        state="retired",
        symbol="RETIRED_PE32_PROJECT_COMPLETION_V2_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-pe32-load-observation-v1",
        version=1,
        owner=_OWNER,
        codec=_OWNER,
        role="observation",
        state="retired",
        symbol="RETIRED_PE32_LOAD_OBSERVATION_V1_FORMAT",
    ),
)

PE32_MODULE_INTERFACE_FORMAT = FORMAT_SPECS[0].literal
RETIRED_PE32_MODULE_DEPLOYMENT_V3_FORMAT = FORMAT_SPECS[1].literal
RETIRED_PE32_LOADER_SURFACE_RECEIPT_V2_FORMAT = FORMAT_SPECS[2].literal
PE32_PROJECT_INTENT_FORMAT = FORMAT_SPECS[3].literal
PE32_PROJECT_LOAD_PLAN_FORMAT = FORMAT_SPECS[4].literal
PE32_LOAD_OBSERVATION_FORMAT = FORMAT_SPECS[5].literal
PE32_OBSERVED_LOAD_GRAPH_FORMAT = FORMAT_SPECS[6].literal
PE32_PROJECT_COMPLETION_FORMAT = FORMAT_SPECS[7].literal
RETIRED_PE32_MODULE_DEPLOYMENT_V2_FORMAT = FORMAT_SPECS[8].literal
RETIRED_PE32_PROJECT_LOAD_PLAN_V1_FORMAT = FORMAT_SPECS[9].literal
RETIRED_PE32_PROJECT_COMPLETION_V2_FORMAT = FORMAT_SPECS[10].literal
RETIRED_PE32_LOAD_OBSERVATION_V1_FORMAT = FORMAT_SPECS[11].literal

__all__ = [spec.symbol for spec in FORMAT_SPECS] + ["FORMAT_SPECS"]
