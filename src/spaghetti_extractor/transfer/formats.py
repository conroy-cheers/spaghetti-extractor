"""Format ownership for canonical executable-transfer artifacts."""

from __future__ import annotations

from ..artifacts.format_spec import FormatSpecV1


_OWNER = __name__

FORMAT_SPECS = (
    FormatSpecV1(
        literal="spaghetti-extractor-executable-transfer-plan-v2",
        version=2,
        owner=_OWNER,
        codec="spaghetti_extractor.transfer.plan",
        role="executable_plan",
        state="active",
        symbol="EXECUTABLE_TRANSFER_PLAN_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-transfer-definedness-use-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.candidate.runtime_program_validation",
        role="analysis_receipt",
        state="active",
        symbol="TRANSFER_DEFINEDNESS_USE_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-module-execution-closure-v2",
        version=2,
        owner=_OWNER,
        codec="spaghetti_extractor.transfer.closure",
        role="execution_closure",
        state="active",
        symbol="MODULE_EXECUTION_CLOSURE_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-module-execution-closure-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.transfer.closure",
        role="execution_closure",
        state="retired",
        symbol="MODULE_EXECUTION_CLOSURE_V1_RETIRED_FORMAT",
    ),
)

EXECUTABLE_TRANSFER_PLAN_FORMAT = FORMAT_SPECS[0].literal
TRANSFER_DEFINEDNESS_USE_FORMAT = FORMAT_SPECS[1].literal
MODULE_EXECUTION_CLOSURE_FORMAT = FORMAT_SPECS[2].literal
MODULE_EXECUTION_CLOSURE_V1_RETIRED_FORMAT = FORMAT_SPECS[3].literal

__all__ = [spec.symbol for spec in FORMAT_SPECS] + ["FORMAT_SPECS"]
