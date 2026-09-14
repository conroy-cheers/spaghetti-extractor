"""Format ownership for the versioned operator discovery and status surface."""

from __future__ import annotations

from ..artifacts.format_spec import FormatSpecV1


FORMAT_SPECS = (
    FormatSpecV1(
        literal="spaghetti-extractor-operator-work-status-v1",
        version=1,
        owner=__name__,
        codec="spaghetti_extractor.operator.work_status",
        role="operator_view",
        state="retired",
        symbol="RETIRED_OPERATOR_WORK_STATUS_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-operator-work-status-v2",
        version=2,
        owner=__name__,
        codec="spaghetti_extractor.operator.work_status",
        role="operator_view",
        state="active",
        symbol="OPERATOR_WORK_STATUS_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-operator-index-v1",
        version=1,
        owner=__name__,
        codec="spaghetti_extractor.operator.index_v1",
        role="operator_view",
        state="active",
        symbol="OPERATOR_INDEX_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-operator-blocker-detail-v1",
        version=1,
        owner=__name__,
        codec="spaghetti_extractor.operator.work_status",
        role="operator_view",
        state="active",
        symbol="OPERATOR_BLOCKER_DETAIL_FORMAT",
    ),
)

RETIRED_OPERATOR_WORK_STATUS_V1_FORMAT = FORMAT_SPECS[0].literal
OPERATOR_WORK_STATUS_FORMAT = FORMAT_SPECS[1].literal
OPERATOR_INDEX_FORMAT = FORMAT_SPECS[2].literal
OPERATOR_BLOCKER_DETAIL_FORMAT = FORMAT_SPECS[3].literal

__all__ = [spec.symbol for spec in FORMAT_SPECS] + ["FORMAT_SPECS"]
