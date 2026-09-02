"""Format ownership for domain-neutral operator work-status views."""

from __future__ import annotations

from ..artifacts.format_spec import FormatSpecV1


FORMAT_SPECS = (
    FormatSpecV1(
        literal="spaghetti-extractor-operator-work-status-v1",
        version=1,
        owner=__name__,
        codec="spaghetti_extractor.operator.work_status",
        role="operator_view",
        state="active",
        symbol="OPERATOR_WORK_STATUS_FORMAT",
    ),
)

OPERATOR_WORK_STATUS_FORMAT = FORMAT_SPECS[0].literal

__all__ = ["FORMAT_SPECS", "OPERATOR_WORK_STATUS_FORMAT"]
