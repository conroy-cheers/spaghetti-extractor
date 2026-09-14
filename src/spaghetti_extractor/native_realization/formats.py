"""Format ownership for the consolidated native realization boundary."""

from __future__ import annotations

from ..artifacts.format_spec import FormatSpecV1


FORMAT_SPECS = (
    FormatSpecV1(
        literal="spaghetti-extractor-native-realization-v2",
        version=2,
        owner=__name__,
        codec="spaghetti_extractor.native_realization.receipt_v2",
        role="native_realization",
        state="active",
        symbol="NATIVE_REALIZATION_V2_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-portable-dispatch-link-receipt-v1",
        version=1,
        owner=__name__,
        codec="spaghetti_extractor.native_realization.receipt_v2",
        role="portable_dispatch_link_receipt",
        state="active",
        symbol="PORTABLE_DISPATCH_LINK_RECEIPT_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-native-realization-v1",
        version=1,
        owner=__name__,
        codec=__name__,
        role="native_realization",
        state="retired",
        symbol="RETIRED_NATIVE_REALIZATION_V1_FORMAT",
    ),
)

NATIVE_REALIZATION_V2_FORMAT = FORMAT_SPECS[0].literal
PORTABLE_DISPATCH_LINK_RECEIPT_V1_FORMAT = FORMAT_SPECS[1].literal
RETIRED_NATIVE_REALIZATION_V1_FORMAT = FORMAT_SPECS[2].literal

__all__ = [
    "FORMAT_SPECS", "NATIVE_REALIZATION_V2_FORMAT",
    "PORTABLE_DISPATCH_LINK_RECEIPT_V1_FORMAT",
    "RETIRED_NATIVE_REALIZATION_V1_FORMAT",
]
