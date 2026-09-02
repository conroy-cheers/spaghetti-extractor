"""Format ownership for semantic implementation providers."""

from __future__ import annotations

from ..artifacts.format_spec import FormatSpecV1


FORMAT_SPECS = (
    FormatSpecV1(
        literal="spaghetti-extractor-semantic-slice-v2",
        version=2,
        owner=__name__,
        codec="spaghetti_extractor.semantic_providers.slices_v2",
        role="semantic_slice",
        state="active",
        symbol="SEMANTIC_SLICE_V2_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-semantic-provider-qualification-v2",
        version=2,
        owner=__name__,
        codec="spaghetti_extractor.semantic_providers.qualification_v2",
        role="semantic_provider_qualification",
        state="active",
        symbol="SEMANTIC_PROVIDER_QUALIFICATION_V2_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-implementation-selection-v2",
        version=2,
        owner=__name__,
        codec="spaghetti_extractor.semantic_providers.selection_v2",
        role="implementation_selection",
        state="active",
        symbol="IMPLEMENTATION_SELECTION_V2_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-semantic-provider-qualification-v1",
        version=1,
        owner=__name__,
        codec=__name__,
        role="semantic_provider_qualification",
        state="retired",
        symbol="RETIRED_SEMANTIC_PROVIDER_QUALIFICATION_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-implementation-selection-v1",
        version=1,
        owner=__name__,
        codec=__name__,
        role="implementation_selection",
        state="retired",
        symbol="RETIRED_IMPLEMENTATION_SELECTION_V1_FORMAT",
    ),
)

SEMANTIC_SLICE_V2_FORMAT = FORMAT_SPECS[0].literal
SEMANTIC_PROVIDER_QUALIFICATION_V2_FORMAT = FORMAT_SPECS[1].literal
IMPLEMENTATION_SELECTION_V2_FORMAT = FORMAT_SPECS[2].literal
RETIRED_SEMANTIC_PROVIDER_QUALIFICATION_V1_FORMAT = FORMAT_SPECS[3].literal
RETIRED_IMPLEMENTATION_SELECTION_V1_FORMAT = FORMAT_SPECS[4].literal

__all__ = [
    "FORMAT_SPECS",
    "IMPLEMENTATION_SELECTION_V2_FORMAT",
    "RETIRED_IMPLEMENTATION_SELECTION_V1_FORMAT",
    "RETIRED_SEMANTIC_PROVIDER_QUALIFICATION_V1_FORMAT",
    "SEMANTIC_PROVIDER_QUALIFICATION_V2_FORMAT",
    "SEMANTIC_SLICE_V2_FORMAT",
]
