"""Versioned artifact identifiers owned by reusable library lifting."""

from ..artifacts.format_spec import FormatSpecV1


_OWNER = __name__

FORMAT_SPECS = (
    FormatSpecV1(
        literal="spaghetti-extractor-reusable-library-source-qualification-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.libraries.behavior_pack_v3",
        role="receipt",
        state="active",
        symbol="REUSABLE_LIBRARY_SOURCE_QUALIFICATION_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-reusable-library-behavior-pack-v3",
        version=3,
        owner=_OWNER,
        codec="spaghetti_extractor.libraries.behavior_pack_v3",
        role="behavior_pack",
        state="active",
        symbol="REUSABLE_LIBRARY_BEHAVIOR_PACK_V3_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-generated-library-component-v2",
        version=2,
        owner=_OWNER,
        codec=_OWNER,
        role="component_package",
        state="retired",
        symbol="RETIRED_GENERATED_LIBRARY_COMPONENT_V2_FORMAT",
    ),
)

REUSABLE_LIBRARY_SOURCE_QUALIFICATION_V1_FORMAT = FORMAT_SPECS[0].literal
REUSABLE_LIBRARY_BEHAVIOR_PACK_V3_FORMAT = FORMAT_SPECS[1].literal
RETIRED_GENERATED_LIBRARY_COMPONENT_V2_FORMAT = FORMAT_SPECS[2].literal

__all__ = [spec.symbol for spec in FORMAT_SPECS] + ["FORMAT_SPECS"]
