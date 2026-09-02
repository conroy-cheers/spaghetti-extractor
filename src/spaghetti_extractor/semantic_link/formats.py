"""Format ownership for checked linked semantic modules."""

from __future__ import annotations

from ..artifacts.format_spec import FormatSpecV1


FORMAT_SPECS = (
    FormatSpecV1(
        literal="spaghetti-extractor-linked-semantic-module-v2",
        version=2,
        owner=__name__,
        codec="spaghetti_extractor.semantic_link.module_v2",
        role="linked_semantic_module",
        state="active",
        symbol="LINKED_SEMANTIC_MODULE_V2_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-linked-semantic-module-v1",
        version=1,
        owner=__name__,
        codec=__name__,
        role="linked_semantic_module",
        state="retired",
        symbol="RETIRED_LINKED_SEMANTIC_MODULE_V1_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-linked-semantic-module-replay-v2",
        version=2,
        owner=__name__,
        codec="spaghetti_extractor.semantic_link.replay",
        role="diagnostic",
        state="active",
        symbol="LINKED_SEMANTIC_MODULE_REPLAY_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-semantic-link-performance-v2",
        version=2,
        owner=__name__,
        codec="spaghetti_extractor.semantic_link.benchmark",
        role="diagnostic",
        state="active",
        symbol="SEMANTIC_LINK_PERFORMANCE_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-semantic-link-performance-v1",
        version=1,
        owner=__name__,
        codec=__name__,
        role="diagnostic",
        state="retired",
        symbol="RETIRED_SEMANTIC_LINK_PERFORMANCE_V1_FORMAT",
    ),
)

LINKED_SEMANTIC_MODULE_V2_FORMAT = FORMAT_SPECS[0].literal
RETIRED_LINKED_SEMANTIC_MODULE_V1_FORMAT = FORMAT_SPECS[1].literal
LINKED_SEMANTIC_MODULE_REPLAY_FORMAT = FORMAT_SPECS[2].literal
SEMANTIC_LINK_PERFORMANCE_FORMAT = FORMAT_SPECS[3].literal
RETIRED_SEMANTIC_LINK_PERFORMANCE_V1_FORMAT = FORMAT_SPECS[4].literal

__all__ = [spec.symbol for spec in FORMAT_SPECS] + ["FORMAT_SPECS"]
