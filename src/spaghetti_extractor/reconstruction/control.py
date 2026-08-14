"""Public pure control-flow analysis API."""

from .control_clusters import propose_semantic_clusters
from .control_jump_tables import (
    pe32_jump_table_index_expression,
    recover_static_pe32_jump_table_inventory,
)
from .control_reachability import (
    canonical_indirect_external_targets,
    classify_overlapping_instruction_starts,
    derive_rooted_reachable_units,
)


__all__ = [
    "derive_rooted_reachable_units",
    "pe32_jump_table_index_expression",
    "propose_semantic_clusters",
    "recover_static_pe32_jump_table_inventory",
]
