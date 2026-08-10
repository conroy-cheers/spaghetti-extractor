"""Stable wire-format names and projections shared by analysis phases."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .artifact_identity_v2 import canonical_sha256

ROOTED_CONTROL_GRAPH_V2_FORMAT = "stage-a-rooted-control-graph-v2"
CHECKED_MEMORY_RANGE_FACT_V2_FORMAT = "stage-a-checked-memory-range-fact-v2"
CHECKED_MEMORY_ACCESS_FACT_V2_FORMAT = "stage-a-checked-memory-access-fact-v2"
INTERPROCEDURAL_AUTHORITY_STATE_V2_FORMAT = (
    "spaghetti-extractor-interprocedural-authority-state-v2"
)


def interprocedural_authority_signature_v2(
    *,
    root_unit_ids: Sequence[str],
    dependency_inventory: Sequence[Mapping[str, Any]],
    call_summaries: Mapping[str, Any],
    recovered_targets: Sequence[Mapping[str, Any]],
    memory_access_facts: Sequence[Mapping[str, Any]] = (),
    call_site_effects: Sequence[Mapping[str, Any]] = (),
) -> str:
    """Bind the exact interprocedural outputs consumed by later phases.

    The digest is an integrity and cache identity, not a proof.  Its purpose is
    to prevent the static gate from accepting a replay marker that was copied
    from a different set of summaries, targets, or dependency facts.
    """

    return canonical_sha256({
        "format": INTERPROCEDURAL_AUTHORITY_STATE_V2_FORMAT,
        "root_unit_ids": sorted(root_unit_ids),
        "dependency_inventory": sorted(
            (dict(row) for row in dependency_inventory),
            key=lambda row: str(row.get("id", "")),
        ),
        "call_summaries": dict(call_summaries),
        "recovered_targets": sorted(
            (dict(row) for row in recovered_targets),
            key=lambda row: str(row.get("id", "")),
        ),
        # The authority digest is embedded back into each sealed access fact.
        # Exclude that self-binding and the derived fact digest here so the
        # signature remains acyclic while still covering all semantic content.
        "memory_access_facts": sorted(
            (
                {
                    key: value
                    for key, value in dict(row).items()
                    if key
                    not in {
                        "interprocedural_authority_sha256",
                        "fact_sha256",
                    }
                }
                for row in memory_access_facts
            ),
            key=lambda row: str(row.get("id", "")),
        ),
        "call_site_effects": sorted(
            (dict(row) for row in call_site_effects),
            key=lambda row: (
                str(row.get("unit_id", "")),
                str(row.get("event_index", "")),
                canonical_sha256(row),
            ),
        ),
    })


__all__ = [
    "CHECKED_MEMORY_RANGE_FACT_V2_FORMAT",
    "CHECKED_MEMORY_ACCESS_FACT_V2_FORMAT",
    "INTERPROCEDURAL_AUTHORITY_STATE_V2_FORMAT",
    "ROOTED_CONTROL_GRAPH_V2_FORMAT",
    "interprocedural_authority_signature_v2",
]
