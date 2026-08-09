"""Low-level mutable-slot and launch facts shared by static v2 phases."""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from .authority_bindings_v2 import canonical_json_bytes
from .mutable_slot_candidates_v2 import (
    constant_address,
    derive_mutable_slot_candidates,
    rooted_reachable_unit_ids,
    writable_image_span,
)
from .stage_binary import StageABinary


def promote_complete_global_slot_evidence_v2(
    provenance: Mapping[str, Any],
    global_slot_evidence: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Expose only complete point-sensitive evidence to v2 constructors."""

    promoted = json.loads(canonical_json_bytes(provenance))
    # The input inventories are untrusted proposals.  In particular, rejected
    # tainted slots must not become entry facts merely because they appeared in
    # an interprocedural discovery pass.
    slots: list[dict[str, Any]] = []
    existing: dict[int, dict[str, Any]] = {}
    for evidence in global_slot_evidence:
        if not isinstance(evidence, Mapping):
            continue
        address = evidence.get("address")
        inventory = evidence.get("reachable_write_inventory")
        alternatives = evidence.get("alternatives")
        if (
            not isinstance(address, int)
            or isinstance(address, bool)
            or evidence.get("analysis_status") != "complete"
            or not isinstance(inventory, Mapping)
            or inventory.get("status") != "complete"
            or not isinstance(alternatives, list)
            or not alternatives
        ):
            continue
        if address not in existing:
            row = {
                "address": address,
                "origins": json.loads(canonical_json_bytes(alternatives)),
                "tainted": False,
                "authority": "exact_rooted_global_slot_replay_v2",
            }
            slots.append(row)
            existing[address] = row
    promoted["static_interface_slots"] = sorted(
        slots,
        key=lambda row: (
            not isinstance(row, Mapping)
            or not isinstance(row.get("address"), int),
            -1
            if not isinstance(row, Mapping)
            or not isinstance(row.get("address"), int)
            else int(row["address"]),
        ),
    )
    promoted["rejected_tainted_slots"] = []
    return promoted


def derive_iat_facts(binary: StageABinary) -> dict[str, Any]:
    return {
        "status": "complete",
        "entries": [
            {
                "dll": imported.dll,
                "symbol": imported.symbol,
                "ordinal": imported.ordinal,
                "iat_rva": imported.thunk_rva,
            }
            for imported in binary.imports
            if imported.thunk_rva is not None
        ],
    }


__all__ = [
    "constant_address",
    "derive_iat_facts",
    "derive_mutable_slot_candidates",
    "promote_complete_global_slot_evidence_v2",
    "rooted_reachable_unit_ids",
    "writable_image_span",
]
