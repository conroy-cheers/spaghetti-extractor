from __future__ import annotations

from typing import Any


RuntimeFrameLocation = tuple[str, int, str, int]


def runtime_frame_location_key(location: dict[str, Any]) -> RuntimeFrameLocation:
    return (
        str(location.get("original_register", "esp")),
        int(location["original"]),
        str(location.get("candidate_register", "esp")),
        int(location["candidate"]),
    )


def runtime_frame_location_payload(
    location: RuntimeFrameLocation,
) -> dict[str, Any]:
    return {
        "original_register": location[0],
        "original": location[1],
        "candidate_register": location[2],
        "candidate": location[3],
    }


def return_frame_claim_for_location(
    relation_row: dict[str, Any],
    location: RuntimeFrameLocation,
) -> dict[str, Any] | None:
    for claim in relation_row.get("return_pop_frame_claims", []):
        if runtime_frame_location_key(claim["offsets"]) == location:
            return claim
    return_claim = relation_row.get("return_pop_claim") or {}
    if (
        location[0] != "esp"
        or location[2] != "esp"
        or location[1] != int(return_claim.get("original_stack_offset", -1))
        or location[3] != int(return_claim.get("candidate_stack_offset", -1))
        or return_claim.get("original_stack_witness") is None
        or return_claim.get("candidate_stack_witness") is None
    ):
        return None
    return {
        "profile": "return_pop_runtime_frame_v1",
        "offsets": runtime_frame_location_payload(location),
        "original_slot_witness": return_claim["original_stack_witness"],
        "candidate_slot_witness": return_claim["candidate_stack_witness"],
    }
