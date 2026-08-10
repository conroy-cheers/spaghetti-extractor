"""Canonical dependency identities shared by Stage A authority artifacts.

Analysis adapters may retain site-specific witnesses for diagnostics.  The
fixed-point authority graph, however, must compare the proof node which closes
the witness.  In particular, an exact internal call-frame witness is closed by
the checked summary of its callee.
"""

from __future__ import annotations

import json
from typing import Iterable


CALL_FRAME_DEPENDENCY_PREFIX = "call-frame:"
CALL_SUMMARY_NODE_PREFIX = "call-summary:"


def call_frame_dependency_id(
    source_unit_id: str, event_index: int, target_unit_id: str
) -> str:
    payload = json.dumps(
        [source_unit_id, event_index, target_unit_id],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return f"{CALL_FRAME_DEPENDENCY_PREFIX}{payload}"


def parse_call_frame_dependency(
    value: object,
) -> tuple[str, int, str] | None:
    if not isinstance(value, str) or not value.startswith(
        CALL_FRAME_DEPENDENCY_PREFIX
    ):
        return None
    try:
        payload = json.loads(value.removeprefix(CALL_FRAME_DEPENDENCY_PREFIX))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if (
        not isinstance(payload, list)
        or len(payload) != 3
        or not isinstance(payload[0], str)
        or not payload[0]
        or not isinstance(payload[1], int)
        or isinstance(payload[1], bool)
        or payload[1] < 0
        or not isinstance(payload[2], str)
        or not payload[2]
    ):
        return None
    return payload[0], payload[1], payload[2]


def canonical_authority_dependency(value: str) -> str:
    """Return the checked fixed-point node which discharges ``value``.

    Unknown or malformed dependency families remain unchanged.  They then
    fail closed unless an authority node with that exact identity exists.
    """

    call_frame = parse_call_frame_dependency(value)
    return (
        value
        if call_frame is None
        else f"{CALL_SUMMARY_NODE_PREFIX}{call_frame[2]}"
    )


def canonical_authority_dependencies(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({
        canonical_authority_dependency(value) for value in values
    }))


__all__ = [
    "CALL_FRAME_DEPENDENCY_PREFIX",
    "CALL_SUMMARY_NODE_PREFIX",
    "call_frame_dependency_id",
    "canonical_authority_dependencies",
    "canonical_authority_dependency",
    "parse_call_frame_dependency",
]
