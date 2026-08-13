"""Stable v3 semantic identities shared across authority phases."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from ..artifact_set_v3 import canonical_json_bytes_v3


def indirect_exit_id_v3(value: Mapping[str, Any]) -> str:
    """Identify one exact indirect exit without legacy schema dependencies."""

    identity = {
        "source_unit_id": value.get("source_unit_id"),
        "source_rva": value.get("source_rva"),
        "source_event_index": value.get("source_event_index"),
        "kind": value.get("kind"),
        "target_expression": value.get("target_expression"),
    }
    return "indirect-exit:" + hashlib.sha256(
        canonical_json_bytes_v3(identity)
    ).hexdigest()[:20]


__all__ = ["indirect_exit_id_v3"]
