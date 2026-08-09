"""Small canonical identity helpers shared by content-addressed phases."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json_v2(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_v2(value).encode("ascii")).hexdigest()


__all__ = ["canonical_json_v2", "canonical_sha256"]
