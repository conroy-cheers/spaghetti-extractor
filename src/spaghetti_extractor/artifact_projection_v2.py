from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


JOINT_INTERPROCEDURAL_FORMAT_V2 = (
    "spaghetti-extractor-joint-interprocedural-analysis-v2"
)


def project_joint_interprocedural_artifact_v2(
    joint: Mapping[str, Any],
    *,
    field: str,
    expected_format: str,
    allowed_statuses: Iterable[str],
) -> dict[str, Any]:
    """Extract a checked child artifact without importing analysis producers."""

    if joint.get("format") != JOINT_INTERPROCEDURAL_FORMAT_V2:
        raise ValueError("joint interprocedural artifact format mismatch")
    if joint.get("status") not in {"complete", "incomplete", "violated"}:
        raise ValueError("joint interprocedural artifact has an invalid status")

    child = joint.get(field)
    if not isinstance(child, dict):
        raise ValueError(f"joint interprocedural artifact has no object field {field!r}")
    if child.get("format") != expected_format:
        raise ValueError(
            f"projected {field!r} format mismatch: "
            f"expected {expected_format!r}, observed {child.get('format')!r}"
        )
    allowed = frozenset(allowed_statuses)
    if child.get("status") not in allowed:
        raise ValueError(
            f"projected {field!r} status is outside the allowed fail-closed set"
        )
    return dict(child)
