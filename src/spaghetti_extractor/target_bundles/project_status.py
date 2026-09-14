"""Non-authorizing work views over materialized semantic-module products."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ..operator.work_status import write_operator_work_status_v2
from ..semantic_link.errors import LinkedSemanticModuleError
from ..semantic_link.formats import LINKED_SEMANTIC_MODULE_V2_FORMAT
from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from ..util import sha256_file
from .status_common import StatusArtifactError


def _v2_next_action(blockers: list[dict[str, Any]]) -> str:
    if not blockers:
        return "inspect a candidate configuration"
    code = blockers[0].get("code")
    return (
        f"resolve semantic hole {code}"
        if isinstance(code, str) and code
        else "inspect the first semantic hole"
    )


def _semantic_blocker(row: Mapping[str, Any]) -> dict[str, str | None]:
    code = row.get("code")
    location = next((
        row.get(field)
        for field in ("symbol_id", "relocation_id", "hole_id", "root_id", "unit_id")
        if row.get(field) is not None
    ), None)
    return {
        "family": str(row.get("family") or "semantic-link"),
        "code": str(code or "unknown_semantic_blocker"),
        "location": None if location is None else str(location),
    }


def build_project_status(
    *,
    target_id: str,
    linked_semantic_module: Path | str,
    out: Path | str,
) -> dict[str, object]:
    """Project checked module products without reconstructing authority.

    Project status supplies only ``linked_semantic_module``. Candidate status
    is projected separately from one exact implementation selection.
    """

    if not target_id:
        raise StatusArtifactError("target ID must be nonempty")
    module_path = Path(linked_semantic_module)
    try:
        raw = json.loads(module_path.read_text(encoding="utf-8"))
        if not isinstance(raw, Mapping):
            raise LinkedSemanticModuleError("linked semantic module must be an object")
        module_format = raw.get("format")
        if module_format != LINKED_SEMANTIC_MODULE_V2_FORMAT:
            raise LinkedSemanticModuleError(
                "linked semantic module format is unsupported"
            )
        module = LinkedSemanticModuleV2.load(module_path)
    except (
        LinkedSemanticModuleError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
    ) as exc:
        raise StatusArtifactError(f"linked semantic module is invalid: {exc}") from exc
    payload = module.payload
    raw_blockers = payload["semantic_holes"]
    if not isinstance(raw_blockers, list) or any(
        not isinstance(row, Mapping) for row in raw_blockers
    ):
        # The strict module parser already checks this.  Keep the projection's
        # boundary explicit so a future parser relaxation cannot become a
        # misleading operator report.
        raise StatusArtifactError("linked semantic module blockers are malformed")
    blockers = [dict(row) for row in raw_blockers]
    normalized_blockers = [_semantic_blocker(row) for row in blockers]
    subjects = [{
        "subject": f"module:{target_id}",
        "kind": "semantic_module",
        "state": payload["status"],
        "authority": "not-applicable",
        "stage": normalized_blockers[0]["family"] if normalized_blockers else None,
        "sources": [{
            "role": "linked-semantic-module",
            "format": module_format,
            "sha256": sha256_file(module_path),
        }],
        "blockers": normalized_blockers,
        "next_action": _v2_next_action(blockers),
    }]
    return write_operator_work_status_v2(
        target_id=target_id,
        scope="project",
        subjects=subjects,
        out=Path(out),
    )


__all__ = ["StatusArtifactError", "build_project_status"]
