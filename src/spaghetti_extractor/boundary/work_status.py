"""Non-authorizing status views over heterogeneous checked boundaries."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ..errors import ToolkitInputError
from ..operator.work_status import write_operator_work_status_v2
from ..util import sha256_file


def _object(path: Path, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ToolkitInputError(f"cannot read {context}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ToolkitInputError(f"{context} must be an object")
    return value


def write_operator_boundary_status(
    *,
    target_id: str,
    packages: Mapping[str, Path],
    kinds: Mapping[str, str],
    out: Path,
) -> dict[str, Any]:
    if set(packages) != set(kinds):
        raise ToolkitInputError("boundary status package identities disagree")
    subjects: list[dict[str, Any]] = []
    for subject, package in sorted(packages.items()):
        kind = kinds[subject]
        if kind not in {"checked_protocol", "checked_schema", "component"}:
            raise ToolkitInputError("boundary status kind is unsupported")
        package = Path(package)
        status_name = (
            "call-status.json"
            if kind == "checked_protocol"
            else "boundary-status.json"
            if kind == "checked_schema"
            else "component-work-package-v6.json"
        )
        status_path = package / status_name
        status = _object(status_path, f"{subject} boundary status")
        state = status.get("status")
        if kind == "component" and state == "ready":
            state = "complete" if not status.get("blockers") else "incomplete"
        if state not in {"complete", "incomplete", "violated"}:
            raise ToolkitInputError(f"{subject} boundary status is unsupported")
        authoritative = (
            state == "complete"
            and kind == "checked_protocol"
            and (package / "checked-call-protocol.json").is_file()
        )
        raw_blockers = status.get("issues", status.get("blockers", []))
        blockers = (
            raw_blockers
            if isinstance(raw_blockers, list)
            else ["boundary status contains a malformed blocker inventory"]
        )
        blocker_rows = []
        for blocker in blockers:
            row = dict(blocker) if isinstance(blocker, Mapping) else {
                "code": "boundary_status_blocker",
                "detail": str(blocker),
            }
            location = next((
                row.get(field)
                for field in (
                    "subject", "operation_id", "symbol_id", "site_id", "rva",
                    "detail",
                )
                if row.get(field) is not None
            ), None)
            blocker_rows.append({
                "family": str(row.get("family") or kind.replace("_", "-")),
                "code": str(row.get("code") or "boundary_status_blocker"),
                "location": None if location is None else str(location),
            })
        status_format = status.get("format")
        if not isinstance(status_format, str) or not status_format:
            raise ToolkitInputError(f"{subject} boundary status format is malformed")
        subjects.append({
            "subject": subject,
            "kind": kind,
            "state": state,
            "authority": "held" if authoritative else (
                "missing" if kind == "checked_protocol" else "not-applicable"
            ),
            "stage": blocker_rows[0]["family"] if blocker_rows else None,
            "sources": [{
                "role": "boundary-status",
                "format": status_format,
                "sha256": sha256_file(status_path),
            }],
            "blockers": blocker_rows,
            "next_action": (
                None
                if authoritative
                else "run the component qualification check"
                if kind == "component" and state == "complete"
                else "resolve the first component development blocker"
                if kind == "component"
                else "supply and check machine-bound boundary evidence"
                if state == "complete"
                else "repair the first reported boundary blocker"
            ),
        })
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    return write_operator_work_status_v2(
        target_id=target_id,
        scope="boundary",
        subjects=subjects,
        out=output / "boundary-status.json",
    )


__all__ = [
    "write_operator_boundary_status",
]
