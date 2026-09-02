"""Non-authorizing status views over heterogeneous checked boundaries."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ..components.formats import COMPONENT_WORK_PACKAGE_INSPECTION_V1_FORMAT
from ..errors import ToolkitInputError
from ..operator.work_status import write_operator_work_status_v1
from ..util import sha256_file


def _object(path: Path, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ToolkitInputError(f"cannot read {context}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ToolkitInputError(f"{context} must be an object")
    return value


def parse_component_work_package_inspection_v1(
    value: object,
) -> dict[str, Any]:
    """Validate the configured-component inspection projection."""

    if not isinstance(value, Mapping):
        raise ToolkitInputError("component work-package inspection must be an object")
    payload = dict(value)
    if set(payload) != {
        "format", "status", "subject", "component_id",
        "proof_classification", "semantic_slice_sha256", "operations",
        "faithful_c_slices", "requirements", "issues", "authority",
    }:
        raise ToolkitInputError(
            "component work-package inspection fields are incomplete"
        )
    if payload.get("format") != COMPONENT_WORK_PACKAGE_INSPECTION_V1_FORMAT:
        raise ToolkitInputError("component work-package inspection format is unsupported")
    if payload.get("status") not in {"complete", "incomplete"}:
        raise ToolkitInputError("component work-package inspection status is unsupported")
    if payload.get("authority") is not False:
        raise ToolkitInputError("component work-package inspection cannot authorize")
    subject = payload.get("subject")
    component_id = payload.get("component_id")
    if (
        not isinstance(subject, str) or not subject.startswith("component:")
        or not isinstance(component_id, str) or not component_id
        or subject != f"component:{component_id}"
    ):
        raise ToolkitInputError("component work-package inspection identity is stale")
    if payload.get("proof_classification") not in {
        "machine_overlay", "encapsulated_owned",
    }:
        raise ToolkitInputError(
            "component work-package inspection proof classification is unsupported"
        )
    digest = payload.get("semantic_slice_sha256")
    if (
        not isinstance(digest, str) or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ToolkitInputError("component work-package inspection slice is malformed")
    for field in ("operations", "faithful_c_slices", "issues"):
        if not isinstance(payload.get(field), list):
            raise ToolkitInputError(
                f"component work-package inspection {field} must be an array"
            )
    if not isinstance(payload.get("requirements"), Mapping):
        raise ToolkitInputError(
            "component work-package inspection requirements must be an object"
        )
    return payload


def write_operator_boundary_status(
    *,
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
        blocker_rows = [
            dict(blocker)
            if isinstance(blocker, Mapping)
            else {
                "code": "boundary_status_blocker",
                "detail": str(blocker),
            }
            for blocker in blockers
        ]
        bindings = [{
            "artifact": status_name,
            "format": status.get("format"),
            "sha256": sha256_file(status_path),
        }]
        protocol_path = package / "checked-call-protocol.json"
        if protocol_path.is_file():
            protocol = _object(protocol_path, f"{subject} checked protocol")
            bindings.append({
                "artifact": "checked-call-protocol.json",
                "format": protocol.get("format"),
                "sha256": sha256_file(protocol_path),
            })
        slice_path = package / "semantic-slice-v2.json"
        if slice_path.is_file():
            semantic_slice = _object(slice_path, f"{subject} semantic slice")
            bindings.append({
                "artifact": "semantic-slice-v2.json",
                "format": semantic_slice.get("format"),
                "sha256": sha256_file(slice_path),
            })
        subjects.append({
            "subject": subject,
            "state": state,
            "authority": authoritative,
            "bindings": bindings,
            "blockers": blocker_rows,
            "dependencies": [],
            "ranked_next_action": (
                None
                if authoritative
                else "author component C and run contextual refinement"
                if kind == "component"
                else "supply and check machine-bound boundary evidence"
                if state == "complete"
                else "repair the first reported boundary blocker"
            ),
        })
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    return write_operator_work_status_v1(
        subjects=subjects,
        out=output / "boundary-status.json",
    )


__all__ = [
    "parse_component_work_package_inspection_v1",
    "write_operator_boundary_status",
]
