"""Canonical manifest I/O."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from .diagnostics import Diagnostic, TestkitError
from .model import ImpactIndex, SuitePlan, canonical_json


def _read_object(path: Path) -> Mapping[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TestkitError(
            Diagnostic(
                "error",
                "manifest_unreadable",
                str(exc),
                location=str(path),
                remediation="Regenerate the manifest with the current testkit.",
            )
        ) from exc
    if not isinstance(value, Mapping):
        raise TestkitError(Diagnostic("error", "manifest_not_object", "manifest must be a JSON object", location=str(path)))
    return value


def load_index(path: Path) -> ImpactIndex:
    return ImpactIndex.from_dict(_read_object(path))


def load_plan(path: Path) -> SuitePlan:
    return SuitePlan.from_dict(_read_object(path))


def write_manifest(path: Path, value: object) -> None:
    payload = value.as_dict() if hasattr(value, "as_dict") else value
    rendered = canonical_json(payload)
    if str(path) == "-":
        print(rendered, end="")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")


__all__ = ["load_index", "load_plan", "write_manifest"]
