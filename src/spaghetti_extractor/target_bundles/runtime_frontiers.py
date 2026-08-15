"""Pure runtime-relevant projection of checked static authority diagnostics."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.formats import AUTHORITY_DIAGNOSTICS_V3_FORMAT
from ..util import sha256_file, write_json
from .status_common import StatusArtifactError, copied_rows, load_object


RUNTIME_FRONTIER_REPORT_FORMAT = "spaghetti-extractor-runtime-frontier-report-v1"

_RUNTIME_FAMILY_TERMS = frozenset(
    {
        "callback",
        "call",
        "control",
        "exception",
        "external",
        "fallback",
        "implementation",
        "indirect",
        "isa",
        "reachability",
        "return",
        "semantic",
        "target",
    }
)


def _runtime_relevant(row: Mapping[str, Any]) -> bool:
    searchable = " ".join(
        str(row.get(name) or "").lower()
        for name in ("family", "code", "record_id")
    )
    return any(term in searchable for term in _RUNTIME_FAMILY_TERMS)


def build_runtime_frontier_report(
    *, authority_diagnostics: Path | str, out: Path | str
) -> dict[str, Any]:
    """Project authority-owned runtime frontiers without generating a candidate."""

    authority_path = Path(authority_diagnostics)
    authority = load_object(authority_path, "authority diagnostics")
    if authority.get("format") != AUTHORITY_DIAGNOSTICS_V3_FORMAT:
        raise StatusArtifactError("authority diagnostics format is unsupported")
    authority_status = authority.get("status")
    if authority_status not in {"complete", "incomplete", "violated"}:
        raise StatusArtifactError("authority diagnostics status is unsupported")
    frontiers = [
        row
        for row in copied_rows(
            authority.get("primary_frontiers", []), "authority primary frontiers"
        )
        if _runtime_relevant(row)
    ]
    frontier_keys = {
        (str(row.get("family") or ""), str(row.get("code") or ""))
        for row in frontiers
    }
    consequences = [
        copy.deepcopy(dict(row))
        for row in authority.get("dependency_consequences", [])
        if isinstance(row, Mapping)
        and (
            (str(row.get("family") or ""), str(row.get("code") or ""))
            in frontier_keys
            or any(
                term
                in " ".join(
                    str(row.get(name) or "").lower()
                    for name in ("family", "code", "root_code")
                )
                for term in _RUNTIME_FAMILY_TERMS
            )
        )
    ]
    status = (
        "violated"
        if any(row.get("status") == "violated" for row in frontiers)
        else "incomplete"
        if frontiers
        else "complete"
    )
    result = {
        "format": RUNTIME_FRONTIER_REPORT_FORMAT,
        "status": status,
        "authorizing": False,
        "authority_input": {
            "format": AUTHORITY_DIAGNOSTICS_V3_FORMAT,
            "sha256": sha256_file(authority_path),
            "status": authority_status,
            "authorizing": authority.get("authorizing") is True,
        },
        "counts": {
            "frontiers": len(frontiers),
            "violated": sum(row.get("status") == "violated" for row in frontiers),
            "incomplete": sum(row.get("status") == "incomplete" for row in frontiers),
            "dependent_groups": len(consequences),
        },
        "frontiers": frontiers,
        "dependency_consequences": consequences,
        "policy": {
            "diagnostic_only": True,
            "authority_recomputed": False,
            "candidate_generated": False,
            "source_generated": False,
            "object_code_emitted": False,
            "runtime_executed": False,
            "original_binary_executed": False,
        },
    }
    write_json(Path(out), result)
    return result


__all__ = [
    "RUNTIME_FRONTIER_REPORT_FORMAT",
    "StatusArtifactError",
    "build_runtime_frontier_report",
]
