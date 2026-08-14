"""Read-only diagnostics over a materialized reference contract."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..util import write_json
from .reference_diagnostics import (
    _load_reference_contract_sidecars,
    _stage_a_smoke_contract_issues,
)
from .reference_utils import (
    _gap_severity_rank,
    _load_json,
    _matches_focus,
    _reference_input_artifact,
)


def stage_a_smoke_contract(
    *, reference_contract: Path, out: Path | None = None
) -> dict[str, Any]:
    reference_contract = Path(reference_contract)
    contract = _load_json(reference_contract)
    issues = _stage_a_smoke_contract_issues(contract, reference_contract)
    result = {
        "format": "stage-a-contract-smoke-v1",
        "status": "qualified" if not issues else "incomplete",
        "reference_contract": _reference_input_artifact(reference_contract),
        "issues": issues,
        "counts": {"issues": len(issues)},
    }
    if out is not None:
        write_json(Path(out), result)
    return result


def stage_a_explain_obligations(
    *, reference_contract: Path, focus: str, out: Path | None = None
) -> dict[str, Any]:
    reference_contract = Path(reference_contract)
    contract = _load_json(reference_contract)
    sidecars = _load_reference_contract_sidecars(contract, reference_contract)
    focus_lower = focus.lower()
    gaps = [
        item
        for item in sidecars.get("coverage_gaps", {}).get("gaps", [])
        if _matches_focus(item, focus_lower)
    ]
    families = [
        item
        for item in contract.get("families", [])
        if isinstance(item, dict) and _matches_focus(item, focus_lower)
    ]
    result = {
        "format": "stage-a-contract-explanation-v1",
        "status": "qualified" if gaps or families else "incomplete",
        "focus": focus,
        "reference_contract": _reference_input_artifact(reference_contract),
        "families": families,
        "gaps": gaps,
        "counts": {"families": len(families), "gaps": len(gaps)},
    }
    if out is not None:
        write_json(Path(out), result)
    return result


def stage_a_diff_obligations(
    *, before: Path, after: Path, out: Path | None = None
) -> dict[str, Any]:
    before = Path(before)
    after = Path(after)
    before_contract = _load_json(before)
    after_contract = _load_json(after)
    before_sidecars = _load_reference_contract_sidecars(before_contract, before)
    after_sidecars = _load_reference_contract_sidecars(after_contract, after)
    before_gaps = {
        str(item.get("gap_id")): item
        for item in before_sidecars.get("coverage_gaps", {}).get("gaps", [])
        if isinstance(item, dict) and item.get("gap_id")
    }
    after_gaps = {
        str(item.get("gap_id")): item
        for item in after_sidecars.get("coverage_gaps", {}).get("gaps", [])
        if isinstance(item, dict) and item.get("gap_id")
    }
    before_ids = set(before_gaps)
    after_ids = set(after_gaps)
    unchanged_ids = before_ids & after_ids
    regressed_ids = [
        gap_id
        for gap_id in unchanged_ids
        if _gap_severity_rank(after_gaps[gap_id].get("severity"))
        > _gap_severity_rank(before_gaps[gap_id].get("severity"))
    ]
    result = {
        "format": "stage-a-contract-diff-v1",
        "status": "qualified",
        "before": _reference_input_artifact(before),
        "after": _reference_input_artifact(after),
        "resolved": [before_gaps[item] for item in sorted(before_ids - after_ids)],
        "new": [after_gaps[item] for item in sorted(after_ids - before_ids)],
        "regressed": [after_gaps[item] for item in sorted(regressed_ids)],
        "unchanged": [after_gaps[item] for item in sorted(unchanged_ids)],
    }
    result["counts"] = {
        "resolved": len(result["resolved"]),
        "new": len(result["new"]),
        "regressed": len(result["regressed"]),
        "unchanged": len(result["unchanged"]),
    }
    if out is not None:
        write_json(Path(out), result)
    return result


__all__ = [
    "stage_a_diff_obligations",
    "stage_a_explain_obligations",
    "stage_a_smoke_contract",
]
