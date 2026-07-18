from __future__ import annotations

from pathlib import Path
from typing import Any

from ..stage_binary import StageABinary
from .diagnostics import _complete_counterexample_assignment
from .executor import _run_lean_relational
from .lean.definitions import _lean_counterexample_source
from .verdict import _counterexample_assignment


def check_relational_counterexample(
    lean_dir: Path,
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    original: bytes,
    candidate: bytes,
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    production: dict[str, Any],
) -> dict[str, Any] | None:
    output = (
        str(production.get("stderr") or "")
        + "\n"
        + str(production.get("stdout") or "")
    )
    assignment = _counterexample_assignment(output)
    if not assignment:
        return None
    for index, region in enumerate(contract["regions"]):
        concrete_assignment = _complete_counterexample_assignment(
            region, assignment
        )
        source = _lean_counterexample_source(
            original_bin,
            candidate_bin,
            original,
            candidate,
            contract["code_targets"],
            contract.get("machine_import_call_contracts", []),
            region,
            index,
            behaviors[index],
            concrete_assignment,
        )
        path = lean_dir / "StageA" / "RelationalCounterexample.lean"
        path.write_text(source, encoding="utf-8")
        checked = _run_lean_relational(
            lean_dir, bundle="RelationalCounterexample"
        )
        if checked.get("status") == "checked":
            return {
                **checked,
                "counterexample": concrete_assignment,
                "region_id": region["id"],
                "theorem": (
                    "StageA.GeneratedRelationalCounterexample."
                    "exactCounterexample"
                ),
            }
    return None


_check_relational_counterexample = check_relational_counterexample
