"""Non-authorizing executable-transfer lowering capability analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..artifacts.artifact_set import canonical_sha256_v3
from ..machine_ir.fallback_capability import (
    FallbackCapabilityAnalysis,
    FallbackLoweringHashes,
)
from ..util import sha256_file, write_json
from .plan import (
    _transfer_payload,
    _unit_binding,
    adapt_exact_machine_ir_rows,
    compile_transfer_rows,
    transfer_blocker_sort_key,
)
from .values import _read_jsonl, _string


def write_transfer_capability_analysis(
    *, machine_ir: Path, out: Path
) -> dict[str, Any]:
    """Check exact transfer-plan lowerability without emitting source or code."""

    machine_ir = Path(machine_ir)
    input_rows = _read_jsonl(machine_ir)
    rows = adapt_exact_machine_ir_rows(input_rows)
    transfers, blockers = compile_transfer_rows(rows, collect_blockers=True)
    blockers.sort(key=transfer_blocker_sort_key)
    blocked_ids = {
        row.get("transfer_id")
        for row in blockers
        if isinstance(row.get("transfer_id"), str)
    }
    lowered_ids = sorted(
        row.identity for row in transfers if row.identity not in blocked_ids
    )
    input_ids = sorted(
        _string(row.get("id"), "machine-IR unit id") for row in input_rows
    )
    unit_bindings = {
        str(row["unit_id"]): row for row in map(_unit_binding, input_rows)
    }
    transfer_root = Path(__file__).resolve().parent
    lowering = FallbackLoweringHashes(
        transfer_rows_sha256=canonical_sha256_v3(
            [_transfer_payload(row, unit_bindings[row.identity]) for row in transfers]
        ),
        transfer_model_sha256=sha256_file(transfer_root / "model.py"),
        evaluator_model_sha256=sha256_file(transfer_root / "evaluator.py"),
    )
    report = FallbackCapabilityAnalysis.create(
        machine_ir_path=machine_ir.name,
        machine_ir_sha256=sha256_file(machine_ir),
        capability_id="machine-ir-fallback-v3",
        lowering=lowering,
        required_unit_ids=input_ids,
        lowerable_unit_ids=lowered_ids,
        blockers=blockers,
        max_word_nodes_per_transfer=max(
            (len(row.nodes) for row in transfers), default=0
        ),
    ).to_payload()
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_json(out, report)
    return report


__all__ = ["write_transfer_capability_analysis"]
