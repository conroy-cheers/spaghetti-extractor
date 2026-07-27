"""Relational-v3 report fixtures for contract and Stage B tests."""

from __future__ import annotations

import json
from pathlib import Path

from spaghetti_extractor.relational.schema import (
    RELATIONAL_FINAL_ACCEPTANCE_THEOREM,
    STAGE_A_RELATIONAL_MODEL_ID,
    STAGE_A_RELATIONAL_PROFILE_ID,
)
from spaghetti_extractor.util import sha256_file


def write_relational_report(
    report: Path,
    *,
    original: Path,
    candidate: Path,
    status: str = "pass",
) -> Path:
    """Write the smallest artifact-bound v3 report accepted by the exporter."""

    report.mkdir(parents=True, exist_ok=True)
    satisfied = status == "pass"
    proof_ir = {
        "format": "stage-a-relational-proof-ir-v3",
        "status": "satisfied" if satisfied else "incomplete",
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "original": {"path": str(original), "sha256": sha256_file(original)},
        "candidate": {"path": str(candidate), "sha256": sha256_file(candidate)},
        "obligations": [
            {
                "id": "fixture:whole-program",
                "kind": "whole_program_acceptance",
                "status": "proved" if satisfied else "incomplete",
                "evidence": "fixture-whole-program-theorem" if satisfied else None,
                "blocker": None if satisfied else "fixture intentionally incomplete",
            }
        ],
    }
    proof_ir_path = report / "relational-proof-ir.json"
    proof_ir_path.write_text(json.dumps(proof_ir, sort_keys=True) + "\n", encoding="utf-8")
    theorem = RELATIONAL_FINAL_ACCEPTANCE_THEOREM
    verdict = {
        "format": "stage-a-relational-nix-build-v1",
        "status": status,
        "verdict": status,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "acceptance_authority": "whole_program_lean",
        "claim_scope": {
            "kind": "whole_program_observational_equivalence",
            "whole_program_observational_equivalence": satisfied,
            "acceptance_eligible": satisfied,
        },
        "original": {"path": str(original), "sha256": sha256_file(original)},
        "candidate": {"path": str(candidate), "sha256": sha256_file(candidate)},
        "proof_ir_sha256": sha256_file(proof_ir_path),
        "expected_final_theorem": theorem,
        "checks": {
            "graph": satisfied,
            "proof": satisfied,
        },
        "lean_audit": {
            "status": "checked" if satisfied else "incomplete",
            "lean_trust": 0 if satisfied else None,
            "theorem": theorem if satisfied else None,
        },
    }
    (report / "verdict.json").write_text(
        json.dumps(verdict, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report
