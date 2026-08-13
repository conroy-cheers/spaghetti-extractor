from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.lift_qualification_v1 import (
    QualificationAssuranceClassV1,
    QualificationStatusV1,
)
from spaghetti_extractor.stage_b_runtime_qualification_v1 import (
    RuntimeQualificationV1Error,
    build_runtime_qualification_v1,
)


def _hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    ).hexdigest()


def _write(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value, sort_keys=True), encoding="ascii")
    return path


def _hashed(path: Path, value: dict[str, object], field: str) -> Path:
    value[field] = _hash(value)
    return _write(path, value)


def _inputs(root: Path, *, unknown: bool = False) -> dict[str, Path]:
    candidate = "a" * 64
    return {
        "linked_islands": _hashed(
            root / "linked.json",
            {
                "format": "stage-b-linked-island-manifest-v2",
                "status": "incomplete" if unknown else "classified",
                "islands": [
                    {
                        "id": "runtime",
                        "kind": "unknown" if unknown else "compiler_runtime",
                        "unit_ids": ["unit"],
                    }
                ],
            },
            "manifest_sha256",
        ),
        "runtime_lock": _write(
            root / "runtime.json",
            {
                "format": "spaghetti-extractor-runtime-lock-v1",
                "status": "complete",
            },
        ),
        "candidate_dependency_audit": _hashed(
            root / "dependency.json",
            {
                "format": "stage-b-candidate-dependency-audit-v1",
                "status": "pass",
                "bindings": {"candidate_sha256": candidate},
                "counts": {"unexpected": 0},
            },
            "audit_sha256",
        ),
        "component_assurance": _hashed(
            root / "assurance.json",
            {
                "format": "stage-b-source-component-assurance-v1",
                "status": "behavior_validated",
                "bindings": {"candidate_binary_sha256": candidate},
            },
            "assurance_sha256",
        ),
        "substitution_plan": _write(
            root / "plan.json",
            {
                "format": "spaghetti-extractor-runtime-substitution-plan-v1",
                "runtime_id": "runtime",
                "accepted_assumptions": [
                    "candidate_validation_is_not_exhaustive",
                    "linked_runtime_machine_to_source_equivalence_not_proven",
                ],
            },
        ),
    }


class RuntimeQualificationV1Tests(unittest.TestCase):
    def test_pinned_runtime_qualifies_without_claiming_semantic_proof(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = build_runtime_qualification_v1(
                **_inputs(Path(directory))
            )
            self.assertIs(result.status, QualificationStatusV1.COMPLETE)
            self.assertIs(
                result.assurance_class,
                QualificationAssuranceClassV1.PINNED_RUNTIME_SUBSTITUTION,
            )
            self.assertFalse(result.proves_semantics)

    def test_unknown_linked_unit_stays_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = build_runtime_qualification_v1(
                **_inputs(Path(directory), unknown=True)
            )
            self.assertIs(result.status, QualificationStatusV1.INCOMPLETE)

    def test_candidate_binding_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            inputs = _inputs(Path(directory))
            assurance = json.loads(
                inputs["component_assurance"].read_text(encoding="ascii")
            )
            assurance.pop("assurance_sha256")
            assurance["bindings"]["candidate_binary_sha256"] = "b" * 64
            _hashed(
                inputs["component_assurance"],
                assurance,
                "assurance_sha256",
            )
            with self.assertRaisesRegex(
                RuntimeQualificationV1Error, "different candidates"
            ):
                build_runtime_qualification_v1(**inputs)


if __name__ == "__main__":
    unittest.main()
