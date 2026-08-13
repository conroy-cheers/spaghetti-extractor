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
from spaghetti_extractor.stage_b_source_qualification_v1 import (
    SourceQualificationV1Error,
    build_source_qualification_v1,
)


def _hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    ).hexdigest()


def _write_hashed(
    path: Path, value: dict[str, object], hash_field: str
) -> Path:
    value[hash_field] = _hash(value)
    path.write_text(json.dumps(value, sort_keys=True), encoding="ascii")
    return path


def _fixture(root: Path, *, complete: bool) -> dict[str, Path]:
    binding = {
        "format": "stage-b-source-project-binding-v1",
        "program_id": "fixture",
        "coverage": {
            "source_bound_unit_ids": ["unit"],
            "reviewed_scope": {
                "fully_source_bound": True,
                "remaining_machine_units": 0,
            },
        },
        "islands": [{"id": "main", "boundary": {}}],
    }
    binding_path = _write_hashed(
        root / "binding.json", binding, "binding_sha256"
    )
    call_report = {
        "format": "stage-b-source-call-binding-report-v1",
        "status": "incomplete",
        "bindings": {},
        "issues": [
            {"status": "incomplete", "code": "call_plan_not_ready"}
        ],
        "counts": {
            "source_calls": 3,
            "covered_by_source_component": 3,
            "unbound_source_local": 0,
        },
    }
    call_path = _write_hashed(
        root / "calls.json", call_report, "report_sha256"
    )
    candidate_sha = "c" * 64
    assurance = {
        "format": "stage-b-source-component-assurance-v1",
        "status": "behavior_validated" if complete else "incomplete",
        "equivalence_status": "not_proven",
        "program_id": "fixture",
        "bindings": {
            "source_project_binding_sha256": binding["binding_sha256"],
            "source_call_report_sha256": call_report["report_sha256"],
            "candidate_binary_sha256": candidate_sha,
        },
        "accepted_assumptions": [
            "integration_coverage_is_not_exhaustive",
            "machine_to_source_component_equivalence_not_proven",
        ],
        "counts": {
            "components": 1,
            "behavior_validated": 1 if complete else 0,
            "incomplete_or_violated": 0 if complete else 1,
            "source_calls": 3,
            "covered_source_calls": 3,
        },
        "authority": {
            "proves_equivalence": False,
            "can_authorize_machine_override": False,
        },
    }
    assurance_path = _write_hashed(
        root / "assurance.json", assurance, "assurance_sha256"
    )
    dependency = {
        "format": "stage-b-candidate-dependency-audit-v1",
        "status": "pass" if complete else "violated",
        "bindings": {"candidate_sha256": candidate_sha},
        "counts": {"unexpected": 0 if complete else 1},
    }
    dependency_path = _write_hashed(
        root / "dependency.json", dependency, "audit_sha256"
    )
    return {
        "source_binding": binding_path,
        "component_assurance": assurance_path,
        "source_call_report": call_path,
        "candidate_dependency_audit": dependency_path,
    }


class SourceQualificationV1Tests(unittest.TestCase):
    def test_validation_backed_source_can_complete_without_claiming_proof(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            qualification = build_source_qualification_v1(
                **_fixture(Path(directory), complete=True)
            )
            self.assertIs(
                qualification.assurance_class,
                QualificationAssuranceClassV1.VALIDATION_BACKED_RECONSTRUCTION,
            )
            self.assertIs(
                qualification.status, QualificationStatusV1.COMPLETE
            )
            self.assertFalse(qualification.proves_semantics)

    def test_candidate_failure_is_a_violation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            qualification = build_source_qualification_v1(
                **_fixture(Path(directory), complete=False)
            )
            self.assertIs(
                qualification.status, QualificationStatusV1.VIOLATED
            )

    def test_stale_evidence_binding_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            inputs = _fixture(Path(directory), complete=True)
            assurance = json.loads(
                inputs["component_assurance"].read_text(encoding="ascii")
            )
            assurance.pop("assurance_sha256")
            assurance["bindings"]["candidate_binary_sha256"] = "d" * 64
            _write_hashed(
                inputs["component_assurance"],
                assurance,
                "assurance_sha256",
            )
            with self.assertRaisesRegex(
                SourceQualificationV1Error, "one candidate project"
            ):
                build_source_qualification_v1(**inputs)


if __name__ == "__main__":
    unittest.main()
