from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.implementation_ledger_v2 import (
    CompletionProfileV2,
    CompletionStatusV2,
    ImplementationOwnerKindV2,
)
from spaghetti_extractor.stage_b_ownership_ledger_v2 import (
    build_implementation_ledger_v2,
    emit_implementation_ledger_v2,
)
from spaghetti_extractor.lift_qualification_v1 import (
    LiftQualificationV1,
    QualificationAssuranceClassV1,
    QualificationEvidenceV1,
    QualificationStatusV1,
    QualificationSubjectKindV1,
)
from spaghetti_extractor.util import sha256_file


def _unit(unit_id: str, start: int) -> dict[str, object]:
    return {
        "format": "stage-a-machine-ir-v2",
        "id": unit_id,
        "source": {
            "original": {"rva_start": start, "rva_end": start + 1},
            "instruction_bytes_sha256": f"{start:064x}"[-64:],
        },
    }


def _machine_ir(root: Path) -> Path:
    root.mkdir()
    rows = (_unit("source", 0x1000), _unit("import", 0x1010), _unit("unknown", 0x1020))
    (root / "machine-ir.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    (root / "machine-ir-manifest.json").write_text(
        json.dumps(
            {
                "format": "stage-a-machine-ir-v2",
                "binary": {"sha256": "a" * 64},
            }
        ),
        encoding="utf-8",
    )
    return root


def _source(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "format": "stage-b-source-project-binding-v1",
                "program_id": "fixture",
                "coverage": {"source_bound_unit_ids": ["source"]},
                "equivalence_status": "pending",
                "authority": {"proves_source_semantics": False},
            }
        ),
        encoding="utf-8",
    )
    return path


def _linked(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "format": "stage-b-linked-island-manifest-v2",
                "islands": [
                    {
                        "id": "import:puts",
                        "kind": "import_thunk",
                        "unit_ids": ["import"],
                        "replacement_authorized": False,
                        "semantic_qualification": "not_attempted",
                    },
                    {
                        "id": "unknown:one",
                        "kind": "unknown",
                        "unit_ids": ["unknown"],
                        "replacement_authorized": False,
                        "semantic_qualification": "not_attempted",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


class OwnershipLedgerWorkflowV2Tests(unittest.TestCase):
    def test_portable_workflow_exposes_unqualified_and_unassigned_units(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = build_implementation_ledger_v2(
                machine_ir=_machine_ir(root / "machine"),
                profile=CompletionProfileV2.PORTABLE_APPLICATION,
                source_binding=_source(root / "source.json"),
                linked_islands=_linked(root / "linked.json"),
            )
            counts = {
                kind: sum(
                    len(record.units)
                    for record in ledger.ownership_records
                    if record.owner.kind is kind
                )
                for kind in ImplementationOwnerKindV2
            }
            self.assertEqual(counts[ImplementationOwnerKindV2.PORTABLE_COMPONENT], 1)
            self.assertEqual(counts[ImplementationOwnerKindV2.LIBRARY_SUBSTITUTION], 1)
            self.assertEqual(counts[ImplementationOwnerKindV2.UNASSIGNED], 1)
            self.assertIs(ledger.status, CompletionStatusV2.INCOMPLETE)
            self.assertEqual(
                {issue.code for issue in ledger.issues},
                {"qualification_identity_missing", "unit_owner_unassigned"},
            )

    def test_static_default_fallback_can_exactly_own_the_universe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fallback = root / "fallback"
            fallback.mkdir()
            (fallback / "manifest.json").write_text("{}", encoding="ascii")
            ledger = build_implementation_ledger_v2(
                machine_ir=_machine_ir(root / "machine"),
                profile=CompletionProfileV2.STATIC_BASELINE,
                fallback_coverage=fallback,
            )
            self.assertIs(ledger.status, CompletionStatusV2.COMPLETE)
            self.assertEqual(len(ledger.ownership_records), 1)
            self.assertIs(
                ledger.ownership_records[0].owner.kind,
                ImplementationOwnerKindV2.MACHINE_IR_FALLBACK,
            )

    def test_source_binding_cannot_self_qualify(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = _source(root / "source.json")
            payload = json.loads(source.read_text(encoding="utf-8"))
            payload["equivalence_status"] = "proven"
            payload["authority"]["proves_source_semantics"] = True
            source.write_text(json.dumps(payload), encoding="utf-8")
            ledger = build_implementation_ledger_v2(
                machine_ir=_machine_ir(root / "machine"),
                profile=CompletionProfileV2.PORTABLE_APPLICATION,
                source_binding=source,
            )
            source_owner = next(
                record.owner
                for record in ledger.ownership_records
                if record.owner.kind is ImplementationOwnerKindV2.PORTABLE_COMPONENT
            )
            self.assertIsNone(source_owner.qualification)

    def test_separate_exact_source_qualification_is_consumed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = _source(root / "source.json")
            evidence = tuple(
                QualificationEvidenceV1(
                    evidence_class=name,
                    artifact_kind=f"{name}-v1",
                    artifact_id=name,
                    artifact_sha256=f"{index + 1:064x}",
                    status=QualificationStatusV1.COMPLETE,
                )
                for index, name in enumerate(
                    (
                        "boundary_coverage",
                        "component_semantics",
                        "interface_contract",
                        "source_call_coverage",
                    )
                )
            )
            qualification = LiftQualificationV1.create(
                subject_kind=QualificationSubjectKindV1.SOURCE_PROJECT,
                assurance_class=(
                    QualificationAssuranceClassV1.CHECKED_SEMANTIC_REFINEMENT
                ),
                subject_id="fixture",
                implementation_sha256=sha256_file(source),
                unit_ids=("source",),
                evidence=evidence,
            )
            qualification_path = root / "qualification.json"
            qualification_path.write_text(qualification.to_json(), encoding="ascii")
            ledger = build_implementation_ledger_v2(
                machine_ir=_machine_ir(root / "machine"),
                profile=CompletionProfileV2.PORTABLE_APPLICATION,
                source_binding=source,
                source_qualification=qualification_path,
            )
            source_owner = next(
                record.owner
                for record in ledger.ownership_records
                if record.owner.kind is ImplementationOwnerKindV2.PORTABLE_COMPONENT
            )
            self.assertIsNotNone(source_owner.qualification)

    def test_validation_backed_source_requires_explicit_validation_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = _source(root / "source.json")
            evidence = tuple(
                QualificationEvidenceV1(
                    evidence_class=name,
                    artifact_kind=f"{name}-v1",
                    artifact_id=name,
                    artifact_sha256=f"{index + 1:064x}",
                    status=QualificationStatusV1.COMPLETE,
                )
                for index, name in enumerate(
                    (
                        "boundary_coverage",
                        "candidate_behavior",
                        "dependency_envelope",
                        "reconstruction_assumptions",
                        "source_call_coverage",
                    )
                )
            )
            qualification = LiftQualificationV1.create(
                subject_kind=QualificationSubjectKindV1.SOURCE_PROJECT,
                assurance_class=(
                    QualificationAssuranceClassV1.VALIDATION_BACKED_RECONSTRUCTION
                ),
                subject_id="fixture",
                implementation_sha256=sha256_file(source),
                unit_ids=("source",),
                evidence=evidence,
            )
            qualification_path = root / "validation-qualification.json"
            qualification_path.write_text(qualification.to_json(), encoding="ascii")

            with self.assertRaisesRegex(
                ValueError, "assurance class is not allowed"
            ):
                build_implementation_ledger_v2(
                    machine_ir=_machine_ir(root / "portable-machine"),
                    profile=CompletionProfileV2.PORTABLE_APPLICATION,
                    source_binding=source,
                    source_qualification=qualification_path,
                )

            ledger = build_implementation_ledger_v2(
                machine_ir=_machine_ir(root / "validation-machine"),
                profile=CompletionProfileV2.VALIDATION_QUALIFIED,
                source_binding=source,
                source_qualification=qualification_path,
            )
            source_owner = next(
                record.owner
                for record in ledger.ownership_records
                if record.owner.kind is ImplementationOwnerKindV2.PORTABLE_COMPONENT
            )
            self.assertIsNotNone(source_owner.qualification)

    def test_report_groups_repeated_primary_frontiers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = emit_implementation_ledger_v2(
                machine_ir=_machine_ir(root / "machine"),
                profile=CompletionProfileV2.PORTABLE_APPLICATION,
                source_binding=_source(root / "source.json"),
                linked_islands=_linked(root / "linked.json"),
                output_directory=root / "out",
            )
            self.assertEqual(report["issue_count"], 3)
            self.assertEqual(
                [row["code"] for row in report["primary_frontiers"]],
                ["qualification_identity_missing", "unit_owner_unassigned"],
            )


if __name__ == "__main__":
    unittest.main()
