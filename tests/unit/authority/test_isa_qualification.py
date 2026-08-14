from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.authority._schema import stable_id
from spaghetti_extractor.authority.exact_units import (
    EXACT_UNIT_CODEC_V3,
    ExactUnitV3,
)
from spaghetti_extractor.authority.isa_qualification import (
    ISA_QUALIFICATION_CODEC_V3,
    ISA_QUALIFICATION_EVIDENCE_ARTIFACT_KIND_V3,
    ISA_QUALIFICATION_EVIDENCE_CODEC_V3,
    ISA_QUALIFICATION_PHASE_V3,
    ISAOracleObservationV3,
    ISAQualificationEvidenceV3,
    isa_occurrence_id_v3,
    isa_qualification_sha256_v3,
)
from spaghetti_extractor.authority.root_closure import (
    LAUNCH_ROOT_CLOSURE_ARTIFACT_KIND_V3,
    LAUNCH_ROOT_CLOSURE_CODEC_V3,
    LaunchRootClosureV3,
)
from spaghetti_extractor.authority.semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
    derive_semantic_index_v3,
)
from spaghetti_extractor.artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
    RecordDependencyV3,
    canonical_sha256_v3,
)


PE_SHA256 = "a" * 64
BINDING = ArtifactBindingV3("binary", "pe32", "fixture.exe", PE_SHA256)


def _unit() -> dict[str, object]:
    instruction = {"rva_start": 0x1000, "rva_end": 0x1001}
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": "unit:1000",
        "status": "qualified",
        "source": {
            "original": {"rva_start": 0x1000, "rva_end": 0x1001},
            "instruction_bytes_sha256": "c" * 64,
        },
        "instructions": [instruction],
        "semantics": {
            "faults": [],
            "external_events": [],
            "outcome": {"kind": "return"},
        },
        "control": {
            "kind": "return",
            "direct_targets": [],
            "has_indirect_target": False,
        },
    }


def _write(
    path: Path,
    kind: str,
    records: tuple[ArtifactRecordV3, ...],
    *,
    status: str = "complete",
) -> Path:
    ArtifactSetWriterV3(
        artifact_kind=kind,
        bindings=(BINDING,),
        status=status,
    ).write(path, records)
    return path


def _base_inputs(root: Path) -> tuple[Path, Path, Path, ExactUnitV3]:
    exact = ExactUnitV3.create(
        _unit(),
        pe_sha256=PE_SHA256,
    )
    exact_path = _write(
        root / "exact",
        "exact-units-v3",
        (EXACT_UNIT_CODEC_V3.write(exact.record_id, exact),),
    )
    dependencies = (RecordDependencyV3("exact_units", exact.unit_id),)
    closure_id = stable_id(
        "launch-root-closure-v3",
        {
            "submitted_root_ids": ["root:entry"],
            "dependency_records": [row.to_payload() for row in dependencies],
        },
    )
    closure = LaunchRootClosureV3(
        record_id=closure_id,
        status="complete",
        authorizing=True,
        submitted_root_ids=("root:entry",),
        admitted_root_ids=("root:entry",),
        reachable_unit_ids=(exact.unit_id,),
        edges=(),
        frontier_ids=(),
        primary_blocker=None,
        dependencies=dependencies,
    )
    closure_path = _write(
        root / "root-closure",
        LAUNCH_ROOT_CLOSURE_ARTIFACT_KIND_V3,
        (
            LAUNCH_ROOT_CLOSURE_CODEC_V3.write(
                closure.record_id,
                closure,
            ),
        ),
    )
    semantic_path = _write(
        root / "semantic-index",
        SEMANTIC_INDEX_ARTIFACT_KIND_V3,
        (
            SEMANTIC_INDEX_CODEC_V3.write(
                exact.record_id, derive_semantic_index_v3(exact)
            ),
        ),
    )
    return exact_path, semantic_path, closure_path, exact


def _evidence(
    exact: ExactUnitV3,
    *,
    pe_sha256: str = PE_SHA256,
    decoded_form_id: str = "form:push-r32",
    selected_form_id: str = "form:push-r32",
    verdict: str = "qualified",
) -> ISAQualificationEvidenceV3:
    instruction = _unit()["instructions"][0]  # type: ignore[index]
    instruction_sha256 = canonical_sha256_v3(instruction)
    provisional = ISAQualificationEvidenceV3(
        record_id=isa_occurrence_id_v3(
            exact.unit_id, 0, instruction_sha256
        ),
        unit_id=exact.unit_id,
        unit_sha256=exact.unit_sha256,
        pe_sha256=pe_sha256,
        unit_ir_sha256=exact.unit_ir_sha256,
        instruction_index=0,
        instruction_sha256=instruction_sha256,
        rva_start=0x1000,
        rva_end=0x1001,
        decoded_form_id=decoded_form_id,
        selected_form_id=selected_form_id,
        semantic_form="push-r32",
        classifier_sha256="d" * 64,
        semantic_kernel_sha256="e" * 64,
        fallback_capability_id="machine-ir-fallback-v3",
        qualification_sha256="0" * 64,
        oracle_observations=(
            ISAOracleObservationV3(
                "lean", verdict, "f" * 64  # type: ignore[arg-type]
            ),
        ),
    )
    return replace(
        provisional,
        qualification_sha256=isa_qualification_sha256_v3(provisional),
    )


class ISAQualificationV3Tests(unittest.TestCase):
    def _run(
        self,
        root: Path,
        evidence_records: tuple[ArtifactRecordV3, ...],
    ):
        _exact_path, semantic_path, _closure_path, _exact = _base_inputs(root)
        evidence_path = _write(
            root / "isa-evidence",
            ISA_QUALIFICATION_EVIDENCE_ARTIFACT_KIND_V3,
            evidence_records,
        )
        output = ISA_QUALIFICATION_PHASE_V3.run(
            output_directory=root / "isa",
            inputs={
                "isa_evidence": evidence_path,
                "semantic_index": semantic_path,
            },
            bindings=(BINDING,),
        ).output_directory
        record = ArtifactSetReaderV3(output).get_record("unit:1000")
        return ISA_QUALIFICATION_CODEC_V3.read(record).value

    def test_positive_exact_form_chain_qualifies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _exact_path, _semantic_path, _closure_path, exact = _base_inputs(root / "seed")
            evidence = _evidence(exact)
            checked = self._run(
                root / "run",
                (
                    ISA_QUALIFICATION_EVIDENCE_CODEC_V3.write(
                        evidence.record_id, evidence
                    ),
                ),
            )
            self.assertEqual(checked.status, "complete")
            self.assertTrue(checked.authorizing)
            self.assertEqual(checked.selections[0].form_id, "form:push-r32")
            self.assertEqual(
                checked.selections[0].fallback_capability_id,
                "machine-ir-fallback-v3",
            )

    def test_missing_evidence_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            checked = self._run(Path(temporary), ())
            self.assertEqual(checked.status, "incomplete")
            self.assertFalse(checked.authorizing)
            self.assertEqual(
                checked.primary_blocker.code,
                "isa_qualification_evidence_missing",
            )
            self.assertEqual(checked.selections, ())

    def test_binary_form_and_disputed_oracle_contradictions_are_violations(
        self,
    ) -> None:
        for label, options, expected_code in (
            (
                "binary",
                {"pe_sha256": "9" * 64},
                "isa_evidence_binding_contradiction",
            ),
            (
                "form",
                {"selected_form_id": "form:other"},
                "isa_selected_form_mismatch",
            ),
            (
                "oracle",
                {"verdict": "disputed"},
                "isa_oracle_disputed",
            ),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _exact_path, _semantic_path, _closure_path, exact = _base_inputs(root / "seed")
                evidence = _evidence(exact, **options)
                checked = self._run(
                    root / "run",
                    (
                        ISA_QUALIFICATION_EVIDENCE_CODEC_V3.write(
                            evidence.record_id, evidence
                        ),
                    ),
                )
                self.assertEqual(checked.status, "violated")
                self.assertFalse(checked.authorizing)
                self.assertEqual(checked.primary_blocker.code, expected_code)
                self.assertEqual(checked.selections, ())


if __name__ == "__main__":
    unittest.main()
