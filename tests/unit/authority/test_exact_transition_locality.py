from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.authority._schema import AnalysisV3Error
from spaghetti_extractor.authority.exact_units import (
    EXACT_UNIT_CODEC_V3,
    EXACT_UNITS_PHASE_V3,
    ExactUnitV3,
    check_exact_units_completeness_v3,
)
from spaghetti_extractor.authority.transition_records import (
    TRANSITION_SUMMARY_CODEC_V3,
)
from spaghetti_extractor.authority.transition_summaries import (
    TRANSITION_SUMMARIES_PHASE_V3,
)
from spaghetti_extractor.artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactDependencyV3,
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
    RecordDependencyV3,
    canonical_sha256_v3,
)
from spaghetti_extractor.phase_framework_v3 import PhaseContextV3


PE_SHA256 = "a" * 64
BINARY = ArtifactBindingV3("binary", "pe32", "fixture.exe", PE_SHA256)


def _unit(unit_id: str, rva: int, target_rva: int) -> dict[str, object]:
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": unit_id,
        "status": "qualified",
        "source": {
            "original": {"rva_start": rva, "rva_end": rva + 8},
            "instruction_bytes_sha256": f"{rva:064x}",
        },
        "expression_model": "stage-a-semantic-ir-v1",
        "instructions": [],
        "semantics": {
            "pre_state": {
                "registers": {},
                "flags": {},
                "memory": {
                    "op": "memory",
                    "name": "mem0",
                    "address_width": 32,
                    "value_width": 8,
                },
            },
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": [],
            "faults": [],
            "ordered_events": [],
            "edge_conditions": [],
            "outcome": {"kind": "direct_jump", "target_rva": target_rva},
            "stack_delta": None,
            "counts": {
                "register_writes": 0,
                "flag_writes": 0,
                "memory_events": 0,
                "external_events": 0,
                "faults": 0,
                "ordered_events": 0,
                "edge_conditions": 0,
            },
        },
        "control": {
            "kind": "direct_jump",
            "direct_targets": [target_rva],
            "has_indirect_target": False,
        },
    }


def _write_artifact(
    path: Path,
    kind: str,
    records: tuple[ArtifactRecordV3, ...],
    *,
    bindings: tuple[ArtifactBindingV3, ...] = (BINARY,),
    dependencies: tuple[ArtifactDependencyV3, ...] = (),
) -> Path:
    ArtifactSetWriterV3(
        artifact_kind=kind,
        bindings=bindings,
        dependencies=dependencies,
    ).write(path, records)
    return path


def _write_machine_ir(path: Path, units: tuple[dict[str, object], ...]) -> Path:
    return _write_artifact(
        path,
        "machine-ir-v3-input",
        tuple(ArtifactRecordV3.create(str(unit["id"]), unit) for unit in units),
    )


def _records(path: Path) -> dict[str, ArtifactRecordV3]:
    return {
        record.record_id: record
        for record in ArtifactSetReaderV3(path).iter_records()
    }


class ExactTransitionLocalityTests(unittest.TestCase):
    def _run_layers(self, root: Path, units: tuple[dict[str, object], ...]):
        machine_ir = _write_machine_ir(root / "machine-ir", units)
        exact = EXACT_UNITS_PHASE_V3.run(
            output_directory=root / "exact",
            inputs={"machine_ir": machine_ir},
            bindings=(BINARY,),
        ).output_directory
        transitions = TRANSITION_SUMMARIES_PHASE_V3.run(
            output_directory=root / "transitions",
            inputs={"exact_units": exact},
            bindings=(BINARY,),
        ).output_directory
        return _records(exact), _records(transitions)

    def test_unit_change_preserves_other_exact_and_transition_records(self) -> None:
        units = (
            _unit("unit:a", 0x1000, 0x1010),
            _unit("unit:b", 0x1010, 0x1000),
        )
        changed = (_unit("unit:a", 0x1000, 0x1020), units[1])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            exact_before, transitions_before = self._run_layers(root / "before", units)
            exact_after, transitions_after = self._run_layers(root / "after", changed)

        self.assertEqual(EXACT_UNITS_PHASE_V3.form, "map_units")
        self.assertEqual(set(exact_before), {"unit:a", "unit:b"})
        self.assertEqual(set(transitions_before), set(exact_before))
        self.assertNotEqual(exact_before["unit:a"].value, exact_after["unit:a"].value)
        self.assertNotEqual(
            transitions_before["unit:a"].value,
            transitions_after["unit:a"].value,
        )
        self.assertEqual(exact_before["unit:b"], exact_after["unit:b"])
        self.assertEqual(transitions_before["unit:b"], transitions_after["unit:b"])
        self.assertEqual(
            exact_before["unit:b"].dependencies,
            (RecordDependencyV3("machine_ir", "unit:b"),),
        )
        self.assertEqual(
            transitions_before["unit:b"].dependencies,
            (RecordDependencyV3("exact_units", "unit:b"),),
        )

        typed = EXACT_UNIT_CODEC_V3.read(exact_before["unit:b"]).value
        self.assertEqual(typed.unit_ir_sha256, canonical_sha256_v3(units[1]))
        self.assertFalse(hasattr(typed, "machine_ir_sha256"))
        self.assertEqual(
            exact_before["unit:b"].value.to_value()["binary"],
            {"pe_sha256": PE_SHA256, "unit_ir_sha256": typed.unit_ir_sha256},
        )

    def test_wrong_source_id_and_binary_binding_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wrong_id = _write_artifact(
                root / "wrong-id",
                "machine-ir-v3-input",
                (ArtifactRecordV3.create("unit:a", _unit("unit:b", 0x1000, 0x1000)),),
            )
            with self.assertRaises(AnalysisV3Error) as raised:
                EXACT_UNITS_PHASE_V3.run(
                    output_directory=root / "wrong-id-exact",
                    inputs={"machine_ir": wrong_id},
                    bindings=(BINARY,),
                )
            self.assertEqual(raised.exception.code, "unit_record_id_mismatch")

            wrong_binding = _write_artifact(
                root / "wrong-binding",
                "machine-ir-v3-input",
                (ArtifactRecordV3.create("unit:a", _unit("unit:a", 0x1000, 0x1000)),),
                bindings=(ArtifactBindingV3("profile", "test", "fixture", "b" * 64),),
            )
            with self.assertRaises(AnalysisV3Error) as raised:
                EXACT_UNITS_PHASE_V3.run(
                    output_directory=root / "wrong-binding-exact",
                    inputs={"machine_ir": wrong_binding},
                    bindings=(BINARY,),
                )
            self.assertEqual(raised.exception.code, "missing_binary_binding")

    def test_completeness_rejects_wrong_pe_and_codecs_reject_corruption(self) -> None:
        unit = _unit("unit:a", 0x1000, 0x1000)
        unit_ir_sha256 = canonical_sha256_v3(unit)
        exact = ExactUnitV3.create(
            unit,
            pe_sha256=PE_SHA256,
        )

        corrupt_exact = EXACT_UNIT_CODEC_V3.write(exact.record_id, exact).value.to_value()
        corrupt_exact["binary"]["unit_ir_sha256"] = "c" * 64
        with self.assertRaises(AnalysisV3Error) as raised:
            EXACT_UNIT_CODEC_V3.decode(corrupt_exact)
        self.assertEqual(raised.exception.code, "stale_unit_ir_digest")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir = _write_machine_ir(root / "machine-ir", (unit,))
            wrong_pe = ExactUnitV3.create(
                unit,
                pe_sha256="d" * 64,
            )
            forged = _write_artifact(
                root / "forged-exact",
                "exact-units-v3",
                (
                    EXACT_UNIT_CODEC_V3.write(
                        wrong_pe.record_id,
                        wrong_pe,
                        dependencies=(RecordDependencyV3("machine_ir", "unit:a"),),
                    ),
                ),
                dependencies=(
                    ArtifactSetReaderV3(machine_ir).dependency_binding("machine_ir"),
                ),
            )
            with self.assertRaises(AnalysisV3Error) as raised:
                check_exact_units_completeness_v3(
                    ArtifactSetReaderV3(forged),
                    PhaseContextV3({"machine_ir": ArtifactSetReaderV3(machine_ir)}),
                )
            self.assertEqual(raised.exception.code, "exact_unit_contradiction")

            exact_path = EXACT_UNITS_PHASE_V3.run(
                output_directory=root / "exact",
                inputs={"machine_ir": machine_ir},
                bindings=(BINARY,),
            ).output_directory
            transition_path = TRANSITION_SUMMARIES_PHASE_V3.run(
                output_directory=root / "transitions",
                inputs={"exact_units": exact_path},
                bindings=(BINARY,),
            ).output_directory
            transition = next(ArtifactSetReaderV3(transition_path).iter_records())

        transition_payload = transition.value.to_value()
        self.assertNotIn("detail", transition_payload)
        self.assertEqual(
            TRANSITION_SUMMARY_CODEC_V3.read(transition).value.unit.unit_id,
            "unit:a",
        )

        corrupt_transition = transition.value.to_value()
        corrupt_transition["semantics_sha256"] = "e" * 64
        with self.assertRaises(AnalysisV3Error):
            TRANSITION_SUMMARY_CODEC_V3.decode(corrupt_transition)


if __name__ == "__main__":
    unittest.main()
