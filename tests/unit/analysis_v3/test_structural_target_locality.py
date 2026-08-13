from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.analysis_v3._schema import AnalysisV3Error
from spaghetti_extractor.analysis_v3.exact_units import EXACT_UNITS_PHASE_V3, ExactUnitV3
from spaghetti_extractor.analysis_v3.semantic_index import (
    SEMANTIC_INDEX_PHASE_V3,
    IndirectExitOccurrenceV3,
    SemanticIndexRecordV3,
    derive_semantic_index_v3,
)
from spaghetti_extractor.analysis_v3.structural_targets import (
    STRUCTURAL_TARGET_UNIT_CODEC_V3,
    STRUCTURAL_TARGETS_PHASE_V3,
    flatten_structural_target_proposals_v3,
)
from spaghetti_extractor.artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
    RecordDependencyV3,
)


PE_SHA256 = "a" * 64
BINARY = ArtifactBindingV3("binary", "pe32", "fixture.exe", PE_SHA256)


def _reg(name: str) -> dict[str, object]:
    return {"op": "register", "name": name, "width": 32}


def _unit(
    unit_id: str,
    rva: int,
    *,
    indirect_control: bool = False,
    indirect_event: bool = False,
    salt: int = 0,
) -> dict[str, object]:
    external_events: list[dict[str, object]] = []
    if indirect_event:
        external_events.append(
            {"kind": "indirect_call", "target": _reg("ecx"), "arguments": []}
        )
    outcome: dict[str, object]
    if indirect_control:
        outcome = {"kind": "indirect_jump", "target": _reg("eax")}
    else:
        outcome = {"kind": "return"}
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": unit_id,
        "status": "qualified",
        "source": {
            "original": {"rva_start": rva, "rva_end": rva + 8},
            "instruction_bytes_sha256": f"{rva + salt:064x}",
        },
        "expression_model": "stage-a-semantic-ir-v1",
        "instructions": [
            {
                "mnemonic": "fixture",
                "rva_start": rva,
                "rva_end": rva + 8,
                "size": 8,
            }
        ],
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
            "external_events": external_events,
            "faults": [],
            "ordered_events": [],
            "edge_conditions": [],
            "outcome": outcome,
            "stack_delta": None,
            "counts": {
                "register_writes": 0,
                "flag_writes": 0,
                "memory_events": 0,
                "external_events": len(external_events),
                "faults": 0,
                "ordered_events": 0,
                "edge_conditions": 0,
            },
        },
        "control": {
            "kind": "indirect_jump" if indirect_control else "return",
            "direct_targets": [],
            "has_indirect_target": indirect_control,
        },
    }


def _write_artifact(
    path: Path,
    kind: str,
    records: tuple[ArtifactRecordV3, ...],
) -> Path:
    ArtifactSetWriterV3(artifact_kind=kind, bindings=(BINARY,)).write(path, records)
    return path


def _write_machine_ir(path: Path, units: tuple[dict[str, object], ...]) -> Path:
    return _write_artifact(
        path,
        "machine-ir-v3-input",
        tuple(ArtifactRecordV3.create(str(unit["id"]), unit) for unit in units),
    )


def _write_hints(
    path: Path, hints: tuple[tuple[str, dict[str, object]], ...]
) -> Path:
    return _write_artifact(
        path,
        "target-hints-v3",
        tuple(ArtifactRecordV3.create(record_id, value) for record_id, value in hints),
    )


def _records(path: Path) -> dict[str, ArtifactRecordV3]:
    return {
        record.record_id: record
        for record in ArtifactSetReaderV3(path).iter_records()
    }


def _semantic_index(unit: dict[str, object]) -> SemanticIndexRecordV3:
    return derive_semantic_index_v3(
        ExactUnitV3.create(unit, pe_sha256=PE_SHA256)
    )


def _hint(
    semantic_index: SemanticIndexRecordV3,
    exit_row: IndirectExitOccurrenceV3,
    *,
    target_unit_ids: object = None,
    status: str = "recovered",
) -> dict[str, object]:
    return {
        "id": exit_row.exit_id,
        "source_unit_id": semantic_index.record_id,
        "source_rva": semantic_index.rva_start,
        "source_event_index": exit_row.event_index,
        "kind": exit_row.transfer_kind,
        "status": status,
        "target_unit_ids": (
            ["unit:deferred-target"]
            if target_unit_ids is None
            else target_unit_ids
        ),
        "external_targets": [],
        "failure": None,
    }


class StructuralTargetLocalityTests(unittest.TestCase):
    def _run(
        self,
        root: Path,
        units: tuple[dict[str, object], ...],
        hints: tuple[tuple[str, dict[str, object]], ...] = (),
    ) -> Path:
        machine_ir = _write_machine_ir(root / "machine-ir", units)
        exact = EXACT_UNITS_PHASE_V3.run(
            output_directory=root / "exact",
            inputs={"machine_ir": machine_ir},
            bindings=(BINARY,),
        ).output_directory
        semantic_index = SEMANTIC_INDEX_PHASE_V3.run(
            output_directory=root / "semantic-index",
            inputs={"exact_units": exact},
            bindings=(BINARY,),
        ).output_directory
        hint_path = _write_hints(root / "hints", hints)
        return STRUCTURAL_TARGETS_PHASE_V3.run(
            output_directory=root / "targets",
            inputs={"semantic_index": semantic_index, "target_hints": hint_path},
            bindings=(BINARY,),
        ).output_directory

    def test_second_unit_change_preserves_first_record_and_dependencies(self) -> None:
        first = _unit("unit:a", 0x1000, indirect_control=True)
        second = _unit("unit:b", 0x2000)
        first_index = _semantic_index(first)
        exit_row = first_index.indirect_exits[0]
        hints = ((exit_row.exit_id, _hint(first_index, exit_row)),)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            before = _records(self._run(root / "before", (first, second), hints))
            after = _records(
                self._run(
                    root / "after",
                    (first, _unit("unit:b", 0x2000, salt=1)),
                    hints,
                )
            )

        self.assertEqual(STRUCTURAL_TARGETS_PHASE_V3.form, "map_units")
        self.assertEqual(before["unit:a"], after["unit:a"])
        self.assertNotEqual(before["unit:b"], after["unit:b"])
        self.assertEqual(
            before["unit:a"].dependencies,
            (
                RecordDependencyV3("semantic_index", "unit:a"),
                RecordDependencyV3("target_hints", exit_row.exit_id),
            ),
        )
        proposals = flatten_structural_target_proposals_v3(before.values())
        self.assertEqual(len(proposals), 1)
        self.assertEqual(proposals[0].status, "recovered")
        self.assertEqual(proposals[0].target_unit_ids, ("unit:deferred-target",))

    def test_zero_and_multiple_exit_units_each_emit_one_canonical_record(self) -> None:
        empty = _unit("unit:empty", 0x1000)
        multiple = _unit(
            "unit:multiple",
            0x2000,
            indirect_control=True,
            indirect_event=True,
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = self._run(Path(temporary), (empty, multiple))
            records = _records(output)

        self.assertEqual(set(records), {"unit:empty", "unit:multiple"})
        empty_set = STRUCTURAL_TARGET_UNIT_CODEC_V3.read(records["unit:empty"]).value
        multiple_set = STRUCTURAL_TARGET_UNIT_CODEC_V3.read(
            records["unit:multiple"]
        ).value
        self.assertEqual(empty_set.proposals, ())
        self.assertEqual(len(multiple_set.proposals), 2)
        self.assertEqual(
            tuple(row.record_id for row in multiple_set.proposals),
            tuple(sorted(row.record_id for row in multiple_set.proposals)),
        )
        self.assertEqual(
            {row.status for row in multiple_set.proposals}, {"incomplete"}
        )
        self.assertEqual(
            records["unit:empty"].dependencies,
            (RecordDependencyV3("semantic_index", "unit:empty"),),
        )

    def test_corrupt_hints_are_violated_while_absent_hints_are_incomplete(self) -> None:
        units = (
            _unit("unit:missing", 0x1000, indirect_control=True),
            _unit("unit:binding", 0x2000, indirect_control=True),
            _unit("unit:malformed", 0x3000, indirect_control=True),
        )
        indexes = [_semantic_index(unit) for unit in units]
        exits = [index.indirect_exits[0] for index in indexes]
        binding = _hint(indexes[1], exits[1])
        binding["source_rva"] = 0xDEAD
        malformed = _hint(
            indexes[2], exits[2], target_unit_ids="not-an-array"
        )
        hints = (
            (exits[1].exit_id, binding),
            (exits[2].exit_id, malformed),
        )

        with tempfile.TemporaryDirectory() as temporary:
            output = self._run(Path(temporary), units, hints)
            output_records = _records(output)
            proposals = {
                row.source_unit_id: row
                for row in flatten_structural_target_proposals_v3(
                    output_records.values()
                )
            }
            binding_payload = output_records["unit:binding"].value.to_value()

        self.assertEqual(proposals["unit:missing"].status, "incomplete")
        self.assertEqual(
            proposals["unit:missing"].issue_codes,
            ("structural_target_proposal_missing",),
        )
        self.assertEqual(proposals["unit:binding"].status, "violated")
        self.assertEqual(
            proposals["unit:binding"].issue_codes,
            ("structural_target_proposal_binding_mismatch",),
        )
        self.assertEqual(proposals["unit:malformed"].status, "violated")
        self.assertEqual(
            proposals["unit:malformed"].issue_codes,
            ("structural_target_proposal_target_set_malformed",),
        )

        corrupt = STRUCTURAL_TARGET_UNIT_CODEC_V3.encode(
            STRUCTURAL_TARGET_UNIT_CODEC_V3.decode(
                binding_payload
            )
        )
        corrupt["unit_sha256"] = "not-a-digest"
        with self.assertRaises(AnalysisV3Error):
            STRUCTURAL_TARGET_UNIT_CODEC_V3.decode(corrupt)


if __name__ == "__main__":
    unittest.main()
