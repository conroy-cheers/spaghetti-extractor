from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.analysis_v3._schema import AnalysisV3Error
from spaghetti_extractor.analysis_v3.exact_units import EXACT_UNITS_PHASE_V3
from spaghetti_extractor.analysis_v3.semantic_index import (
    SEMANTIC_INDEX_CODEC_V3,
    SEMANTIC_INDEX_PHASE_V3,
    check_semantic_index_completeness_v3,
)
from spaghetti_extractor.artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
    RecordDependencyV3,
    canonical_sha256_v3,
)
from spaghetti_extractor.phase_framework_v3 import PhaseContextV3


PE_SHA256 = "a" * 64
BINARY = ArtifactBindingV3("binary", "pe32", "fixture.exe", PE_SHA256)


def _register(name: str) -> dict[str, object]:
    return {"op": "register", "name": name, "width": 32}


def _unit(
    unit_id: str,
    rva: int,
    *,
    empty_instructions: bool = False,
    status: str = "qualified",
    salt: int = 0,
    rich_semantics: bool = False,
) -> dict[str, object]:
    instructions: list[dict[str, object]]
    if empty_instructions:
        instructions = []
    else:
        instructions = [
            {
                "mnemonic": f"fixture-{salt}",
                "rva_start": rva,
                "rva_end": rva + 3,
                "size": 3,
            },
            {
                "mnemonic": "fixture-tail",
                "rva_start": rva + 3,
                "rva_end": rva + 8,
                "size": 5,
            },
        ]
    external_events: list[dict[str, object]] = []
    faults: list[dict[str, object]] = []
    direct_targets: list[int] = []
    outcome: dict[str, object] = {"kind": "return"}
    control_kind = "return"
    has_indirect_target = False
    if rich_semantics:
        external_events = [
            {"kind": "internal_call", "target_rva": rva + 0x100},
            {
                "kind": "indirect_call",
                "target": _register("ecx"),
                "arguments": [],
            },
            {
                "kind": "indirect_jump",
                "target": _register("edx"),
            },
        ]
        faults = [
            {"kind": "divide_error", "predicate": {"op": "eq", "value": 0}},
            {"kind": "page_fault", "address": _register("ebx")},
        ]
        direct_targets = [rva + 0x20, rva + 0x10, rva + 0x20]
        outcome = {"kind": "indirect_jump", "target": _register("eax")}
        control_kind = "indirect_jump"
        has_indirect_target = True
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": unit_id,
        "status": status,
        "source": {
            "original": {"rva_start": rva, "rva_end": rva + 8},
            "instruction_bytes_sha256": f"{rva + salt:064x}",
        },
        "expression_model": "stage-a-semantic-ir-v1",
        "instructions": instructions,
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
            "faults": faults,
            "ordered_events": [],
            "edge_conditions": [],
            "outcome": outcome,
            "stack_delta": None,
            "counts": {
                "register_writes": 0,
                "flag_writes": 0,
                "memory_events": 0,
                "external_events": len(external_events),
                "faults": len(faults),
                "ordered_events": 0,
                "edge_conditions": 0,
            },
        },
        "control": {
            "kind": control_kind,
            "direct_targets": direct_targets,
            "has_indirect_target": has_indirect_target,
        },
    }


def _write_artifact(
    path: Path,
    kind: str,
    records: tuple[ArtifactRecordV3, ...],
    *,
    dependencies=(),
) -> Path:
    ArtifactSetWriterV3(
        artifact_kind=kind,
        bindings=(BINARY,),
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


def _run_layers(
    root: Path, units: tuple[dict[str, object], ...]
) -> tuple[Path, Path]:
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
    return exact, semantic_index


class SemanticIndexTests(unittest.TestCase):
    def test_projects_exact_facts_and_uses_stable_native_indirect_exit_ids(self) -> None:
        unit = _unit("unit:rich", 0x1000, rich_semantics=True)

        with tempfile.TemporaryDirectory() as temporary:
            _exact, output = _run_layers(Path(temporary), (unit,))
            record = _records(output)["unit:rich"]
            index = SEMANTIC_INDEX_CODEC_V3.read(record).value

        self.assertEqual(index.record_id, "unit:rich")
        self.assertEqual(index.pe_sha256, PE_SHA256)
        self.assertEqual(index.rva_start, 0x1000)
        self.assertEqual(index.rva_end, 0x1008)
        self.assertEqual(index.unit_status, "qualified")
        self.assertEqual(
            tuple((row.index, row.rva_start, row.rva_end) for row in index.instructions),
            ((0, 0x1000, 0x1003), (1, 0x1003, 0x1008)),
        )
        self.assertEqual(
            tuple(row.instruction_sha256 for row in index.instructions),
            tuple(canonical_sha256_v3(row) for row in unit["instructions"]),
        )
        self.assertEqual(
            tuple(row.fault_sha256 for row in index.faults),
            tuple(canonical_sha256_v3(row) for row in unit["semantics"]["faults"]),
        )
        self.assertEqual(index.direct_target_rvas, (0x1010, 0x1020))
        self.assertEqual(
            tuple((row.event_index, row.target_rva) for row in index.internal_calls),
            ((0, 0x1100),),
        )

        self.assertEqual(
            {
                (row.event_index, row.transfer_kind): row.exit_id
                for row in index.indirect_exits
            },
            {
                (None, "indirect_jump"): "indirect-exit:44f0c9d901278c71ce6d",
                (1, "indirect_call"): "indirect-exit:a86d040b52180cd470fb",
                (2, "indirect_jump"): "indirect-exit:0a99c93c1a02493e04de",
            },
        )
        self.assertEqual(
            {(row.event_index, row.transfer_kind) for row in index.indirect_exits},
            {
                (None, "indirect_jump"),
                (1, "indirect_call"),
                (2, "indirect_jump"),
            },
        )

    def test_empty_instruction_inventory_remains_non_authorizing_evidence(self) -> None:
        unit = _unit(
            "unit:empty-decode",
            0x2000,
            empty_instructions=True,
            status="incomplete",
        )

        with tempfile.TemporaryDirectory() as temporary:
            _exact, output = _run_layers(Path(temporary), (unit,))
            record = _records(output)["unit:empty-decode"]
            index = SEMANTIC_INDEX_CODEC_V3.read(record).value

        self.assertEqual(index.instructions, ())
        self.assertEqual(index.unit_status, "incomplete")
        self.assertEqual(index.rva_start, 0x2000)
        self.assertEqual(index.rva_end, 0x2008)

    def test_corruption_and_stale_projection_fail_closed(self) -> None:
        unit = _unit("unit:a", 0x1000)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            exact, output = _run_layers(root / "valid", (unit,))
            original = _records(output)["unit:a"]

            corrupt_payload = original.value.to_value()
            corrupt_payload["instructions"][0]["instruction_sha256"] = "not-a-digest"
            with self.assertRaises(AnalysisV3Error) as raised:
                SEMANTIC_INDEX_CODEC_V3.decode(corrupt_payload)
            self.assertEqual(raised.exception.code, "record_schema_mismatch")

            stale_payload = original.value.to_value()
            stale_payload["direct_target_rvas"] = [0x4000]
            exact_reader = ArtifactSetReaderV3(exact)
            stale = _write_artifact(
                root / "stale",
                "semantic-index-v3",
                (
                    ArtifactRecordV3.create(
                        "unit:a",
                        stale_payload,
                        dependencies=(
                            RecordDependencyV3("exact_units", "unit:a"),
                        ),
                    ),
                ),
                dependencies=(exact_reader.dependency_binding("exact_units"),),
            )
            with self.assertRaises(AnalysisV3Error) as raised:
                check_semantic_index_completeness_v3(
                    ArtifactSetReaderV3(stale),
                    PhaseContextV3({"exact_units": exact_reader}),
                )
            self.assertEqual(raised.exception.code, "semantic_index_contradiction")

    def test_one_unit_change_preserves_other_record_and_local_dependencies(self) -> None:
        first = _unit("unit:a", 0x1000)
        second = _unit("unit:b", 0x2000)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _exact_before, before_path = _run_layers(
                root / "before", (first, second)
            )
            _exact_after, after_path = _run_layers(
                root / "after", (first, _unit("unit:b", 0x2000, salt=1))
            )
            before = _records(before_path)
            after = _records(after_path)

        self.assertEqual(SEMANTIC_INDEX_PHASE_V3.form, "map_units")
        self.assertEqual(before["unit:a"], after["unit:a"])
        self.assertNotEqual(before["unit:b"], after["unit:b"])
        self.assertEqual(
            before["unit:a"].dependencies,
            (RecordDependencyV3("exact_units", "unit:a"),),
        )
        self.assertEqual(
            before["unit:b"].dependencies,
            (RecordDependencyV3("exact_units", "unit:b"),),
        )


if __name__ == "__main__":
    unittest.main()
