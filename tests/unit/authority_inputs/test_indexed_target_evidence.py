from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from spaghetti_extractor.authority.exact_units import EXACT_UNITS_PHASE_V3
from spaghetti_extractor.authority.semantic_index import (
    SEMANTIC_INDEX_CODEC_V3,
    SEMANTIC_INDEX_PHASE_V3,
)
from spaghetti_extractor.authority.structural_targets import (
    STRUCTURAL_TARGETS_PHASE_V3,
)
from spaghetti_extractor.authority.target_certificate_checker import (
    INDIRECT_TARGET_CERTIFICATES_PHASE_V3,
)
from spaghetti_extractor.authority.target_certificate_records import (
    INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3,
    TARGET_EVALUATION_EVIDENCE_CODEC_V3,
)
from spaghetti_extractor.authority.transition_summaries import (
    TRANSITION_SUMMARIES_PHASE_V3,
)
from spaghetti_extractor.artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
    canonical_json_bytes_v3,
)
from spaghetti_extractor.authority_inputs.indexed_target_evidence import (
    generate_indexed_target_evidence_v3,
)
from tests.pe_fixtures import pe32_image_with_pointer_slot


IMAGE_BASE = 0x400000
TABLE_RVA = 0x2040


def _const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def _reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _selector() -> dict[str, object]:
    return {"op": "and32", "args": [_reg("eax"), _const(0xFF)]}


def _table_expression(
    selector: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "op": "load",
        "width": 4,
        "address": {
            "op": "add32",
            "args": [
                _const(IMAGE_BASE + TABLE_RVA),
                {"op": "mul32", "args": [selector or _selector(), _const(4)]},
            ],
        },
    }


def _counts(
    *,
    guards: int = 0,
    memory: int = 0,
    register_writes: int = 0,
    flag_writes: int = 0,
) -> dict[str, int]:
    return {
        "register_writes": register_writes,
        "flag_writes": flag_writes,
        "memory_events": memory,
        "external_events": 0,
        "faults": 0,
        "ordered_events": 0,
        "edge_conditions": guards,
    }


def _unit(
    unit_id: str,
    rva_start: int,
    rva_end: int,
    *,
    instructions: list[dict[str, object]],
    outcome: dict[str, object],
    direct_targets: list[int],
    edge_conditions: list[dict[str, object]] | None = None,
    memory_events: list[dict[str, object]] | None = None,
    register_writes: list[dict[str, object]] | None = None,
    flag_writes: list[dict[str, object]] | None = None,
    pre_flags: tuple[str, ...] = (),
) -> dict[str, object]:
    edge_conditions = [] if edge_conditions is None else edge_conditions
    memory_events = [] if memory_events is None else memory_events
    register_writes = [] if register_writes is None else register_writes
    flag_writes = [] if flag_writes is None else flag_writes
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": unit_id,
        "status": "qualified",
        "source": {
            "original": {"rva_start": rva_start, "rva_end": rva_end},
            "instruction_bytes_sha256": f"{rva_start:064x}",
        },
        "expression_model": "stage-a-semantic-ir-v1",
        "instructions": instructions,
        "semantics": {
            "pre_state": {
                "registers": {"eax": _reg("eax")},
                "flags": {
                    name: {"op": "flag", "name": name}
                    for name in pre_flags
                },
                "memory": {
                    "op": "memory",
                    "name": "mem0",
                    "address_width": 32,
                    "value_width": 8,
                },
            },
            "register_writes": register_writes,
            "flag_writes": flag_writes,
            "memory_events": memory_events,
            "external_events": [],
            "faults": [],
            "ordered_events": [],
            "edge_conditions": edge_conditions,
            "outcome": outcome,
            "stack_delta": None,
            "counts": _counts(
                guards=len(edge_conditions),
                memory=len(memory_events),
                register_writes=len(register_writes),
                flag_writes=len(flag_writes),
            ),
        },
        "control": {
            "kind": str(outcome["kind"]),
            "direct_targets": sorted(set(direct_targets)),
            "has_indirect_target": outcome["kind"] == "indirect_jump",
        },
    }


def _fixture_units(
    *,
    guarded: bool = True,
    target_expression: dict[str, object] | None = None,
    unknown_write: bool = False,
    guard_condition: dict[str, object] | None = None,
    predecessor_selector_value: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    guard_selector = predecessor_selector_value or _selector()
    guards = (
        [
            {
                "kind": "branch_guard",
                "target_rva": 0x1010,
                "condition": guard_condition
                or {"op": "ule32", "args": [guard_selector, _const(1)]},
            }
        ]
        if guarded
        else []
    )
    memory_events = (
        [
            {
                "kind": "write",
                "width": 4,
                "instruction_rva": 0x1013,
                "address": _reg("ecx"),
                "value": _const(0),
            }
        ]
        if unknown_write
        else []
    )
    return [
        _unit(
            "guard",
            0x1000,
            0x1004,
            instructions=[
                {"mnemonic": "cmp", "rva_start": 0x1000, "rva_end": 0x1002, "size": 2},
                {"mnemonic": "ja", "rva_start": 0x1002, "rva_end": 0x1004, "size": 2},
            ],
            outcome={
                "kind": "branch",
                "true_target_rva": 0x1100,
                "false_target_rva": 0x1010,
            },
            direct_targets=[0x1010, 0x1100],
            edge_conditions=guards,
            register_writes=(
                []
                if predecessor_selector_value is None
                else [
                    {
                        "register": "eax",
                        "value": predecessor_selector_value,
                    }
                ]
            ),
        ),
        _unit(
            "dispatch",
            0x1010,
            0x1018,
            instructions=[
                {"mnemonic": "movzx", "rva_start": 0x1010, "rva_end": 0x1013, "size": 3},
                {"mnemonic": "jmp", "rva_start": 0x1013, "rva_end": 0x1018, "size": 5},
            ],
            outcome={
                "kind": "indirect_jump",
                "target": (
                    _table_expression(_reg("eax"))
                    if target_expression is None
                    and predecessor_selector_value is not None
                    else _table_expression()
                    if target_expression is None
                    else target_expression
                ),
            },
            direct_targets=[],
            memory_events=memory_events,
        ),
        _unit(
            "case-zero",
            0x1100,
            0x1101,
            instructions=[
                {"mnemonic": "ret", "rva_start": 0x1100, "rva_end": 0x1101, "size": 1}
            ],
            outcome={"kind": "return"},
            direct_targets=[],
        ),
        _unit(
            "case-one",
            0x1110,
            0x1111,
            instructions=[
                {"mnemonic": "ret", "rva_start": 0x1110, "rva_end": 0x1111, "size": 1}
            ],
            outcome={"kind": "return"},
            direct_targets=[],
        ),
    ]


def _split_compare_guard_units() -> list[dict[str, object]]:
    selector = _selector()
    units = _fixture_units(guarded=False)
    units[0] = _unit(
        "branch",
        0x1000,
        0x1002,
        instructions=[
            {"mnemonic": "ja", "rva_start": 0x1000, "rva_end": 0x1002, "size": 2}
        ],
        outcome={
            "kind": "branch",
            "true_target_rva": 0x1100,
            "false_target_rva": 0x1010,
        },
        direct_targets=[0x1010, 0x1100],
        edge_conditions=[
            {
                "kind": "branch_guard",
                "target_rva": 0x1010,
                "condition": {
                    "op": "not",
                    "args": [
                        {
                            "op": "and_bool",
                            "args": [
                                {
                                    "op": "not",
                                    "args": [{"op": "flag", "name": "cf"}],
                                },
                                {
                                    "op": "not",
                                    "args": [{"op": "flag", "name": "zf"}],
                                },
                            ],
                        }
                    ],
                },
            }
        ],
        pre_flags=("cf", "zf"),
    )
    units.insert(
        0,
        _unit(
            "compare",
            0x0FF0,
            0x0FF3,
            instructions=[
                {
                    "mnemonic": "cmp",
                    "rva_start": 0x0FF0,
                    "rva_end": 0x0FF2,
                    "size": 2,
                },
                {
                    "mnemonic": "jmp",
                    "rva_start": 0x0FF2,
                    "rva_end": 0x0FF3,
                    "size": 1,
                },
            ],
            outcome={"kind": "jump", "target_rva": 0x1000},
            direct_targets=[0x1000],
            flag_writes=[
                {
                    "flag": "cf",
                    "value": {"op": "ult32", "args": [selector, _const(1)]},
                },
                {
                    "flag": "zf",
                    "value": {
                        "op": "eq",
                        "args": [
                            {"op": "sub32", "args": [selector, _const(1)]},
                            _const(0),
                        ],
                    },
                },
            ],
        ),
    )
    return units


def _pe(*, writable: bool, targets: tuple[int, int]) -> bytes:
    image = bytearray(
        pe32_image_with_pointer_slot(
            b"\x90" * 0x200,
            target_rva=targets[0],
            slot_rva=TABLE_RVA,
            writable=writable,
        )
    )
    data_raw = 0x400
    table_offset = data_raw + TABLE_RVA - 0x2000
    image[table_offset + 4 : table_offset + 8] = (IMAGE_BASE + targets[1]).to_bytes(
        4, "little"
    )
    return bytes(image)


class _Fixture:
    def __init__(
        self,
        root: Path,
        *,
        writable: bool = False,
        guarded: bool = True,
        targets: tuple[int, int] = (0x1100, 0x1110),
        target_expression: dict[str, object] | None = None,
        corrupt_expected_table_hash: bool = False,
        unknown_write: bool = False,
        guard_condition: dict[str, object] | None = None,
        predecessor_selector_value: dict[str, object] | None = None,
        split_compare_guard: bool = False,
    ) -> None:
        root.mkdir()
        self.root = root
        self.binary = root / "fixture.exe"
        self.binary.write_bytes(_pe(writable=writable, targets=targets))
        pe_sha256 = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.binding = ArtifactBindingV3(
            "binary", "pe32", "fixture.exe", pe_sha256
        )
        units = (
            _split_compare_guard_units()
            if split_compare_guard
            else _fixture_units(
                guarded=guarded,
                target_expression=target_expression,
                unknown_write=unknown_write,
                guard_condition=guard_condition,
                predecessor_selector_value=predecessor_selector_value,
            )
        )
        self.machine_ir = root / "machine-ir.jsonl"
        self.machine_ir.write_bytes(
            b"".join(canonical_json_bytes_v3(unit) + b"\n" for unit in units)
        )
        machine_ir_sha256 = hashlib.sha256(self.machine_ir.read_bytes()).hexdigest()
        machine_input = root / "machine-input"
        ArtifactSetWriterV3(
            artifact_kind="machine-ir-v3-input", bindings=(self.binding,)
        ).write(
            machine_input,
            tuple(
                ArtifactRecordV3.create(str(unit["id"]), unit) for unit in units
            ),
        )
        exact = EXACT_UNITS_PHASE_V3.run(
            output_directory=root / "exact",
            inputs={"machine_ir": machine_input},
            bindings=(self.binding,),
        ).output_directory
        self.semantic = SEMANTIC_INDEX_PHASE_V3.run(
            output_directory=root / "semantic",
            inputs={"exact_units": exact},
            bindings=(self.binding,),
        ).output_directory
        self.transitions = TRANSITION_SUMMARIES_PHASE_V3.run(
            output_directory=root / "transitions",
            inputs={"exact_units": exact},
            bindings=(self.binding,),
        ).output_directory
        semantic_dispatch = SEMANTIC_INDEX_CODEC_V3.read(
            ArtifactSetReaderV3(self.semantic).get_record("dispatch")
        ).value
        self.exit_id = semantic_dispatch.indirect_exits[0].exit_id
        target_ids = [
            unit_id
            for target_rva in sorted(set(targets))
            for unit_id, unit_rva in (
                ("case-zero", 0x1100),
                ("case-one", 0x1110),
            )
            if target_rva == unit_rva
        ]
        hints = root / "hints"
        ArtifactSetWriterV3(
            artifact_kind="target-hints-v3", bindings=(self.binding,)
        ).write(
            hints,
            (
                ArtifactRecordV3.create(
                    self.exit_id,
                    {
                        "id": self.exit_id,
                        "source_unit_id": "dispatch",
                        "source_rva": 0x1010,
                        "source_event_index": None,
                        "kind": "indirect_jump",
                        "status": "recovered",
                        "target_unit_ids": sorted(set(target_ids or ["case-zero", "case-one"])),
                        "external_targets": [],
                        "failure": None,
                    },
                ),
            ),
        )
        self.hints = hints
        self.structural = STRUCTURAL_TARGETS_PHASE_V3.run(
            output_directory=root / "structural",
            inputs={"semantic_index": self.semantic, "target_hints": hints},
            bindings=(self.binding,),
        ).output_directory
        table_bytes = b"".join(
            (IMAGE_BASE + target).to_bytes(4, "little") for target in targets
        )
        table_sha256 = hashlib.sha256(table_bytes).hexdigest()
        if corrupt_expected_table_hash:
            table_sha256 = "0" * 64
        self.manifest = root / "machine-ir-manifest.json"
        self.manifest.write_text(
            json.dumps(
                {
                    "format": "stage-a-machine-ir-manifest-v2",
                    "artifacts": {
                        "machine_ir": {
                            "path": self.machine_ir.name,
                            "sha256": machine_ir_sha256,
                        }
                    },
                    "control": {
                        "recovered_indirect_targets": [
                            {
                                "id": self.exit_id,
                                "status": "recovered",
                                "table": {
                                    "rva_start": TABLE_RVA,
                                    "entry_width": 4,
                                    "bytes_sha256": table_sha256,
                                },
                            }
                        ]
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="ascii",
        )

    def run(self, name: str) -> tuple[dict[str, Any], ArtifactSetReaderV3]:
        output = self.root / name
        report = generate_indexed_target_evidence_v3(
            binary_path=self.binary,
            machine_ir_path=self.machine_ir,
            machine_ir_manifest_path=self.manifest,
            semantic_index_path=self.semantic,
            transition_summaries_path=self.transitions,
            structural_targets_path=self.structural,
            target_hints_path=self.hints,
            output_directory=output,
        )
        return report, ArtifactSetReaderV3(output / "artifact")


class IndexedTargetEvidenceV3Tests(unittest.TestCase):
    def test_cmp_ja_movzx_indexed_table_emits_exact_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary) / "fixture")
            first, reader = fixture.run("first")
            second, _ = fixture.run("second")

            self.assertEqual(first, second)
            self.assertEqual(first["status"], "complete")
            self.assertFalse(first["authorizing"])
            self.assertEqual(first["counts"]["evidence_records"], 1)
            exit_report = first["exits"][0]
            self.assertEqual(exit_report["entry_count"], 2)
            self.assertEqual(
                exit_report["target_unit_ids"], ["case-one", "case-zero"]
            )
            self.assertRegex(exit_report["table_sha256"], r"^[0-9a-f]{64}$")
            record = reader.get_record(fixture.exit_id)
            evidence = TARGET_EVALUATION_EVIDENCE_CODEC_V3.read(record).value
            self.assertEqual(
                evidence.target_unit_ids, ("case-one", "case-zero")
            )
            self.assertEqual(
                evidence.evaluation_method, "checked_indexed_pe_table"
            )
            self.assertIsNone(evidence.inductive_fact_id)
            self.assertIsNotNone(evidence.evaluation_certificate)

            memory = self._empty_authority_input(
                fixture.root / "memory", "memory-versions-v3", fixture.binding
            )
            inductive = self._empty_authority_input(
                fixture.root / "inductive", "inductive-inputs-v3", fixture.binding
            )
            certificates = INDIRECT_TARGET_CERTIFICATES_PHASE_V3.run(
                output_directory=fixture.root / "certificates",
                inputs={
                    "inductive_inputs": inductive,
                    "memory_versions": memory,
                    "semantic_index": fixture.semantic,
                    "semantic_index_global": fixture.semantic,
                    "structural_targets": fixture.structural,
                    "target_evidence": fixture.root / "first" / "artifact",
                    "transition_summaries": fixture.transitions,
                },
                bindings=(fixture.binding,),
            ).output_directory
            unit = INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.read(
                ArtifactSetReaderV3(certificates).get_record("dispatch")
            ).value
            self.assertEqual(unit.status, "complete")
            self.assertTrue(unit.authorizing)
            self.assertEqual(unit.certificates[0].status, "complete")
            self.assertTrue(unit.certificates[0].authorizing)

    @staticmethod
    def _empty_authority_input(
        path: Path, kind: str, binding: ArtifactBindingV3
    ) -> Path:
        ArtifactSetWriterV3(
            artifact_kind=kind,
            bindings=(binding,),
            status="complete",
        ).write(path, ())
        return path

    def test_corrupt_bound_table_hash_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary) / "fixture", corrupt_expected_table_hash=True
            )
            report, reader = fixture.run("output")
            self.assertEqual(report["status"], "violated")
            self.assertEqual(reader.manifest.status, "violated")
            self.assertEqual(
                report["exits"][0]["issue"]["code"],
                "indexed_table_sha256_contradiction",
            )
            self.assertEqual(reader.manifest.record_count, 0)

    def test_normalized_flag_formula_proves_the_same_finite_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary) / "fixture",
                guard_condition={
                    "op": "not",
                    "args": [
                        {"op": "ult32", "args": [_const(1), _selector()]}
                    ],
                },
            )
            report, reader = fixture.run("output")
            self.assertEqual(report["status"], "complete")
            self.assertEqual(reader.manifest.record_count, 1)
            self.assertEqual(report["exits"][0]["entry_count"], 2)

    def test_predecessor_register_output_is_substituted_into_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stack_selector = {
                "op": "and32",
                "args": [
                    {
                        "op": "load",
                        "width": 1,
                        "address": {
                            "op": "add32",
                            "args": [_reg("esp"), _const(4)],
                        },
                    },
                    _const(0xFF),
                ],
            }
            fixture = _Fixture(
                Path(temporary) / "fixture",
                predecessor_selector_value=stack_selector,
            )
            report, reader = fixture.run("output")
            self.assertEqual(report["status"], "complete")
            self.assertEqual(reader.manifest.record_count, 1)
            self.assertEqual(report["exits"][0]["entry_count"], 2)

    def test_unsigned_above_flag_formula_bounds_unmasked_selector(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            predecessor_value = {
                "op": "sub32",
                "args": [_reg("ecx"), _const(100)],
            }
            guard = {
                "op": "not",
                "args": [
                    {
                        "op": "and_bool",
                        "args": [
                            {
                                "op": "not",
                                "args": [
                                    {
                                        "op": "eq",
                                        "args": [
                                            {
                                                "op": "sub32",
                                                "args": [
                                                    predecessor_value,
                                                    _const(1),
                                                ],
                                            },
                                            _const(0),
                                        ],
                                    }
                                ],
                            },
                            {
                                "op": "not",
                                "args": [
                                    {
                                        "op": "ult32",
                                        "args": [
                                            predecessor_value,
                                            _const(1),
                                        ],
                                    }
                                ],
                            },
                        ],
                    }
                ],
            }
            fixture = _Fixture(
                Path(temporary) / "fixture",
                predecessor_selector_value=predecessor_value,
                guard_condition=guard,
            )
            report, reader = fixture.run("output")
            self.assertEqual(report["status"], "complete")
            self.assertEqual(reader.manifest.record_count, 1)
            self.assertEqual(report["exits"][0]["entry_count"], 2)

    def test_compare_and_flag_guard_can_span_checked_direct_units(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary) / "fixture", split_compare_guard=True
            )
            report, reader = fixture.run("output")
            self.assertEqual(report["status"], "complete")
            self.assertEqual(reader.manifest.record_count, 1)
            predecessor = report["exits"][0]["predecessors"][0]
            self.assertEqual(predecessor["upper_exclusive"], 2)
            self.assertEqual(
                predecessor["support_unit_ids"], ["branch", "compare"]
            )

    def test_writable_table_section_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary) / "fixture", writable=True)
            report, reader = fixture.run("output")
            self.assertEqual(report["status"], "incomplete")
            self.assertEqual(reader.manifest.status, "incomplete")
            self.assertEqual(
                report["exits"][0]["issue"]["code"],
                "indexed_table_section_mutable",
            )

    def test_unguarded_dispatch_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary) / "fixture", guarded=False)
            report, _ = fixture.run("output")
            self.assertEqual(report["status"], "incomplete")
            self.assertEqual(
                report["exits"][0]["issue"]["code"],
                "indexed_selector_guard_coverage_missing",
            )

    def test_out_of_range_table_target_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary) / "fixture", targets=(0x1100, 0x1300)
            )
            report, reader = fixture.run("output")
            self.assertEqual(report["status"], "incomplete")
            self.assertEqual(reader.manifest.record_count, 0)
            self.assertEqual(
                report["exits"][0]["issue"]["code"],
                "indexed_table_target_not_executable",
            )

    def test_unsupported_target_expression_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary) / "fixture", target_expression=_reg("eax")
            )
            report, _ = fixture.run("output")
            self.assertEqual(report["status"], "incomplete")
            self.assertEqual(
                report["exits"][0]["issue"]["code"],
                "indexed_target_expression_unsupported",
            )

    def test_unknown_relevant_write_alias_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary) / "fixture", unknown_write=True)
            report, _ = fixture.run("output")
            self.assertEqual(report["status"], "incomplete")
            self.assertEqual(
                report["exits"][0]["issue"]["code"],
                "indexed_table_write_alias_unknown",
            )


if __name__ == "__main__":
    unittest.main()
