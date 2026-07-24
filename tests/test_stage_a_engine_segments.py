from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path
from typing import Callable, TypedDict
from unittest import mock

import spaghetti_extractor.relational.engine_segments as engine_segments_module
from spaghetti_extractor.relational.engine_segments import (
    ENGINE_SEGMENT_EVIDENCE_FORMAT,
    EngineSegmentEvidenceError,
    build_engine_segment_evidence,
)
from spaghetti_extractor.stage_b_engine_layout import (
    STAGE_B_ENGINE_LAYOUT_HEADER_WORDS,
    STAGE_B_ENGINE_LAYOUT_MAGIC,
    STAGE_B_ENGINE_LAYOUT_RECORD_WORDS,
    STAGE_B_ENGINE_LAYOUT_VERSION,
    EngineFieldKind,
    canonical_stage_b_machine_state_spec,
)
from spaghetti_extractor.stage_b_interpreter_backend import (
    write_stage_b_interpreter_package,
)
from spaghetti_extractor.stage_b_state_machine import (
    normalize_stage_a_semantic_transfer,
)
from spaghetti_extractor.util import sha256_bytes, sha256_file


_IMAGE_BASE = 0x400000
_TEXT_RVA = 0x1000
_RDATA_RVA = 0x2000


class _BuildArguments(TypedDict):
    semantic_transfers: Path
    interpreter_program_manifest: Path
    interpreter_package_manifest: Path
    candidate_pe: Path
    linker_map: Path
    engine_layout: Path
    product_cutpoints: tuple[int, ...]


def _semantic_row(
    identity: str,
    start: int,
    instruction_bytes: tuple[bytes, ...] = (b"\x90", b"\x90", b"\xc3"),
) -> dict[str, object]:
    encoded = b"".join(instruction_bytes)
    cursor = start
    instructions: list[dict[str, object]] = []
    for item in instruction_bytes:
        instructions.append({"rva": cursor, "size": len(item), "bytes": item.hex()})
        cursor += len(item)
    raw: dict[str, object] = {
        "format": "stage-a-semantic-transfer-contract-v1",
        "id": identity,
        "function": "fixture",
        "block_id": identity.removeprefix("semantic-transfer:"),
        "unit_kind": "semantic_transfer",
        "status": "reimplementable",
        "reachable": True,
        "original": {"rva_start": start, "rva_end": cursor, "size": len(encoded)},
        "instructions": instructions,
        "instruction_bytes_sha256": sha256_bytes(encoded),
        "expression_model": "stage-a-semantic-ir-v1",
        "pre_state": {},
        "register_writes": [],
        "flag_writes": [],
        "memory_events": [],
        "external_events": [],
        "faults": [],
        "ordered_events": [],
        "edge_conditions": [],
        "outcome": {
            "kind": "return",
            "value": {"op": "reg", "name": "esp", "width": 32},
        },
        "stack_delta": 0,
        "fpu_state": None,
        "counts": {},
        "acceptance": "guidance only",
    }
    return normalize_stage_a_semantic_transfer(raw)


def _json_sha256(value: dict[str, object]) -> str:
    return sha256_bytes(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    )


def _write_callback_plan(
    path: Path,
    fixture: "_Fixture",
    *,
    site_rva: int = _TEXT_RVA,
    target_rva: int = _TEXT_RVA + 0x50,
    pointer_cell_rva: int = _RDATA_RVA + 0xFF0,
) -> None:
    candidate_bytes = bytearray(fixture.candidate.read_bytes())
    rdata_raw_pointer = 0x400
    struct.pack_into(
        "<I",
        candidate_bytes,
        rdata_raw_pointer + pointer_cell_rva - _RDATA_RVA,
        _IMAGE_BASE + target_rva,
    )
    fixture.candidate.write_bytes(candidate_bytes)
    candidate_sha256 = sha256_file(fixture.candidate)
    instruction = b"\xff\xd0"
    entry = b"\xc3"
    core: dict[str, object] = {
        "format": "stage-a-relational-interpreter-kernel-callback-plan-v1",
        "status": "incomplete",
        "acceptance_authority": False,
        "candidate": {
            "sha256": candidate_sha256,
            "size": fixture.candidate.stat().st_size,
        },
        "sites": [{
            "id": 0,
            "role": "runtime_fixture_callback",
            "function_role": "programLookup",
            "rva": site_rva,
            "instruction_bytes": instruction.hex(),
            "instruction_sha256": sha256_bytes(instruction),
            "continuation_rva": site_rva + len(instruction),
            "target_operand": {"kind": "register", "register": "eax"},
            "cdecl": {
                "argument_count": 0,
                "argument_offsets": [],
                "caller_stack_delta": 0,
                "preserved_registers": ["ebx", "esi", "edi", "ebp"],
                "return_kind": "word_in_eax",
            },
            "target_provenance": "relocation_backed_runtime_cell",
            "targets": [{
                "id": 0,
                "rva": target_rva,
                "entry_bytes": entry.hex(),
                "entry_sha256": sha256_bytes(entry),
                "pointer_cells": [pointer_cell_rva],
            }],
            "dynamic_requirements": [
                "runtime_pointer_identity",
                "runtime_target_cell_preserved",
                "callback_target_execution_refinement",
            ],
        }],
        "issues": [],
        "proof_obligations": [],
    }
    core["artifact_sha256"] = _json_sha256(core)
    path.write_text(
        json.dumps(core, sort_keys=True, indent=2) + "\n", encoding="ascii"
    )


def _x87_replay_row(identity: str, start: int) -> dict[str, object]:
    row = _semantic_row(identity, start, (b"\xd9\xe8", b"\xc3"))
    row.pop("contract_sha256", None)
    transfer_sha = str(row["instruction_bytes_sha256"])
    records: list[dict[str, object]] = []

    x87_record: dict[str, object] = {
        "index": 0,
        "rva_start": start,
        "rva_end": start + 2,
        "bytes": "d9e8",
        "bytes_sha256": sha256_bytes(b"\xd9\xe8"),
        "transfer_bytes_sha256": transfer_sha,
        "instruction_class": "x87_singleton_checked_replay",
        "classification": {
            "status": "proposal_requires_lean_exact_byte_replay",
            "proof_authority": False,
            "checked_decoder": "StageA.Relational.X87.decodeSingletonCommand",
            "checked_executor": "StageA.Relational.X87.executeSingletonCommand",
        },
        "x87_singleton_replay": {
            "rva_start": start,
            "rva_end": start + 2,
            "bytes": "d9e8",
            "bytes_sha256": sha256_bytes(b"\xd9\xe8"),
            "checked_decoder": "StageA.Relational.X87.decodeSingletonCommand",
            "checked_executor": "StageA.Relational.X87.executeSingletonCommand",
            "physical_state_effect": (
                "produced_by_checked_executor_not_inferred_by_exporter"
            ),
        },
    }
    x87_record["record_sha256"] = _json_sha256(x87_record)
    records.append(x87_record)

    ordinary_record: dict[str, object] = {
        "index": 1,
        "rva_start": start + 2,
        "rva_end": start + 3,
        "bytes": "c3",
        "bytes_sha256": sha256_bytes(b"\xc3"),
        "transfer_bytes_sha256": transfer_sha,
        "instruction_class": "ordinary_symbolic_instruction",
        "classification": {
            "status": "proposal_requires_lean_exact_byte_replay",
            "proof_authority": False,
            "checked_decoder": "StageA.Formal.decodeInstructionExact",
            "checked_executor": "StageA.Formal.executeInstruction",
        },
        "effects": {
            "ordered_events": [],
            "register_writes": [],
            "defined_flag_writes": [],
            "undefined_flag_writes": [],
        },
    }
    ordinary_record["record_sha256"] = _json_sha256(ordinary_record)
    records.append(ordinary_record)

    schedule: dict[str, object] = {
        "format": "stage-a-instruction-ordered-effect-schedule-v1",
        "status": "complete",
        "proof_authority": False,
        "ordering": "strict_contiguous_rva_order",
        "transfer_bytes_sha256": transfer_sha,
        "records": records,
        "blockers": [],
        "counts": {
            "instructions": 2,
            "ordinary_instructions": 1,
            "x87_singletons": 1,
            "blockers": 0,
        },
    }
    schedule["schedule_sha256"] = _json_sha256(schedule)
    row["status"] = "incomplete"
    row["blocker"] = "physical x87 state requires exact checked replay"
    row["blocker_category"] = (
        "x87_physical_state_requires_native_exact_command_replay"
    )
    row["next_action"] = "discharge the exact x87 replay obligation in Lean"
    row["instruction_effect_schedule"] = schedule
    row["fpu_state"] = {
        "model": "native_exact_x87_command_replay_obligation_v1",
        "status": "required",
        "authoritative_state_type": "StageA.X87.PhysicalState",
        "required_fields": [
            "stack",
            "tags",
            "control",
            "status",
            "pending_exception",
            "last_opcode",
            "instruction_pointer",
            "code_selector",
            "data_pointer",
            "data_selector",
        ],
        "missing_or_invalid_fields": ["tags"],
        "replay": {
            "format": "stage-a-native-exact-x87-command-replay-obligation-v1",
            "checked_decoder": "StageA.Relational.X87.decodeSingletonCommand",
            "checked_executor": "StageA.Relational.X87.executeSingletonCommand",
            "architecture": "x86",
            "bitness": 32,
            "image_base": _IMAGE_BASE,
            "rva_start": start,
            "rva_end": start + 3,
            "bytes": "d9e8c3",
            "bytes_sha256": transfer_sha,
            "instructions": row["instructions"],
            "instruction_effect_schedule": schedule,
        },
    }
    return normalize_stage_a_semantic_transfer(row)


def _external_tail_row(identity: str, start: int) -> dict[str, object]:
    row = _semantic_row(identity, start)
    row.pop("contract_sha256", None)
    row["outcome"] = {
        "kind": "external_jump",
        "dll": "KERNEL32.dll",
        "symbol": "ExitProcess",
        "ordinal": None,
    }
    row["external_events"] = [
        {
            "kind": "external_call",
            "dll": "kernel32.DLL",
            "symbol": "ExitProcess",
            "ordinal": None,
        }
    ]
    return normalize_stage_a_semantic_transfer(row)


def _write_rows(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
            for row in rows
        ),
        encoding="ascii",
    )


def _engine_layout_payload() -> bytes:
    spec = canonical_stage_b_machine_state_spec(
        include_fs_base=True,
        include_original_rva=True,
    )
    widths = {
        EngineFieldKind.X87_STACK: 10,
        EngineFieldKind.X87_TAG: 1,
        EngineFieldKind.X87_PENDING_EXCEPTION: 1,
        EngineFieldKind.X87_CONTROL: 2,
        EngineFieldKind.X87_STATUS: 2,
        EngineFieldKind.X87_LAST_OPCODE: 2,
        EngineFieldKind.X87_CODE_SELECTOR: 2,
        EngineFieldKind.X87_DATA_SELECTOR: 2,
    }
    records: list[int] = []
    offset = 0
    for item in spec.fields:
        size = widths.get(item.field.kind, 4)
        records.extend((int(item.field.kind), item.field.index, offset, size))
        offset += size
    total_words = STAGE_B_ENGINE_LAYOUT_HEADER_WORDS + len(records)
    header = [
        STAGE_B_ENGINE_LAYOUT_MAGIC,
        STAGE_B_ENGINE_LAYOUT_VERSION,
        total_words,
        STAGE_B_ENGINE_LAYOUT_HEADER_WORDS,
        STAGE_B_ENGINE_LAYOUT_RECORD_WORDS,
        len(spec.fields),
        offset,
        spec.x87_slot_count,
        int(spec.features),
        0,
    ]
    return struct.pack(f"<{len(header) + len(records)}I", *(header + records))


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _pe32_engine_image(text: bytes, rdata: bytes) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_raw_size = _align(len(text), file_alignment)
    rdata_raw_size = _align(len(rdata), file_alignment)
    text_raw = headers_size
    rdata_raw = text_raw + text_raw_size
    size_of_image = _align(_RDATA_RVA + rdata_raw_size, section_alignment)

    dos = bytearray(0x80)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B,
        0,
        0,
        text_raw_size,
        rdata_raw_size,
        0,
        _TEXT_RVA,
        _TEXT_RVA,
        _RDATA_RVA,
        _IMAGE_BASE,
        section_alignment,
        file_alignment,
        4,
        0,
        0,
        0,
        4,
        0,
        0,
        size_of_image,
        headers_size,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    optional = optional_prefix + b"\0" * (16 * 8)
    text_section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        text_raw_size,
        _TEXT_RVA,
        text_raw_size,
        text_raw,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    rdata_section = struct.pack(
        "<8sIIIIIIHHI",
        b".rdata\0\0",
        rdata_raw_size,
        _RDATA_RVA,
        rdata_raw_size,
        rdata_raw,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    headers = (
        bytes(dos)
        + b"PE\0\0"
        + coff
        + optional
        + text_section
        + rdata_section
    ).ljust(headers_size, b"\0")
    return (
        headers
        + text.ljust(text_raw_size, b"\0")
        + rdata.ljust(rdata_raw_size, b"\0")
    )


class _Fixture:
    def __init__(
        self,
        root: Path,
        *,
        transfer_count: int = 1,
        first_function_offset: int = 0,
        first_function_code: bytes = b"\xc3",
        overlap_arrays: bool = False,
        omit_symbol: str | None = None,
        duplicate_layout: bool = False,
        row_factory: Callable[[str, int], dict[str, object]] = _semantic_row,
        function_codes: dict[str, bytes] | None = None,
        synthetic_helpers: dict[int, bytes] | None = None,
    ) -> None:
        rows = [
            row_factory(
                f"semantic-transfer:fixture-{index}", 0x3000 + index * 0x10
            )
            for index in range(transfer_count)
        ]
        self.machine = root / "state-machine.jsonl"
        _write_rows(self.machine, rows)
        self.package_dir = root / "package"
        write_stage_b_interpreter_package(state_machine=self.machine, out=self.package_dir)
        self.program = self.package_dir / "state-machine-interpreter-program.json"
        self.package = self.package_dir / "state-machine-interpreter-package.json"
        program = json.loads(self.program.read_text(encoding="utf-8"))

        layout = _engine_layout_payload()
        rdata = bytearray(0x2000)
        table_rva = _RDATA_RVA
        count_rva = _RDATA_RVA + 0x80
        cursor = _RDATA_RVA + 0x100
        first_nodes_rva: int | None = None
        for index, (declared, semantic) in enumerate(
            zip(program["transfers"], rows, strict=True)
        ):
            counts = declared["counts"]
            word_size = max(counts["word_nodes"], 1) * 36
            x87_size = max(counts["x87_nodes"], 1) * 36
            action_size = counts["actions"] * 32
            call_size = max(counts["calls"], 1) * 64
            replay_size = max(counts.get("x87_replays", 0), 1) * 44
            nodes_rva = cursor
            if overlap_arrays and index == 1 and first_nodes_rva is not None:
                nodes_rva = first_nodes_rva
            else:
                cursor = _align(cursor + word_size, 0x10)
            if first_nodes_rva is None:
                first_nodes_rva = nodes_rva
            x87_rva = cursor
            cursor = _align(cursor + x87_size, 0x10)
            actions_rva = cursor
            cursor = _align(cursor + action_size, 0x10)
            calls_rva = cursor
            cursor = _align(cursor + call_size, 0x10)
            replays_rva = cursor
            cursor = _align(cursor + replay_size, 0x10)
            if counts.get("x87_replays", 0):
                schedule = semantic["instruction_effect_schedule"]
                replay_records = [
                    record
                    for record in schedule["records"]
                    if record["instruction_class"]
                    == "x87_singleton_checked_replay"
                ]
                for replay_index, replay_record in enumerate(replay_records):
                    singleton = replay_record["x87_singleton_replay"]
                    referenced: list[int] = []
                    values = (
                        bytes.fromhex(singleton["bytes"]),
                        singleton["bytes_sha256"].encode("ascii") + b"\0",
                        semantic["instruction_bytes_sha256"].encode("ascii") + b"\0",
                        semantic["contract_sha256"].encode("ascii") + b"\0",
                        singleton["checked_decoder"].encode("ascii") + b"\0",
                        singleton["checked_executor"].encode("ascii") + b"\0",
                    )
                    for value in values:
                        value_rva = cursor
                        value_offset = value_rva - _RDATA_RVA
                        rdata[value_offset : value_offset + len(value)] = value
                        cursor = _align(cursor + len(value), 4)
                        referenced.append(_IMAGE_BASE + value_rva)
                    replay_offset = (
                        replays_rva - _RDATA_RVA + replay_index * 44
                    )
                    struct.pack_into(
                        "<11I",
                        rdata,
                        replay_offset,
                        _IMAGE_BASE,
                        singleton["rva_start"],
                        singleton["rva_end"],
                        1,
                        len(values[0]),
                        *referenced,
                    )
            record = struct.pack(
                "<10I",
                declared["rva_start"],
                counts["word_nodes"],
                counts["x87_nodes"],
                counts["actions"],
                counts.get("x87_replays", 0),
                _IMAGE_BASE + nodes_rva,
                _IMAGE_BASE + x87_rva,
                _IMAGE_BASE + actions_rva,
                _IMAGE_BASE + calls_rva,
                _IMAGE_BASE + replays_rva,
            )
            offset = table_rva - _RDATA_RVA + index * 40
            rdata[offset : offset + 40] = record
        struct.pack_into("<I", rdata, count_rva - _RDATA_RVA, transfer_count)
        layout_rva = _align(cursor, 0x10)
        layout_offset = layout_rva - _RDATA_RVA
        rdata[layout_offset : layout_offset + len(layout)] = layout
        if duplicate_layout:
            second = _align(layout_offset + len(layout), 0x10)
            rdata[second : second + len(layout)] = layout

        functions = (
            "stage_b_program_lookup",
            "stage_b_interpreter_step",
            "stage_b_run_function",
            "stage_b_invoke_call",
        )
        text = bytearray(0x200)
        if first_function_offset:
            text[0] = 0x55
        starts = [first_function_offset + index * 0x10 for index in range(4)]
        codes = {functions[0]: first_function_code}
        if function_codes is not None:
            codes.update(function_codes)
        for function, start in zip(functions, starts, strict=True):
            code = codes.get(function, b"\xc3")
            if len(code) > 0x10:
                raise ValueError(f"fixture function {function} exceeds its map slot")
            text[start : start + len(code)] = code
        for start, code in (synthetic_helpers or {}).items():
            if not 0 <= start < len(text) or start + len(code) > len(text):
                raise ValueError("synthetic helper lies outside fixture text")
            text[start : start + len(code)] = code
        self.candidate = root / "candidate.exe"
        self.candidate.write_bytes(_pe32_engine_image(bytes(text), bytes(rdata)))
        self.linker_map = root / "candidate.map"
        map_lines: list[str] = []
        for function, start in zip(functions, starts, strict=True):
            if function == omit_symbol:
                continue
            address = _IMAGE_BASE + _TEXT_RVA + start
            map_lines.extend(
                (
                    f" .text.{function} 0x{address:08x} 0x10",
                    f" 0x{address:08x} _{function}",
                )
            )
        map_lines.extend(
            (
                f" 0x{_IMAGE_BASE + table_rva:08x} _stage_b_program_transfers",
                f" 0x{_IMAGE_BASE + count_rva:08x} _stage_b_program_transfer_count",
            )
        )
        self.linker_map.write_text("\n".join(map_lines) + "\n", encoding="ascii")
        self.layout = root / "engine-layout.bin"
        self.layout.write_bytes(layout)

    def arguments(self, *, cutpoints: tuple[int, ...] = ()) -> _BuildArguments:
        return {
            "semantic_transfers": self.machine,
            "interpreter_program_manifest": self.program,
            "interpreter_package_manifest": self.package,
            "candidate_pe": self.candidate,
            "linker_map": self.linker_map,
            "engine_layout": self.layout,
            "product_cutpoints": cutpoints,
        }


class StageAEngineSegmentTests(unittest.TestCase):
    def test_binds_exact_records_kernel_and_interior_product_cutpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            evidence = build_engine_segment_evidence(
                **fixture.arguments(cutpoints=(0x3001,))
            )

            self.assertEqual(evidence.status, "evidence_ready")
            self.assertFalse(evidence.acceptance_authority)
            self.assertEqual(len(evidence.transfers), 1)
            self.assertEqual(evidence.transfers[0].record_rva, _RDATA_RVA)
            self.assertEqual(evidence.cutpoint_owners[0].offset, 1)
            self.assertEqual(len(evidence.kernel_ranges), 4)
            self.assertTrue(all(item.kind == "return" for item in evidence.control_sites))
            required_coverage = [
                item
                for item in evidence.executable_coverage
                if item.required_for_kernel_closure
            ]
            self.assertEqual(len(required_coverage), 4)
            self.assertTrue(
                all(
                    item.classification == "required_kernel_function"
                    for item in required_coverage
                )
            )
            payload = evidence.to_payload()
            self.assertEqual(payload["format"], ENGINE_SEGMENT_EVIDENCE_FORMAT)
            self.assertIs(payload["acceptance_authority"], False)
            self.assertEqual(len(payload["artifact_sha256"]), 64)
            self.assertTrue(
                all(
                    item["proof_authority"] is False
                    for item in payload["executable_coverage"]
                )
            )
            self.assertTrue(
                any(
                    item.family == "interior_cutpoint_composition"
                    for item in evidence.obligations
                )
            )

    def test_stale_program_binding_and_missing_kernel_symbol_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root)
            program = json.loads(fixture.program.read_text(encoding="utf-8"))
            program["transfers"][0]["contract_sha256"] = "f" * 64
            fixture.program.write_text(
                json.dumps(program, sort_keys=True, indent=2) + "\n", encoding="ascii"
            )
            package = json.loads(fixture.package.read_text(encoding="utf-8"))
            package["program"]["sha256"] = sha256_file(fixture.program)
            fixture.package.write_text(
                json.dumps(package, sort_keys=True, indent=2) + "\n", encoding="ascii"
            )
            with self.assertRaisesRegex(
                EngineSegmentEvidenceError, "program transfer binding differs"
            ):
                build_engine_segment_evidence(**fixture.arguments())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary), omit_symbol="stage_b_run_function")
            with self.assertRaisesRegex(
                EngineSegmentEvidenceError, "required kernel symbol stage_b_run_function"
            ):
                build_engine_segment_evidence(**fixture.arguments())

    def test_inventories_direct_helper_calls_without_treating_them_as_escapes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary),
                first_function_code=b"\xe8\x0b\x00\x00\x00\xc3",
            )
            evidence = build_engine_segment_evidence(**fixture.arguments())
            helper_calls = [
                item for item in evidence.control_sites if item.kind == "helper_call"
            ]
            self.assertEqual(evidence.status, "evidence_ready")
            self.assertEqual(len(helper_calls), 1)
            self.assertEqual(helper_calls[0].target_rva, _TEXT_RVA + 0x10)
            self.assertEqual(
                helper_calls[0].target_symbol, "stage_b_interpreter_step"
            )

    def test_inventories_direct_helper_tail_jumps_as_kernel_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary),
                first_function_code=b"\xe9\x0b\x00\x00\x00",
            )
            evidence = build_engine_segment_evidence(**fixture.arguments())
            helper_jumps = [
                item
                for item in evidence.control_sites
                if item.kind == "helper_tail_jump"
            ]

            self.assertEqual(evidence.status, "evidence_ready")
            self.assertEqual(len(helper_jumps), 1)
            self.assertEqual(helper_jumps[0].target_rva, _TEXT_RVA + 0x10)
            self.assertEqual(
                helper_jumps[0].target_symbol, "stage_b_interpreter_step"
            )

    def test_transitively_closes_unlabelled_internal_helper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary),
                first_function_code=b"\xe8\x4b\x00\x00\x00\xc3",
                synthetic_helpers={0x50: b"\xc3"},
            )
            evidence = build_engine_segment_evidence(**fixture.arguments())

            helper = next(
                item
                for item in evidence.kernel_ranges
                if item.rva_start == _TEXT_RVA + 0x50
            )
            self.assertEqual(evidence.status, "evidence_ready")
            self.assertEqual(helper.symbol, "synthetic_kernel_helper_00001050")
            self.assertEqual(helper.rva_end, _TEXT_RVA + 0x51)
            self.assertTrue(
                any(
                    item.owner == helper.symbol
                    and item.required_for_kernel_closure
                    for item in evidence.executable_coverage
                )
            )
            self.assertTrue(
                any(
                    item.family == "interpreter_kernel_semantics"
                    and item.subject == helper.symbol
                    for item in evidence.obligations
                )
            )

    def test_recursive_shared_unlabelled_helper_is_closed_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary),
                first_function_code=b"\xe8\x4b\x00\x00\x00\xc3",
                function_codes={
                    "stage_b_interpreter_step": b"\xe8\x3b\x00\x00\x00\xc3"
                },
                synthetic_helpers={0x50: b"\xe8\xfb\xff\xff\xff\xc3"},
            )
            evidence = build_engine_segment_evidence(**fixture.arguments())

            helpers = [
                item
                for item in evidence.kernel_ranges
                if item.rva_start == _TEXT_RVA + 0x50
            ]
            calls = [
                item
                for item in evidence.control_sites
                if item.kind == "helper_call"
                and item.target_rva == _TEXT_RVA + 0x50
            ]
            self.assertEqual(evidence.status, "evidence_ready")
            self.assertEqual(len(helpers), 1)
            self.assertEqual(len(calls), 3)

    def test_overlapping_ambiguous_and_non_executable_helpers_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary),
                first_function_code=b"\xe8\xfc\xff\xff\xff\xc3",
            )
            evidence = build_engine_segment_evidence(**fixture.arguments())

            self.assertEqual(evidence.status, "incomplete")
            self.assertTrue(
                any(
                    item.code == "ambiguous_kernel_ownership"
                    and "inside required kernel" in item.message
                    for item in evidence.issues
                )
            )

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary),
                first_function_code=b"\xe8\x4b\x00\x00\x00\xc3",
                function_codes={
                    "stage_b_interpreter_step": b"\xe8\x3c\x00\x00\x00\xc3"
                },
                synthetic_helpers={0x50: b"\x90\x90\xc3"},
            )
            evidence = build_engine_segment_evidence(**fixture.arguments())

            self.assertEqual(evidence.status, "incomplete")
            self.assertIn(
                "ambiguous_kernel_ownership",
                {item.code for item in evidence.issues},
            )

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary),
                first_function_code=b"\xe8\xfb\x0f\x00\x00\xc3",
            )
            evidence = build_engine_segment_evidence(**fixture.arguments())

            self.assertEqual(evidence.status, "incomplete")
            self.assertTrue(
                any(
                    item.code == "unsupported_native_escape"
                    and "outside" in item.message
                    for item in evidence.issues
                )
            )

    def test_overlapping_program_records_and_duplicate_layout_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary), transfer_count=2, overlap_arrays=True)
            with self.assertRaisesRegex(EngineSegmentEvidenceError, "ranges overlap"):
                build_engine_segment_evidence(**fixture.arguments())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary), duplicate_layout=True)
            with self.assertRaisesRegex(
                EngineSegmentEvidenceError, "2 exact read-only engine layout"
            ):
                build_engine_segment_evidence(**fixture.arguments())

    def test_indirect_exit_x87_and_native_escape_are_incomplete(self) -> None:
        cases: tuple[tuple[int, bytes, str], ...] = (
            (
                0,
                b"\xff\xe0",
                "unclassified_kernel_exit",
            ),
            (
                0,
                b"\xd9\xe8\xc3",
                "unsupported_x87_kernel_instruction",
            ),
            (
                0,
                b"\xe9\xfb\x0f\x00\x00",
                "unsupported_native_escape",
            ),
            (
                0,
                b"\xff\xd0\xc3",
                "unsupported_native_escape",
            ),
        )
        for offset, code, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temporary:
                fixture = _Fixture(
                    Path(temporary),
                    first_function_offset=offset,
                    first_function_code=code,
                )
                evidence = build_engine_segment_evidence(**fixture.arguments())
                self.assertEqual(evidence.status, "incomplete")
                self.assertIn(expected, {item.code for item in evidence.issues})
                self.assertFalse(evidence.acceptance_authority)

    def test_callback_plan_supplies_checked_finite_indirect_target_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(
                root,
                first_function_code=b"\xff\xd0\xc3",
                synthetic_helpers={0x50: b"\xc3"},
            )
            callback_plan = root / "callback-plan.json"
            _write_callback_plan(callback_plan, fixture)

            without_inventory = build_engine_segment_evidence(**fixture.arguments())
            self.assertIn(
                "unsupported_native_escape",
                {item.code for item in without_inventory.issues},
            )
            with self.assertRaisesRegex(
                EngineSegmentEvidenceError, "lacks a PE32 HIGHLOW relocation"
            ):
                build_engine_segment_evidence(
                    **fixture.arguments(), kernel_callback_plan=callback_plan
                )

            with mock.patch(
                "spaghetti_extractor.relational.engine_segments._highlow_relocations",
                return_value=frozenset({_RDATA_RVA + 0xFF0}),
            ):
                evidence = build_engine_segment_evidence(
                    **fixture.arguments(), kernel_callback_plan=callback_plan
                )

            self.assertEqual(evidence.status, "evidence_ready")
            self.assertNotIn(
                "unsupported_native_escape", {item.code for item in evidence.issues}
            )
            site = next(
                item
                for item in evidence.control_sites
                if item.kind == "checked_helper_indirect_call"
            )
            self.assertEqual(site.target_rvas, (_TEXT_RVA + 0x50,))
            self.assertEqual(
                site.capability_id,
                "native-indirect-call:00001000",
            )
            capability = evidence.native_indirect_call_capabilities[0]
            self.assertEqual(capability.call_site_rva, _TEXT_RVA)
            self.assertEqual(capability.targets[0].rva, _TEXT_RVA + 0x50)
            self.assertEqual(
                capability.targets[0].pointer_slots[0].stored_word,
                _IMAGE_BASE + _TEXT_RVA + 0x50,
            )
            self.assertIn(
                "kernel_callback_plan", {item.role for item in evidence.inputs}
            )
            families = {item.family for item in evidence.obligations}
            self.assertIn("native_indirect_call_exact_candidate_evidence", families)
            self.assertIn("native_indirect_call_abi_refinement", families)
            self.assertIn("native_indirect_call_target_flow", families)
            self.assertIn("native_indirect_call_target_execution", families)

    def test_callback_plan_staleness_and_ambiguous_targets_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(
                root,
                first_function_code=b"\xff\xd0\xc3",
                synthetic_helpers={0x50: b"\xc3"},
            )
            callback_plan = root / "callback-plan.json"
            _write_callback_plan(callback_plan, fixture)
            payload = json.loads(callback_plan.read_text(encoding="ascii"))
            payload["sites"][0]["instruction_bytes"] = "90"
            callback_plan.write_text(
                json.dumps(payload, sort_keys=True, indent=2) + "\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                EngineSegmentEvidenceError, "stale artifact SHA-256"
            ):
                build_engine_segment_evidence(
                    **fixture.arguments(), kernel_callback_plan=callback_plan
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(
                root,
                first_function_code=b"\xff\xd0\xc3",
                synthetic_helpers={0x50: b"\xc3"},
            )
            callback_plan = root / "callback-plan.json"
            _write_callback_plan(callback_plan, fixture)
            payload = json.loads(callback_plan.read_text(encoding="ascii"))
            payload["sites"][0]["targets"].append(
                dict(payload["sites"][0]["targets"][0])
            )
            payload.pop("artifact_sha256")
            payload["artifact_sha256"] = _json_sha256(payload)
            callback_plan.write_text(
                json.dumps(payload, sort_keys=True, indent=2) + "\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                EngineSegmentEvidenceError, "duplicate target identity"
            ):
                with mock.patch(
                    "spaghetti_extractor.relational.engine_segments._highlow_relocations",
                    return_value=frozenset({_RDATA_RVA + 0xFF0}),
                ):
                    build_engine_segment_evidence(
                        **fixture.arguments(), kernel_callback_plan=callback_plan
                    )

    def test_callback_plan_operand_and_provenance_fail_closed(self) -> None:
        for field, value, message in (
            (
                "target_operand",
                {"kind": "register", "register": "edx"},
                "target operand disagrees with candidate",
            ),
            (
                "target_provenance",
                "linker_symbol_name",
                "unsupported target provenance",
            ),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixture = _Fixture(
                    root,
                    first_function_code=b"\xff\xd0\xc3",
                    synthetic_helpers={0x50: b"\xc3"},
                )
                callback_plan = root / "callback-plan.json"
                _write_callback_plan(callback_plan, fixture)
                payload = json.loads(callback_plan.read_text(encoding="ascii"))
                payload["sites"][0][field] = value
                payload.pop("artifact_sha256")
                payload["artifact_sha256"] = _json_sha256(payload)
                callback_plan.write_text(
                    json.dumps(payload, sort_keys=True, indent=2) + "\n",
                    encoding="ascii",
                )
                with self.assertRaisesRegex(EngineSegmentEvidenceError, message):
                    with mock.patch(
                        "spaghetti_extractor.relational.engine_segments._highlow_relocations",
                        return_value=frozenset({_RDATA_RVA + 0xFF0}),
                    ):
                        build_engine_segment_evidence(
                            **fixture.arguments(), kernel_callback_plan=callback_plan
                        )

    def test_mutable_callback_slot_requires_explicit_preservation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(
                root,
                first_function_code=b"\xff\xd0\xc3",
                synthetic_helpers={0x50: b"\xc3"},
            )
            callback_plan = root / "callback-plan.json"
            _write_callback_plan(callback_plan, fixture)

            candidate = bytearray(fixture.candidate.read_bytes())
            rdata_characteristics_offset = 0x80 + 4 + 20 + 224 + 40 + 36
            struct.pack_into(
                "<I", candidate, rdata_characteristics_offset, 0xC0000040
            )
            fixture.candidate.write_bytes(candidate)
            payload = json.loads(callback_plan.read_text(encoding="ascii"))
            payload["candidate"]["sha256"] = sha256_file(fixture.candidate)
            payload["sites"][0]["dynamic_requirements"] = [
                "runtime_pointer_identity",
                "callback_target_execution_refinement",
            ]
            payload.pop("artifact_sha256")
            payload["artifact_sha256"] = _json_sha256(payload)
            callback_plan.write_text(
                json.dumps(payload, sort_keys=True, indent=2) + "\n",
                encoding="ascii",
            )

            with self.assertRaisesRegex(
                EngineSegmentEvidenceError,
                "mutable target provenance without a preservation obligation",
            ):
                binary = engine_segments_module._parse_stage_a_pe(fixture.candidate)
                try:
                    with mock.patch(
                        "spaghetti_extractor.relational.engine_segments._highlow_relocations",
                        return_value=frozenset({_RDATA_RVA + 0xFF0}),
                    ):
                        engine_segments_module._load_kernel_callback_capabilities(
                            callback_plan, binary
                        )
                finally:
                    binary.pe.close()

    def test_exact_runtime_layout_binds_the_complete_pointer_field_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(
                root,
                first_function_code=b"\xff\xd0\xc3",
                synthetic_helpers={0x50: b"\xc3"},
            )
            callback_plan = root / "callback-plan.json"
            _write_callback_plan(callback_plan, fixture)
            payload = json.loads(callback_plan.read_text(encoding="ascii"))
            pointer_cell = _RDATA_RVA + 0xFF0
            candidate = fixture.candidate.read_bytes()
            pointer_bytes = candidate[0x400 + 0xFF0 : 0x400 + 0xFF4]
            payload["sites"][0]["target_provenance"] = "exact_runtime_layout"
            payload["sites"][0]["runtime_layout"] = {
                "format": "stage-a-exact-runtime-layout-evidence-v1",
                "instance_rva": pointer_cell,
                "size": 4,
                "initial_bytes_sha256": sha256_bytes(pointer_bytes),
                "pointer_fields": [{"offset": 0, "target_id": 0}],
            }
            payload.pop("artifact_sha256")
            payload["artifact_sha256"] = _json_sha256(payload)
            callback_plan.write_text(
                json.dumps(payload, sort_keys=True, indent=2) + "\n",
                encoding="ascii",
            )

            with mock.patch(
                "spaghetti_extractor.relational.engine_segments._highlow_relocations",
                return_value=frozenset({pointer_cell}),
            ):
                evidence = build_engine_segment_evidence(
                    **fixture.arguments(), kernel_callback_plan=callback_plan
                )

            self.assertEqual(evidence.status, "evidence_ready")
            self.assertEqual(
                evidence.native_indirect_call_capabilities[0].provenance,
                "exact_runtime_layout",
            )
            runtime_layout = evidence.to_payload()[
                "native_indirect_call_capabilities"
            ][0]["runtime_layout"]
            self.assertEqual(runtime_layout["instance_rva"], pointer_cell)
            self.assertEqual(
                runtime_layout["pointer_fields"],
                [{"offset": 0, "target_id": 0}],
            )

    def test_reviewed_x87_frame_instruction_is_not_a_false_frontier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary),
                first_function_code=b"\xdd\x60\x20\xc3",
            )
            evidence = build_engine_segment_evidence(**fixture.arguments())

        self.assertNotIn(
            "unsupported_x87_kernel_instruction",
            {item.code for item in evidence.issues},
        )

    def test_payload_bytes_outside_required_kernels_are_non_authoritative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary),
                first_function_offset=0x10,
                first_function_code=b"\xc3",
            )
            evidence = build_engine_segment_evidence(**fixture.arguments())
            outside = [
                item
                for item in evidence.executable_coverage
                if item.classification
                == "unclassified_payload_outside_required_kernel"
            ]
            self.assertEqual(evidence.status, "evidence_ready")
            self.assertTrue(outside)
            self.assertTrue(
                all(not item.required_for_kernel_closure for item in outside)
            )
            self.assertTrue(
                all(
                    item.to_payload()["proof_authority"] is False
                    for item in outside
                )
            )

    def test_exact_x87_replay_is_a_pending_lean_obligation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary), row_factory=_x87_replay_row)
            evidence = build_engine_segment_evidence(**fixture.arguments())

            self.assertEqual(evidence.status, "evidence_ready")
            self.assertEqual(len(evidence.x87_replay_obligations), 1)
            self.assertNotIn(
                "semantic_transfer_not_reimplementable",
                {item.code for item in evidence.issues},
            )
            self.assertNotIn(
                "unsupported_x87_transfer", {item.code for item in evidence.issues}
            )
            obligation = next(
                item
                for item in evidence.obligations
                if item.family == "exact_x87_command_replay"
            )
            self.assertEqual(obligation.status, "pending_lean_check")
            payload = evidence.to_payload()["x87_replay_obligations"][0]
            self.assertIs(payload["proof_authority"], False)

    def test_external_tail_identity_is_bound_or_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary), row_factory=_external_tail_row)
            evidence = build_engine_segment_evidence(**fixture.arguments())

            self.assertEqual(evidence.status, "evidence_ready")
            self.assertEqual(len(evidence.external_tail_bindings), 1)
            binding = evidence.external_tail_bindings[0]
            self.assertEqual(binding.dll, "KERNEL32.dll")
            self.assertEqual(binding.symbol, "ExitProcess")
            self.assertTrue(
                any(
                    item.family == "external_tail_import_refinement"
                    and item.status == "pending_lean_check"
                    for item in evidence.obligations
                )
            )

        def ambiguous_tail(identity: str, start: int) -> dict[str, object]:
            row = _external_tail_row(identity, start)
            row.pop("contract_sha256", None)
            events = list(row["external_events"])
            events.append(dict(events[0]))
            row["external_events"] = events
            return normalize_stage_a_semantic_transfer(row)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary), row_factory=ambiguous_tail)
            evidence = build_engine_segment_evidence(**fixture.arguments())
            self.assertEqual(evidence.status, "incomplete")
            self.assertEqual(evidence.external_tail_bindings, ())
            self.assertIn(
                "external_tail_identity_unmaterialized",
                {item.code for item in evidence.issues},
            )

    def test_unowned_product_cutpoint_is_reported_without_claiming_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            evidence = build_engine_segment_evidence(
                **fixture.arguments(cutpoints=(0x5000,))
            )
            self.assertEqual(evidence.status, "incomplete")
            self.assertEqual(evidence.cutpoint_owners, ())
            self.assertIn(
                "product_cutpoint_unowned", {item.code for item in evidence.issues}
            )


if __name__ == "__main__":
    unittest.main()
