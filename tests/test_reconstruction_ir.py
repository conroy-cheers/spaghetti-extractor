from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.reconstruction_ir import (
    MACHINE_IR_FILENAME,
    MACHINE_IR_FORMAT,
    MACHINE_IR_MANIFEST_FILENAME,
    MachineIRExportError,
    RvaSpan,
    _Instruction,
    _callback_registration_roots,
    _newly_eligible_callback_roots,
    _recover_unknown_fallthrough,
    export_machine_ir_package,
)
from spaghetti_extractor.stage_b_state_machine import (
    normalize_stage_a_semantic_transfer,
)
from spaghetti_extractor.util import sha256_bytes
from spaghetti_extractor.util import sha256_file

from pe_fixtures import pe32_image
from tests.stage_a_relational_support import _pe32_tls_image


_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_FLAGS = ("cf", "zf", "sf", "of", "pf", "df")
_X87_FIELDS = [
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
]


def _expr_register(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _row(
    identity: str,
    rva: int,
    encoded: bytes,
    *,
    outcome: dict[str, object],
    status: str = "reimplementable",
    external_events: list[dict[str, object]] | None = None,
    ordered_events: list[dict[str, object]] | None = None,
    register_writes: list[dict[str, object]] | None = None,
    fpu_state: dict[str, object] | None = None,
    control_disposition: dict[str, object] | None = None,
) -> dict[str, object]:
    mnemonic = {
        b"\x90": ("nop", ""),
        b"\xc3": ("ret", ""),
        b"\xc2\x0c\x00": ("ret", "0xc"),
        b"\xd9\x00": ("fld", "dword ptr [eax]"),
    }[encoded]
    transfer = {
        "format": "stage-a-semantic-transfer-contract-v1",
        "id": identity,
        "function": "fixture_main",
        "block_id": identity.removeprefix("semantic-transfer:"),
        "unit_kind": "semantic_transfer",
        "status": status,
        "reachable": True,
        "original": {
            "rva_start": rva,
            "rva_end": rva + len(encoded),
            "size": len(encoded),
        },
        "instructions": [
            {
                "rva": rva,
                "size": len(encoded),
                "bytes": encoded.hex(),
                "mnemonic": mnemonic[0],
                "op_str": mnemonic[1],
            }
        ],
        "instruction_bytes_sha256": sha256_bytes(encoded),
        "expression_model": "stage-a-semantic-ir-v1",
        "pre_state": {
            "registers": {name: _expr_register(name) for name in _REGISTERS},
            "flags": {name: {"op": "flag", "name": name} for name in _FLAGS},
            "memory": {
                "op": "memory",
                "name": "mem0",
                "address_width": 32,
                "value_width": 8,
            },
        },
        "register_writes": register_writes or [],
        "flag_writes": [],
        "memory_events": [],
        "external_events": external_events or [],
        "faults": [],
        "ordered_events": ordered_events or [],
        "edge_conditions": [],
        "outcome": outcome,
        "stack_delta": {
            "status": "derived",
            "net_bytes": 0,
            "expression": _expr_register("esp"),
        },
        "fpu_state": fpu_state,
        "counts": {
            "register_writes": len(register_writes or []),
            "flag_writes": 0,
            "memory_events": 0,
            "external_events": len(external_events or []),
            "faults": 0,
            "ordered_events": len(ordered_events or []),
            "edge_conditions": 0,
        },
        "acceptance": "test semantic transfer",
        "blocker_category": None if status == "reimplementable" else "x87_typed_lowering_required",
        "blocker": None if status == "reimplementable" else "x87 replay has not yet been typed",
        "next_action": None if status == "reimplementable" else "consume the typed x87 micro-op",
    }
    if control_disposition is not None:
        transfer["control_disposition"] = control_disposition
    return normalize_stage_a_semantic_transfer(transfer)


def _x87_state(rva: int, encoded: bytes) -> dict[str, object]:
    digest = sha256_bytes(encoded)
    return {
        "model": "native_exact_x87_command_replay_obligation_v1",
        "status": "required",
        "authoritative_state_type": "StageA.X87.PhysicalState",
        "required_fields": list(_X87_FIELDS),
        "missing_or_invalid_fields": [
            "tags",
            "pending_exception",
            "last_opcode",
            "instruction_pointer",
            "code_selector",
            "data_pointer",
            "data_selector",
        ],
        "logical_state_guidance": {
            "stack": [{"op": "fpu_reg", "args": [index]} for index in range(8)],
            "control": {"op": "fpu_control", "args": []},
            "status": {"op": "fpu_status", "args": []},
        },
        "replay": {
            "format": "stage-a-native-exact-x87-command-replay-obligation-v1",
            "checked_decoder": "StageA.Relational.X87.decodeSingletonCommand",
            "checked_executor": "StageA.Relational.X87.executeSingletonCommand",
            "architecture": "x86",
            "bitness": 32,
            "image_base": 0x400000,
            "rva_start": rva,
            "rva_end": rva + len(encoded),
            "bytes": encoded.hex(),
            "bytes_sha256": digest,
            "instructions": [
                {"rva": rva, "size": len(encoded), "bytes": encoded.hex()}
            ],
        },
    }


def _write_machine(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def _write_reference_contract(path: Path, original: Path) -> None:
    original_digest = sha256_file(original)
    payload = {
        "format": "stage-a-reference-contract-v1",
        "generator": "stage-a-export-reference-contract",
        "generated_at": "1970-01-01T00:00:00+00:00",
        "model": "x86-pe32-env-v1",
        "status": "pass",
        "tool_versions": {},
        "inputs": {
            "original": {"path": original.name, "sha256": original_digest, "exists": True},
            "candidate": None,
            "mapping": None,
            "validation_report": None,
            "layout_contract": None,
        },
        "original": {
            "sha256": original_digest,
            "machine": "i386",
            "bitness": 32,
        },
        "candidate": None,
        "constraints": {
            "executable_byte_coverage": {
                "status": "satisfied",
                "original": {
                    "mapped_code_ranges": [
                        {"rva_start": 0x1000, "rva_end": 0x1001, "size": 1}
                    ],
                    "waived_noncode_ranges": [],
                    "gaps": [],
                },
            },
            "function_ranges": {"status": "satisfied", "functions": []},
            "basic_blocks_and_cfg": {"status": "satisfied", "basic_blocks": []},
            "roots_and_jump_tables": {
                "status": "satisfied",
                "roots": [{"kind": "entry", "block_id": "return"}],
                "jump_table_targets": [],
            },
            "import_thunks": {"status": "not_applicable", "mapped_import_thunks": []},
            "proof_obligation_inventory": {"status": "satisfied", "obligations": []},
        },
        "families": {},
        "coverage": {},
        "assumptions": [],
        "issues": [],
        "counts": {},
        "sidecars": {
            "unit_contracts": {
                "directory": ".",
                "semantic_transfer_contracts": {"path": "semantic-transfers.jsonl"},
            }
        },
    }
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def _read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _raw_instruction_keys(value: object) -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {
                "bytes",
                "instruction_bytes",
                "opcode_bytes",
                "raw_bytes",
                "encoded_instruction",
            }:
                result.add(key)
            result.update(_raw_instruction_keys(item))
    elif isinstance(value, list):
        for item in value:
            result.update(_raw_instruction_keys(item))
    return result


class ReconstructionIRTests(unittest.TestCase):
    def test_unknown_non_control_terminal_instruction_recovers_fallthrough(self):
        instruction = _Instruction(
            rva=0x1000,
            size=1,
            digest="0" * 64,
            mnemonic="inc",
            operands=(),
            registers_read=("eax",),
            registers_written=("eax",),
            groups=("not64bitmode",),
        )

        recovered = _recover_unknown_fallthrough(
            {"kind": "unknown"}, [instruction], RvaSpan(0x1000, 0x1001)
        )

        self.assertEqual(
            recovered["outcome"],
            {"kind": "fallthrough", "target_rva": 0x1001},
        )

    def test_unknown_control_or_trap_instruction_does_not_recover_fallthrough(self):
        def instruction(mnemonic: str, groups: tuple[str, ...]) -> _Instruction:
            return _Instruction(
                rva=0x1000,
                size=2,
                digest="0" * 64,
                mnemonic=mnemonic,
                operands=(),
                registers_read=(),
                registers_written=(),
                groups=groups,
            )

        span = RvaSpan(0x1000, 0x1002)
        self.assertIsNone(
            _recover_unknown_fallthrough(
                {"kind": "unknown"}, [instruction("jmp", ("jump",))], span
            )
        )
        self.assertIsNone(
            _recover_unknown_fallthrough(
                {"kind": "unknown"}, [instruction("ud2", ())], span
            )
        )

    def test_global_target_profile_does_not_replace_finite_site_inventory(self) -> None:
        row = _row(
            "semantic-transfer:indirect",
            0x1000,
            b"\xc3",
            outcome={"kind": "indirect_jump", "target": _expr_register("eax")},
        )
        profile = {
            "format": "stage-a-indirect-target-profile-v1",
            "id": "pe32-static-cutpoints-and-paired-callables-v1",
            "status": "accepted_assumption",
            "internal_target_domain": "all_checked_machine_ir_unit_starts",
            "external_target_domain": "paired_external_callable_resources",
            "runtime_rejection_required": True,
            "assumption": {
                "id": "complete-static-indirect-target-recovery",
                "scope": "fixture",
                "statement": "Fixture indirect targets remain in the checked domains.",
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            profile_path = root / "target-profile.json"
            original.write_bytes(pe32_image(b"\xc3", virtual_size=1))
            _write_machine(machine, [row])
            profile_path.write_text(json.dumps(profile), encoding="utf-8")

            unprofiled = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "unprofiled"
            )
            profiled = export_machine_ir_package(
                state_machine=machine,
                original_pe=original,
                indirect_target_profile=profile_path,
                out=root / "profiled",
            )
            manifest = _read_json(profiled.manifest)

            self.assertEqual(unprofiled.status, "incomplete")
            self.assertEqual(profiled.status, "incomplete")
            self.assertEqual(
                manifest["control"]["counts"]["closed_indirect_exits"], 0
            )
            self.assertEqual(
                manifest["control"]["indirect_exits"][0]["closure"],
                "explicit_trusted_target_profile_without_inventory",
            )
            self.assertEqual(
                manifest["control"]["reachability"]["status"], "incomplete"
            )
            self.assertEqual(
                manifest["trust_assumptions"][0]["id"],
                "complete-static-indirect-target-recovery",
            )

    def test_terminating_external_disposition_removes_nominal_fallthrough(self) -> None:
        event = {
            "kind": "external_call",
            "instruction_rva": 0x1000,
            "dll": "msvcrt.dll",
            "symbol": "abort",
            "ordinal": None,
            "arguments": [],
        }
        row = _row(
            "semantic-transfer:abort",
            0x1000,
            b"\x90",
            outcome={"kind": "fallthrough", "target_rva": 0x1001},
            external_events=[event],
            control_disposition={
                "kind": "terminates_after_external_event",
                "authority": "external_profile_machine_import_contract",
            },
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\x90", virtual_size=1))
            _write_machine(machine, [row])

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            manifest = _read_json(package.manifest)
            unit = _read_jsonl(package.machine_ir)[0]

            self.assertEqual(package.status, "qualified")
            self.assertEqual(manifest["control"]["counts"]["direct_targets"], 0)
            self.assertEqual(unit["control"]["direct_targets"], [])
            self.assertEqual(
                unit["control"]["disposition"]["kind"],
                "terminates_after_external_event",
            )

    def test_exports_deterministic_full_span_ir_with_exact_effects_and_control(self) -> None:
        code = b"\x90\xc3"
        write = {
            "register": "eax",
            "value": {
                "op": "add32",
                "args": [_expr_register("eax"), {"op": "const", "value": 1, "width": 32}],
            },
        }
        external = {
            "kind": "external_call",
            "instruction_rva": 0x1000,
            "dll": "KERNEL32.dll",
            "symbol": "GetLastError",
            "ordinal": None,
            "arguments": [],
        }
        rows = [
            _row(
                "semantic-transfer:first",
                0x1000,
                b"\x90",
                outcome={"kind": "jump", "target_rva": 0x1001},
                register_writes=[write],
                external_events=[external],
                ordered_events=[{"family": "external", **external}],
            ),
            _row(
                "semantic-transfer:return",
                0x1001,
                b"\xc3",
                outcome={"kind": "return", "value": _expr_register("eax")},
            ),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(code, virtual_size=len(code)))
            _write_machine(machine, rows)

            first = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "first"
            )
            second = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "second"
            )
            manifest = _read_json(first.manifest)
            units = _read_jsonl(first.machine_ir)

            self.assertEqual(first.status, "qualified")
            self.assertEqual(manifest["format"], MACHINE_IR_FORMAT)
            self.assertEqual(manifest["coverage"]["counts"]["unknown_bytes"], 0)
            self.assertEqual(manifest["control"]["direct_targets"][0]["target_rva"], 0x1001)
            self.assertEqual(manifest["external"]["events"][0]["symbol"], "GetLastError")
            self.assertEqual(units[0]["semantics"]["register_writes"], [write])
            self.assertEqual(
                units[0]["source"]["instruction_bytes_sha256"],
                sha256_bytes(b"\x90"),
            )
            self.assertEqual(
                (first.machine_ir).read_bytes(), (second.machine_ir).read_bytes()
            )
            self.assertEqual(
                (first.manifest).read_bytes(), (second.manifest).read_bytes()
            )
            self.assertEqual(_raw_instruction_keys(units), set())
            self.assertEqual(_raw_instruction_keys(manifest), set())

    def test_x87_replay_becomes_typed_mnemonic_operand_micro_op_without_bytes(self) -> None:
        encoded = b"\xd9\x00"  # fld dword ptr [eax]
        row = _row(
            "semantic-transfer:x87",
            0x1000,
            encoded,
            status="incomplete",
            outcome={"kind": "return"},
            fpu_state=_x87_state(0x1000, encoded),
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(encoded, virtual_size=len(encoded)))
            _write_machine(machine, [row])

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            unit = _read_jsonl(package.machine_ir)[0]
            serialized = package.machine_ir.read_text(encoding="utf-8")

            self.assertEqual(package.status, "qualified")
            self.assertEqual(len(unit["x87_micro_ops"]), 1)
            micro_op = unit["x87_micro_ops"][0]
            self.assertEqual(micro_op["mnemonic"], "fld")
            self.assertEqual(
                micro_op["operands"][0],
                {
                    "kind": "memory",
                    "segment": None,
                    "base": "eax",
                    "index": None,
                    "scale": 1,
                    "displacement": 0,
                    "width_bits": 32,
                    "access": "read",
                },
            )
            self.assertEqual(micro_op["instruction_sha256"], sha256_bytes(encoded))
            self.assertEqual(_raw_instruction_keys(unit), set())
            self.assertNotIn(encoded.hex(), serialized)
            self.assertNotIn("replay", unit["semantics"]["fpu_state"])

    def test_reports_source_mapped_executable_coverage_gap(self) -> None:
        code = b"\xc3\x90"
        row = _row(
            "semantic-transfer:return",
            0x1000,
            b"\xc3",
            outcome={"kind": "return"},
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(code, virtual_size=len(code)))
            _write_machine(machine, [row])

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            manifest = _read_json(package.manifest)
            issue = next(
                item
                for item in manifest["issues"]
                if item["category"] == "unclassified_executable_span"
            )

            self.assertEqual(package.status, "incomplete")
            self.assertEqual(issue["status"], "incomplete")
            self.assertEqual(issue["location"]["rva_start"], 0x1001)
            self.assertEqual(issue["location"]["rva_end"], 0x1002)
            self.assertEqual(manifest["coverage"]["counts"]["unknown_bytes"], 1)

    def test_reports_source_mapped_violation_for_unit_outside_executable_section(self) -> None:
        image = bytearray(pe32_image(b"\xc3", virtual_size=1))
        section_header = 0x80 + 4 + 20 + 224
        struct.pack_into("<I", image, section_header + 36, 0x40000020)
        row = _row(
            "semantic-transfer:return",
            0x1000,
            b"\xc3",
            outcome={"kind": "return"},
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(image)
            _write_machine(machine, [row])

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            manifest = _read_json(package.manifest)
            issue = next(
                item
                for item in manifest["issues"]
                if item["category"] == "semantic_unit_outside_executable_section"
            )

            self.assertEqual(package.status, "violated")
            self.assertEqual(issue["status"], "violated")
            self.assertEqual(issue["location"]["unit_id"], "semantic-transfer:return")
            self.assertEqual(issue["location"]["rva_start"], 0x1000)

    def test_rejects_duplicate_unit_ids_before_writing_package(self) -> None:
        first = _row(
            "semantic-transfer:duplicate",
            0x1000,
            b"\x90",
            outcome={"kind": "jump", "target_rva": 0x1001},
        )
        second = _row(
            "semantic-transfer:duplicate",
            0x1001,
            b"\xc3",
            outcome={"kind": "return"},
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            out = root / "out"
            original.write_bytes(pe32_image(b"\x90\xc3", virtual_size=2))
            _write_machine(machine, [first, second])

            with self.assertRaisesRegex(MachineIRExportError, "duplicate machine unit id") as raised:
                export_machine_ir_package(
                    state_machine=machine, original_pe=original, out=out
                )

            self.assertEqual(raised.exception.code, "duplicate_machine_unit_id")
            self.assertFalse(out.exists())

    def test_rejects_stale_digest_and_original_pe_byte_mismatch(self) -> None:
        row = _row(
            "semantic-transfer:return",
            0x1000,
            b"\xc3",
            outcome={"kind": "return"},
        )
        stale = dict(row)
        stale["outcome"] = {"kind": "jump", "target_rva": 0x1000}

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\xc3", virtual_size=1))
            _write_machine(machine, [stale])
            with self.assertRaisesRegex(MachineIRExportError, "stale contract digest") as stale_error:
                export_machine_ir_package(
                    state_machine=machine, original_pe=original, out=root / "stale"
                )
            self.assertEqual(
                stale_error.exception.code, "state_machine_contract_digest_mismatch"
            )

            _write_machine(machine, [row])
            original.write_bytes(pe32_image(b"\x90", virtual_size=1))
            with self.assertRaisesRegex(MachineIRExportError, "supplied original PE") as pe_error:
                export_machine_ir_package(
                    state_machine=machine, original_pe=original, out=root / "mismatch"
                )
            self.assertEqual(pe_error.exception.code, "original_pe_unit_binding_mismatch")

    def test_rejects_raw_instruction_material_hidden_in_semantic_effects(self) -> None:
        row = _row(
            "semantic-transfer:return",
            0x1000,
            b"\xc3",
            outcome={"kind": "return"},
            ordered_events=[{"family": "fault", "bytes": "c3"}],
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\xc3", virtual_size=1))
            _write_machine(machine, [row])

            with self.assertRaisesRegex(MachineIRExportError, "raw instruction material") as raised:
                export_machine_ir_package(
                    state_machine=machine, original_pe=original, out=root / "out"
                )
            self.assertEqual(raised.exception.code, "raw_instruction_bytes_in_semantics")

    def test_rejects_malformed_semantic_inventory(self) -> None:
        row = _row(
            "semantic-transfer:return",
            0x1000,
            b"\xc3",
            outcome={"kind": "return"},
        )
        malformed = dict(row)
        malformed["external_events"] = "not-an-inventory"
        malformed = normalize_stage_a_semantic_transfer(malformed)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\xc3", virtual_size=1))
            _write_machine(machine, [malformed])

            with self.assertRaisesRegex(MachineIRExportError, "external_events") as raised:
                export_machine_ir_package(
                    state_machine=machine, original_pe=original, out=root / "out"
                )
            self.assertEqual(raised.exception.code, "malformed_semantic_unit_effects")

    def test_package_uses_stable_filenames(self) -> None:
        row = _row(
            "semantic-transfer:return",
            0x1000,
            b"\xc3",
            outcome={"kind": "return"},
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\xc3", virtual_size=1))
            _write_machine(machine, [row])
            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            self.assertEqual(package.machine_ir.name, MACHINE_IR_FILENAME)
            self.assertEqual(package.manifest.name, MACHINE_IR_MANIFEST_FILENAME)

    def test_optional_reference_contract_is_hash_bound_and_projects_block_root(self) -> None:
        row = _row(
            "semantic-transfer:return",
            0x1000,
            b"\xc3",
            outcome={"kind": "return"},
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            reference = root / "reference-contract.json"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\xc3", virtual_size=1))
            _write_reference_contract(reference, original)
            row["stage_a_export"] = {
                "format": "stage-a-semantic-export-binding-v1",
                "reference_contract_sha256": sha256_file(reference),
                "semantic_transfer_sha256": "b" * 64,
            }
            _write_machine(machine, [row])

            package = export_machine_ir_package(
                state_machine=machine,
                original_pe=original,
                reference_contract=reference,
                out=root / "out",
            )
            manifest = _read_json(package.manifest)

            self.assertEqual(package.status, "qualified")
            self.assertEqual(
                manifest["inputs"]["reference_contract"]["sha256"],
                sha256_file(reference),
            )
            self.assertEqual(manifest["control"]["roots"][0]["block_id"], "return")
            self.assertEqual(manifest["control"]["roots"][0]["rva"], 0x1000)
            self.assertEqual(
                manifest["reference_inventory"]["roots_and_jump_tables"]["status"],
                "satisfied",
            )

    def test_binary_tls_callbacks_are_roots_even_with_a_submitted_root(self) -> None:
        rows = [
            _row(
                "semantic-transfer:return",
                0x1000,
                b"\xc3",
                outcome={"kind": "return"},
            ),
            _row(
                "semantic-transfer:tls",
                0x1010,
                b"\xc2\x0c\x00",
                outcome={"kind": "return"},
            ),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            reference = root / "reference-contract.json"
            machine = root / "state-machine.jsonl"
            original.write_bytes(_pe32_tls_image((0x1010,)))
            _write_reference_contract(reference, original)
            for row in rows:
                row["stage_a_export"] = {
                    "format": "stage-a-semantic-export-binding-v1",
                    "reference_contract_sha256": sha256_file(reference),
                    "semantic_transfer_sha256": "b" * 64,
                }
            _write_machine(machine, rows)

            package = export_machine_ir_package(
                state_machine=machine,
                original_pe=original,
                reference_contract=reference,
                out=root / "out",
            )
            roots = _read_json(package.manifest)["control"]["roots"]

            self.assertEqual([root["rva"] for root in roots], [0x1000, 0x1010])
            self.assertEqual(roots[0]["kind"], "pe_entrypoint")
            self.assertEqual(roots[0]["block_id"], "return")
            self.assertEqual(roots[1]["kind"], "pe_tls_callback")

    def test_callback_registration_uses_checked_stack_input_as_a_root(self) -> None:
        callback_rva = 0x2200
        callback_va = 0x400000 + callback_rva
        units = [
            {
                "id": "unit:register",
                "source": {"original": {"rva_start": 0x1100}},
                "semantics": {
                    "external_events": [
                        {
                            "kind": "external_call",
                            "dll": "kernel32.dll",
                            "symbol": "SetUnhandledExceptionFilter",
                            "arguments": [
                                {
                                    "op": "load",
                                    "address": _expr_register("esp"),
                                    "width": 4,
                                }
                            ],
                            "stack_inputs": [
                                {
                                    "offset": 0,
                                    "width": 4,
                                    "value": {
                                        "op": "const",
                                        "value": callback_va,
                                        "width": 32,
                                    },
                                }
                            ],
                            "abi_contract": {
                                "world_effect": "callbackRegistration",
                                "world_effect_argument": 0,
                                "callback_abi": {
                                    "kind": "generic_callback",
                                    "argument_words": 1,
                                    "stack_cleanup_bytes": 4,
                                    "nullable": True,
                                },
                            },
                        }
                    ]
                },
            },
            {
                "id": "unit:callback",
                "source": {"original": {"rva_start": callback_rva}},
                "semantics": {"external_events": []},
            },
        ]

        roots = _callback_registration_roots(
            SimpleNamespace(image_base=0x400000), units
        )

        self.assertEqual(len(roots), 1)
        self.assertEqual(roots[0]["rva"], callback_rva)
        self.assertEqual(roots[0]["source_unit_id"], "unit:register")

    def test_callback_root_requires_a_reachable_registration_source(self) -> None:
        proposals = [
            {
                "kind": "registered_callback",
                "rva": 0x2200,
                "source_unit_id": "unit:registration",
            }
        ]

        self.assertEqual(
            _newly_eligible_callback_roots(proposals, {"unit:other"}, {}), []
        )
        self.assertEqual(
            _newly_eligible_callback_roots(
                proposals, {"unit:registration"}, {}
            ),
            proposals,
        )


if __name__ == "__main__":
    unittest.main()
