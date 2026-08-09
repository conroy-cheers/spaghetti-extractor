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
    PREPARED_MACHINE_IR_FORMAT,
    MachineIRExportError,
    RvaSpan,
    _Instruction,
    _assert_byte_free,
    _bounded_predecessor_instruction_history,
    _callback_root_proposals_from_provenance,
    _classify_executable_data_before_control,
    _exceptional_control_inventory,
    _local_callback_cutpoint_proposals,
    _newly_eligible_callback_roots,
    _recovery_failure_message,
    _recover_unknown_fallthrough,
    _sanitize_schedule,
    export_machine_ir_package,
    prepare_machine_ir_units_package,
)
from spaghetti_extractor.interprocedural_analysis import (
    _prefer_indirect_recoveries,
)
from spaghetti_extractor.stage_b_state_machine import (
    normalize_stage_a_semantic_transfer,
)
from spaghetti_extractor.stage_binary import _parse_stage_a_pe
from spaghetti_extractor.util import sha256_bytes
from spaghetti_extractor.util import sha256_file

from tests.pe_fixtures import pe32_image, pe32_import_image, pe32_tls_image


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
    faults: list[dict[str, object]] | None = None,
    register_writes: list[dict[str, object]] | None = None,
    memory_events: list[dict[str, object]] | None = None,
    edge_conditions: list[dict[str, object]] | None = None,
    fpu_state: dict[str, object] | None = None,
    control_disposition: dict[str, object] | None = None,
) -> dict[str, object]:
    mnemonic = {
        b"\x90": ("nop", ""),
        b"\xc3": ("ret", ""),
        b"\xc2\x0c\x00": ("ret", "0xc"),
        b"\xd9\x00": ("fld", "dword ptr [eax]"),
        b"\xeb\xfe": ("jmp", "0x401000"),
        b"\xff\xe0": ("jmp", "eax"),
        b"\xff\x24\x85\x10\x10\x40\x00": (
            "jmp",
            "dword ptr [eax*4 + 0x401010]",
        ),
        b"\xff\x15\x40\x20\x40\x00": ("call", "dword ptr [0x402040]"),
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
        "memory_events": memory_events or [],
        "external_events": external_events or [],
        "faults": faults or [],
        "ordered_events": ordered_events or [],
        "edge_conditions": edge_conditions or [],
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
            "memory_events": len(memory_events or []),
            "external_events": len(external_events or []),
            "faults": len(faults or []),
            "ordered_events": len(ordered_events or []),
            "edge_conditions": len(edge_conditions or []),
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
            "checked_decoder": "StageA.Formal.decodeInstructionExact",
            "checked_executor": "StageA.Formal.executeInstruction",
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
    def test_structured_recovery_failure_does_not_require_legacy_message(self) -> None:
        self.assertEqual(
            _recovery_failure_message({"code": "value_origin_unresolved"}),
            "value_origin_unresolved",
        )

    def test_executable_data_and_instruction_interiors_precede_control_closure(self) -> None:
        def unit(
            identity: str,
            start: int,
            end: int,
            *,
            outcome: dict[str, object],
            instruction_end: int | None = None,
        ) -> dict[str, object]:
            return {
                "id": identity,
                "source": {
                    "original": {"rva_start": start, "rva_end": end},
                },
                "source_location": {"block_id": identity},
                "instructions": [{
                    "rva_start": start,
                    "rva_end": instruction_end or end,
                    "instruction_sha256": "a" * 64,
                }],
                "semantics": {
                    "outcome": outcome,
                    "external_events": [],
                    "register_writes": [],
                },
                "control": {
                    "kind": outcome["kind"],
                    "direct_targets": (
                        [outcome["target_rva"]]
                        if isinstance(outcome.get("target_rva"), int)
                        else []
                    ),
                    "has_indirect_target": outcome["kind"] == "indirect_jump",
                },
            }

        table_expression = {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [
                    {"op": "const", "value": 0x401010, "width": 32},
                    {
                        "op": "mul32",
                        "args": [
                            {"op": "const", "value": 0, "width": 32},
                            {"op": "const", "value": 4, "width": 32},
                        ],
                    },
                ],
            },
        }
        units = [
            unit(
                "root",
                0x1000,
                0x1002,
                outcome={"kind": "indirect_jump", "target": table_expression},
            ),
            unit(
                "table-decode",
                0x1010,
                0x1014,
                outcome={"kind": "fallthrough", "target_rva": 0x1014},
            ),
            unit(
                "target",
                0x1020,
                0x1025,
                outcome={"kind": "return"},
            ),
            unit(
                "interior-decode",
                0x1021,
                0x1023,
                outcome={"kind": "return"},
            ),
        ]
        image = bytearray(0x30)
        image[0x10:0x14] = (0x401020).to_bytes(4, "little")
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "original.exe"
            original.write_bytes(pe32_image(bytes(image), virtual_size=len(image)))
            binary = _parse_stage_a_pe(original)
            try:
                retained, classification, issues, recoveries = (
                    _classify_executable_data_before_control(
                        binary=binary,
                        units=units,
                        reference={"roots": [], "noncode_ranges": []},
                    )
                )
            finally:
                binary.pe.close()

        self.assertEqual(classification["status"], "complete")
        self.assertEqual(issues, [])
        self.assertEqual(len(recoveries), 1)
        self.assertEqual(recoveries[0]["kind"], "indirect_jump")
        self.assertEqual(
            recoveries[0]["recovery_kind"],
            "pe32_indexed_absolute_jump_table",
        )
        self.assertEqual(
            recoveries[0]["target_set_dependency"]["dependency_kind"],
            "bounded_selector",
        )
        self.assertEqual(
            [row["id"] for row in retained],
            ["root", "target"],
        )
        self.assertEqual(
            [
                (row["rva_start"], row["rva_end"])
                for row in classification["immutable_data_ranges"]
            ],
            [(0x1010, 0x1014)],
        )
        self.assertEqual(
            {row["unit_id"]: row["reason"] for row in classification["excluded_units"]},
            {
                "table-decode": "intersects_checked_immutable_executable_data",
                "interior-decode": "starts_inside_rooted_reachable_instruction",
            },
        )

    def test_byte_free_boundary_allows_numeric_byte_counts_only(self) -> None:
        _assert_byte_free({"size": {"kind": "fixed", "bytes": 16}})
        for raw in ("90", [0x90], True, -1):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(AssertionError, "raw instruction field"):
                    _assert_byte_free({"bytes": raw})

    def test_predecessor_history_crosses_one_instruction_cutpoint(self) -> None:
        compare = {
            "id": "compare",
            "source": {"original": {"rva_start": 0x1000, "rva_end": 0x1003}},
            "instructions": [{"mnemonic": "cmp"}],
            "semantics": {
                "external_events": [],
                "outcome": {"kind": "fallthrough", "target_rva": 0x1003},
            },
        }
        branch = {
            "id": "branch",
            "source": {"original": {"rva_start": 0x1003, "rva_end": 0x1005}},
            "instructions": [{"mnemonic": "ja"}],
            "semantics": {
                "external_events": [],
                "outcome": {
                    "kind": "branch",
                    "true_target_rva": 0x1100,
                    "false_target_rva": 0x1005,
                },
            },
        }

        history = _bounded_predecessor_instruction_history(
            branch,
            predecessors_by_target={0x1003: [compare]},
        )

        self.assertEqual(
            [instruction["mnemonic"] for instruction in history],
            ["cmp", "ja"],
        )

    def test_conflicting_indirect_recovery_mechanisms_fail_closed(self) -> None:
        static = [{
            "id": "exit",
            "status": "incomplete",
            "failure": {"code": "unresolved"},
        }]
        value = [{
            "id": "exit",
            "status": "recovered",
            "target_rvas": [0x1000],
            "target_unit_ids": ["one"],
            "external_targets": [],
        }]
        interface = [{
            "id": "exit",
            "status": "recovered",
            "target_rvas": [],
            "target_unit_ids": [],
            "external_targets": [{"external_protocol": {"kind": "different"}}],
        }]

        selected = _prefer_indirect_recoveries(static, value, interface)[0]

        self.assertEqual(selected["status"], "incomplete")
        self.assertEqual(
            selected["failure"]["code"],
            "conflicting_indirect_recovery_evidence",
        )

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
            b"\xff\xe0",
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
            original.write_bytes(pe32_image(b"\xff\xe0", virtual_size=2))
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

    def test_exact_finite_target_is_materialized_from_pe_bytes(self) -> None:
        encoded = b"\xff\x24\x85\x10\x10\x40\x00"
        target_expression = {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [
                    {"op": "const", "value": 0x401010, "width": 32},
                    {
                        "op": "mul32",
                        "args": [
                            {"op": "const", "value": 0, "width": 32},
                            {"op": "const", "value": 4, "width": 32},
                        ],
                    },
                ],
            },
        }
        row = _row(
            "semantic-transfer:dispatch",
            0x1000,
            encoded,
            outcome={"kind": "indirect_jump", "target": target_expression},
        )
        code = bytearray(b"\x90" * 0x22)
        code[: len(encoded)] = encoded
        code[0x10:0x14] = (0x401020).to_bytes(4, "little")
        code[0x20:0x22] = b"\x90\xc3"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(bytes(code), virtual_size=len(code)))
            _write_machine(machine, [row])

            package = export_machine_ir_package(
                state_machine=machine,
                original_pe=original,
                out=root / "out",
            )
            manifest = _read_json(package.manifest)
            units = _read_jsonl(package.machine_ir)
            recovery = manifest["control"]["recovered_indirect_targets"][0]

        materialized = next(
            unit
            for unit in units
            if unit["source"]["original"]["rva_start"] == 0x1020
        )
        self.assertEqual(materialized["status"], "qualified")
        self.assertEqual(
            materialized["preparation"]["target_cutpoint_materialization"][
                "target_rva"
            ],
            0x1020,
        )
        self.assertEqual(recovery["unit_binding"]["status"], "complete")
        self.assertEqual(recovery["target_unit_ids"], [materialized["id"]])
        self.assertEqual(manifest["counts"]["materialized_target_units"], 1)
        self.assertEqual(
            manifest["control"]["target_cutpoint_materialization"]["status"],
            "complete",
        )

    def test_rooted_direct_target_materialization_reaches_fixed_point(self) -> None:
        root = _row(
            "semantic-transfer:root",
            0x1000,
            b"\x90",
            outcome={"kind": "fallthrough", "target_rva": 0x1001},
        )
        code = b"\x90\xeb\x01\x90\xc3"

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            original = directory / "original.exe"
            machine = directory / "state-machine.jsonl"
            original.write_bytes(pe32_image(code, virtual_size=len(code)))
            _write_machine(machine, [root])

            package = export_machine_ir_package(
                state_machine=machine,
                original_pe=original,
                out=directory / "out",
            )
            manifest = _read_json(package.manifest)
            units = _read_jsonl(package.machine_ir)

        materialized_starts = {
            unit["source"]["original"]["rva_start"]
            for unit in units
            if "target_cutpoint_materialization" in unit["preparation"]
        }
        closure = manifest["control"]["target_cutpoint_materialization"]
        self.assertEqual(materialized_starts, {0x1001, 0x1004})
        self.assertTrue(closure["cutpoint_closure_converged"])
        self.assertEqual(
            [row["materialized_units"] for row in closure["cutpoint_closure_iterations"]],
            [1, 1, 0],
        )

    def test_unreachable_direct_target_is_not_materialized(self) -> None:
        root = _row(
            "semantic-transfer:root",
            0x1000,
            b"\xc3",
            outcome={"kind": "return", "stack_pop_bytes": 4},
        )
        speculative = _row(
            "semantic-transfer:speculative",
            0x1001,
            b"\xeb\xfe",
            outcome={"kind": "direct_jump", "target_rva": 0xDEADBEEF},
        )
        code = b"\xc3\xeb\xfe"

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            original = directory / "original.exe"
            machine = directory / "state-machine.jsonl"
            original.write_bytes(pe32_image(code, virtual_size=len(code)))
            _write_machine(machine, [root, speculative])

            package = export_machine_ir_package(
                state_machine=machine,
                original_pe=original,
                out=directory / "out",
            )
            manifest = _read_json(package.manifest)

        closure = manifest["control"]["target_cutpoint_materialization"]
        self.assertEqual(closure["status"], "complete")
        self.assertEqual(closure["counts"]["materialized_units"], 0)
        self.assertEqual(closure["issues"], [])

    def test_terminating_external_disposition_removes_nominal_fallthrough(self) -> None:
        event = {
            "kind": "external_call",
            "instruction_rva": 0x1000,
            "return_rva": 0x1006,
            "dll": "msvcrt.dll",
            "symbol": "abort",
            "ordinal": None,
            "arguments": [],
        }
        row = _row(
            "semantic-transfer:abort",
            0x1000,
            b"\xff\x15\x40\x20\x40\x00",
            outcome={"kind": "fallthrough", "target_rva": 0x1006},
            external_events=[event],
            ordered_events=[{"family": "external", **event}],
            control_disposition={
                "kind": "terminates_after_external_event",
                "authority": "external_profile_machine_import_contract",
            },
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(
                pe32_import_image(
                    b"\xff\x15\x40\x20\x40\x00",
                    symbol="abort",
                    dll="msvcrt.dll",
                )
            )
            _write_machine(machine, [row])

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            manifest = _read_json(package.manifest)
            unit = _read_jsonl(package.machine_ir)[0]

            self.assertEqual(package.status, "qualified")
            self.assertEqual(
                manifest["authority_bindings"]["binary"]["machine_ir_sha256"],
                manifest["artifacts"]["machine_ir"]["sha256"],
            )
            self.assertEqual(
                manifest["authority_bindings"]["units"][0]["unit_id"],
                unit["id"],
            )
            self.assertEqual(manifest["control"]["counts"]["direct_targets"], 0)
            self.assertEqual(unit["control"]["direct_targets"], [])
            self.assertEqual(
                unit["control"]["disposition"]["kind"],
                "terminates_after_external_event",
            )

    def test_exceptional_control_closes_only_explicit_terminal_faults(self) -> None:
        terminal_fault = {
            "kind": "divide_error",
            "condition": {"op": "true"},
            "instruction_rva": 0x1000,
        }
        row = _row(
            "semantic-transfer:fault",
            0x1000,
            b"\x90",
            outcome={"kind": "fault", "fault_kind": "divide_error"},
            faults=[terminal_fault],
            ordered_events=[{"family": "fault", **terminal_fault}],
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
            inventory = _read_json(package.manifest)["control"][
                "exceptional_control"
            ]
            transition = inventory["transitions"][0]

            self.assertEqual(inventory["status"], "complete")
            self.assertEqual(transition["status"], "complete")
            self.assertEqual(transition["disposition"]["kind"], "termination")
            self.assertTrue(transition["disposition"]["observable"])
            self.assertEqual(
                transition["fault_sha256"],
                sha256_bytes(
                    json.dumps(
                        terminal_fault, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ),
            )
            certificate = transition["disposition"]["evidence"]["certificate"]
            self.assertEqual(certificate["fault_sha256"], transition["fault_sha256"])
            self.assertEqual(
                certificate["source_contract_sha256"], row["contract_sha256"]
            )

    def test_exceptional_control_leaves_conditional_fault_unresolved(self) -> None:
        conditional_fault = {
            "kind": "divide_error",
            "condition": {"op": "flag", "name": "zf"},
            "instruction_rva": 0x1000,
        }
        rows = [
            _row(
                "semantic-transfer:divide",
                0x1000,
                b"\x90",
                outcome={"kind": "fallthrough", "target_rva": 0x1001},
                faults=[conditional_fault],
                ordered_events=[{"family": "fault", **conditional_fault}],
            ),
            _row(
                "semantic-transfer:return",
                0x1001,
                b"\xc3",
                outcome={"kind": "return", "value": _expr_register("eax")},
            ),
            _row(
                "semantic-transfer:unreachable-fault",
                0x1002,
                b"\x90",
                outcome={"kind": "fault", "fault_kind": "invalid_opcode"},
                faults=[{
                    "kind": "invalid_opcode",
                    "condition": {"op": "true"},
                    "instruction_rva": 0x1002,
                }],
            ),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\x90\xc3\x90", virtual_size=3))
            _write_machine(machine, rows)

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            inventory = _read_json(package.manifest)["control"][
                "exceptional_control"
            ]
            transition = inventory["transitions"][0]

            self.assertEqual(inventory["status"], "incomplete")
            self.assertEqual(len(inventory["transitions"]), 1)
            self.assertEqual(
                transition["source_unit_id"], "semantic-transfer:divide"
            )
            self.assertEqual(transition["status"], "incomplete")
            self.assertEqual(transition["disposition"]["kind"], "unresolved")
            self.assertEqual(
                transition["disposition"]["evidence"]["status"],
                "checked_possible",
            )

    def test_exceptional_control_closes_proved_infeasible_divide_error(self) -> None:
        condition = {
            "op": "not",
            "args": [
                {
                    "op": "udiv_valid32",
                    "args": [
                        {"op": "const", "value": 0, "width": 32},
                        {"op": "reg", "name": "eax", "width": 32},
                        {"op": "const", "value": 15, "width": 32},
                    ],
                }
            ],
        }
        fault = {
            "kind": "divide_error",
            "condition": condition,
            "instruction_rva": 0x1000,
        }
        rows = [
            _row(
                "semantic-transfer:divide",
                0x1000,
                b"\x90",
                outcome={"kind": "fallthrough", "target_rva": 0x1001},
                faults=[fault],
                ordered_events=[{"family": "fault", **fault}],
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
            original.write_bytes(pe32_image(b"\x90\xc3", virtual_size=2))
            _write_machine(machine, rows)

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            inventory = _read_json(package.manifest)["control"][
                "exceptional_control"
            ]
            transition = inventory["transitions"][0]

            self.assertEqual(inventory["status"], "complete")
            self.assertEqual(transition["status"], "complete")
            self.assertEqual(transition["disposition"]["kind"], "infeasible")
            self.assertFalse(transition["disposition"]["observable"])
            evidence = transition["disposition"]["evidence"]
            self.assertEqual(evidence["status"], "checked")
            self.assertEqual(
                evidence["checker"],
                "stage-a-machine-ir-qf-bv-fault-infeasibility-v1",
            )
            certificate = evidence["certificate"]
            self.assertEqual(certificate["fault_kind"], "divide_error")
            self.assertEqual(
                certificate["predicate_sha256"],
                sha256_bytes(
                    json.dumps(
                        condition, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ),
            )
            self.assertEqual(
                certificate["source_contract_sha256"], rows[0]["contract_sha256"]
            )

    def test_exceptional_control_does_not_close_platform_false_predicates(
        self,
    ) -> None:
        faults = [
            {
                "kind": kind,
                "condition": {"op": "false"},
                "instruction_rva": 0x1000,
            }
            for kind in (
                "page_fault",
                "general_protection",
                "x87_exception",
            )
        ]
        rows = [
            _row(
                "semantic-transfer:x87",
                0x1000,
                b"\x90",
                outcome={"kind": "fallthrough", "target_rva": 0x1001},
                faults=faults,
                ordered_events=[
                    {"family": "fault", **fault} for fault in faults
                ],
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
            original.write_bytes(pe32_image(b"\x90\xc3", virtual_size=2))
            _write_machine(machine, rows)

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            transitions = _read_json(package.manifest)["control"][
                "exceptional_control"
            ]["transitions"]

            self.assertEqual(len(transitions), 3)
            for transition in transitions:
                self.assertEqual(transition["status"], "incomplete")
                self.assertEqual(
                    transition["disposition"]["kind"], "unresolved"
                )
                self.assertEqual(
                    transition["disposition"]["evidence"]["status"],
                    "unchecked",
                )

    def test_exceptional_control_abstracts_loads_for_infeasibility_only(self) -> None:
        loaded_dividend = {
            "op": "load",
            "width": 4,
            "address": {"op": "reg", "name": "esp", "width": 32},
        }
        loaded_divisor = {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [
                    {"op": "reg", "name": "esp", "width": 32},
                    {"op": "const", "value": 4, "width": 32},
                ],
            },
        }
        faults = [
            {
                "kind": "divide_error",
                "condition": {
                    "op": "not",
                    "args": [
                        {
                            "op": "udiv_valid32",
                            "args": [
                                {"op": "const", "value": 0, "width": 32},
                                loaded_dividend,
                                {"op": "const", "value": 15, "width": 32},
                            ],
                        }
                    ],
                },
                "instruction_rva": 0x1000,
            },
            {
                "kind": "divide_error",
                "condition": {
                    "op": "not",
                    "args": [
                        {
                            "op": "udiv_valid32",
                            "args": [
                                {"op": "const", "value": 0, "width": 32},
                                {"op": "reg", "name": "eax", "width": 32},
                                loaded_divisor,
                            ],
                        }
                    ],
                },
                "instruction_rva": 0x1000,
            },
        ]
        rows = [
            _row(
                "semantic-transfer:divide",
                0x1000,
                b"\x90",
                outcome={"kind": "fallthrough", "target_rva": 0x1001},
                faults=faults,
                ordered_events=[
                    {"family": "fault", **fault} for fault in faults
                ],
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
            original.write_bytes(pe32_image(b"\x90\xc3", virtual_size=2))
            _write_machine(machine, rows)

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            transitions = _read_json(package.manifest)["control"][
                "exceptional_control"
            ]["transitions"]

            self.assertEqual(transitions[0]["status"], "complete")
            abstraction = transitions[0]["disposition"]["evidence"][
                "certificate"
            ]["stateful_leaf_abstractions"]
            self.assertEqual(len(abstraction), 1)
            self.assertEqual(abstraction[0]["source_op"], "load")
            self.assertEqual(abstraction[0]["width"], 32)
            self.assertEqual(transitions[1]["status"], "incomplete")
            self.assertEqual(
                transitions[1]["disposition"]["evidence"]["status"],
                "checked_abstract_possible",
            )
            analysis = transitions[1]["disposition"]["evidence"]["analysis"]
            self.assertEqual(
                analysis["stateful_leaf_abstractions"][0]["source_op"], "load"
            )

    def test_exceptional_control_requires_scc_invariant_for_branch_fact(self) -> None:
        zero = {"op": "const", "value": 0, "width": 32}
        divisor = {"op": "reg", "name": "esi", "width": 32}
        is_zero = {
            "op": "eq",
            "args": [
                {"op": "and32", "args": [divisor, divisor]},
                zero,
            ],
        }
        nonzero = {"op": "not", "args": [is_zero]}
        fault = {
            "kind": "divide_error",
            "condition": {
                "op": "not",
                "args": [
                    {
                        "op": "udiv_valid32",
                        "args": [zero, _expr_register("eax"), divisor],
                    }
                ],
            },
            "instruction_rva": 0x1001,
        }
        predecessor = _row(
            "semantic-transfer:guard",
            0x1000,
            b"\x90",
            outcome={
                "kind": "branch",
                "condition": is_zero,
                "true_target_rva": 0x1002,
                "false_target_rva": 0x1001,
            },
            edge_conditions=[
                {"target_rva": 0x1002, "condition": is_zero},
                {"target_rva": 0x1001, "condition": nonzero},
            ],
        )
        rows = [
            predecessor,
            _row(
                "semantic-transfer:divide",
                0x1001,
                b"\x90",
                outcome={"kind": "fallthrough", "target_rva": 0x1002},
                faults=[fault],
                ordered_events=[{"family": "fault", **fault}],
            ),
            _row(
                "semantic-transfer:return",
                0x1002,
                b"\xc3",
                outcome={"kind": "return", "value": _expr_register("eax")},
            ),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\x90\x90\xc3", virtual_size=3))
            _write_machine(machine, rows)

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            transition = _read_json(package.manifest)["control"][
                "exceptional_control"
            ]["transitions"][0]

            self.assertEqual(transition["status"], "incomplete")
            evidence = transition["disposition"]["evidence"]
            requirement = evidence["scc_invariant_requirement"]
            self.assertEqual(
                requirement["format"],
                "stage-a-scc-exception-invariant-requirement-v2",
            )
            self.assertEqual(
                requirement["reason"],
                "checked_scc_invariant_certificate_required",
            )
            self.assertEqual(requirement["source_unit_id"], rows[1]["id"])

    def test_terminal_fault_without_exact_fault_record_is_incomplete(self) -> None:
        row = _row(
            "semantic-transfer:fault",
            0x1000,
            b"\x90",
            outcome={"kind": "fault", "fault_kind": "invalid_opcode"},
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

            self.assertEqual(package.status, "incomplete")
            self.assertEqual(
                manifest["control"]["exceptional_control"]["transitions"], []
            )
            self.assertIn(
                "terminal_fault_missing_fault_record",
                {issue["category"] for issue in manifest["issues"]},
            )

    def test_ret_misdeclared_as_jump_self_loop_violates_reconciliation(self) -> None:
        row = _row(
            "semantic-transfer:false-loop",
            0x1000,
            b"\xc3",
            outcome={"kind": "jump", "target_rva": 0x1000},
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
            manifest = _read_json(package.manifest)
            unit = _read_jsonl(package.machine_ir)[0]
            reconciliation = unit["control"]["decoded_reconciliation"]

            self.assertEqual(package.status, "violated")
            self.assertEqual(unit["status"], "incomplete")
            self.assertEqual(reconciliation["status"], "violated")
            self.assertEqual(
                reconciliation["terminal_instruction"]["return_class"],
                "near_return",
            )
            self.assertIn(
                "return_class_mismatch",
                {check["code"] for check in reconciliation["checks"]},
            )
            self.assertIn(
                "decoded_control_reconciliation",
                {issue["category"] for issue in manifest["issues"]},
            )

    def test_decoded_direct_target_mismatch_violates_reconciliation(self) -> None:
        row = _row(
            "semantic-transfer:wrong-target",
            0x1000,
            b"\xeb\xfe",
            outcome={"kind": "jump", "target_rva": 0x1001},
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\xeb\xfe", virtual_size=2))
            _write_machine(machine, [row])

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            reconciliation = _read_jsonl(package.machine_ir)[0]["control"][
                "decoded_reconciliation"
            ]

            self.assertEqual(package.status, "violated")
            self.assertEqual(reconciliation["status"], "violated")
            target_check = next(
                check
                for check in reconciliation["checks"]
                if check["code"] == "direct_targets_mismatch"
            )
            self.assertEqual(target_check["expected"], [0x1000])
            self.assertEqual(target_check["actual"], [0x1001])

    def test_decoded_external_call_identity_mismatch_violates_reconciliation(
        self,
    ) -> None:
        call = b"\xff\x15\x40\x20\x40\x00"
        event = {
            "kind": "external_call",
            "instruction_rva": 0x1000,
            "return_rva": 0x1006,
            "dll": "KERNEL32.dll",
            "symbol": "SetLastError",
            "ordinal": None,
            "arguments": [],
        }
        rows = [
            _row(
                "semantic-transfer:call",
                0x1000,
                call,
                outcome={"kind": "fallthrough", "target_rva": 0x1006},
                external_events=[event],
                ordered_events=[{"family": "external", **event}],
            ),
            _row(
                "semantic-transfer:return",
                0x1006,
                b"\xc3",
                outcome={"kind": "return"},
            ),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(
                pe32_import_image(call + b"\xc3", symbol="GetLastError")
            )
            _write_machine(machine, rows)

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            reconciliation = _read_jsonl(package.machine_ir)[0]["control"][
                "decoded_reconciliation"
            ]

            self.assertEqual(package.status, "violated")
            self.assertEqual(reconciliation["status"], "violated")
            self.assertIn(
                "call_event_0_import_mismatch",
                {check["code"] for check in reconciliation["checks"]},
            )

    def test_checked_decode_site_is_bound_into_canonical_call_event(self) -> None:
        call = b"\xff\x15\x40\x20\x40\x00"
        event = {
            "kind": "external_call",
            "return_rva": 0x1006,
            "dll": "KERNEL32.dll",
            "symbol": "GetLastError",
            "ordinal": None,
            "arguments": [],
        }
        rows = [
            _row(
                "semantic-transfer:call",
                0x1000,
                call,
                outcome={"kind": "fallthrough", "target_rva": 0x1006},
                external_events=[event],
                ordered_events=[{
                    "family": "external",
                    "instruction_rva": 0x1000,
                    **event,
                }],
            ),
            _row(
                "semantic-transfer:return",
                0x1006,
                b"\xc3",
                outcome={"kind": "return"},
            ),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(
                pe32_import_image(call + b"\xc3", symbol="GetLastError")
            )
            _write_machine(machine, rows)

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            unit = _read_jsonl(package.machine_ir)[0]

            self.assertEqual(package.status, "qualified")
            self.assertEqual(
                unit["semantics"]["external_events"][0]["instruction_rva"],
                0x1000,
            )

    def test_exports_deterministic_full_span_ir_with_exact_effects_and_control(self) -> None:
        call = b"\xff\x15\x40\x20\x40\x00"
        code = call + b"\xc3"
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
            "return_rva": 0x1006,
            "dll": "KERNEL32.dll",
            "symbol": "GetLastError",
            "ordinal": None,
            "arguments": [],
        }
        rows = [
            _row(
                "semantic-transfer:first",
                0x1000,
                call,
                outcome={"kind": "fallthrough", "target_rva": 0x1006},
                register_writes=[write],
                external_events=[external],
                ordered_events=[{"family": "external", **external}],
            ),
            _row(
                "semantic-transfer:return",
                0x1006,
                b"\xc3",
                outcome={"kind": "return", "value": _expr_register("eax")},
            ),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(
                pe32_import_image(code, symbol="GetLastError")
            )
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
            self.assertEqual(manifest["control"]["direct_targets"][0]["target_rva"], 0x1006)
            self.assertEqual(manifest["external"]["events"][0]["symbol"], "GetLastError")
            self.assertEqual(units[0]["semantics"]["register_writes"], [write])
            self.assertEqual(
                units[0]["source"]["instruction_bytes_sha256"],
                sha256_bytes(call),
            )
            self.assertEqual(
                units[0]["control"]["decoded_reconciliation"]["status"],
                "complete",
            )
            self.assertEqual(
                (first.machine_ir).read_bytes(), (second.machine_ir).read_bytes()
            )
            self.assertEqual(
                (first.manifest).read_bytes(), (second.manifest).read_bytes()
            )
            self.assertEqual(_raw_instruction_keys(units), set())
            self.assertEqual(_raw_instruction_keys(manifest), set())

    def test_final_export_reuses_only_exactly_bound_prepared_units(self) -> None:
        rows = [
            _row(
                "semantic-transfer:first",
                0x1000,
                b"\x90",
                outcome={"kind": "jump", "target_rva": 0x1001},
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
            provisional_machine = root / "provisional-state-machine.jsonl"
            final_machine = root / "final-state-machine.jsonl"
            original.write_bytes(pe32_image(b"\x90\xc3", virtual_size=2))
            _write_machine(provisional_machine, rows[:1])
            _write_machine(final_machine, rows)

            provisional = export_machine_ir_package(
                state_machine=provisional_machine,
                original_pe=original,
                out=root / "provisional",
            )
            reused = export_machine_ir_package(
                state_machine=final_machine,
                original_pe=original,
                prepared_machine_ir=provisional.machine_ir.parent,
                out=root / "reused",
            )
            clean = export_machine_ir_package(
                state_machine=final_machine,
                original_pe=original,
                out=root / "clean",
            )
            manifest = _read_json(reused.manifest)

            self.assertEqual(manifest["counts"]["prepared_units_reused"], 1)
            self.assertEqual(manifest["counts"]["prepared_units_computed"], 1)
            self.assertEqual(reused.machine_ir.read_bytes(), clean.machine_ir.read_bytes())

            provisional.machine_ir.write_bytes(
                provisional.machine_ir.read_bytes() + b"\n"
            )
            with self.assertRaisesRegex(
                MachineIRExportError, "prepared machine IR input or artifact binding is stale"
            ):
                export_machine_ir_package(
                    state_machine=final_machine,
                    original_pe=original,
                    prepared_machine_ir=provisional.machine_ir.parent,
                    out=root / "stale",
                )

    def test_prepared_unit_phase_is_deterministic_and_reusable(self) -> None:
        rows = [
            _row(
                "semantic-transfer:first",
                0x1000,
                b"\x90",
                outcome={"kind": "jump", "target_rva": 0x1001},
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
            direct_machine = root / "direct-state-machine.jsonl"
            final_machine = root / "final-state-machine.jsonl"
            original.write_bytes(pe32_image(b"\x90\xc3", virtual_size=2))
            _write_machine(direct_machine, rows[:1])
            _write_machine(final_machine, rows)

            direct = prepare_machine_ir_units_package(
                state_machine=direct_machine,
                original_pe=original,
                out=root / "direct",
            )
            final = prepare_machine_ir_units_package(
                state_machine=final_machine,
                original_pe=original,
                prepared_machine_ir=direct.prepared_units.parent,
                out=root / "final",
            )
            clean = prepare_machine_ir_units_package(
                state_machine=final_machine,
                original_pe=original,
                out=root / "clean",
            )
            manifest = _read_json(final.manifest)

            self.assertEqual(manifest["format"], PREPARED_MACHINE_IR_FORMAT)
            self.assertEqual(manifest["counts"]["units_reused"], 1)
            self.assertEqual(manifest["counts"]["units_computed"], 1)
            self.assertEqual(
                final.prepared_units.read_bytes(), clean.prepared_units.read_bytes()
            )
            self.assertEqual(_raw_instruction_keys(manifest), set())
            self.assertEqual(
                _raw_instruction_keys(_read_jsonl(final.prepared_units)), set()
            )

            malformed_manifest = _read_json(final.manifest)
            malformed_manifest["artifacts"] = []
            final.manifest.write_text(
                json.dumps(malformed_manifest), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                MachineIRExportError,
                "prepared machine IR input or artifact binding is stale",
            ):
                export_machine_ir_package(
                    state_machine=final_machine,
                    original_pe=original,
                    prepared_machine_ir=final.prepared_units.parent,
                    out=root / "malformed",
                )

    def test_x87_replay_becomes_typed_mnemonic_operand_micro_op_without_bytes(self) -> None:
        encoded = b"\xd9\x00"  # fld dword ptr [eax]
        row = _row(
            "semantic-transfer:x87",
            0x1000,
            encoded,
            status="incomplete",
            outcome={"kind": "fallthrough", "target_rva": 0x1002},
            fpu_state=_x87_state(0x1000, encoded),
        )
        return_row = _row(
            "semantic-transfer:return",
            0x1002,
            b"\xc3",
            outcome={"kind": "return"},
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(
                pe32_image(encoded + b"\xc3", virtual_size=len(encoded) + 1)
            )
            _write_machine(machine, [row, return_row])

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

    def test_schedule_sanitization_preserves_and_reseals_integrity(self) -> None:
        record = {
            "index": 0,
            "bytes": "90",
            "bytes_sha256": sha256_bytes(b"\x90"),
            "effects": {"raw_bytes": "90", "register_writes": []},
        }
        record["record_sha256"] = sha256_bytes(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        schedule = {
            "format": "stage-a-instruction-ordered-effect-schedule-v1",
            "records": [record],
            "blockers": [],
        }
        schedule["schedule_sha256"] = sha256_bytes(
            json.dumps(schedule, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )

        sanitized = _sanitize_schedule(schedule, "semantic-transfer:test")
        sanitized_record = sanitized["records"][0]

        self.assertEqual(
            sanitized["source_schedule_sha256"], schedule["schedule_sha256"]
        )
        self.assertEqual(
            sanitized_record["source_record_sha256"], record["record_sha256"]
        )
        self.assertEqual(_raw_instruction_keys(sanitized), set())
        record_body = dict(sanitized_record)
        del record_body["record_sha256"]
        self.assertEqual(
            sanitized_record["record_sha256"],
            sha256_bytes(
                json.dumps(record_body, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            ),
        )
        schedule_body = dict(sanitized)
        del schedule_body["schedule_sha256"]
        self.assertEqual(
            sanitized["schedule_sha256"],
            sha256_bytes(
                json.dumps(schedule_body, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            ),
        )

        corrupted_record = dict(sanitized_record)
        corrupted_record["index"] = 1
        corrupted_record_body = dict(corrupted_record)
        del corrupted_record_body["record_sha256"]
        self.assertNotEqual(
            corrupted_record["record_sha256"],
            sha256_bytes(
                json.dumps(
                    corrupted_record_body, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            ),
        )

    def test_schedule_sanitization_rejects_corrupted_source_digests(self) -> None:
        record = {"index": 0, "bytes": "90"}
        record["record_sha256"] = sha256_bytes(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        schedule = {"records": [record]}
        schedule["schedule_sha256"] = sha256_bytes(
            json.dumps(schedule, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )

        corrupted_record = json.loads(json.dumps(schedule))
        corrupted_record["records"][0]["index"] = 1
        corrupted_record_body = dict(corrupted_record)
        del corrupted_record_body["schedule_sha256"]
        corrupted_record["schedule_sha256"] = sha256_bytes(
            json.dumps(
                corrupted_record_body, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        )
        with self.assertRaisesRegex(
            MachineIRExportError, "source schedule record 0 digest does not match"
        ):
            _sanitize_schedule(corrupted_record, "semantic-transfer:test")

        corrupted_schedule = json.loads(json.dumps(schedule))
        corrupted_schedule["records"].append(dict(record))
        with self.assertRaisesRegex(
            MachineIRExportError,
            "source instruction effect schedule digest does not match",
        ):
            _sanitize_schedule(corrupted_schedule, "semantic-transfer:test")

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
            original.write_bytes(pe32_tls_image((0x1010,)))
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

    def test_checked_callback_provenance_proposes_a_root(self) -> None:
        callback_rva = 0x2200
        roots = _callback_root_proposals_from_provenance({
            "callback_registrations": [{
                "format": "stage-a-callback-registration-provenance-v1",
                "status": "complete",
                "unit_id": "unit:register",
                "event_index": 0,
                "import": {
                    "dll": "kernel32.dll",
                    "symbol": "SetUnhandledExceptionFilter",
                    "ordinal": None,
                },
                "callback_source": {
                    "kind": "argument_word",
                    "argument": 0,
                },
                "callback_abi": {
                    "kind": "generic_callback",
                    "argument_words": 1,
                    "stack_cleanup_bytes": 4,
                    "nullable": True,
                },
                "target_rvas": [callback_rva],
            }],
        })

        self.assertEqual(len(roots), 1)
        self.assertEqual(roots[0]["rva"], callback_rva)
        self.assertEqual(roots[0]["source_unit_id"], "unit:register")

    def test_incomplete_callback_provenance_does_not_propose_a_root(self) -> None:
        callback_rva = 0x2203
        roots = _callback_root_proposals_from_provenance({
            "callback_registrations": [{
                "format": "stage-a-callback-registration-provenance-v1",
                "status": "incomplete",
                "unit_id": "unit:register",
                "event_index": 0,
                "target_rvas": [callback_rva],
                "failure": {"code": "callback_target_not_canonical_code"},
            }],
        })

        self.assertEqual(roots, [])

    def test_local_direct_callback_bootstraps_an_interior_cutpoint(self) -> None:
        stack_address = {
            "op": "sub32",
            "args": [
                _expr_register("esp"),
                {"op": "const", "value": 4, "width": 32},
            ],
        }
        callback_rva = 0x2203
        event = {
            "kind": "external_call",
            "dll": "kernel32.dll",
            "symbol": "SetUnhandledExceptionFilter",
            "ordinal": None,
            "return_rva": 0x110B,
            "stack_inputs": [{
                "offset": 0,
                "width": 4,
                "value": {"op": "load", "address": stack_address, "width": 4},
            }],
            "abi_contract": {
                "argument_words": 1,
                "world_effect": "callbackRegistration",
                "callback_source": {
                    "kind": "argument_word",
                    "argument": 0,
                },
                "callback_abi": {
                    "kind": "generic_callback",
                    "argument_words": 1,
                    "stack_cleanup_bytes": 4,
                    "nullable": True,
                },
            },
        }
        units = [{
            "id": "unit:registration",
            "semantics": {
                "external_events": [event],
                "ordered_events": [
                    {
                        "kind": "write",
                        "instruction_rva": 0x1100,
                        "address": stack_address,
                        "width": 4,
                        "value": {
                            "op": "const",
                            "value": 0x400000 + callback_rva,
                            "width": 32,
                        },
                    },
                    {**event, "instruction_rva": 0x1105},
                ],
            },
        }]
        binary = SimpleNamespace(
            image_base=0x400000,
            sections=(SimpleNamespace(
                executable=True,
                rva_start=0x2000,
                rva_end=0x2300,
            ),),
        )

        roots = _local_callback_cutpoint_proposals(binary, units)

        self.assertEqual([root["rva"] for root in roots], [callback_rva])
        self.assertFalse(roots[0]["proof_authority"])

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
