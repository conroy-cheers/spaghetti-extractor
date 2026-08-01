from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import pefile

from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.stage_b_native_engine import (
    plan_stage_b_native_engine,
    write_stage_b_native_engine_package,
)
from spaghetti_extractor.util import sha256_bytes


def _transfer(*, event: dict | None = None) -> dict:
    instructions = []
    ordered = []
    if event is not None:
        instructions = [{
            "rva": event["instruction_rva"],
            "size": 6,
            "bytes": "ff159c214300",
            "mnemonic": "call",
            "op_str": "dword ptr [0x43219c]",
        }]
        ordered = [{"family": "external", **event}]
    return {
        "id": "semantic-transfer:entry",
        "original": {"rva_start": 0x1420, "rva_end": 0x1430},
        "instructions": instructions,
        "ordered_events": ordered,
        "fpu_state": None,
    }


def _x87_replay_transfer() -> dict:
    encoded = bytes.fromhex("d9e8")
    digest = sha256_bytes(encoded)
    row = _transfer()
    row.update({
        "contract_sha256": "a" * 64,
        "instruction_bytes_sha256": digest,
        "original": {"rva_start": 0x1420, "rva_end": 0x1422, "size": 2},
        "instructions": [{
            "rva": 0x1420,
            "size": 2,
            "bytes": encoded.hex(),
            "mnemonic": "fld1",
            "op_str": "",
        }],
        "outcome": {"kind": "fallthrough", "target_rva": 0x1422},
        "fpu_state": {
            "model": "native_exact_x87_command_replay_obligation_v1",
            "status": "required",
            "authoritative_state_type": "StageA.X87.PhysicalState",
            "required_fields": [
                "stack", "tags", "control", "status", "pending_exception",
                "last_opcode", "instruction_pointer", "code_selector",
                "data_pointer", "data_selector",
            ],
            "missing_or_invalid_fields": [
                "tags", "pending_exception", "last_opcode",
                "instruction_pointer", "code_selector", "data_pointer",
                "data_selector",
            ],
            "logical_state_guidance": {},
            "replay": {
                "format": "stage-a-native-exact-x87-command-replay-obligation-v1",
                "checked_decoder": "StageA.Relational.X87.decodeSingletonCommand",
                "checked_executor": "StageA.Relational.X87.executeSingletonCommand",
                "architecture": "x86",
                "bitness": 32,
                "image_base": 0x400000,
                "rva_start": 0x1420,
                "rva_end": 0x1422,
                "bytes": encoded.hex(),
                "bytes_sha256": digest,
                "instructions": [{
                    "rva": 0x1420, "size": 2, "bytes": encoded.hex()
                }],
            },
        },
    })
    return row


def _absolute_x87_replay_transfer() -> dict:
    row = _x87_replay_transfer()
    encoded = bytes.fromhex("d90534124000")
    digest = sha256_bytes(encoded)
    row["stage_a_export"] = {"reference_contract_sha256": "c" * 64}
    row["instruction_bytes_sha256"] = digest
    row["original"] = {
        "rva_start": 0x1420,
        "rva_end": 0x1420 + len(encoded),
        "size": len(encoded),
    }
    row["instructions"] = [{
        "rva": 0x1420,
        "size": len(encoded),
        "bytes": encoded.hex(),
        "mnemonic": "fld",
        "op_str": "dword ptr [0x401234]",
    }]
    row["outcome"] = {
        "kind": "fallthrough",
        "target_rva": 0x1420 + len(encoded),
    }
    replay = row["fpu_state"]["replay"]
    replay.update({
        "rva_end": 0x1420 + len(encoded),
        "bytes": encoded.hex(),
        "bytes_sha256": digest,
        "instructions": [{
            "rva": 0x1420,
            "size": len(encoded),
            "bytes": encoded.hex(),
        }],
    })
    return row


def _relocation_evidence(
    relocations: list[dict] | None = None,
    *,
    reference_contract_sha256: str = "c" * 64,
) -> dict:
    return {
        "format": "stage-b-pe32-base-relocation-evidence-v1",
        "complete": True,
        "pe_sha256": "d" * 64,
        "reference_contract_sha256": reference_contract_sha256,
        "image_base": 0x400000,
        "relocations": relocations if relocations is not None else [{
            "source_rva": 0x1422,
            "type": 3,
            "kind": "highlow",
            "width": 4,
            "preferred_value": 0x401234,
        }],
    }


_RUNTIME_HEADER = r"""#ifndef STAGE_B_STATE_MACHINE_RUNTIME_H
#define STAGE_B_STATE_MACHINE_RUNTIME_H
#include <stdint.h>
typedef struct stage_b_x87_value {
  uint8_t value_bytes[10];
  uint32_t empty;
  uint8_t tag;
} stage_b_x87_value;
typedef struct stage_b_machine_state {
  uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp;
  uint32_t cf, zf, sf, of, pf, df;
  stage_b_x87_value x87_stack[8];
  uint16_t x87_control;
  uint16_t x87_status;
  uint8_t x87_pending_exception;
  uint16_t x87_last_opcode;
  uint32_t x87_instruction_pointer;
  uint16_t x87_code_selector;
  uint32_t x87_data_pointer;
  uint16_t x87_data_selector;
  uint32_t eflags;
  uint32_t fs_base;
  uint32_t original_rva;
} stage_b_machine_state;
typedef struct stage_b_stack_input {
  uint32_t offset, width, value;
} stage_b_stack_input;
typedef enum stage_b_call_event_kind {
  STAGE_B_CALL_EXTERNAL_IMPORT = 0,
  STAGE_B_CALL_INTERNAL_DIRECT = 1,
  STAGE_B_CALL_INDIRECT = 2
} stage_b_call_event_kind;
typedef struct stage_b_call_event {
  stage_b_call_event_kind kind;
  uint32_t instruction_rva, call_index, target_rva, return_rva;
  const char *dll, *symbol;
  uint32_t ordinal, has_ordinal;
  const uint32_t *arguments;
  uint32_t argument_count;
  const stage_b_stack_input *stack_inputs;
  uint32_t stack_input_count;
} stage_b_call_event;
typedef struct stage_b_runtime stage_b_runtime;
typedef enum stage_b_call_status {
  STAGE_B_CALL_OK = 0,
  STAGE_B_CALL_UNIMPLEMENTED = 1,
  STAGE_B_CALL_DIVIDE_ERROR = 2,
  STAGE_B_CALL_MEMORY_FAULT = 3,
  STAGE_B_CALL_EXTERNAL_FAULT = 4
} stage_b_call_status;
typedef stage_b_call_status (*stage_b_external_call_handler)(
    stage_b_runtime *, const stage_b_call_event *,
    const stage_b_machine_state *, stage_b_machine_state *);
typedef uint32_t (*stage_b_code_target_resolver)(
    stage_b_runtime *, uint32_t, uint32_t *);
struct stage_b_runtime {
  void *context;
  uint32_t (*read)(void *, uint32_t, uint32_t, uint32_t *);
  void (*write)(void *, uint32_t, uint32_t, uint32_t, uint32_t *);
  uint32_t (*undefined_value)(
      void *, uint32_t, const stage_b_machine_state *, uint32_t);
  stage_b_external_call_handler external_call_fallback;
  stage_b_code_target_resolver resolve_code_target;
  void *replay_checked_x87_command;
};
#endif
"""


def _x87_runtime_header() -> str:
    header = _RUNTIME_HEADER.replace(
        "typedef struct stage_b_runtime stage_b_runtime;",
        """typedef struct stage_b_x87_replay_program {
  uint32_t image_base, rva_start, rva_end, instruction_count, byte_count;
  const uint8_t *instruction_bytes;
  const char *instruction_bytes_sha256;
  const char *transfer_instruction_bytes_sha256;
  const char *contract_sha256;
  const char *checked_decoder;
  const char *checked_executor;
} stage_b_x87_replay_program;
typedef struct stage_b_runtime stage_b_runtime;""",
    )
    header = header.replace(
        "typedef uint32_t (*stage_b_code_target_resolver)(",
        """typedef stage_b_call_status (*stage_b_x87_replay_handler)(
    stage_b_runtime *, const stage_b_x87_replay_program *,
    const stage_b_machine_state *, stage_b_machine_state *);
typedef uint32_t (*stage_b_code_target_resolver)(""",
    )
    return header.replace(
        "  void *replay_checked_x87_command;",
        "  stage_b_x87_replay_handler replay_checked_x87_command;",
    )


class StageBNativeEngineTests(unittest.TestCase):
    def _write(self, root: Path, rows: list[dict]) -> Path:
        path = root / "state-machine.jsonl"
        path.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
        return path

    def test_plans_exact_external_callsite_without_a_prototype(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x1430,
                "dll": "KERNEL32.dll",
                "symbol": "Sleep",
                "ordinal": None,
            })])
            plan = plan_stage_b_native_engine(
                state_machine=machine, entry_rva=0x1420
            )
            self.assertEqual(plan.status, "ready")
            self.assertEqual(plan.external_sites[0].dll, "kernel32.dll")
            self.assertEqual(plan.external_sites[0].instruction_bytes.hex(), "ff159c214300")
            self.assertEqual(plan.external_sites[0].iat_va, 0x43219C)
            self.assertEqual(plan.external_sites[0].disposition, "returns_here")

    def test_relative_import_call_requires_exact_original_iat_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = _transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x142F,
                "dll": "kernel32.dll",
                "symbol": "Sleep",
                "ordinal": None,
            })
            row["instructions"][0].update({
                "bytes": "e8d10b0000",
                "size": 5,
                "mnemonic": "call",
                "op_str": "0x2000",
            })
            machine = self._write(root, [row])
            missing = plan_stage_b_native_engine(
                state_machine=machine, entry_rva=0x1420
            )
            bound = plan_stage_b_native_engine(
                state_machine=machine,
                entry_rva=0x1420,
                import_iat_vas={("kernel32.dll", "Sleep"): 0x43219C},
            )
            self.assertEqual(missing.status, "incomplete")
            self.assertEqual(
                missing.blockers[0]["category"], "external_import_iat_evidence_missing"
            )
            self.assertEqual(bound.status, "ready")
            self.assertEqual(bound.external_sites[0].iat_va, 0x43219C)

    def test_direct_e8_to_checked_local_thunk_stays_internal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            caller = _transfer()
            caller["ordered_events"] = [{
                "family": "external",
                "kind": "internal_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x142F,
                "target_rva": 0x2000,
            }]
            caller["instructions"] = [{
                "rva": 0x142A,
                "size": 5,
                "bytes": "e8d10b0000",
                "mnemonic": "call",
                "op_str": "0x2000",
            }]
            thunk = _transfer()
            thunk["id"] = "semantic-transfer:thunk"
            thunk["original"] = {"rva_start": 0x2000, "rva_end": 0x2006}
            thunk["instructions"] = [{
                "rva": 0x2000,
                "size": 6,
                "bytes": "ff259c214300",
                "mnemonic": "jmp",
                "op_str": "dword ptr [0x43219c]",
            }]
            thunk["ordered_events"] = [{
                "family": "external",
                "kind": "external_call",
                "instruction_rva": 0x2000,
                "return_rva": 0x2006,
                "dll": "kernel32.dll",
                "symbol": "Sleep",
                "ordinal": None,
            }]
            thunk["outcome"] = {
                "kind": "external_jump",
                "dll": "kernel32.dll",
                "symbol": "Sleep",
            }
            plan = plan_stage_b_native_engine(
                state_machine=self._write(root, [caller, thunk]),
                entry_rva=0x1420,
            )
            self.assertEqual(plan.status, "ready", plan.blockers)
            self.assertEqual(len(plan.external_sites), 1)
            self.assertEqual(plan.external_sites[0].instruction_rva, 0x2000)
            self.assertEqual(plan.external_sites[0].disposition, "tail_jump")

    def test_qualified_external_tail_import_records_continuation_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = _transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x1430,
                "dll": "msvcrt.dll",
                "symbol": "atexit",
                "ordinal": None,
            })
            row["instructions"][0].update({
                "bytes": "ff259c214300",
                "size": 6,
                "mnemonic": "jmp",
                "op_str": "dword ptr [0x43219c]",
            })
            row["outcome"] = {
                "kind": "external_jump", "dll": "msvcrt.dll", "symbol": "atexit"
            }
            machine = self._write(root, [row])
            plan = plan_stage_b_native_engine(
                state_machine=machine, entry_rva=0x1420
            )
            self.assertEqual(plan.status, "ready", plan.blockers)
            site = plan.external_sites[0]
            self.assertEqual(site.disposition, "tail_jump")
            self.assertEqual(site.iat_va, 0x43219C)
            payload = plan.payload(state_machine_sha256=sha256_bytes(machine.read_bytes()))
            self.assertEqual(
                payload["external_sites"][0]["continuation_evidence"],
                {
                    "kind": "replace-saved-caller-return",
                    "stack_offset": 0,
                    "width": 4,
                    "restored_at_capture": True,
                    "normal_call_frame_shift": False,
                },
            )
            self.assertRegex(
                payload["external_sites"][0]["transfer_sha256"],
                r"^[0-9a-f]{64}$",
            )
            package = root / "tail-package"
            write_stage_b_native_engine_package(
                state_machine=machine, entry_rva=0x1420, out=package
            )
            assembly = (package / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            wrapper = (package / "native-engine-wrapper.c").read_text(
                encoding="ascii"
            )
            self.assertIn(
                "mov DWORD PTR [esp], OFFSET FLAT:_stage_b_native_capture",
                assembly,
            )
            self.assertIn("mov DWORD PTR [ecx - 4], ebx", assembly)
            self.assertNotIn("add esp, 4", assembly)
            self.assertNotIn("runtime->read", wrapper)
            self.assertIn("stage_b_native_fixed_flat_read_u32(", wrapper)
            self.assertIn("input->esp, &frame.saved_continuation", wrapper)
            self.assertIn("frame.continuation_replaced != 0U", wrapper)

    def test_generated_bridge_switch_is_direct_complete_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            higher = _transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x202A,
                "return_rva": 0x2030,
                "dll": "kernel32.dll",
                "symbol": "Sleep",
                "ordinal": None,
            })
            higher["id"] = "semantic-transfer:higher"
            higher["original"] = {"rva_start": 0x2000, "rva_end": 0x2030}
            lower = _transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x1430,
                "dll": "msvcrt.dll",
                "symbol": "atexit",
                "ordinal": None,
            })
            machine = self._write(root, [higher, lower])
            first = root / "first"
            second = root / "second"
            write_stage_b_native_engine_package(
                state_machine=machine, entry_rva=0x1420, out=first
            )
            write_stage_b_native_engine_package(
                state_machine=machine, entry_rva=0x1420, out=second
            )
            source = (first / "native-engine-wrapper.c").read_text(encoding="ascii")
            repeated = (second / "native-engine-wrapper.c").read_text(
                encoding="ascii"
            )
            assembly = (first / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            self.assertEqual(source, repeated)
            self.assertNotIn("entry->bridge", source.split(
                "stage_b_call_status stage_b_dispatch_external_call", 1
            )[1])
            self.assertNotIn("runtime->read", source)
            self.assertNotIn("stage_b_native_bridge_fn", source)
            self.assertEqual(source.count("stage_b_native_bridge();"), 1)
            self.assertIn(
                "stage_b_native_dispatch_bridge();",
                source,
            )
            self.assertNotIn("switch (instruction_rva)", source)
            self.assertEqual(assembly.count("_stage_b_native_bridge:\n"), 1)
            self.assertEqual(assembly.count("_stage_b_native_capture:\n"), 1)
            self.assertNotIn("_stage_b_native_bridge_0000", assembly)
            self.assertNotIn("_stage_b_native_bridge_0001", assembly)
            self.assertNotIn(".stgbcl", assembly)

    def test_plans_prototype_free_dynamic_indirect_call_bridge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = _transfer()
            row["ordered_events"] = [{
                "family": "external",
                "kind": "indirect_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x142C,
            }]
            row["instructions"] = [{
                "rva": 0x142A,
                "size": 2,
                "bytes": "ffd3",
                "mnemonic": "call",
                "op_str": "ebx",
            }]
            machine = self._write(root, [row])
            plan = plan_stage_b_native_engine(
                state_machine=machine, entry_rva=0x1420
            )
            self.assertEqual(plan.status, "ready")
            self.assertEqual(plan.indirect_call_count, 1)
            self.assertEqual(plan.external_sites[0].site_kind, "dynamic_target")
            self.assertIsNone(plan.external_sites[0].dll)
            self.assertIsNone(plan.external_sites[0].symbol)
            self.assertEqual(plan.external_sites[0].instruction_bytes, b"\xff\xd3")

    def test_uses_evaluated_target_for_absolute_indirect_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = _transfer()
            row["ordered_events"] = [{
                "family": "external",
                "kind": "indirect_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x1430,
            }]
            row["instructions"] = [{
                "rva": 0x142A,
                "size": 6,
                "bytes": "ff159c214300",
                "mnemonic": "call",
                "op_str": "dword ptr [0x43219c]",
            }]
            plan = plan_stage_b_native_engine(
                state_machine=self._write(root, [row]), entry_rva=0x1420
            )
            self.assertEqual(plan.status, "ready")
            self.assertEqual(plan.external_sites[0].site_kind, "dynamic_target")

    def test_unqualified_x87_transfer_remains_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = _transfer()
            row["fpu_state"] = {
                "model": "symbolic_x87_stack_v1",
                "stack": [{"op": "fpu_reg", "args": [index]} for index in range(8)],
            }
            plan = plan_stage_b_native_engine(
                state_machine=self._write(root, [row]), entry_rva=0x1420
            )
            self.assertEqual(plan.status, "incomplete")
            self.assertEqual(
                plan.blockers[0]["category"], "x87_physical_state_unqualified"
            )

    def test_callback_rva_without_abi_remains_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_transfer()])
            plan = plan_stage_b_native_engine(
                state_machine=machine,
                entry_rva=0x1420,
                callback_targets=[0x1420],
            )
            self.assertEqual(plan.status, "incomplete")
            self.assertEqual(
                plan.blockers[0]["category"], "callback_abi_ambiguous"
            )

    def test_tls_callback_plan_binds_exact_transfer_abi_and_export_symbol(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_transfer()])
            callback = {
                "rva": 0x1420,
                "kind": "tls_callback",
                "stack_cleanup_bytes": 12,
            }
            plan = plan_stage_b_native_engine(
                state_machine=machine,
                entry_rva=0x1420,
                callback_targets=[callback],
            )
            self.assertEqual(plan.status, "ready", plan.blockers)
            target = plan.callback_targets[0]
            self.assertEqual(target.kind, "tls_callback")
            self.assertEqual(target.stack_cleanup_bytes, 12)
            self.assertEqual(target.symbol, "stage_b_payload_callback_00001420")
            payload = plan.payload(state_machine_sha256=sha256_bytes(machine.read_bytes()))
            self.assertEqual(payload["callback_targets"], [0x1420])
            self.assertEqual(
                payload["callback_abis"][0]["symbol"],
                "stage_b_payload_callback_00001420",
            )
            self.assertRegex(payload["callback_abis"][0]["transfer_sha256"], r"^[0-9a-f]{64}$")
            package = root / "callback-package"
            write_stage_b_native_engine_package(
                state_machine=machine,
                entry_rva=0x1420,
                callback_targets=[callback],
                out=package,
            )
            assembly = (package / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            callback_assembly = assembly.split(
                "stage_b_payload_callback_00001420:", 1
            )[1]
            self.assertIn("_stage_b_native_callback_failure_0000", callback_assembly)
            self.assertIn("_stage_b_native_root_callback_fault", callback_assembly)
            self.assertNotIn("jne _stage_b_native_halt", callback_assembly)

    def test_tls_callback_rejects_non_stdcall_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = plan_stage_b_native_engine(
                state_machine=self._write(root, [_transfer()]),
                entry_rva=0x1420,
                callback_targets=[{
                    "rva": 0x1420,
                    "kind": "tls_callback",
                    "stack_cleanup_bytes": 0,
                }],
            )
            self.assertEqual(plan.status, "incomplete")
            self.assertEqual(plan.blockers[0]["category"], "callback_abi_ambiguous")

    def test_generic_callback_requires_and_records_explicit_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = plan_stage_b_native_engine(
                state_machine=self._write(root, [_transfer()]),
                entry_rva=0x1420,
                callback_targets=[{
                    "rva": 0x1420,
                    "kind": "generic_callback",
                    "stack_cleanup_bytes": 8,
                }],
            )
            self.assertEqual(plan.status, "ready", plan.blockers)
            self.assertEqual(plan.callback_targets[0].stack_cleanup_bytes, 8)

    def test_qualified_x87_replay_preserves_physical_fnsave_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_x87_replay_transfer()])
            plan = plan_stage_b_native_engine(
                state_machine=machine, entry_rva=0x1420
            )
            self.assertEqual(plan.status, "ready", plan.blockers)
            self.assertEqual(len(plan.x87_replays), 1)
            package = root / "package"
            result = write_stage_b_native_engine_package(
                state_machine=machine,
                entry_rva=0x1420,
                callback_targets=[{
                    "rva": 0x1420,
                    "kind": "tls_callback",
                    "stack_cleanup_bytes": 12,
                }],
                out=package,
            )
            self.assertEqual(result["status"], "ready", result)
            header = (package / "native-engine-wrapper.h").read_text(encoding="ascii")
            source = (package / "native-engine-wrapper.c").read_text(encoding="ascii")
            assembly = (package / "native-engine-bridges.S").read_text(encoding="ascii")
            self.assertIn("physical_registers[8][10]", header)
            self.assertIn("uint16_t tag_word", header)
            self.assertIn("FNSAVE image must be 108 bytes", source)
            self.assertIn("physical_registers[(top + i) & 7U][j]", source)
            self.assertIn(
                "physical_registers[physical][j]",
                source,
            )
            self.assertIn("top = (image->status_word >> 11U) & 7U", source)
            self.assertIn("entry->bridge();", source)
            self.assertIn("fnsave", assembly)
            self.assertIn("frstor", assembly)
            self.assertIn(".byte 0xd9, 0xe8", assembly)
            x87_capture = assembly.split(
                "_stage_b_native_x87_capture_0000:", maxsplit=1
            )[1]
            self.assertIn("push eax", x87_capture)
            self.assertNotIn("pushad", x87_capture)
            self.assertIn("mov ecx, DWORD PTR [esp]", x87_capture)
            self.assertIn("mov ebx, DWORD PTR [esp + 4]", x87_capture)
            self.assertIn("mov DWORD PTR [edx + 0], ecx", x87_capture)
            for offset in (4, 8, 12, 16, 20, 24, 28):
                self.assertNotIn(
                    f"mov DWORD PTR [edx + {offset}], ecx", x87_capture
                )
            for flag, offset in (("setc", 32), ("setz", 36), ("sets", 40),
                                 ("seto", 44), ("setp", 48)):
                self.assertIn(
                    f"{flag} BYTE PTR [edx + {offset}]", x87_capture
                )
            self.assertIn("and ebx, 0x00000cd5", x87_capture)
            self.assertIn("mov DWORD PTR [edx + 240], ecx", x87_capture)

    def test_x87_callback_passes_preserved_input_fnsave_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_x87_replay_transfer()])
            package = root / "package"
            write_stage_b_native_engine_package(
                state_machine=machine,
                entry_rva=0x1420,
                callback_targets=[{
                    "rva": 0x1420,
                    "kind": "tls_callback",
                    "stack_cleanup_bytes": 12,
                }],
                out=package,
            )
            assembly = (package / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            callback_call = assembly.split(
                "_stage_b_native_callback_x87_buffers_ready_0000:", 1
            )[1].split(
                "_stage_b_native_callback_dispatch_return_00001420:", 1
            )[0]
            self.assertIn("    mov esi, ecx", callback_call)
            self.assertIn(
                "    push eax\n"
                "    push esi\n"
                "    push ebx\n"
                "    push edx\n"
                "    push 12\n"
                "    push 0x00001420\n"
                "    call _stage_b_native_run_callback",
                callback_call,
            )
            self.assertNotIn("    push eax\n    push ecx\n", callback_call)

    def test_x87_absolute_disp32_replay_is_rejected_for_dynamicbase(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = _x87_replay_transfer()
            encoded = bytes.fromhex("d90578563412")
            digest = sha256_bytes(encoded)
            row["instruction_bytes_sha256"] = digest
            row["original"] = {
                "rva_start": 0x1420,
                "rva_end": 0x1420 + len(encoded),
                "size": len(encoded),
            }
            row["instructions"] = [{
                "rva": 0x1420,
                "size": len(encoded),
                "bytes": encoded.hex(),
                "mnemonic": "fld",
                "op_str": "dword ptr [0x12345678]",
            }]
            row["outcome"] = {
                "kind": "fallthrough",
                "target_rva": 0x1420 + len(encoded),
            }
            replay = row["fpu_state"]["replay"]
            replay.update({
                "rva_end": 0x1420 + len(encoded),
                "bytes": encoded.hex(),
                "bytes_sha256": digest,
                "instructions": [{
                    "rva": 0x1420,
                    "size": len(encoded),
                    "bytes": encoded.hex(),
                }],
            })
            plan = plan_stage_b_native_engine(
                state_machine=self._write(root, [row]), entry_rva=0x1420
            )
            self.assertEqual(plan.status, "incomplete")
            self.assertEqual(plan.blockers[0]["category"], "x87_replay_aslr_unsafe")
            self.assertIn("HIGHLOW", plan.blockers[0]["next_action"])

    def test_x87_absolute_disp32_accepts_exact_hash_bound_highlow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_absolute_x87_replay_transfer()])
            plan = plan_stage_b_native_engine(
                state_machine=machine,
                entry_rva=0x1420,
                base_relocation_evidence=_relocation_evidence(),
            )
            self.assertEqual(plan.status, "ready", plan.blockers)
            replay = plan.x87_replays[0]
            self.assertEqual(replay.relocation_source_rva, 0x1422)
            self.assertEqual(replay.operand_byte_offset, 2)
            self.assertEqual(replay.preferred_value, 0x401234)
            self.assertEqual(replay.target_rva, 0x1234)
            self.assertEqual((replay.relocation_type, replay.relocation_width), (3, 4))
            payload = plan.payload(state_machine_sha256=sha256_bytes(machine.read_bytes()))
            relocation = payload["x87_replays"][0]["base_relocation"]
            self.assertEqual(relocation["reference_contract_sha256"], "c" * 64)
            self.assertEqual(relocation["pe_sha256"], "d" * 64)
            package = root / "package"
            write_stage_b_native_engine_package(
                state_machine=machine,
                entry_rva=0x1420,
                base_relocation_evidence=_relocation_evidence(),
                out=package,
            )
            assembly = (package / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            self.assertIn(".byte 0xd9, 0x05", assembly)
            self.assertIn(".long ___ImageBase + 0x00001234", assembly)
            self.assertNotIn("0x34, 0x12, 0x40, 0x00", assembly)

    def test_x87_relocation_evidence_must_bind_same_reference_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_absolute_x87_replay_transfer()])
            with self.assertRaisesRegex(
                StageAInputError, "bind different reference contracts"
            ):
                plan_stage_b_native_engine(
                    state_machine=machine,
                    entry_rva=0x1420,
                    base_relocation_evidence=_relocation_evidence(
                        reference_contract_sha256="e" * 64
                    ),
                )

    def test_relocation_evidence_does_not_require_export_on_non_x87_rows(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = plan_stage_b_native_engine(
                state_machine=self._write(root, [_transfer()]),
                entry_rva=0x1420,
                base_relocation_evidence=_relocation_evidence(),
            )
            self.assertEqual(plan.status, "ready", plan.blockers)

    def test_x87_relocation_evidence_rejects_unqualified_cells(self) -> None:
        base = {
            "source_rva": 0x1422,
            "type": 3,
            "kind": "highlow",
            "width": 4,
            "preferred_value": 0x401234,
        }
        cases = {
            "non_highlow": [{**base, "type": 2, "kind": "other"}],
            "width_mismatch": [{**base, "width": 2}],
            "out_of_instruction": [{**base, "source_rva": 0x1423}],
            "preferred_mismatch": [{**base, "preferred_value": 0x401238}],
        }
        for name, relocations in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                plan = plan_stage_b_native_engine(
                    state_machine=self._write(root, [_absolute_x87_replay_transfer()]),
                    entry_rva=0x1420,
                    base_relocation_evidence=_relocation_evidence(relocations),
                )
                self.assertEqual(plan.status, "incomplete")
                self.assertEqual(
                    plan.blockers[0]["category"], "x87_replay_aslr_unsafe"
                )
        for name, relocations in {
            "duplicate": [base, dict(base)],
            "overlap": [base, {**base, "source_rva": 0x1424}],
        }.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                with self.assertRaisesRegex(StageAInputError, "duplicate|overlap"):
                    plan_stage_b_native_engine(
                        state_machine=self._write(
                            root, [_absolute_x87_replay_transfer()]
                        ),
                        entry_rva=0x1420,
                        base_relocation_evidence=_relocation_evidence(relocations),
                    )

    def test_rejects_return_rva_not_matching_exact_instruction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x1431,
                "dll": "kernel32.dll",
                "symbol": "Sleep",
                "ordinal": None,
            })])
            plan = plan_stage_b_native_engine(
                state_machine=machine, entry_rva=0x1420
            )
            self.assertEqual(plan.status, "incomplete")
            self.assertEqual(plan.blockers[0]["category"], "external_return_rva_mismatch")

    def test_package_is_deterministic_and_marks_generation_only_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x1430,
                "dll": "kernel32.dll",
                "symbol": "Sleep",
                "ordinal": None,
            })])
            first = write_stage_b_native_engine_package(
                state_machine=machine, entry_rva=0x1420, out=root / "first"
            )
            second = write_stage_b_native_engine_package(
                state_machine=machine, entry_rva=0x1420, out=root / "second"
            )
            self.assertEqual(first["status"], "ready")
            self.assertIn("Stage A proof required", first["authority"])
            self.assertEqual(
                [item["sha256"] for item in first["sources"]],
                [item["sha256"] for item in second["sources"]],
            )
            assembly = (root / "first" / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            self.assertNotRegex(assembly, r"(?i)\bint3\b")
            self.assertIn("_stage_b_payload_entry:", assembly)
            self.assertIn("call _stage_b_native_run_entry", assembly)
            self.assertIn("pushfd", assembly)
            self.assertIn("popfd", assembly)
            self.assertIn("pushad", assembly)
            self.assertIn("popad", assembly)
            self.assertIn("mov DWORD PTR [esp], edx", assembly)
            self.assertIn("OFFSET FLAT:_stage_b_native_capture", assembly)
            self.assertIn(".globl _stage_b_native_bridge", assembly)
            self.assertIn(".globl _stage_b_native_capture", assembly)
            self.assertNotIn(".stgbcl", assembly)
            self.assertNotIn("_stage_b_native_bridge_0000", assembly)
            wrapper = (root / "first" / "native-engine-wrapper.c").read_text(
                encoding="ascii"
            )
            self.assertIn("stage_b_native_runtime_run_at_rva(", wrapper)
            self.assertNotIn("static stage_b_runtime", wrapper)
            self.assertNotIn("stage_b_native_read(", wrapper)
            self.assertIn("stage_b_native_original_iat_target", wrapper)
            self.assertIn("frame.call_target", wrapper)
            self.assertIn("frame.parent = stage_b_native_active_bridge", wrapper)
            self.assertIn("stage_b_native_active_bridge = frame.parent", wrapper)
            self.assertIn("offsetof(stage_b_machine_state, eflags) == 240U", wrapper)
            layout = (root / "first" / "native-engine-layout.c").read_text(
                encoding="ascii"
            )
            self.assertIn("stage_b_engine_layout_table", layout)
            self.assertIn("x87_stack[7].value_bytes", layout)
            self.assertIn("x87_stack[7].empty", layout)
            self.assertIn("offsetof(stage_b_machine_state, eflags)", layout)

    @unittest.skipUnless(
        shutil.which("i686-w64-mingw32-gcc")
        and shutil.which("i686-w64-mingw32-nm"),
        "i686 MinGW compiler and nm are unavailable",
    )
    def test_generated_sources_compile_and_link_as_freestanding_pe32(self) -> None:
        compiler = shutil.which("i686-w64-mingw32-gcc")
        nm = shutil.which("i686-w64-mingw32-nm")
        assert compiler is not None and nm is not None
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x1430,
                "dll": "kernel32.dll",
                "symbol": "Sleep",
                "ordinal": None,
            })])
            package = root / "package"
            result = write_stage_b_native_engine_package(
                state_machine=machine,
                entry_rva=0x1420,
                callback_targets=[{
                    "rva": 0x1420,
                    "kind": "tls_callback",
                    "stack_cleanup_bytes": 12,
                }],
                out=package,
            )
            self.assertEqual(result["status"], "ready", result)
            (package / "state-machine-runtime.h").write_text(
                _RUNTIME_HEADER, encoding="ascii"
            )
            stub = package / "semantic-stub.c"
            stub.write_text(
                """#include \"native-engine-wrapper.h\"
stage_b_runtime stage_b_native_runtime_instance;
stage_b_call_status stage_b_native_runtime_run_at_rva(
    uint32_t entry_rva,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)entry_rva;
  *output = *input;
  return STAGE_B_CALL_OK;
}
stage_b_call_status stage_b_native_runtime_run_nested_callback(
    uint32_t callback_rva, uint32_t stack_cleanup_bytes,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)callback_rva;
  *output = *input;
  output->esp += 4U + stack_cleanup_bytes;
  return STAGE_B_CALL_OK;
}
""",
                encoding="ascii",
            )
            sources = (
                package / "native-engine-bridges.S",
                package / "native-engine-wrapper.c",
                package / "native-engine-layout.c",
                stub,
            )
            objects: list[Path] = []
            for index, source in enumerate(sources):
                target = package / f"{index}.o"
                command = [
                    compiler,
                    "-std=c11",
                    "-Os",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-ffreestanding",
                    "-fno-builtin",
                    "-I",
                    str(package),
                    "-c",
                    str(source),
                    "-o",
                    str(target),
                ]
                subprocess.run(command, check=True, text=True, capture_output=True)
                objects.append(target)
            payload = package / "payload.exe"
            subprocess.run(
                [
                    compiler,
                    "-nostdlib",
                    "-Wl,--entry,_stage_b_payload_entry",
                    "-Wl,--subsystem,console",
                    "-Wl,--dynamicbase",
                    "-Wl,--enable-reloc-section",
                    "-Wl,--disable-auto-import",
                    "-Wl,--disable-runtime-pseudo-reloc",
                    "-Wl,--no-insert-timestamp",
                    *(str(path) for path in objects),
                    "-o",
                    str(payload),
                ],
                check=True,
                text=True,
                capture_output=True,
            )
            symbols = subprocess.run(
                [nm, str(payload)], check=True, text=True, capture_output=True
            ).stdout
            self.assertRegex(
                symbols, re.compile(r"(?m)^[0-9a-fA-F]+ T _stage_b_payload_entry$")
            )
            self.assertRegex(
                symbols,
                re.compile(
                    r"(?m)^[0-9a-fA-F]+ T _?stage_b_payload_callback_00001420$"
                ),
            )

    @unittest.skipUnless(
        shutil.which("i686-w64-mingw32-gcc")
        and shutil.which("i686-w64-mingw32-nm"),
        "i686 MinGW compiler and nm are unavailable",
    )
    def test_relocated_x87_replay_links_one_payload_highlow(self) -> None:
        compiler = shutil.which("i686-w64-mingw32-gcc")
        nm = shutil.which("i686-w64-mingw32-nm")
        assert compiler is not None and nm is not None
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_absolute_x87_replay_transfer()])
            package = root / "package"
            result = write_stage_b_native_engine_package(
                state_machine=machine,
                entry_rva=0x1420,
                base_relocation_evidence=_relocation_evidence(),
                out=package,
            )
            self.assertEqual(result["status"], "ready", result)
            assembly = (package / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            replay_bridge = assembly.split(
                "_stage_b_native_x87_bridge_0000:", maxsplit=1
            )[1].split("_stage_b_native_x87_capture_0000:", maxsplit=1)[0]
            self.assertNotIn("popad", replay_bridge)
            for instruction in (
                "mov ebx, DWORD PTR [eax + 4]",
                "mov ecx, DWORD PTR [eax + 8]",
                "mov edx, DWORD PTR [eax + 12]",
                "mov esi, DWORD PTR [eax + 16]",
                "mov edi, DWORD PTR [eax + 20]",
                "mov ebp, DWORD PTR [eax + 24]",
                "mov esp, DWORD PTR [eax + 28]",
                "push DWORD PTR [eax + 240]",
                "push DWORD PTR [eax + 0]",
            ):
                self.assertIn(instruction, replay_bridge)
            replay_capture = assembly.split(
                "_stage_b_native_x87_capture_0000:", maxsplit=1
            )[1].split("_stage_b_native_x87_return_0000:", maxsplit=1)[0]
            for instruction in (
                "sets BYTE PTR [edx + 40]",
                "seto BYTE PTR [edx + 44]",
                "and ecx, 0xfffff32a",
                "and ebx, 0x00000cd5",
            ):
                self.assertIn(instruction, replay_capture)
            (package / "state-machine-runtime.h").write_text(
                _x87_runtime_header(), encoding="ascii"
            )
            stub = package / "semantic-stub.c"
            stub.write_text(
                """#include "native-engine-wrapper.h"
stage_b_runtime stage_b_native_runtime_instance;
stage_b_call_status stage_b_native_runtime_run_at_rva(
    uint32_t rva, const stage_b_machine_state *input,
    stage_b_machine_state *output) {
  (void)rva; *output = *input; return STAGE_B_CALL_OK;
}
stage_b_call_status stage_b_native_runtime_run_nested_callback(
    uint32_t rva, uint32_t cleanup, const stage_b_machine_state *input,
    stage_b_machine_state *output) {
  (void)rva; *output = *input; output->esp += 4U + cleanup;
  return STAGE_B_CALL_OK;
}
""",
                encoding="ascii",
            )
            sources = (
                package / "native-engine-bridges.S",
                package / "native-engine-wrapper.c",
                package / "native-engine-layout.c",
                stub,
            )
            objects: list[Path] = []
            for index, source in enumerate(sources):
                target = package / f"relocated-{index}.o"
                subprocess.run(
                    [
                        compiler,
                        "-std=c11",
                        "-Os",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-ffreestanding",
                        "-fno-builtin",
                        "-I",
                        str(package),
                        "-c",
                        str(source),
                        "-o",
                        str(target),
                    ],
                    check=True,
                    text=True,
                    capture_output=True,
                )
                objects.append(target)
            payload = package / "relocated-x87.exe"
            subprocess.run(
                [
                    compiler,
                    "-nostdlib",
                    "-Wl,--entry,_stage_b_payload_entry",
                    "-Wl,--subsystem,console",
                    "-Wl,--dynamicbase",
                    "-Wl,--enable-reloc-section",
                    "-Wl,--disable-auto-import",
                    "-Wl,--disable-runtime-pseudo-reloc",
                    "-Wl,--no-insert-timestamp",
                    *(str(path) for path in objects),
                    "-o",
                    str(payload),
                ],
                check=True,
                text=True,
                capture_output=True,
            )
            symbols = subprocess.run(
                [nm, str(payload)], check=True, text=True, capture_output=True
            ).stdout
            match = re.search(
                r"(?m)^([0-9a-fA-F]+) T _stage_b_native_x87_instruction_0000$",
                symbols,
            )
            self.assertIsNotNone(match)
            assert match is not None
            pe = pefile.PE(str(payload))
            try:
                image_base = int(pe.OPTIONAL_HEADER.ImageBase)
                instruction_rva = int(match.group(1), 16) - image_base
                relocation_rva = instruction_rva + 2
                highlow_rvas = {
                    int(block.struct.VirtualAddress) + int(entry.rva) % 0x1000
                    for block in pe.DIRECTORY_ENTRY_BASERELOC
                    for entry in block.entries
                    if int(entry.type) == 3
                }
                self.assertIn(relocation_rva, highlow_rvas)
                self.assertEqual(
                    int.from_bytes(pe.get_data(relocation_rva, 4), "little"),
                    image_base + 0x1234,
                )
            finally:
                pe.close()


if __name__ == "__main__":
    unittest.main()
