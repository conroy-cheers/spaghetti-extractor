from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.stage_b_interpreter_backend import (
    write_stage_b_interpreter_package,
)
from spaghetti_extractor.stage_b_native_engine import (
    write_stage_b_native_engine_package,
)
from spaghetti_extractor.stage_b_native_runtime import (
    DEFINEDNESS_USE_FORMAT,
    StageBNativeRuntimeError,
    plan_stage_b_native_runtime,
    write_stage_b_native_runtime_package,
)
from spaghetti_extractor.util import sha256_bytes, sha256_file


_CONTRACT_SHA256 = "a" * 64
_INSTRUCTION_SHA256 = "b" * 64


def _transfer(rva: int = 0x1000) -> dict[str, object]:
    return {
        "id": f"semantic-transfer:{rva:08x}",
        "contract_sha256": _CONTRACT_SHA256,
        "instruction_bytes_sha256": _INSTRUCTION_SHA256,
        "original": {"rva_start": rva, "rva_end": rva + 1, "size": 1},
        "instructions": [],
        "ordered_events": [],
        "register_writes": [],
        "flag_writes": [],
        "fpu_state": None,
        "outcome": {"kind": "return", "value": {"op": "reg", "name": "eax"}},
    }


def _write_state_machine(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def _packages(
    root: Path,
    rows: list[dict[str, object]] | None = None,
    *,
    callback_targets: list[dict[str, object]] | None = None,
    import_iat_vas: dict[tuple[str, str], int] | None = None,
    machine_ir: bool = False,
    modeled_termination: bool = False,
) -> tuple[Path, Path]:
    semantic_input = root / (
        "machine-ir.jsonl" if machine_ir else "state-machine.jsonl"
    )
    _write_state_machine(semantic_input, rows or [_transfer()])
    interpreter = root / "interpreter"
    engine = root / "engine"
    interpreter_input = (
        {"machine_ir": semantic_input}
        if machine_ir
        else {"state_machine": semantic_input}
    )
    write_stage_b_interpreter_package(**interpreter_input, out=interpreter)
    engine_input = (
        {"machine_ir": semantic_input}
        if machine_ir
        else {"state_machine": semantic_input}
    )
    write_stage_b_native_engine_package(
        **engine_input,
        entry_rva=0x1000,
        callback_targets=callback_targets or [],
        import_iat_vas=(
            import_iat_vas
            if import_iat_vas is not None
            else {("msvcrt.dll", "_amsg_exit"): 0x4321D8}
            if modeled_termination
            else None
        ),
        termination_import=(
            {
                "dll": "msvcrt.dll",
                "symbol": "_amsg_exit",
                "disposition": "terminates",
            }
            if modeled_termination
            else None
        ),
        out=engine,
    )
    return interpreter, engine


def _stable_slot(value: str) -> int:
    result = 2166136261
    for byte in value.encode("utf-8"):
        result = ((result ^ byte) * 16777619) & 0xFFFFFFFF
    return result


def _undefined_transfer() -> dict[str, object]:
    row = _transfer()
    row["outcome"] = {
        "kind": "return",
        "value": {
            "op": "undefined_bv",
            "width": 32,
            "reason": "fixture",
            "id": "fixture:undefined:eax",
        },
    }
    return row


def _internal_indirect_rows() -> list[dict[str, object]]:
    registers = {
        name: {"op": "reg", "name": name}
        for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    }
    flags = {
        name: {"op": "flag", "name": name}
        for name in ("cf", "zf", "sf", "of", "pf", "df")
    }
    source = _transfer(0x1000)
    encoded = bytes.fromhex("ffd3")
    source.update({
        "instruction_bytes_sha256": sha256_bytes(encoded),
        "original": {"rva_start": 0x1000, "rva_end": 0x1002, "size": 2},
        "instructions": [{
            "rva": 0x1000,
            "size": 2,
            "bytes": encoded.hex(),
            "mnemonic": "call",
            "op_str": "ebx",
        }],
        "ordered_events": [{
            "family": "external",
            "kind": "indirect_call",
            "instruction_rva": 0x1000,
            "return_rva": 0x1002,
            "target": {"op": "reg", "name": "ebx"},
            "register_inputs": registers,
            "flag_inputs": flags,
            "arguments": [],
            "stack_inputs": [],
        }],
    })
    return [source, _transfer(0x2000)]


def _internal_tail_import_rows() -> list[dict[str, object]]:
    registers = {
        name: {"op": "reg", "name": name}
        for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    }
    flags = {
        name: {"op": "flag", "name": name}
        for name in ("cf", "zf", "sf", "of", "pf", "df")
    }
    caller = _transfer(0x1000)
    caller_bytes = bytes.fromhex("e8fb0f0000")
    caller.update({
        "instruction_bytes_sha256": sha256_bytes(caller_bytes),
        "original": {"rva_start": 0x1000, "rva_end": 0x1005, "size": 5},
        "instructions": [{
            "rva": 0x1000,
            "size": 5,
            "bytes": caller_bytes.hex(),
            "mnemonic": "call",
            "op_str": "0x2000",
        }],
        "ordered_events": [{
            "family": "external",
            "kind": "internal_call",
            "instruction_rva": 0x1000,
            "return_rva": 0x1005,
            "target_rva": 0x2000,
            "register_inputs": registers,
            "flag_inputs": flags,
            "arguments": [],
            "stack_inputs": [],
        }],
    })
    thunk = _transfer(0x2000)
    thunk_bytes = bytes.fromhex("ff259c214300")
    thunk.update({
        "instruction_bytes_sha256": sha256_bytes(thunk_bytes),
        "original": {"rva_start": 0x2000, "rva_end": 0x2006, "size": 6},
        "instructions": [{
            "rva": 0x2000,
            "size": 6,
            "bytes": "ff259c214300",
            "mnemonic": "jmp",
            "op_str": "dword ptr [0x43219c]",
        }],
        "ordered_events": [{
            "family": "external",
            "kind": "external_call",
            "instruction_rva": 0x2000,
            "return_rva": 0x2006,
            "dll": "kernel32.dll",
            "symbol": "Sleep",
            "ordinal": None,
            "register_inputs": registers,
            "flag_inputs": flags,
            "arguments": [],
            "stack_inputs": [],
        }],
        "outcome": {
            "kind": "external_jump",
            "dll": "kernel32.dll",
            "symbol": "Sleep",
        },
    })
    return [caller, thunk]


def _external_result_rows() -> list[dict[str, object]]:
    registers = {
        name: {"op": "reg", "name": name}
        for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    }
    flags = {
        name: {"op": "flag", "name": name}
        for name in ("cf", "zf", "sf", "of", "pf", "df")
    }
    row = _transfer(0x1000)
    encoded = bytes.fromhex("ff159c214300")
    row.update({
        "instruction_bytes_sha256": sha256_bytes(encoded),
        "original": {"rva_start": 0x1000, "rva_end": 0x1006, "size": 6},
        "instructions": [{
            "rva": 0x1000,
            "size": 6,
            "bytes": encoded.hex(),
            "mnemonic": "call",
            "op_str": "dword ptr [0x43219c]",
        }],
        "ordered_events": [{
            "family": "external",
            "kind": "external_call",
            "instruction_rva": 0x1000,
            "return_rva": 0x1006,
            "dll": "msvcrt.dll",
            "symbol": "__p__commode",
            "ordinal": None,
            "register_inputs": registers,
            "flag_inputs": flags,
            "arguments": [],
            "stack_inputs": [],
        }],
    })
    return [row]


def _machine_ir_indirect_external_result_rows() -> list[dict[str, object]]:
    registers = {
        name: {"op": "reg", "name": name, "width": 32}
        for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    }
    flags = {
        name: {"op": "flag", "name": name}
        for name in ("cf", "zf", "sf", "of", "pf", "df")
    }
    event = {
        "family": "external",
        "kind": "indirect_call",
        "instruction_rva": 0x1000,
        "return_rva": 0x1006,
        "target": {
        "op": "load",
        "width": 4,
        "address": {"op": "const", "width": 32, "value": 0x43219C},
        },
        "register_inputs": registers,
        "flag_inputs": flags,
        "stack_inputs": [],
    }
    return [{
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": "semantic-transfer:typed-00001000",
        "status": "qualified",
        "source": {
            "original": {"rva_start": 0x1000, "rva_end": 0x1006, "size": 6},
            "contract_sha256": _CONTRACT_SHA256,
            "instruction_bytes_sha256": _INSTRUCTION_SHA256,
            "semantic_export": None,
        },
        "instructions": [{
            "rva_start": 0x1000,
            "rva_end": 0x1006,
            "size": 6,
            "instruction_sha256": _INSTRUCTION_SHA256,
            "mnemonic": "call",
            "operands": [],
            "registers_read": [],
            "registers_written": [],
            "groups": ["call"],
        }],
        "x87_micro_ops": [],
        "semantics": {
            "pre_state": {},
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": [event],
            "faults": [],
            "ordered_events": [event],
            "edge_conditions": [],
            "outcome": {"kind": "fallthrough", "target_rva": 0x1006},
            "stack_delta": 0,
            "counts": {},
            "fpu_state": None,
            "instruction_effect_schedule": None,
        },
    }]


def _write_external_profile(path: Path, *, size_kind: str = "fixed") -> None:
    size: dict[str, object] = {"kind": size_kind, "bytes": 4}
    path.write_text(json.dumps({
        "format": "stage-a-external-environment-profile-v1",
        "id": "fixture-external-range-profile-v1",
        "machine_import_call_contracts": [{
            "id": "fixture-commode-range",
            "import": {"dll": "msvcrt.dll", "symbol": "__p__commode"},
            "result_register_relations": [{
                "register": "eax",
                "relation": "dynamic_range_base",
                "size": size,
                "minimum_size": 4,
                "nullable": False,
            }],
            "world_effect": "dynamicRanges",
        }],
    }, sort_keys=True), encoding="utf-8")


def _qualified_x87_transfer() -> dict[str, object]:
    encoded = bytes.fromhex("d9e8")
    digest = sha256_bytes(encoded)
    row = _transfer()
    row.update({
        "instruction_bytes_sha256": digest,
        "original": {"rva_start": 0x1000, "rva_end": 0x1002, "size": 2},
        "instructions": [{
            "rva": 0x1000,
            "size": 2,
            "bytes": encoded.hex(),
            "mnemonic": "fld1",
            "op_str": "",
        }],
        "outcome": {"kind": "fallthrough", "target_rva": 0x1002},
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
                "checked_decoder": "StageA.Formal.decodeInstructionExact",
                "checked_executor": "StageA.Formal.executeInstruction",
                "architecture": "x86",
                "bitness": 32,
                "image_base": 0x400000,
                "rva_start": 0x1000,
                "rva_end": 0x1002,
                "bytes": encoded.hex(),
                "bytes_sha256": digest,
                "instructions": [{
                    "rva": 0x1000, "size": 2, "bytes": encoded.hex()
                }],
            },
        },
    })
    return row


def _attach_definedness_metadata(
    interpreter: Path,
    *,
    classification: str,
    include_defined_value: bool = False,
) -> int:
    program_path = interpreter / "state-machine-interpreter-program.json"
    program = json.loads(program_path.read_text(encoding="utf-8"))
    slot = _stable_slot("fixture:undefined:eax")
    undefined_id = "fixture:undefined:eax"
    obligations = (
        [{
            "kind": "fault_dominance",
            "transfer_id": "semantic-transfer:00001000",
            "rva_start": 0x1000,
            "json_pointer": "/register_writes/0/value",
            "detail": "fixture exact fault dominance",
        }]
        if classification == "unconstrained_conditionally_noninterfering"
        else []
    )
    if classification in {
        "unconstrained_noninterfering",
        "unconstrained_conditionally_noninterfering",
    }:
        witness_policy = "zero"
        choice_source = {
            "format": "stage-a-definedness-choice-source-v1",
            "kind": "noninterfering_zero",
            "slot": slot,
            "undefined_id": undefined_id,
            "requires_semantic_obligations": bool(obligations),
        }
    elif classification == "synchronized_behavior_relevant":
        witness_policy = "synchronized"
        input_expression = {
            "op": "reg",
            "name": "eax",
            "width": 32,
        }
        choice_source = {
            "format": "stage-a-definedness-choice-source-v3",
            "kind": "related_machine_input",
            "slot": slot,
            "undefined_id": undefined_id,
            "profile": "ia32-bsr-zero-preserves-destination-v1",
            "instruction_rva": 0x1000,
            "instruction_bytes": "0fbdc0",
            "location": {"family": "register", "name": "eax"},
            "input_expression": input_expression,
            "input_expression_sha256": sha256_bytes(
                json.dumps(
                    input_expression,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("ascii")
            ),
        }
    else:
        witness_policy = None
        choice_source = None
    program["counts"]["undefined_nodes"] = 1
    metadata = {
        "format": DEFINEDNESS_USE_FORMAT,
        "status": "complete",
        "proof_authority": False,
        "state_machine_sha256": program["state_machine_sha256"],
        "definedness_evidence_sha256": "c" * 64,
        "transfer_inventory_sha256": sha256_bytes(
            json.dumps(
                program["transfers"],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ),
        "undefined_node_count": 1,
        "slots": [{
            "slot": slot,
            "undefined_id": undefined_id,
            "classification": classification,
            "witness_policy": witness_policy,
            "choice_source": choice_source,
            "proof_obligations": obligations,
            "uses": [{
                "transfer_id": "semantic-transfer:00001000",
                "node_index": 0,
                "op": "undefined_bv",
                **(
                    {"defined_value_node": 1}
                    if (
                        classification == "synchronized_behavior_relevant"
                        or include_defined_value
                    )
                    else {}
                ),
            }],
        }],
    }
    metadata["metadata_sha256"] = sha256_bytes(
        json.dumps(
            metadata,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    )
    program["definedness_use"] = metadata
    program_path.write_text(
        json.dumps(program, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    manifest_path = interpreter / "state-machine-interpreter-package.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["program"]["sha256"] = sha256_file(program_path)
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return slot


class StageBNativeRuntimeTests(unittest.TestCase):
    def test_external_result_ranges_are_profile_bound_and_generic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root, rows=_external_result_rows())
            profile = root / "external-profile.json"
            _write_external_profile(profile)
            package = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                external_profile=profile,
                out=root / "runtime",
            )

            rules = package["inputs"]["external_range_contracts"]["rules"]
            self.assertEqual(len(rules), 1)
            self.assertEqual(rules[0]["instruction_rva"], 0x1000)
            self.assertEqual(rules[0]["action"], "add_result_range")
            self.assertEqual(rules[0]["register"], "eax")
            source = (root / "runtime/native-runtime.c").read_text(encoding="ascii")
            self.assertIn("STAGE_B_NATIVE_MAX_EXTERNAL_RANGES 8192U", source)
            self.assertIn("stage_b_native_inside_external_range", source)
            self.assertIn("stage_b_native_runtime_record_external_result", source)
            self.assertNotIn("__p__commode", source)

    def test_iat_loaded_dynamic_call_uses_the_same_result_range_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(
                root,
                rows=_machine_ir_indirect_external_result_rows(),
                import_iat_vas={("msvcrt.dll", "__p__commode"): 0x43219C},
                machine_ir=True,
            )
            profile = root / "external-profile.json"
            _write_external_profile(profile)

            package = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                external_profile=profile,
                out=root / "runtime",
            )

            plan = json.loads(
                (engine / "native-engine-plan.json").read_text(encoding="utf-8")
            )
            self.assertEqual(plan["external_sites"][0]["site_kind"], "dynamic_target")
            self.assertEqual(plan["external_sites"][0]["import"], {
                "dll": "msvcrt.dll",
                "symbol": "__p__commode",
                "ordinal": None,
            })
            self.assertEqual(plan["external_sites"][0]["iat_va"], 0x43219C)
            rules = package["inputs"]["external_range_contracts"]["rules"]
            self.assertEqual(len(rules), 1)
            self.assertEqual(rules[0]["action"], "add_result_range")
            self.assertEqual(rules[0]["instruction_rva"], 0x1000)

    def test_external_result_range_rejects_unknown_size_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root, rows=_external_result_rows())
            profile = root / "external-profile.json"
            _write_external_profile(profile, size_kind="unknown")
            with self.assertRaisesRegex(
                StageBNativeRuntimeError, "unsupported range size"
            ):
                plan_stage_b_native_runtime(
                    interpreter_package=interpreter,
                    native_engine_package=engine,
                    external_profile=profile,
                )

    def test_package_binds_both_manifests_and_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root)
            first = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=root / "first",
            )
            second = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=root / "second",
            )

            self.assertEqual(first, second)
            self.assertEqual(first["status"], "ready")
            self.assertFalse(first["acceptance_authority"])
            self.assertEqual(
                first["counts"],
                {"transfers": 1, "callable_external_routes": 0},
            )
            self.assertEqual(first["inputs"]["entry_rva"], 0x1000)
            self.assertEqual(first["inputs"]["transfer_rvas"], [0x1000])
            for name in ("native-runtime.h", "native-runtime.c"):
                self.assertEqual(
                    (root / "first" / name).read_bytes(),
                    (root / "second" / name).read_bytes(),
                )

    def test_generated_runtime_is_generic_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root)
            package = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=root / "runtime",
            )
            source = (root / "runtime/native-runtime.c").read_text(encoding="ascii")
            header = (root / "runtime/native-runtime.h").read_text(encoding="ascii")

            self.assertIn("stage_b_native_flat_read", source)
            self.assertIn("stage_b_native_flat_write", source)
            self.assertIn("stage_b_native_atomic_compare_exchange", source)
            self.assertIn("stage_b_runtime_atomic_compare_exchange", source)
            self.assertIn("stage_b_native_atomic_exchange", source)
            self.assertIn("stage_b_runtime_atomic_exchange", source)
            self.assertIn(
                ".atomic_compare_exchange = "
                "stage_b_native_atomic_compare_exchange",
                source,
            )
            self.assertIn(
                ".atomic_exchange = stage_b_native_atomic_exchange",
                source,
            )
            self.assertIn("__atomic_compare_exchange_n", source)
            self.assertIn("__atomic_exchange_n", source)
            self.assertIn("STAGE_B_NATIVE_IMAGE_SCN_MEM_EXECUTE", source)
            self.assertIn("stage_b_native_transfer_rvas", source)
            self.assertIn("stage_b_program_lookup(rva)", source)
            self.assertIn("target_word - context->image_base", source)
            self.assertIn("STAGE_B_NATIVE_TERMINAL_UNDEFINED_VALUE", source)
            self.assertIn("context->undefined_fault = 1U", source)
            self.assertNotIn(
                "stage_b_native_halt(STAGE_B_NATIVE_TERMINAL_UNDEFINED_VALUE)",
                source,
            )
            self.assertIn("__sync_lock_test_and_set", source)
            self.assertIn("stage_b_run_function(", source)
            self.assertIn("stage_b_native_runtime_run_at_rva(", source)
            self.assertIn("stage_b_native_runtime_run_nested_callback(", source)
            self.assertIn("stage_b_runtime stage_b_native_runtime_instance", source)
            self.assertNotIn("static stage_b_runtime stage_b_native_runtime", source)
            self.assertNotIn("stage_b_native_replay_checked_x87_command", source)
            self.assertIn(
                "stage_b_native_terminate(stage_b_native_terminal_status)", source
            )
            self.assertIn("__attribute__((noreturn))", header)
            self.assertNotIn("hello", source.lower())
            self.assertNotIn("ExitProcess", source)
            self.assertEqual(
                package["policy"]["terminal_control"],
                "record-status-and-unsupported-native-halt",
            )
            self.assertTrue(
                package["inputs"]["runtime_abi"][
                    "atomic_compare_exchange_handler"
                ]
            )
            self.assertTrue(
                package["inputs"]["runtime_abi"]["atomic_exchange_handler"]
            )

    def test_modeled_termination_and_root_callback_buffers_are_emitted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(
                root,
                rows=[_transfer(0x1000), _transfer(0x2000)],
                callback_targets=[{
                    "rva": 0x2000,
                    "kind": "tls_callback",
                    "stack_cleanup_bytes": 12,
                }],
                modeled_termination=True,
            )
            runtime = root / "runtime"
            package = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=runtime,
            )

            plan = json.loads(
                (engine / "native-engine-plan.json").read_text(encoding="utf-8")
            )
            engine_package = json.loads(
                (engine / "native-engine-package.json").read_text(encoding="utf-8")
            )
            assembly = (engine / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            self.assertEqual(
                plan["termination_import"],
                {
                    "argument_source": "cdecl-stack-word-0-from-eax",
                    "dll": "msvcrt.dll",
                    "iat_va": 0x4321D8,
                    "ordinal": None,
                    "required_disposition": "terminates",
                    "symbol": "_amsg_exit",
                    "transfer": "tail_jump",
                },
            )
            self.assertIn("jmp DWORD PTR ds:0x004321d8", assembly)
            self.assertNotIn("ud2", assembly)
            self.assertIn("_stage_b_native_entry_dispatch_return:", assembly)
            self.assertIn("_stage_b_native_entry_return:", assembly)
            self.assertIn("_stage_b_native_termination:", assembly)
            self.assertIn(
                "_stage_b_native_callback_dispatch_return_00002000:",
                assembly,
            )
            self.assertIn(
                "mov edx, OFFSET FLAT:_stage_b_native_launch_state", assembly
            )
            self.assertIn(
                "mov ebx, OFFSET FLAT:_stage_b_native_launch_output", assembly
            )
            self.assertIn(
                "mov DWORD PTR [edx + 248], 0x00001000", assembly
            )
            self.assertIn(
                "mov DWORD PTR [edx + 248], 0x00002000", assembly
            )
            self.assertIn(
                "mov DWORD PTR [edx + 44], ecx", assembly
            )
            self.assertEqual(
                engine_package["policy"]["nested_callback_engine_buffers"],
                "stack-local-requires-checked-runtime-frame",
            )
            self.assertEqual(
                plan["launch_wrapper_symbols"],
                {
                    "entry_dispatch_return":
                        "stage_b_native_entry_dispatch_return",
                    "entry_return": "stage_b_native_entry_return",
                    "termination": "stage_b_native_termination",
                    "callback_dispatch_returns": [
                        "stage_b_native_callback_dispatch_return_00002000"
                    ],
                },
            )
            self.assertEqual(
                package["policy"]["terminal_control"],
                "record-status-and-modeled-environment-termination",
            )

    def test_undefined_nodes_require_complete_hash_bound_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root, [_undefined_transfer()])
            program_path = interpreter / "state-machine-interpreter-program.json"
            program = json.loads(program_path.read_text(encoding="utf-8"))
            del program["definedness_use"]
            program_path.write_text(
                json.dumps(program, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            manifest_path = interpreter / "state-machine-interpreter-package.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["program"]["sha256"] = sha256_file(program_path)
            manifest_path.write_text(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                StageBNativeRuntimeError,
                "uses undefined_bv/undefined_flag but has no complete",
            ):
                plan_stage_b_native_runtime(
                    interpreter_package=interpreter,
                    native_engine_package=engine,
                )

    def test_qualified_unobserved_undefined_slot_uses_recorded_zero_witness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root, [_undefined_transfer()])
            slot = _attach_definedness_metadata(
                interpreter,
                classification="unconstrained_noninterfering",
            )
            package = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=root / "runtime",
            )
            definedness = package["inputs"]["definedness_use"]
            self.assertEqual(definedness["format"], DEFINEDNESS_USE_FORMAT)
            self.assertRegex(definedness["metadata_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(definedness["slots"], [{
                "slot": slot,
                "undefined_id": "fixture:undefined:eax",
                "classification": "unconstrained_noninterfering",
                "witness_policy": "zero",
                "choice_kind": "noninterfering_zero",
                "input_location": None,
                "obligation_count": 0,
                "use_count": 1,
            }])
            source = (root / "runtime/native-runtime.c").read_text(encoding="ascii")
            self.assertIn(f"{{ 0x{slot:08x}U, 0U, 0U }}", source)
            undefined_body = source.split(
                "static uint32_t stage_b_native_undefined_value", 1
            )[1].split("static uint32_t stage_b_native_resolve_code_target", 1)[0]
            self.assertIn("return 0U;", undefined_body)
            self.assertNotIn("stage_b_native_halt", undefined_body)

    def test_unknown_slot_latches_and_returns_unimplemented(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root, [_undefined_transfer()])
            slot = _attach_definedness_metadata(
                interpreter,
                classification="unknown",
                include_defined_value=True,
            )
            write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=root / "runtime",
            )
            source = (root / "runtime/native-runtime.c").read_text(encoding="ascii")
            self.assertIn(f"{{ 0x{slot:08x}U, 2U, 0U }}", source)
            self.assertIn("context->undefined_fault = 1U", source)
            self.assertIn(
                "if (context->undefined_fault != 0U) return STAGE_B_CALL_UNIMPLEMENTED;",
                source,
            )
            undefined_body = source.split(
                "static uint32_t stage_b_native_undefined_value", 1
            )[1].split("static uint32_t stage_b_native_resolve_code_target", 1)[0]
            self.assertNotIn("stage_b_native_halt", undefined_body)

    def test_synchronized_slot_uses_checked_machine_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root, [_undefined_transfer()])
            slot = _attach_definedness_metadata(
                interpreter, classification="synchronized_behavior_relevant"
            )
            package = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=root / "runtime",
            )
            self.assertEqual(
                package["inputs"]["definedness_use"]["slots"][0]["choice_kind"],
                "related_machine_input",
            )
            self.assertEqual(
                package["inputs"]["definedness_use"]["slots"][0]["input_location"],
                "eax",
            )
            source = (root / "runtime/native-runtime.c").read_text(encoding="ascii")
            self.assertIn(f"{{ 0x{slot:08x}U, 1U, 0U }}", source)
            undefined_body = source.split(
                "static uint32_t stage_b_native_undefined_value", 1
            )[1].split("static uint32_t stage_b_native_resolve_code_target", 1)[0]
            self.assertIn("return defined_value;", undefined_body)
            self.assertIn("context->undefined_fault = 1U", undefined_body)
            self.assertNotIn("undefined_choice_provider", source)

    def test_manifest_or_artifact_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root)
            (interpreter / "state-machine-program.c").write_text(
                "tampered\n", encoding="ascii"
            )

            with self.assertRaisesRegex(
                StageBNativeRuntimeError, "interpreter source .* SHA-256 mismatch"
            ):
                plan_stage_b_native_runtime(
                    interpreter_package=interpreter,
                    native_engine_package=engine,
                )

    @unittest.skipUnless(
        shutil.which("i686-w64-mingw32-gcc")
        and shutil.which("i686-w64-mingw32-nm"),
        "i686 MinGW compiler and nm are unavailable",
    )
    def test_internal_indirect_target_uses_authoritative_interpreter_runtime(self) -> None:
        compiler = shutil.which("i686-w64-mingw32-gcc")
        nm = shutil.which("i686-w64-mingw32-nm")
        assert compiler is not None and nm is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root, _internal_indirect_rows())
            runtime = root / "runtime"
            write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=runtime,
            )

            interpreter_source = (
                interpreter / "state-machine-interpreter.c"
            ).read_text(encoding="ascii")
            invoke = interpreter_source.split(
                "stage_b_call_status stage_b_invoke_call", 1
            )[1]
            resolve_index = invoke.index("resolve_code_target")
            indirect_invoke_index = invoke.index(
                "return stage_b_invoke_internal_call(", resolve_index
            )
            self.assertLess(resolve_index, indirect_invoke_index)
            self.assertLess(
                indirect_invoke_index,
                invoke.index("return stage_b_dispatch_external_call"),
            )
            self.assertIn("call_input.esp -= 4U;", interpreter_source)
            self.assertIn("event->return_rva, &memory_fault", interpreter_source)
            runtime_source = (runtime / "native-runtime.c").read_text(encoding="ascii")
            engine_source = (engine / "native-engine-wrapper.c").read_text(
                encoding="ascii"
            )
            self.assertIn("0x00002000U", runtime_source)
            self.assertIn(
                ".resolve_code_target = stage_b_native_resolve_code_target",
                runtime_source,
            )
            self.assertIn("stage_b_native_runtime_run_at_rva(", engine_source)
            self.assertIn("stage_b_native_read_allowed", runtime_source)
            self.assertIn("context->headers_size = headers_size;", runtime_source)
            self.assertIn("STAGE_B_NATIVE_TEB_READ_BYTES 0x1000U", runtime_source)
            self.assertIn("address >= context->owner_fs_base", runtime_source)
            self.assertNotIn("static stage_b_runtime", engine_source)
            self.assertNotIn(".resolve_code_target = 0", engine_source)

            sources = [
                interpreter / "state-machine-interpreter.c",
                interpreter / "state-machine-program.c",
                engine / "native-engine-bridges.S",
                engine / "native-engine-wrapper.c",
                engine / "native-engine-layout.c",
                runtime / "native-runtime.c",
            ]
            objects: list[Path] = []
            for index, source in enumerate(sources):
                target = root / f"unified-{index}.o"
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
                        "-mno-stack-arg-probe",
                        "-I",
                        str(interpreter),
                        "-I",
                        str(engine),
                        "-I",
                        str(runtime),
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
            payload = root / "unified-runtime.exe"
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
            self.assertEqual(
                len(re.findall(
                    r"(?m)^\S+ [BD] _stage_b_native_runtime_instance$", symbols
                )),
                1,
            )
            self.assertRegex(
                symbols,
                r"(?m)^\S+ T _stage_b_native_runtime_run_at_rva$",
            )
            self.assertRegex(
                symbols,
                r"(?m)^\S+ T _stage_b_native_runtime_run_nested_callback$",
            )
            self.assertEqual(
                len(re.findall(
                    r"(?m)^\S+ T _stage_b_dispatch_external_call$", symbols
                )),
                1,
            )
            self.assertNotIn("stage_b_native_replay_checked_x87_command", symbols)

    @unittest.skipUnless(
        shutil.which("i686-w64-mingw32-gcc")
        and shutil.which("i686-w64-mingw32-nm"),
        "i686 MinGW compiler and nm are unavailable",
    )
    def test_nonzero_x87_inventory_links_exactly_one_engine_handler(self) -> None:
        compiler = shutil.which("i686-w64-mingw32-gcc")
        nm = shutil.which("i686-w64-mingw32-nm")
        assert compiler is not None and nm is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root, [_qualified_x87_transfer()])
            runtime = root / "runtime"
            write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=runtime,
            )
            runtime_source = (runtime / "native-runtime.c").read_text(encoding="ascii")
            bridge_source = (engine / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            self.assertIn("mov WORD PTR [edx + 216], ax", bridge_source)
            self.assertIn("mov BYTE PTR [edx + 220], al", bridge_source)
            self.assertIn("mov WORD PTR [edx + 236], ax", bridge_source)
            self.assertIn("shr ecx, 11", bridge_source)
            self.assertIn("imul ecx, ecx, 10", bridge_source)
            self.assertIn(
                "extern stage_b_call_status stage_b_native_execute_typed_x87_operation",
                runtime_source,
            )
            self.assertIn(
                ".execute_typed_x87_operation = "
                "stage_b_native_execute_typed_x87_operation",
                runtime_source,
            )

            sources = [
                interpreter / "state-machine-interpreter.c",
                interpreter / "state-machine-program.c",
                engine / "native-engine-bridges.S",
                engine / "native-engine-wrapper.c",
                engine / "native-engine-layout.c",
                runtime / "native-runtime.c",
            ]
            objects: list[Path] = []
            for index, source in enumerate(sources):
                target = root / f"x87-{index}.o"
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
                        "-mno-stack-arg-probe",
                        "-I",
                        str(interpreter),
                        "-I",
                        str(engine),
                        "-I",
                        str(runtime),
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
            runtime_object_symbols = subprocess.run(
                [nm, str(objects[-1])], check=True, text=True, capture_output=True
            ).stdout
            self.assertRegex(
                runtime_object_symbols,
                r"(?m)^\s+U _stage_b_native_execute_typed_x87_operation$",
            )
            payload = root / "x87-runtime.exe"
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
            self.assertEqual(
                len(re.findall(
                    r"(?m)^\S+ T _stage_b_native_execute_typed_x87_operation$",
                    symbols,
                )),
                1,
            )
            self.assertEqual(
                len(re.findall(
                    r"(?m)^\S+ [BD] _stage_b_native_runtime_instance$", symbols
                )),
                1,
            )

    def test_typed_x87_inventory_rejects_reintroduced_instruction_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root, [_qualified_x87_transfer()])
            plan_path = engine / "native-engine-plan.json"
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            plan["x87_operations"][0]["instruction_bytes"] = "d9e8"
            plan_path.write_text(
                json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            manifest_path = engine / "native-engine-package.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["plan"]["sha256"] = sha256_file(plan_path)
            manifest_path.write_text(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                StageBNativeRuntimeError, "forbidden instruction payload"
            ):
                plan_stage_b_native_runtime(
                    interpreter_package=interpreter,
                    native_engine_package=engine,
                )

    @unittest.skipUnless(
        shutil.which("i686-w64-mingw32-gcc"),
        "i686 MinGW compiler is unavailable",
    )
    def test_internal_call_to_tail_import_thunk_links_without_callsite_shift(self) -> None:
        compiler = shutil.which("i686-w64-mingw32-gcc")
        assert compiler is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root, _internal_tail_import_rows())
            runtime = root / "runtime"
            write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=runtime,
            )
            plan = json.loads(
                (engine / "native-engine-plan.json").read_text(encoding="utf-8")
            )
            self.assertEqual(plan["status"], "ready", plan["blockers"])
            self.assertEqual(len(plan["external_sites"]), 1)
            self.assertEqual(plan["external_sites"][0]["instruction_rva"], 0x2000)
            self.assertEqual(plan["external_sites"][0]["disposition"], "tail_jump")
            assembly = (engine / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            self.assertIn("mov DWORD PTR [ecx - 4], ebx", assembly)
            self.assertIn("sub esp, 4", assembly)
            self.assertNotIn("add esp, 4", assembly)

            sources = [
                interpreter / "state-machine-interpreter.c",
                interpreter / "state-machine-program.c",
                engine / "native-engine-bridges.S",
                engine / "native-engine-wrapper.c",
                engine / "native-engine-layout.c",
                runtime / "native-runtime.c",
            ]
            objects: list[Path] = []
            for index, source in enumerate(sources):
                target = root / f"tail-{index}.o"
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
                        "-mno-stack-arg-probe",
                        "-I",
                        str(interpreter),
                        "-I",
                        str(engine),
                        "-I",
                        str(runtime),
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
                    str(root / "tail-runtime.exe"),
                ],
                check=True,
                text=True,
                capture_output=True,
            )

    def test_generated_source_compiles_as_freestanding_i686(self) -> None:
        compiler = shutil.which("i686-w64-mingw32-gcc")
        nm = shutil.which("i686-w64-mingw32-nm")
        if compiler is None or nm is None:
            self.skipTest("i686 MinGW compiler/nm is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root)
            runtime = root / "runtime"
            write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=runtime,
            )

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
                    str(runtime),
                    "-I",
                    str(interpreter),
                    "-c",
                    str(runtime / "native-runtime.c"),
                    "-o",
                    str(runtime / "native-runtime.o"),
                ],
                check=True,
                text=True,
                capture_output=True,
            )
            runtime_symbols = subprocess.run(
                [nm, str(runtime / "native-runtime.o")],
                check=True,
                text=True,
                capture_output=True,
            ).stdout
            self.assertNotIn("stage_b_native_replay_checked_x87_command", runtime_symbols)
            stub = runtime / "interpreter-stub.c"
            stub.write_text(
                """#include "native-runtime.h"
const stage_b_program_transfer *stage_b_program_lookup(uint32_t source_rva) {
  return source_rva == 0x1000U ? (const stage_b_program_transfer *)1 : 0;
}
stage_b_call_status stage_b_run_function(
    stage_b_runtime *runtime, uint32_t entry_rva,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)runtime;
  (void)entry_rva;
  *output = *input;
  return STAGE_B_CALL_OK;
}
stage_b_call_status stage_b_dispatch_external_call(
    stage_b_runtime *runtime, const stage_b_call_event *event,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)runtime;
  (void)event;
  *output = *input;
  return STAGE_B_CALL_UNIMPLEMENTED;
}
void stage_b_native_terminate(stage_b_native_terminal_kind status) {
  (void)status;
  for (;;) {}
}
""",
                encoding="ascii",
            )
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
                    str(runtime),
                    "-I",
                    str(interpreter),
                    "-c",
                    str(stub),
                    "-o",
                    str(runtime / "interpreter-stub.o"),
                ],
                check=True,
                text=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    compiler,
                    "-nostdlib",
                    "-Wl,--entry,_stage_b_native_runtime_coordinate",
                    "-Wl,--subsystem,console",
                    "-Wl,--disable-runtime-pseudo-reloc",
                    str(runtime / "native-runtime.o"),
                    str(runtime / "interpreter-stub.o"),
                    "-o",
                    str(runtime / "native-runtime.exe"),
                ],
                check=True,
                text=True,
                capture_output=True,
            )
            linked_symbols = subprocess.run(
                [nm, str(runtime / "native-runtime.exe")],
                check=True,
                text=True,
                capture_output=True,
            ).stdout
            self.assertEqual(
                len(re.findall(
                    r"(?m)^\S+ [BD] _stage_b_native_runtime_instance$",
                    linked_symbols,
                )),
                1,
            )


if __name__ == "__main__":
    unittest.main()
