from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.external.contracts import (
    ExternalSiteIdentity,
    checked_external_site_contract_from_event,
)
from spaghetti_extractor.external.machine_import_profiles import (
    load_machine_import_profile_set,
)
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.candidate.interpreter import (
    write_stage_b_interpreter_package,
)
from spaghetti_extractor.candidate.engine import (
    write_stage_b_native_engine_package,
)
from spaghetti_extractor.candidate.runtime import (
    DEFINEDNESS_USE_FORMAT,
    StageBNativeRuntimeError,
    plan_stage_b_native_runtime,
    write_stage_b_native_runtime_package,
)
from spaghetti_extractor.util import sha256_bytes, sha256_file
from tests.unit.candidate.native_engine._support import _canonical_external_sites


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
    selected_portable_components: list[dict[str, object]] | None = None,
    external_profile: Path | None = None,
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
    canonical_external_sites = None
    profiles: tuple[Path, ...] = ()
    if external_profile is not None:
        profiles = (external_profile,)
        selected = load_machine_import_profile_set(profiles)
        if len(selected.contracts) != 1:
            raise AssertionError("runtime fixture requires one selected import contract")
        selected_contract = selected.contracts[0]
        if selected_contract.argument_words is None:
            raise AssertionError("runtime fixture requires one fixed-arity import contract")
        fixture_units = rows or [_transfer()]
        event_candidates = [
            (unit, event)
            for unit in fixture_units
            for event in (
                unit["semantics"]["external_events"]
                if machine_ir
                else unit["ordered_events"]
            )
            if event.get("kind") in {
                "external_call", "external_jump", "indirect_call"
            }
        ]
        preferred = [pair for pair in event_candidates if pair[1].get("dll")]
        unit, event = (preferred or event_candidates)[0]
        imported = event if event.get("dll") else {
            "dll": selected_contract.identity.dll,
            (
                "symbol"
                if selected_contract.identity.kind == "symbol"
                else "ordinal"
            ): selected_contract.identity.value,
        }
        identity = ExternalSiteIdentity.imported(
            imported, context="native runtime fixture"
        )
        identity_payload = {
            "kind": "import",
            "dll": identity.dll,
            "symbol": identity.symbol,
            "ordinal": identity.ordinal,
        }
        resolved = dict(selected_contract.contract)
        resolved.update({
            "abi_template": resolved.get("abi_template", "pe32-cdecl-v1"),
            "arity": {
                "kind": "fixed",
                "words": selected_contract.argument_words,
            },
            "disposition": resolved.get("disposition", "returns"),
            "memory_effect": resolved.get("memory_effect", "relationalState"),
            "memory_footprints": resolved.get("memory_footprints", []),
            "world_effect": resolved.get("world_effect", "none"),
            "callback_effect": resolved.get("callback_effect", "none"),
            "profile_binding": {
                "profile_id": selected_contract.profile_id,
                "profile_sha256": selected_contract.profile_sha256,
                "entry_key": selected_contract.entry_key,
                "entry_index": selected_contract.entry_index,
            },
        })
        contract = checked_external_site_contract_from_event(
            event=event,
            identity=identity,
            transfer_kind=("jump" if event.get("kind") == "external_jump" else "call"),
            disposition=("tail_jump" if event.get("kind") == "external_jump" else "returns_here"),
            resolved_machine_contract=resolved,
            context="native runtime fixture",
        )
        canonical_external_sites = _canonical_external_sites(
            root,
            unit=unit,
            event_index=0,
            identity=identity_payload,
            contract=contract,
            event=event,
            unit_sha256=canonical_sha256_v3(unit),
        )
    write_stage_b_native_engine_package(
        **engine_input,
        entry_rva=0x1000,
        preferred_image_base=0x400000,
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
        selected_portable_components=selected_portable_components or [],
        machine_import_profiles=profiles,
        canonical_external_sites=canonical_external_sites,
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
    size: dict[str, object] = (
        {"kind": "argument", "argument": 1, "scale": 1}
        if size_kind == "argument"
        else {
            "kind": "bounded_zero_run",
            "unit_bytes": 2,
            "zero_units": 2,
            "max_units": 4096,
        }
        if size_kind == "bounded_zero_run"
        else {"kind": size_kind, "bytes": 4}
    )
    path.write_text(json.dumps({
        "format": "stage-a-external-environment-profile-v1",
        "id": "fixture-external-range-profile-v1",
        "machine_import_call_contracts": [{
            "id": "fixture-commode-range",
            "import": {"dll": "msvcrt.dll", "symbol": "__p__commode"},
            "argument_words": 2 if size_kind == "argument" else 0,
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


def _write_out_interface_profile(path: Path) -> None:
    path.write_text(json.dumps({
        "format": "stage-a-external-environment-profile-v1",
        "id": "fixture-out-interface-profile-v1",
        "machine_import_call_contracts": [{
            "id": "fixture-interface-factory",
            "import": {"dll": "msvcrt.dll", "symbol": "__p__commode"},
            "argument_words": 2,
            "out_interface_relations": [{
                "argument_index": 1,
                "interface_id": "IFixture",
                "write_width": 4,
                "object_size": 4,
                "vtable_size": 24,
                "nullable": True,
                "success_condition": "hresult_succeeded_eax",
            }],
            "world_effect": "opaqueResources",
        }],
    }, sort_keys=True), encoding="utf-8")


def _write_sleep_profile(path: Path) -> None:
    path.write_text(json.dumps({
        "format": "stage-a-external-environment-profile-v1",
        "id": "fixture-kernel32-sleep-profile-v1",
        "machine_import_call_contracts": [{
            "id": "fixture-kernel32-sleep",
            "import": {"dll": "kernel32.dll", "symbol": "Sleep"},
            "abi_template": "pe32-stdcall-v1",
            "arity": {"kind": "fixed", "words": 0},
            "disposition": "returns",
            "result_register_relations": [],
            "memory_effect": "readOnly",
            "memory_footprints": [],
            "world_effect": "none",
            "callback_effect": "none",
        }],
    }, sort_keys=True), encoding="utf-8")


def _callback_adapter_packages(root: Path) -> tuple[Path, Path, Path]:
    profile = root / "callback-profile.json"
    callback_source = {
        "kind": "argument_pointee",
        "argument": 0,
        "offset": 4,
    }
    callback_abi = {
        "kind": "generic_callback",
        "argument_words": 4,
        "stack_cleanup_bytes": 16,
        "nullable": False,
    }
    profile_contract = {
        "id": "fixture-register-class-a",
        "import": {"dll": "user32.dll", "symbol": "RegisterClassA"},
        "abi_template": "pe32-stdcall-v1",
        "arity": {"kind": "fixed", "words": 1},
        "disposition": "returns",
        "result_register_relations": [
            {"register": "eax", "relation": "exact"}
        ],
        "memory_effect": "readOnly",
        "memory_footprints": [{
            "access": "read",
            "base_argument": 0,
            "offset": 0,
            "size": {"kind": "fixed", "bytes": 40},
            "nullable": False,
        }],
        "world_effect": "callbackRegistration",
        "callback_effect": "explicit",
        "callback_source": callback_source,
        "callback_lifetime": "until_class_unregistered_or_process_exit",
        "callback_abi": callback_abi,
    }
    profile.write_text(json.dumps({
        "format": "stage-a-external-environment-profile-v1",
        "id": "fixture-callback-profile-v1",
        "machine_import_call_contracts": [profile_contract],
    }, sort_keys=True), encoding="utf-8")
    profile_binding = {
        "profile_id": "fixture-callback-profile-v1",
        "profile_sha256": sha256_file(profile),
        "entry_key": "machine_import_call_contracts",
        "entry_index": 0,
    }
    registers = {
        name: {"op": "reg", "name": name, "width": 32}
        for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    }
    flags = {
        name: {"op": "flag", "name": name}
        for name in ("cf", "zf", "sf", "of", "pf", "df")
    }
    argument = {"op": "reg", "name": "eax", "width": 32}
    event = {
        "family": "external",
        "kind": "external_call",
        "instruction_rva": 0x1000,
        "return_rva": 0x1006,
        "dll": "user32.dll",
        "symbol": "RegisterClassA",
        "ordinal": None,
        "arguments": [argument],
        "register_inputs": registers,
        "flag_inputs": flags,
        "stack_inputs": [{"offset": 0, "width": 4, "value": argument}],
        "abi_contract": {
            "template": "pe32-stdcall-v1",
            "argument_words": 1,
            "argument_base_offset": 0,
            "contract_id": "fixture-register-class-a",
            "profile_binding": profile_binding,
            "disposition": "returns",
            "result_register_relations": profile_contract[
                "result_register_relations"
            ],
            "memory_effect": "readOnly",
            "memory_footprints": [{
                "access": "read",
                "base_argument": 0,
                "offset": 0,
                "size": {"kind": "fixed", "byte_count": 40},
                "nullable": False,
            }],
            "world_effect": "callbackRegistration",
            "callback_effect": "explicit",
            "callback_source": callback_source,
            "callback_lifetime": "until_class_unregistered_or_process_exit",
            "callback_abi": callback_abi,
        },
    }

    def unit(rva: int, *, registration: bool) -> dict[str, object]:
        size = 6 if registration else 1
        ordered = [event] if registration else []
        return {
            "format": "stage-a-machine-ir-v2",
            "record_kind": "unit",
            "id": f"semantic-transfer:typed-{rva:08x}",
            "status": "qualified",
            "source": {
                "original": {"rva_start": rva, "rva_end": rva + size, "size": size},
                "contract_sha256": _CONTRACT_SHA256,
                "instruction_bytes_sha256": _INSTRUCTION_SHA256,
                "semantic_export": None,
            },
            "instructions": [{
                "rva_start": rva,
                "rva_end": rva + size,
                "size": size,
                "instruction_sha256": _INSTRUCTION_SHA256,
                "mnemonic": "call" if registration else "ret",
                "operands": [],
                "registers_read": [],
                "registers_written": [],
                "groups": ["call"] if registration else ["ret"],
            }],
            "x87_micro_ops": [],
            "semantics": {
                "pre_state": {},
                "register_writes": [],
                "flag_writes": [],
                "memory_events": [],
                "external_events": ordered,
                "faults": [],
                "ordered_events": ordered,
                "edge_conditions": [],
                "outcome": (
                    {"kind": "fallthrough", "target_rva": rva + size}
                    if registration
                    else {
                        "kind": "return",
                        "value": {"op": "reg", "name": "eax", "width": 32},
                    }
                ),
                "stack_delta": 0,
                "counts": {},
                "fpu_state": None,
                "instruction_effect_schedule": None,
            },
        }

    registration = unit(0x1000, registration=True)
    callback = unit(0x3000, registration=False)
    machine_ir = root / "callback-machine-ir.jsonl"
    _write_state_machine(machine_ir, [registration, callback])
    manifest = root / "callback-machine-ir-manifest.json"
    callback_evidence = {
        "format": "stage-a-callback-registration-provenance-v1",
        "record_kind": "callback_registration",
        "status": "complete",
        "unit_id": registration["id"],
        "event_index": 0,
        "instruction_rva": 0x1000,
        "callback_source": callback_source,
        "callback_abi": callback_abi,
        "callback_lifetime": "until_class_unregistered_or_process_exit",
        "callback_behavior": "registration",
        "target_rvas": [0x3000],
        "target_unit_ids": [callback["id"]],
        "failure": None,
    }
    manifest.write_text(json.dumps({
        "format": "stage-a-machine-ir-v2",
        "artifacts": {
            "machine_ir": {
                "format": "stage-a-machine-ir-v2",
                "sha256": sha256_file(machine_ir),
            },
        },
        "control": {
            "internal_call_preservation": {
                "fixed_point_complete": True,
                "summaries": [],
            },
            "external_interface_provenance": {
                "callback_registrations": [callback_evidence],
            },
        },
    }, sort_keys=True), encoding="utf-8")
    interpreter = root / "callback-interpreter"
    engine = root / "callback-engine"
    identity_payload = {
        "kind": "import",
        "dll": "user32.dll",
        "symbol": "RegisterClassA",
        "ordinal": None,
    }
    checked_contract = checked_external_site_contract_from_event(
        event=event,
        identity=ExternalSiteIdentity.imported(
            identity_payload, context="runtime callback fixture"
        ),
        transfer_kind="call",
        disposition="returns_here",
        callback_evidence=callback_evidence,
        context="runtime callback fixture",
    )
    canonical_external_sites = _canonical_external_sites(
        root,
        unit=registration,
        event_index=0,
        identity=identity_payload,
        contract=checked_contract,
        callback_target_rvas=(0x3000,),
    )
    write_stage_b_interpreter_package(machine_ir=machine_ir, out=interpreter)
    write_stage_b_native_engine_package(
        machine_ir=machine_ir,
        machine_ir_manifest=manifest,
        entry_rva=0x1000,
        fixed_image_base=0x400000,
        preferred_image_base=0x400000,
        import_iat_vas={("user32.dll", "RegisterClassA"): 0x432000},
        canonical_external_sites=canonical_external_sites,
        out=engine,
    )
    return interpreter, engine, profile


def _rewrite_callback_engine_plan(
    engine: Path, mutate: object
) -> None:
    plan_path = engine / "native-engine-plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert callable(mutate)
    mutate(plan)
    plan_path.write_text(
        json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    manifest_path = engine / "native-engine-package.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["plan"]["sha256"] = sha256_file(plan_path)
    manifest["callback_adapter_receipts"] = plan[
        "callback_adapter_receipts"
    ]
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _rehash_callback_receipt(receipt: dict[str, object]) -> None:
    body = {
        key: value
        for key, value in receipt.items()
        if key not in {"format", "receipt_sha256"}
    }
    receipt["receipt_sha256"] = sha256_bytes(
        json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    )


def _rehash_implementation_entry(entry: dict[str, object]) -> None:
    body = {key: value for key, value in entry.items() if key != "entry_sha256"}
    entry["entry_sha256"] = sha256_bytes(
        json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    )


def _rehash_implementation_receipt(receipt: dict[str, object]) -> None:
    body = {
        key: value
        for key, value in receipt.items()
        if key not in {"format", "receipt_sha256"}
    }
    receipt["receipt_sha256"] = sha256_bytes(
        json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    )


def _rewrite_implementation_engine_plan(engine: Path, mutate: object) -> None:
    plan_path = engine / "native-engine-plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    receipt = plan["implementation_dispatch_receipt"]
    assert callable(mutate)
    mutate(receipt)
    _rehash_implementation_receipt(receipt)
    plan_path.write_text(
        json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    manifest_path = engine / "native-engine-package.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["plan"]["sha256"] = sha256_file(plan_path)
    manifest["implementation_dispatch_receipt"] = receipt
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


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
        "evidence_slot_count": 1,
        "unused_evidence_slot_count": 0,
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


__all__ = tuple(name for name in globals() if not name.startswith("__"))
