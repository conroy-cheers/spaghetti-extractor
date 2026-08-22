from __future__ import annotations
import json
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.candidate.engine import write_spx_native_engine_package
from spaghetti_extractor.candidate.interpreter import write_spx_interpreter_package
from spaghetti_extractor.external.contracts import (
    ExternalSiteIdentity,
    checked_external_site_contract_from_event,
)
from spaghetti_extractor.util import sha256_bytes, sha256_file
from tests.unit.candidate.native_engine._support import (
    _canonical_callback_authority,
    _candidate_execution_artifacts,
    _canonical_external_sites,
)
from tests.unit.candidate.native_runtime._support import (
    _CONTRACT_SHA256,
    _INSTRUCTION_SHA256,
    _write_machine_ir,
)


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
        "format": "spaghetti-extractor-external-environment-profile-v1",
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
            "format": "spaghetti-extractor-machine-ir-v3",
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
            "control": {
                "kind": "fallthrough" if registration else "return",
                "direct_targets": [rva + size] if registration else [],
                "has_indirect_target": False,
            },
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
    continuation = unit(0x1006, registration=False)
    callback = unit(0x3000, registration=False)
    machine_ir = root / "callback-machine-ir.jsonl"
    registration, continuation, callback = _write_machine_ir(
        machine_ir, [registration, continuation, callback]
    )
    manifest = root / "callback-machine-ir-manifest.json"
    callback_evidence = {
        "format": "spaghetti-extractor-callback-registration-provenance-v1",
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
        "format": "spaghetti-extractor-machine-ir-v3",
        "artifacts": {
            "machine_ir": {
                "format": "spaghetti-extractor-machine-ir-v3",
                "sha256": sha256_file(machine_ir),
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
    write_spx_interpreter_package(machine_ir=machine_ir, out=interpreter)
    execution_authority = _candidate_execution_artifacts(
        root, units=[registration, continuation, callback]
    )
    callback_authority = _canonical_callback_authority(
        root,
        registration_unit=registration,
        event_index=0,
        identity=identity_payload,
        contract=checked_contract,
        target_units=(callback,),
    )
    write_spx_native_engine_package(
        machine_ir=machine_ir,
        machine_ir_manifest=manifest,
        entry_rva=0x1000,
        fixed_image_base=0x400000,
        preferred_image_base=0x400000,
        import_iat_vas={("user32.dll", "RegisterClassA"): 0x432000},
        canonical_external_sites=canonical_external_sites,
        callback_authority=callback_authority,
        root_closure=execution_authority[0],
        target_certificates=execution_authority[1],
        parametric_summaries=execution_authority[2],
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


__all__ = tuple(name for name in globals() if not name.startswith("__"))
