from __future__ import annotations

import json
import copy
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
from spaghetti_extractor.artifacts.artifact_set import (
    ArtifactSetWriterV3,
    canonical_sha256_v3,
)
from spaghetti_extractor.authority.external_site_records import (
    CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
)
from spaghetti_extractor.candidate.interpreter import (
    write_spx_interpreter_package,
)
from spaghetti_extractor.candidate.interpreter_model import CandidateInterpreterError
from spaghetti_extractor.candidate.engine import (
    write_spx_native_engine_package,
)
from spaghetti_extractor.candidate.runtime import (
    DEFINEDNESS_USE_FORMAT,
    CandidateRuntimeError,
    plan_spx_native_runtime,
    write_spx_native_runtime_package,
)
from spaghetti_extractor.util import sha256_bytes, sha256_file
from spaghetti_extractor.errors import ToolkitInputError
from tests.unit.candidate.native_engine._support import (
    _canonical_external_sites,
    _implementation_manifest,
    _machine_ir_x87_transfer,
)


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


def _as_machine_ir(row: dict[str, object]) -> dict[str, object]:
    if row.get("format") == "spaghetti-extractor-machine-ir-v2":
        unit = copy.deepcopy(row)
        original = unit["source"]["original"]
        outcome = unit["semantics"].get("outcome")
    else:
        original = dict(row["original"])
        outcome = row.get("outcome")
        instructions = []
        for instruction in row.get("instructions", []):
            rva = int(instruction["rva"])
            size = int(instruction["size"])
            encoded = bytes.fromhex(str(instruction["bytes"]))
            mnemonic = str(instruction["mnemonic"])
            instructions.append({
                "rva_start": rva,
                "rva_end": rva + size,
                "size": size,
                "instruction_sha256": sha256_bytes(encoded),
                "mnemonic": mnemonic,
                "operands": [],
                "registers_read": [],
                "registers_written": [],
                "groups": [
                    group
                    for group in ("call", "jump", "ret")
                    if (
                        (group == "call" and mnemonic == "call")
                        or (group == "jump" and mnemonic.startswith("j"))
                        or (group == "ret" and mnemonic.startswith("ret"))
                    )
                ],
            })
        unit = {
            "format": "spaghetti-extractor-machine-ir-v2",
            "record_kind": "unit",
            "id": row["id"],
            "status": "qualified",
            "reachable": True,
            "source": {
                "original": original,
                "contract_sha256": row.get("contract_sha256", _CONTRACT_SHA256),
                "instruction_bytes_sha256": row.get(
                    "instruction_bytes_sha256", _INSTRUCTION_SHA256
                ),
                "semantic_export": None,
            },
            "instructions": instructions,
            "x87_micro_ops": row.get("x87_micro_ops", []),
            "semantics": {
                "pre_state": row.get("pre_state", {}),
                "register_writes": row.get("register_writes", []),
                "flag_writes": row.get("flag_writes", []),
                "memory_events": row.get("memory_events", []),
                "external_events": row.get("ordered_events", []),
                "faults": row.get("faults", []),
                "ordered_events": row.get("ordered_events", []),
                "edge_conditions": row.get("edge_conditions", []),
                "outcome": outcome,
                "stack_delta": row.get("stack_delta", 0),
                "counts": row.get("counts", {}),
                "fpu_state": row.get("fpu_state"),
                "instruction_effect_schedule": row.get(
                    "instruction_effect_schedule"
                ),
            },
        }
    start = int(original["rva_start"])
    end = int(original["rva_end"])
    if not unit.get("instructions"):
        mnemonic = "ret" if isinstance(outcome, dict) and outcome.get("kind") == "return" else "nop"
        unit["instructions"] = [{
            "rva_start": start,
            "rva_end": end,
            "size": end - start,
            "instruction_sha256": unit["source"]["instruction_bytes_sha256"],
            "mnemonic": mnemonic,
            "operands": [],
            "registers_read": [],
            "registers_written": [],
            "groups": ["ret"] if mnemonic == "ret" else [],
        }]
    if not isinstance(unit.get("control"), dict):
        kind = outcome.get("kind") if isinstance(outcome, dict) else "return"
        direct = []
        if isinstance(outcome, dict):
            for key in ("target_rva", "true_target_rva", "false_target_rva"):
                if isinstance(outcome.get(key), int):
                    direct.append(outcome[key])
        unit["control"] = {
            "kind": kind,
            "direct_targets": sorted(set(direct)),
            "has_indirect_target": kind in {"indirect", "indirect_call"},
        }
    return unit


def _write_machine_ir(path: Path, rows: list[dict[str, object]]) -> list[dict[str, object]]:
    units = [_as_machine_ir(row) for row in rows]
    path.write_text(
        "".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
            for row in units
        ),
        encoding="utf-8",
    )
    return units


def _packages(
    root: Path,
    rows: list[dict[str, object]] | None = None,
    *,
    callback_targets: list[dict[str, object]] | None = None,
    import_iat_vas: dict[tuple[str, str], int] | None = None,
    modeled_termination: bool = False,
    selected_portable_components: list[dict[str, object]] | None = None,
    external_profile: Path | None = None,
) -> tuple[Path, Path]:
    semantic_input = root / "machine-ir.jsonl"
    fixture_units = [_as_machine_ir(row) for row in (rows or [_transfer()])]
    starts = {
        int(unit["source"]["original"]["rva_start"])
        for unit in fixture_units
    }
    for unit in tuple(fixture_units):
        for direct_target in unit["control"]["direct_targets"]:
            if direct_target not in starts:
                fixture_units.append(_as_machine_ir(_transfer(direct_target)))
                starts.add(direct_target)
        for event in unit["semantics"]["external_events"]:
            if event.get("kind") not in {
                "external_call", "indirect_call", "internal_call"
            }:
                continue
            return_rva = event.get("return_rva")
            if isinstance(return_rva, int) and return_rva not in starts:
                fixture_units.append(_as_machine_ir(_transfer(return_rva)))
                starts.add(return_rva)
    fixture_units = _write_machine_ir(semantic_input, fixture_units)
    resolutions = []
    summaries = []
    by_rva = {
        int(unit["source"]["original"]["rva_start"]): unit
        for unit in fixture_units
    }
    for unit in fixture_units:
        for event_index, event in enumerate(unit["semantics"]["external_events"]):
            if event.get("kind") == "indirect_call" and not event.get("dll"):
                internal_targets = [
                    candidate["id"]
                    for rva, candidate in sorted(by_rva.items())
                    if rva not in {
                        int(unit["source"]["original"]["rva_start"]),
                        event.get("return_rva"),
                    }
                ]
                resolutions.append({
                    "status": "recovered",
                    "source_unit_id": unit["id"],
                    "source_event_index": event_index,
                    "target_unit_ids": internal_targets,
                })
            if event.get("kind") == "internal_call":
                target_rva = int(event["target_rva"])
                target = by_rva[target_rva]
                target_outcome = target["semantics"].get("outcome")
                summaries.append({
                    "target_rva": target_rva,
                    "return_behavior": {
                        "may_return": not (
                            isinstance(target_outcome, dict)
                            and target_outcome.get("kind") == "external_jump"
                        )
                    },
                })
    manifest = root / "machine-ir-manifest.json"
    manifest.write_text(
        json.dumps(
            _implementation_manifest(
                semantic_input,
                roots=[str(fixture_units[0]["id"])],
                reachable=[str(unit["id"]) for unit in fixture_units],
                resolutions=resolutions,
                summaries=summaries,
            ),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    interpreter = root / "interpreter"
    engine = root / "engine"
    write_spx_interpreter_package(machine_ir=semantic_input, out=interpreter)
    canonical_external_sites = root / "canonical-external-sites"
    profiles: tuple[Path, ...] = ()
    if external_profile is not None:
        profiles = (external_profile,)
        selected = load_machine_import_profile_set(profiles)
        if len(selected.contracts) != 1:
            raise AssertionError("runtime fixture requires one selected import contract")
        selected_contract = selected.contracts[0]
        if selected_contract.argument_words is None:
            raise AssertionError("runtime fixture requires one fixed-arity import contract")
        event_candidates = [
            (unit, event)
            for unit in fixture_units
            for event in (
                unit["semantics"]["external_events"]
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
        if import_iat_vas is None:
            import_iat_vas = {(
                selected_contract.identity.dll,
                selected_contract.identity.value,
            ): 0x43219C}
    else:
        ArtifactSetWriterV3(
            artifact_kind=CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
            bindings=(),
        ).write(canonical_external_sites, [])
    write_spx_native_engine_package(
        machine_ir=semantic_input,
        machine_ir_manifest=manifest,
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
        "format": "spaghetti-extractor-machine-ir-v2",
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
        "format": "spaghetti-extractor-external-environment-profile-v1",
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
        "format": "spaghetti-extractor-external-environment-profile-v1",
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
        "format": "spaghetti-extractor-external-environment-profile-v1",
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


def _qualified_x87_transfer() -> dict[str, object]:
    return copy.deepcopy(_machine_ir_x87_transfer(
        rva=0x1000,
        mnemonic="fadd",
        encoded=bytes.fromhex("d8c1"),
    ))


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
            "format": "spaghetti-extractor-definedness-choice-source-v1",
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
            "format": "spaghetti-extractor-definedness-choice-source-v3",
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
