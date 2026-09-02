from __future__ import annotations

import json
from pathlib import Path

from spaghetti_extractor.artifacts.formats import MACHINE_IR_FORMAT
from spaghetti_extractor.machine_ir.memory_actions import build_memory_action_graph

from spaghetti_extractor.libraries.abi_catalog import LibraryAbiCatalogV3
from spaghetti_extractor.libraries.abi_records import (
    BehaviorBoundaryV3,
    BoundaryEffectV3,
    CallbackSlotV3,
    CheckedQualificationV3,
    LibraryAbiProfileV3,
    LibraryBehaviorEntryV3,
    LibraryFunctionSignatureV3,
    StackCleanupV3,
    ValueLocationV3,
    VariadicPolicyV3,
)
from spaghetti_extractor.libraries.signature_graph import (
    ProcedureCandidateSetV3,
    ProcedureCandidateV3,
)
from spaghetti_extractor.util import sha256_file, write_json


def abi_profile(
    profile_id: str = "x86-cdecl",
    *,
    hidden_sret: bool = False,
    variadic: str = "none",
    callback_slots: tuple[CallbackSlotV3, ...] = (),
    preserved_registers: tuple[str, ...] = ("ebp", "ebx", "edi", "esi"),
) -> LibraryAbiProfileV3:
    arguments = [ValueLocationV3("stack", 32, stack_offset=4)]
    if hidden_sret:
        arguments.insert(0, ValueLocationV3("stack", 32, stack_offset=0))
    return LibraryAbiProfileV3(
        profile_id=profile_id,
        architecture="x86",
        object_format="pe32",
        calling_convention="cdecl",
        stack_cleanup=StackCleanupV3("caller", 0),
        arguments=tuple(arguments),
        returns=(ValueLocationV3("register", 32, register="eax"),),
        hidden_sret=hidden_sret,
        variadic=VariadicPolicyV3(
            variadic,
            1,
            0 if variadic in {"format", "sentinel"} else None,
        ),
        preserved_registers=preserved_registers,
        callback_slots=callback_slots,
        structure_layout_ids=(),
        boundary_effects=(BoundaryEffectV3("memory", "argument:0", "read"),),
    )


def machine_unit(
    unit_id: str,
    rva: int,
    digest: str,
    abi: LibraryAbiProfileV3 | None,
    *,
    direct_targets: tuple[int, ...] = (),
    control_kind: str = "return",
    external_events: tuple[dict[str, object], ...] = (),
    extra: dict[str, object] | None = None,
) -> dict[str, object]:
    row: dict[str, object] = {
        "format": MACHINE_IR_FORMAT,
        "record_kind": "unit",
        "id": unit_id,
        "status": "qualified",
        "function_id": unit_id,
        "source": {
            "original": {"rva_start": rva, "rva_end": rva + 8, "size": 8},
            "contract_sha256": digest,
            "instruction_bytes_sha256": digest,
        },
        "instructions": [],
        "x87_micro_ops": [],
        "reachable": True,
        "semantics": {
            "pre_state": {},
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": list(external_events),
            "faults": [],
            "ordered_events": [],
            "edge_conditions": [],
            "memory_actions": build_memory_action_graph(
                instructions=[], memory_events=[], ordered_events=[]
            ),
            "outcome": (
                {
                    "kind": "return",
                    "value": {"op": "reg", "name": "eax", "width": 32},
                }
                if control_kind == "return"
                else {"kind": control_kind}
            ),
            "stack_delta": 0,
            "counts": {},
            "fpu_state": None,
            "instruction_effect_schedule": None,
        },
        "control": {
            "kind": control_kind,
            "direct_targets": list(direct_targets),
            "has_indirect_target": False,
        },
    }
    if abi is not None:
        row["abi_envelope"] = abi.to_payload()
    if extra:
        row.update(extra)
    return row


def write_machine(
    root: Path,
    units: list[dict[str, object]],
    *,
    binary_bytes: bytes | None = None,
) -> Path:
    package = root / "machine-ir"
    package.mkdir()
    binary = root / "fixture.exe"
    binary.write_bytes(binary_bytes or (b"MZ" + b"\0" * 62))
    ir = package / "machine-ir.jsonl"
    ir.write_text(
        "".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
            for row in units
        ),
        encoding="utf-8",
    )
    source_map = [
        {
            "unit_id": row["id"],
            "rva_start": row["source"]["original"]["rva_start"],
            "contract_sha256": row["source"].get(
                "contract_sha256", row["source"]["instruction_bytes_sha256"]
            ),
        }
        for row in units
    ]
    write_json(
        package / "machine-ir-manifest.json",
        {
            "format": MACHINE_IR_FORMAT,
            "record_kind": "manifest",
            "binary": {"sha256": sha256_file(binary)},
            "authority_bindings": {
                "binary": {"pe_sha256": sha256_file(binary)}
            },
            "artifacts": {
                "machine_ir": {
                    "path": "machine-ir.jsonl",
                    "sha256": sha256_file(ir),
                }
            },
            "counts": {"units": len(units)},
            "source_map": source_map,
        },
    )
    return package


def procedure_candidates(
    machine: Path, groups: tuple[tuple[str, tuple[str, ...]], ...]
) -> ProcedureCandidateSetV3:
    return ProcedureCandidateSetV3.create(
        machine_ir_sha256=sha256_file(machine / "machine-ir.jsonl"),
        candidates=tuple(
            ProcedureCandidateV3(identity, tuple(sorted(unit_ids)))
            for identity, unit_ids in groups
        ),
    )


def function_signature(
    *,
    function_id: str,
    release: str,
    exact_hash: str | None,
    unit_merkle_hash: str | None = None,
    abi_profile_id: str | None = "x86-cdecl",
    member_id: str | None = None,
    cfg_hash: str | None = None,
    direct_callees: tuple[str, ...] = (),
    retention_model: str = "unknown",
) -> LibraryFunctionSignatureV3:
    return LibraryFunctionSignatureV3(
        function_id=function_id,
        catalog_id="fixture-library",
        family_id="fixture-family",
        release_id=release,
        member_id=member_id or f"{function_id}.obj",
        symbols=(function_id,),
        normalized_bytes_sha256=None,
        exact_bytes_sha256=exact_hash,
        unit_merkle_sha256=unit_merkle_hash,
        cfg_sha256=cfg_hash,
        direct_callees=direct_callees,
        imports=(),
        constants=(),
        strings=(),
        data_refs=(),
        abi_profile_id=abi_profile_id,
        object_size=8,
        retention_model=retention_model,
    )


def behavior(
    *,
    releases: tuple[str, ...] = ("1.0",),
    boundaries: tuple[BehaviorBoundaryV3, ...] = (),
    qualified: bool = True,
) -> LibraryBehaviorEntryV3:
    qualification = (
        CheckedQualificationV3(
            "reusable_certificate",
            "fixture-checker-v1",
            "d" * 64,
            "fixture-behavior",
            None,
        )
        if qualified
        else None
    )
    return LibraryBehaviorEntryV3(
        behavior_entry_id="fixture-behavior",
        family_id="fixture-family",
        compatible_releases=releases,
        abi_profile_ids=("x86-cdecl",),
        portable_symbol="fixture_portable",
        portable_source_sha256="e" * 64,
        boundaries=boundaries,
        reusable_qualification=qualification,
    )


def catalog(
    functions: tuple[LibraryFunctionSignatureV3, ...],
    *,
    profiles: tuple[LibraryAbiProfileV3, ...] | None = None,
    behaviors: tuple[LibraryBehaviorEntryV3, ...] = (),
) -> LibraryAbiCatalogV3:
    return LibraryAbiCatalogV3.create(
        catalog_id="fixture-library",
        abi_profiles=profiles or (abi_profile(),),
        functions=functions,
        behaviors=behaviors,
    )
