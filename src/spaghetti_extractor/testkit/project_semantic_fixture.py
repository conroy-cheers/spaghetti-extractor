# spaghetti-extractor-python-role: developer
"""Small checked semantic inputs for the multi-image loader fixture."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.calls.frame import PhysicalCallFrameV2
from spaghetti_extractor.external.formats import (
    RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT,
)
from spaghetti_extractor.external.resolved import bind_launch_policy_v1
from spaghetti_extractor.pe32.behavioral_roots import (
    generate_behavioral_roots,
)
from spaghetti_extractor.testkit.native_module_fixture import (
    _fixture_checked_boundary_v1,
    _fixture_machine_import_boundary_v1,
)
from spaghetti_extractor.testkit.transfer_fixture import (
    as_machine_ir_unit,
    set_eax_return_semantics,
    transfer_row,
    write_fixture_transfer_plan,
)
from spaghetti_extractor.util import json_dumps, sha256_file, write_json


def _mapping(value: object, description: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{description} must be an object")
    return value


def _checked_export_boundaries(
    interface: Mapping[str, Any],
) -> tuple[list[dict[str, object]], dict[str, str]]:
    image_id = str(interface["image_id"])
    directory = _mapping(interface["export_directory"], "export directory")
    by_rva: dict[int, list[Mapping[str, Any]]] = {}
    for raw in directory["slots"]:
        slot = _mapping(raw, "export slot")
        if slot.get("kind") == "code":
            by_rva.setdefault(int(slot["rva"]), []).append(slot)

    boundaries: list[dict[str, object]] = []
    frames: dict[str, str] = {}
    for target_rva, slots in sorted(by_rva.items()):
        names = sorted({
            str(name)
            for slot in slots
            for name in slot.get("names", ())
        })
        subject_id = names[0] if names else (
            f"ordinal:{min(int(slot['ordinal']) for slot in slots)}"
        )
        subject = {
            "kind": "export",
            "id": subject_id,
            "image_selector": image_id,
        }
        transport = PhysicalCallFrameV2.create(
            subject=subject,
            transfer_kind="direct",
            target="i686-pc-windows-pe32",
            abi_dialect="pe32-i386-gnu-v1",
            calling_convention="cdecl",
            arguments=[],
            results=[],
            stack={
                "coordinate": "callee-entry-esp-v1",
                "alignment_bytes": 4,
                "cleanup": "caller",
                "cleanup_bytes": 0,
                "reserved_bytes": 0,
            },
            preserved_state=["ebp", "ebx", "edi", "esi", "esp"],
            clobbered_state=[
                "eax", "ecx", "edx", "eflags", "st0", "st1",
                "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5",
                "xmm6", "xmm7",
            ],
            outcomes=["normal"],
        )
        boundary = _fixture_checked_boundary_v1(
            subject=subject, transport=transport,
        )
        frame = boundary["artifacts"]["physical_call_frame_v3"]["payload"]
        if not isinstance(frame, Mapping):
            raise ValueError("fixture export frame is malformed")
        frame_id = str(frame["id"])
        boundaries.append(boundary)
        for slot in slots:
            ordinal = int(slot["ordinal"])
            frames[f"ordinal:{ordinal}"] = frame_id
            for name in slot.get("names", ()):
                frames[str(name)] = frame_id
        frames[f"rva:{target_rva:08x}"] = frame_id
    boundaries.sort(key=lambda row: str(row["subject"]))
    return boundaries, frames


def write_project_semantic_inputs(
    *, original_pe: Path, module_interface: Path, out: Path,
) -> dict[str, Path]:
    """Write a transfer-v2/environment/root package for loader tests.

    These deliberately tiny transfer bodies are test inputs, not evidence that
    the fixture's original C implementation has been semantically recovered.
    They exist so loader/project tests exercise the production semantic-object
    and linked-module package boundaries instead of a raw-interface bypass.
    """

    original_pe = Path(original_pe)
    module_interface = Path(module_interface)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    interface = json.loads(module_interface.read_text(encoding="utf-8"))
    roots = generate_behavioral_roots(original_pe)
    write_json(out / "behavioral-roots.json", roots)

    private_imports = {
        str(row.get("symbol")): _mapping(row, "project fixture import")
        for row in interface.get("imports", ())
        if str(row.get("dll", "")).lower() == "private.dll"
        and isinstance(row.get("symbol"), str)
    }
    ping_import = private_imports.get("Ping")
    shared_value_import = private_imports.get("SharedValue")
    entry_rva = int(_mapping(interface["loader"], "module loader")["entry_rva"])
    image_base = int(
        _mapping(interface["loader"], "module loader")["preferred_base"]
    )

    machine_ir = out / "machine-ir.jsonl"
    rows = []
    for index, rva in enumerate(sorted({
        int(root["rva"]) for root in roots["roots"]
    })):
        row = transfer_row()
        row["id"] = f"semantic-transfer:project-root-{index:04d}-{rva:08x}"
        row["original"] = {
            "rva_start": rva,
            "rva_end": rva + 1,
            "size": 1,
        }
        row["register_writes"] = []
        if rva == entry_rva and ping_import is not None:
            call_event = {
                "family": "external",
                "kind": "external_call",
                "instruction_rva": rva,
                "target_rva": 0,
                "return_rva": rva + 1,
                "dll": ping_import["dll"],
                "symbol": ping_import["symbol"],
                "ordinal": ping_import["ordinal"],
                "register_inputs": {
                    name: {"op": "reg", "name": name, "width": 32}
                    for name in (
                        "eax", "ebx", "ecx", "edx",
                        "esi", "edi", "ebp", "esp",
                    )
                },
                "flag_inputs": {
                    name: {"op": "flag", "name": name}
                    for name in ("cf", "zf", "sf", "of", "pf", "df")
                },
                "arguments": [],
                "stack_inputs": [],
            }
            row["external_events"] = [call_event]
            row["ordered_events"] = [call_event]
        if rva == entry_rva and shared_value_import is not None:
            pointer = {
                "op": "load",
                "width": 4,
                "address": {
                    "op": "const",
                    "value": image_base + int(shared_value_import["iat_rva"]),
                    "width": 32,
                },
            }
            read = {
                "family": "memory", "kind": "read", "width": 4,
                "address": pointer,
            }
            write = {
                "family": "memory", "kind": "write", "width": 4,
                "address": pointer,
                "value": {"op": "const", "value": 7, "width": 32},
            }
            row["memory_events"] = [
                {key: value for key, value in event.items() if key != "family"}
                for event in (read, write)
            ]
            row.setdefault("ordered_events", [])[:0] = [read, write]
        set_eax_return_semantics(
            row, {"op": "const", "value": 0, "width": 32},
        )
        rows.append(row)
    machine_ir.write_text(
        "".join(json_dumps(as_machine_ir_unit(row)) + "\n" for row in rows),
        encoding="utf-8",
    )
    transfer = write_fixture_transfer_plan(
        machine_ir, pe_sha256=sha256_file(original_pe),
    )

    boundaries, export_frames = _checked_export_boundaries(interface)
    machine_import_contracts: list[dict[str, object]] = []
    if ping_import is not None:
        ping_profile = {
            "id": "project-fixture-ping-cdecl-v1",
            "abi_template": "pe32-cdecl-v1",
            "argument_words": 0,
            "arity": {"kind": "fixed", "words": 0},
            "disposition": "returns",
            "result_register_relations": [],
            "memory_effect": "none",
            "memory_footprints": [],
            "world_effect": "none",
            "out_pointer_relations": [],
            "out_interface_relations": [],
        }
        identity = {
            "dll": ping_import["dll"],
            "symbol": ping_import["symbol"],
            "ordinal": ping_import["ordinal"],
        }
        machine_import_contracts.append({
            "import_kind": "ordinary",
            "identity": identity,
            "descriptor_index": ping_import["descriptor_index"],
            "cell_index": ping_import["cell_index"],
            "iat_rva": ping_import["iat_rva"],
            "contract": {
                "profile_id": ping_profile["id"],
                "profile_sha256": canonical_sha256_v3(ping_profile),
                "entry_key": "machine_import_signatures",
                "entry_index": 0,
                "payload": ping_profile,
            },
            "boundary": _fixture_machine_import_boundary_v1(
                identity=identity, profile=ping_profile, entry_index=0,
            ),
        })
    environment_core = {
        "format": RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT,
        "status": "complete",
        "bindings": {
            "module_interface_sha256": interface["interface_sha256"],
            "module_pe_sha256": interface["identity"]["pe_sha256"],
            "environment_intent_sha256": canonical_sha256_v3({
                "id": "project-semantic-fixture-v1",
                "image_id": interface["image_id"],
            }),
            "runtime_profile_pack_sha256s": [],
            "interface_profile_pack_sha256s": [],
        },
        "target": {
            "abi": "pe32-i686-mingw32",
            "data_layout": "pe32-ilp32-v1",
        },
        "launch_policy": bind_launch_policy_v1(
            {
                "format": (
                    "spaghetti-extractor-pe32-launch-assumption-template-v1"
                ),
                "schema_version": 1,
            },
            source_sha256="0" * 64,
            filename="project-semantic-fixture-launch.json",
        ),
        "canonical_boundaries": boundaries,
        "interface_method_catalogs": [],
        "machine_import_contracts": machine_import_contracts,
        "original_semantic_imports": machine_import_contracts,
        "generated_runtime_support_imports": [],
        "loader_service_contracts": [],
        "static_authority_bindings": [],
        "checked_exception_protocols": [],
        "blockers": [],
        "authority": "checked_static_environment",
    }
    environment_root = out / "environment"
    environment_root.mkdir()
    environment_path = environment_root / "resolved-external-environment.json"
    write_json(environment_path, {
        **environment_core,
        "resolved_environment_sha256": canonical_sha256_v3(environment_core),
    })
    write_json(out / "export-physical-frames.json", export_frames)
    return {
        "transfer_plan": transfer,
        "resolved_environment": environment_path,
        "behavioral_roots": out / "behavioral-roots.json",
        "export_physical_frames": out / "export-physical-frames.json",
    }
