"""Synthetic module-link inputs shared by native integration checks."""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Mapping

import capstone
import pefile

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.artifacts.formats import (
    BOUNDARY_LIFECYCLE_RECEIPT_V1_FORMAT,
    BOUNDARY_LIFECYCLE_V1_FORMAT,
    CHECKED_CALL_PROTOCOL_V2_FORMAT,
    PHYSICAL_CALL_FRAME_V3_FORMAT,
)
from spaghetti_extractor.candidate.behavioral_c import (
    write_spx_behavioral_c_package,
)
from spaghetti_extractor.candidate.native_ingress_plan import (
    write_pe32_machine_object_authority_v2,
)
from spaghetti_extractor.candidate.project import write_pe32_module_interface
from spaghetti_extractor.calls.frame import PhysicalCallFrameV2
from spaghetti_extractor.candidate.outcomes import (
    PinnedCodeLayoutAuthorityV2,
)
from spaghetti_extractor.semantic_objects.object_authority import (
    LoaderRealizedLocatorV2,
    MachineObjectAuthorityV2,
    MachineObjectRuleV2,
)
from spaghetti_extractor.external.formats import RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT
from spaghetti_extractor.external.environment import (
    lower_machine_import_boundary_v1,
)
from spaghetti_extractor.external.resolved import (
    ResolvedExternalEnvironmentV1,
    bind_checked_exception_protocol_v1,
    bind_launch_policy_v1,
)
from spaghetti_extractor.external.machine_import_profiles import (
    MachineImportIdentity,
    SelectedMachineImportContract,
    load_machine_import_profile_set,
)
from spaghetti_extractor.external.interface_profiles import (
    load_external_interface_profile,
)
from spaghetti_extractor.external.machine_callback_boundary import (
    interface_callback_boundary_catalog_v1,
    machine_callback_boundary_catalog_v1,
)
from spaghetti_extractor.machine_ir.memory_actions import (
    build_memory_action_graph,
)
from spaghetti_extractor.testkit.transfer_fixture import (
    as_machine_ir_unit,
    set_eax_return_semantics,
    transfer_row,
    write_fixture_transfer_plan,
)
from spaghetti_extractor.transfer.formats import MODULE_EXECUTION_CLOSURE_FORMAT
from spaghetti_extractor.transfer.closure import (
    ExecutionClosureContextV1,
    build_module_execution_closure_v1,
)
from spaghetti_extractor.transfer.plan import _transfer_from_payload
from spaghetti_extractor.transfer.provenance import (
    ReferenceAtomV1,
    ReferenceCatalogV1,
    ReferenceStateV1,
    finite_reference_value_v1,
)
from spaghetti_extractor.transfer.operations import (
    call_native_exception_fault_payload_v3,
)
from spaghetti_extractor.transfer.exception_semantics import (
    derive_checked_exception_transitions_v1,
)
from spaghetti_extractor.util import sha256_bytes, sha256_file, write_json


def _bind_exact_instruction_inventory(
    rows: list[dict[str, object]], original_pe: Path,
) -> None:
    """Bind synthetic semantic rows to exact IA-32 spans in the fixture PE.

    The native-module fixture authors checked transfer effects directly, but
    platform selection still needs an exact occurrence inventory.  Decode the
    same number of physical instructions as each authored effect schedule (or
    one instruction for an unscheduled row), update the unit span and bind its
    exact bytes.  This is fixture construction, not an instruction-semantics
    oracle; the authored transfer effects remain the checked input under test.
    """

    parsed = pefile.PE(str(original_pe), fast_load=True)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = False
    try:
        image_base = int(parsed.OPTIONAL_HEADER.ImageBase)
        for row in rows:
            original = row.get("original")
            if not isinstance(original, dict):
                raise ValueError("fixture transfer has no original span")
            start = int(original["rva_start"])
            schedule = row.get("instruction_effect_schedule")
            records = (
                schedule.get("records")
                if isinstance(schedule, dict) else None
            )
            instruction_count = len(records) if isinstance(records, list) else 1
            decoded = list(decoder.disasm(
                parsed.get_data(start, 15 * instruction_count),
                image_base + start,
                count=instruction_count,
            ))
            if len(decoded) != instruction_count:
                raise ValueError(
                    f"fixture transfer at RVA 0x{start:x} has no exact "
                    "instruction inventory"
                )
            projections = []
            instruction_bytes = bytearray()
            for instruction in decoded:
                rva_start = int(instruction.address) - image_base
                encoded = bytes(instruction.bytes)
                rva_end = rva_start + len(encoded)
                projections.append({
                    "rva_start": rva_start,
                    "rva_end": rva_end,
                    "size": len(encoded),
                    "instruction_sha256": sha256_bytes(encoded),
                    "mnemonic": str(instruction.mnemonic),
                    "operands": [],
                })
                instruction_bytes.extend(encoded)
            end = int(projections[-1]["rva_end"])
            original.update({
                "rva_start": start, "rva_end": end, "size": end - start,
            })
            row["instructions"] = projections
            row["instruction_bytes_sha256"] = sha256_bytes(
                bytes(instruction_bytes)
            )
            if not isinstance(records, list):
                continue

            old_starts = [int(record["rva_start"]) for record in records]
            translated_rvas = {
                old: int(projection["rva_start"])
                for old, projection in zip(old_starts, projections)
            }
            old_end = int(schedule["rva_end"])
            translated_rvas[old_end] = end
            if end != old_end:
                for candidate in rows:
                    if candidate is row:
                        continue
                    candidate_span = candidate.get("original")
                    if (
                        isinstance(candidate_span, dict)
                        and candidate_span.get("rva_start") == old_end
                    ):
                        candidate_size = int(candidate_span["size"])
                        candidate_span.update({
                            "rva_start": end,
                            "rva_end": end + candidate_size,
                        })
            schedule["rva_start"] = start
            schedule["rva_end"] = end

            def translate_control(value: object) -> None:
                if not isinstance(value, dict):
                    return
                for key in (
                    "target_rva", "true_target_rva", "false_target_rva"
                ):
                    target = value.get(key)
                    if target in translated_rvas:
                        value[key] = translated_rvas[target]

            for index, (record, projection) in enumerate(
                zip(records, projections)
            ):
                record["rva_start"] = projection["rva_start"]
                record["rva_end"] = projection["rva_end"]
                effects = record.get("effects")
                control = effects.get("control") if isinstance(effects, dict) else None
                if (
                    isinstance(control, dict)
                    and control.get("kind") == "fallthrough"
                ):
                    control["target_rva"] = (
                        projections[index + 1]["rva_start"]
                        if index + 1 < len(projections) else end
                    )
                else:
                    translate_control(control)

            def translate_faults(value: object) -> None:
                if not isinstance(value, list):
                    return
                for event in value:
                    if not isinstance(event, dict):
                        continue
                    instruction_rva = event.get("instruction_rva")
                    if instruction_rva in translated_rvas:
                        event["instruction_rva"] = translated_rvas[instruction_rva]

            translate_faults(row.get("faults"))
            translate_faults(row.get("ordered_events"))
            translate_control(row.get("outcome"))
            memory_actions = row.get("memory_actions")
            if isinstance(memory_actions, dict):
                translate_faults(memory_actions.get("actions"))
            for record in records:
                effects = record.get("effects")
                if isinstance(effects, dict):
                    translate_faults(effects.get("ordered_events"))
    finally:
        parsed.close()


def _fixture_machine_import_boundary_v1(
    *, identity: Mapping[str, object], profile: Mapping[str, object],
    entry_index: int,
) -> dict[str, object]:
    profile_id = str(profile["id"])
    profile_sha256 = canonical_sha256_v3(profile)
    arity = profile["arity"]
    if not isinstance(arity, Mapping):
        raise ValueError("fixture machine-import arity is malformed")
    selected = SelectedMachineImportContract(
        identity=MachineImportIdentity.from_mapping(
            identity, context="fixture machine import"
        ),
        profile_id=profile_id,
        profile_path=Path(f"fixture-profile:{profile_id}"),
        profile_sha256=profile_sha256,
        profile_format="spaghetti-extractor-static-machine-import-profile-v2",
        entry_key="machine_import_signatures",
        entry_index=entry_index,
        contract=profile,
        arity_kind=str(arity["kind"]),
        argument_words=(
            int(arity["words"])
            if arity.get("kind") == "fixed" else None
        ),
    )
    return lower_machine_import_boundary_v1(
        selected, abi_dialect="pe32-i386-gnu-v1"
    )


def _fixture_checked_boundary_v1(
    *, subject: Mapping[str, object], transport: PhysicalCallFrameV2,
) -> dict[str, object]:
    """Build one complete checked-boundary catalog row for native ingress."""

    transport_payload = transport.to_payload()
    subject_id = str(subject["id"])
    signature_id = f"fixture-signature:{subject['kind']}:{subject_id}"
    schema_sha256 = canonical_sha256_v3({
        "subject": dict(subject),
        "arguments": transport_payload["arguments"],
        "results": transport_payload["results"],
    })
    layout_sha256 = canonical_sha256_v3({
        "transport": transport_payload,
    })
    bindings = [
        {
            "slot_id": str(slot["id"]),
            "path": {
                "root": (
                    "parameter"
                    if slot["role"] == "parameter" else "result"
                ),
                "value_id": str(slot["id"]),
                "fields": [],
            },
            "transport": "semantic",
        }
        for slot in (
            *transport_payload["arguments"],
            *transport_payload["results"],
        )
    ]
    frame_core = {
        "format": PHYSICAL_CALL_FRAME_V3_FORMAT,
        "schema_sha256": schema_sha256,
        "layout_sha256": layout_sha256,
        "signature_id": signature_id,
        "transport": transport_payload,
        "bindings": bindings,
        "dialect_rule_ids": ["fixture.checked-pe32-boundary.v1"],
    }
    frame = {
        **frame_core,
        "id": f"physical-call-frame-v3:{canonical_sha256_v3(frame_core)}",
    }
    lifecycle_core = {
        "format": BOUNDARY_LIFECYCLE_V1_FORMAT,
        "schema_sha256": schema_sha256,
        "signature_id": signature_id,
        "roots": [],
        "bindings": [],
    }
    lifecycle = {
        **lifecycle_core,
        "lifecycle_sha256": canonical_sha256_v3(lifecycle_core),
    }
    receipt_core = {
        "format": BOUNDARY_LIFECYCLE_RECEIPT_V1_FORMAT,
        "lifecycle_sha256": lifecycle["lifecycle_sha256"],
        "status": "complete",
        "obligations": [{
            "id": "boundary.empty-lifecycle",
            "status": "checked",
            "code": "empty_lifecycle_checked",
        }],
    }
    receipt = {
        **receipt_core,
        "receipt_sha256": canonical_sha256_v3(receipt_core),
    }
    call_core = {
        "format": CHECKED_CALL_PROTOCOL_V2_FORMAT,
        "status": "complete",
        "schema_id": f"fixture-schema:{subject['kind']}:{subject_id}",
        "schema_sha256": schema_sha256,
        "layout_sha256": layout_sha256,
        "signature_id": signature_id,
        "physical_frame_id": frame["id"],
        "evidence_receipt_id": (
            f"fixture-checked-boundary:{subject['kind']}:{subject_id}"
        ),
        "lifecycle_sha256": lifecycle["lifecycle_sha256"],
        "lifecycle_receipt_sha256": receipt["receipt_sha256"],
        "projection_sha256": None,
        "projection_receipt_sha256": None,
        "issues": [],
    }
    call = {
        **call_core,
        "id": f"checked-call-protocol-v2:{canonical_sha256_v3(call_core)}",
    }
    return {
        "kind": "checked_protocol",
        "subject": f"{subject['kind']}:{subject_id}",
        "artifacts": {
            "checked_call_protocol": {"payload": call},
            "physical_call_frame_v3": {"payload": frame},
            "boundary_lifecycle": {"payload": lifecycle},
            "boundary_lifecycle_receipt": {"payload": receipt},
        },
    }


def set_pe32_tls_zero_fill(module: Path, zero_fill_bytes: int) -> None:
    """Set the synthetic fixture's typed PE32 TLS zero-fill field exactly."""

    import pefile

    if (
        not isinstance(zero_fill_bytes, int)
        or isinstance(zero_fill_bytes, bool)
        or zero_fill_bytes <= 0
    ):
        raise ValueError("fixture TLS zero fill must be a positive integer")
    path = Path(module)
    raw = bytearray(path.read_bytes())
    parsed = pefile.PE(data=bytes(raw), fast_load=False)
    try:
        tls = getattr(parsed, "DIRECTORY_ENTRY_TLS", None)
        if tls is None:
            raise ValueError("fixture module has no typed TLS directory")
        field_offset = tls.struct.get_field_absolute_offset("SizeOfZeroFill")
        checksum_offset = parsed.OPTIONAL_HEADER.get_field_absolute_offset(
            "CheckSum"
        )
    finally:
        parsed.close()
    struct.pack_into("<I", raw, field_offset, zero_fill_bytes)
    struct.pack_into("<I", raw, checksum_offset, 0)
    checksum_pe = pefile.PE(data=bytes(raw), fast_load=True)
    try:
        checksum = checksum_pe.generate_checksum()
    finally:
        checksum_pe.close()
    struct.pack_into("<I", raw, checksum_offset, checksum)
    path.write_bytes(raw)


def _fixture_exact_instruction_rvas(
    original_pe: Path, start_rva: int, count: int,
    *, other_entry_rvas: set[int],
) -> list[int]:
    """Select exact non-overlapping instruction identities for one fixture path."""

    parsed = pefile.PE(str(original_pe), fast_load=True)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    try:
        image_base = int(parsed.OPTIONAL_HEADER.ImageBase)
        decoded = list(decoder.disasm(
            parsed.get_data(start_rva, 15 * count),
            image_base + start_rva,
            count=count,
        ))
    finally:
        parsed.close()
    if len(decoded) != count:
        raise ValueError(
            f"fixture interface path at RVA 0x{start_rva:x} has only "
            f"{len(decoded)} of {count} exact instruction identities"
        )
    rvas = [int(instruction.address) - image_base for instruction in decoded]
    collision = sorted((set(rvas) - {start_rva}) & other_entry_rvas)
    if collision:
        raise ValueError(
            "fixture interface path crossed another semantic entry: "
            + ", ".join(f"0x{rva:x}" for rva in collision)
        )
    return rvas


def _fixture_interface_transfer_rows(
    *, original_pe: Path, target_rva: int, unit_suffix: str,
    factory_import: Mapping[str, object], other_entry_rvas: set[int],
    image_base: int, callback_target_rva: int | None,
) -> list[dict[str, object]]:
    """Author the end-to-end factory/vtable fixture as exact transfer units."""

    stale = unit_suffix == "fixture-interface-stale"
    record = unit_suffix == "fixture-interface-record"
    callback_flow = unit_suffix == "fixture-interface-callback"
    if unit_suffix not in {
        "fixture-interface", "fixture-interface-stale",
        "fixture-interface-record",
        "fixture-interface-callback",
    }:
        raise ValueError("fixture interface transfer suffix is unsupported")
    if callback_flow and callback_target_rva is None:
        raise ValueError("fixture interface callback flow has no target entry")
    count = 6 if stale else 5 if (record or callback_flow) else 8
    rvas = _fixture_exact_instruction_rvas(
        original_pe, target_rva, count, other_entry_rvas=other_entry_rvas,
    )

    def const(value: int) -> dict[str, object]:
        return {"op": "const", "value": value, "width": 32}

    def reg(name: str) -> dict[str, object]:
        return {"op": "reg", "name": name, "width": 32}

    def add(base: dict[str, object], offset: int) -> dict[str, object]:
        operation = "add32" if offset >= 0 else "sub32"
        return {"op": operation, "args": [base, const(abs(offset))]}

    def load(address: dict[str, object]) -> dict[str, object]:
        return {"op": "load", "width": 4, "address": address}

    def write(
        address: dict[str, object], value: dict[str, object],
    ) -> dict[str, object]:
        return {
            "family": "memory", "kind": "write", "width": 4,
            "address": address, "value": value,
        }

    def row(index: int, label: str) -> dict[str, object]:
        result = transfer_row()
        result["id"] = f"semantic-transfer:{unit_suffix}-{label}"
        result["original"] = {
            "rva_start": rvas[index],
            "rva_end": rvas[index] + 1,
            "size": 1,
        }
        result["register_writes"] = []
        result["outcome"] = (
            {"kind": "fallthrough", "target_rva": rvas[index + 1]}
            if index + 1 < len(rvas) else
            {"kind": "return", "value": const(0)}
        )
        return result

    def register_inputs(stack: dict[str, object]) -> dict[str, object]:
        return {
            name: stack if name == "esp" else reg(name)
            for name in (
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
            )
        }

    def flag_inputs() -> dict[str, object]:
        return {
            name: {"op": "flag", "name": name}
            for name in ("cf", "zf", "sf", "of", "pf", "df")
        }

    def call_row(
        index: int, label: str, *, arguments: list[dict[str, object]],
        stack_offset: int, target: dict[str, object] | None,
        slot: int | None = None,
        after: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        result = row(index, label)
        base = reg("esi")
        call_stack = add(base, -stack_offset)
        writes = [
            write(add(call_stack, argument_index * 4), value)
            for argument_index, value in enumerate(arguments)
        ]
        event: dict[str, object] = {
            "family": "external",
            "kind": "external_call" if target is None else "indirect_call",
            "instruction_rva": rvas[index],
            "target_rva": 0,
            "return_rva": (
                rvas[index + 1] if index + 1 < len(rvas) else rvas[index] + 1
            ),
            "register_inputs": register_inputs(call_stack),
            "flag_inputs": flag_inputs(),
            "arguments": arguments,
            "stack_inputs": [
                {"offset": argument_index * 4, "width": 4, "value": value}
                for argument_index, value in enumerate(arguments)
            ],
        }
        if target is None:
            event.update({
                "dll": str(factory_import["dll"]),
                "symbol": factory_import.get("symbol"),
                "ordinal": factory_import.get("ordinal"),
            })
        else:
            event["target"] = target
            if slot is None:
                raise ValueError("fixture interface call has no exact vtable slot")
        trailing = list(after or [])
        ordered = [*writes, event, *trailing]
        result["memory_events"] = [
            {key: value for key, value in item.items() if key != "family"}
            for item in (*writes, *trailing)
        ]
        result["external_events"] = [event]
        result["ordered_events"] = ordered
        return result

    entry_stack = reg("esp")
    base = reg("esi")
    saved_esi = add(base, -4)
    root_cell = add(base, -8)
    nested_cell = add(base, -12)
    result_cell = add(base, -16)
    stale_record_cell = add(base, -16)
    stale_target_cell = add(base, -20)
    stale_result_cell = add(base, -24)

    def finish_operation(
        finish: dict[str, object], result: dict[str, object]
    ) -> None:
        """Model the shared cdecl epilogue and its distinct EAX result."""

        finish["register_writes"] = [
            {"register": "esi", "value": load(saved_esi)},
            {"register": "eax", "value": result},
            {"register": "esp", "value": add(base, 4)},
        ]
        finish["outcome"] = {"kind": "return", "value": load(base)}

    def method_target(receiver: dict[str, object], slot: int) -> dict[str, object]:
        return load(add(load(receiver), slot * 4))

    setup = row(0, "setup")
    setup_writes = [
        write(add(entry_stack, -4), reg("esi")),
        write(add(entry_stack, -8), const(0)),
        (
            write(add(entry_stack, -16), const(8))
            if stale or record else write(add(entry_stack, -12), const(0))
        ),
        *([] if stale or record else [write(add(entry_stack, -16), const(0))]),
    ]
    setup["memory_events"] = [
        {key: value for key, value in item.items() if key != "family"}
        for item in setup_writes
    ]
    setup["ordered_events"] = setup_writes
    setup["register_writes"] = [{"register": "esi", "value": entry_stack}]

    root = load(root_cell)
    factory = call_row(
        1, "factory", arguments=[root_cell], stack_offset=32, target=None,
        after=(
            [write(stale_target_cell, method_target(root, 2))]
            if stale else None
        ),
    )

    if callback_flow:
        callback_result = {
            "op": "call_response", "call_index": 0,
            "register": "eax", "width": 32,
        }
        remember_callback_result = write(result_cell, callback_result)
        enumerate_call = call_row(
            2, "enumerate",
            arguments=[
                root,
                const(image_base + int(callback_target_rva)),
                const(0x13572468),
            ],
            stack_offset=40,
            target=method_target(root, 4),
            slot=4,
            after=[remember_callback_result],
        )
        release = call_row(
            3, "release", arguments=[root], stack_offset=56,
            target=method_target(root, 3), slot=3,
        )
        finish = row(4, "return")
        result = load(result_cell)
        finish_operation(finish, result)
        return [setup, factory, enumerate_call, release, finish]

    if record:
        fill_record = call_row(
            2, "fill-record", arguments=[root, stale_record_cell],
            stack_offset=40, target=method_target(root, 5), slot=5,
        )
        release = call_row(
            3, "release", arguments=[root], stack_offset=48,
            target=method_target(root, 3), slot=3,
        )
        finish = row(4, "return")
        result = load(add(stale_record_cell, 4))
        finish_operation(finish, result)
        return [setup, factory, fill_record, release, finish]

    if stale:
        fill_record = call_row(
            2, "fill-record", arguments=[root, stale_record_cell],
            stack_offset=40, target=method_target(root, 5), slot=5,
        )
        release = call_row(
            3, "release", arguments=[root], stack_offset=48,
            target=method_target(root, 3), slot=3,
        )
        stale_call_result = {
            "op": "call_response", "call_index": 0,
            "register": "eax", "width": 32,
        }
        stale_get = call_row(
            4, "stale-get", arguments=[root], stack_offset=56,
            target=load(stale_target_cell), slot=2,
            after=[write(stale_result_cell, stale_call_result)],
        )
        finish = row(5, "return")
        result = {
            "op": "xor32",
            "args": [load(add(stale_record_cell, 4)), load(stale_result_cell)],
        }
        finish_operation(finish, result)
        return [setup, factory, fill_record, release, stale_get, finish]

    nested = load(nested_cell)
    clone = call_row(
        2, "clone", arguments=[root, nested_cell], stack_offset=40,
        target=method_target(root, 0), slot=0,
    )
    set_value = call_row(
        3, "set-value", arguments=[nested, const(0xFACEB00C)],
        stack_offset=48, target=method_target(nested, 1), slot=1,
    )
    get_result = {
        "op": "call_response", "call_index": 0,
        "register": "eax", "width": 32,
    }
    remember_result = write(result_cell, get_result)
    get_value = call_row(
        4, "get-value", arguments=[nested], stack_offset=56,
        target=method_target(nested, 2), slot=2, after=[remember_result],
    )
    release_nested = call_row(
        5, "release-nested", arguments=[nested], stack_offset=64,
        target=method_target(nested, 3), slot=3,
    )
    release_root = call_row(
        6, "release-root", arguments=[root], stack_offset=72,
        target=method_target(root, 3), slot=3,
    )
    finish = row(7, "return")
    result = load(result_cell)
    finish_operation(finish, result)
    return [
        setup, factory, clone, set_value, get_value,
        release_nested, release_root, finish,
    ]


def _fixture_interface_callback_target_rows(
    *, original_pe: Path, target_rva: int, other_entry_rvas: set[int],
) -> list[dict[str, object]]:
    """Model the provider-to-guest callback and its nested interface call."""

    rvas = _fixture_exact_instruction_rvas(
        original_pe, target_rva, 2, other_entry_rvas=other_entry_rvas,
    )

    def const(value: int) -> dict[str, object]:
        return {"op": "const", "value": value, "width": 32}

    def reg(name: str) -> dict[str, object]:
        return {"op": "reg", "name": name, "width": 32}

    def add(base: dict[str, object], offset: int) -> dict[str, object]:
        return {
            "op": "add32" if offset >= 0 else "sub32",
            "args": [base, const(abs(offset))],
        }

    def load(address: dict[str, object]) -> dict[str, object]:
        return {"op": "load", "width": 4, "address": address}

    entry_esp = reg("esp")
    # Native ingress preserves the IA-32 callee-entry coordinate: logical ESP
    # addresses the physical return word and callback argument 0 follows it.
    receiver = load(add(entry_esp, 4))
    saved_esi = add(entry_esp, -4)
    call_stack = add(entry_esp, -16)
    target = load(add(load(receiver), 8))
    save_esi = {
        "family": "memory", "kind": "write", "width": 4,
        "address": saved_esi, "value": reg("esi"),
    }
    write_argument = {
        "family": "memory", "kind": "write", "width": 4,
        "address": call_stack, "value": receiver,
    }
    event = {
        "family": "external",
        "kind": "indirect_call",
        "instruction_rva": rvas[0],
        "target_rva": 0,
        "return_rva": rvas[1],
        "target": target,
        "register_inputs": {
            name: (
                call_stack if name == "esp" else
                entry_esp if name == "esi" else
                reg(name)
            )
            for name in (
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
            )
        },
        "flag_inputs": {
            name: {"op": "flag", "name": name}
            for name in ("cf", "zf", "sf", "of", "pf", "df")
        },
        "arguments": [receiver],
        "stack_inputs": [{"offset": 0, "width": 4, "value": receiver}],
    }
    call = transfer_row()
    call["id"] = "semantic-transfer:fixture-interface-callback-target-call"
    call["original"] = {
        "rva_start": rvas[0], "rva_end": rvas[0] + 1, "size": 1,
    }
    call["memory_events"] = [
        {key: value for key, value in item.items() if key != "family"}
        for item in (save_esi, write_argument)
    ]
    call["external_events"] = [event]
    call["ordered_events"] = [save_esi, write_argument, event]
    call["register_writes"] = []
    call["outcome"] = {"kind": "fallthrough", "target_rva": rvas[1]}

    finish = transfer_row()
    finish["id"] = "semantic-transfer:fixture-interface-callback-target-return"
    finish["original"] = {
        "rva_start": rvas[1], "rva_end": rvas[1] + 1, "size": 1,
    }
    # Preserve the callback entry coordinate in callee-saved ESI across the
    # outgoing stdcall.  This is the same frame-base discipline used by the
    # larger interface fixture and avoids depending on outgoing ESP while the
    # checked bridge translates the physical callee cleanup.
    value = {
        "op": "xor32",
        "args": [reg("eax"), load(add(reg("esi"), 8))],
    }
    finish["register_writes"] = [
        {"register": "esi", "value": load(add(reg("esi"), -4))},
        {"register": "eax", "value": value},
    ]
    finish["outcome"] = {"kind": "return", "value": value}
    return [call, finish]


def write_native_module_fixture(
    root: Path, *, original_pe: Path | None = None,
    interface_profile: Path | None = None,
    include_export_ingress: bool = False,
    callback_target_rva: int | None = None,
    exception_handler_rva: int | None = None,
    exception_resumption_rva: int | None = None,
    exception_finally_inner_rva: int | None = None,
    exception_finally_outer_rva: int | None = None,
    nonlocal_callee_rva: int | None = None,
    nonlocal_continuation_rva: int | None = None,
    unwind_handler_rva: int | None = None,
    unwind_continuation_rva: int | None = None,
    pin_numeric_exception_addresses: bool = False,
) -> dict[str, Path]:
    if include_export_ingress and original_pe is None:
        raise ValueError(
            "export-ingress fixture requires an exact original module interface"
        )
    if interface_profile is not None and (
        original_pe is None or not include_export_ingress
    ):
        raise ValueError(
            "interface fixture requires an exact exported PE32 module"
        )
    if callback_target_rva is not None and (
        not include_export_ingress
        or not isinstance(callback_target_rva, int)
        or isinstance(callback_target_rva, bool)
        or callback_target_rva <= 0
    ):
        raise ValueError("callback target RVA requires checked export ingress")
    exception_targets = (
        exception_handler_rva,
        exception_resumption_rva,
        exception_finally_inner_rva,
        exception_finally_outer_rva,
    )
    if any(value is not None for value in exception_targets) and (
        not include_export_ingress
        or any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value <= 0
            for value in exception_targets
        )
    ):
        raise ValueError("guest exception RVAs require one checked set")
    if pin_numeric_exception_addresses and any(
        value is None for value in exception_targets
    ):
        raise ValueError("pinned numeric fixture requires checked exceptions")
    nonlocal_targets = (nonlocal_callee_rva, nonlocal_continuation_rva)
    if any(value is not None for value in nonlocal_targets) and (
        not include_export_ingress
        or any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value <= 0
            for value in nonlocal_targets
        )
    ):
        raise ValueError("checked nonlocal fixture RVAs require one exact pair")
    unwind_targets = (unwind_handler_rva, unwind_continuation_rva)
    if any(value is not None for value in unwind_targets) and (
        not include_export_ingress
        or any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value <= 0
            for value in unwind_targets
        )
    ):
        raise ValueError("checked unwind fixture RVAs require one exact pair")
    load_contract: Path | None = None
    module_interface: Path | None = None
    module_interface_sha256 = "a" * 64
    module_interface_identity = module_interface_sha256
    module_pe_sha256 = "f" * 64
    image_id = "fixture.exe"
    module_kind = "executable"
    image_base = 0x400000
    entry_rva = 0x1000
    export_targets: list[dict[str, object]] = []
    tls_callbacks: list[dict[str, int]] = []
    tls_template_bytes = 0
    tls_zero_fill_bytes = 0
    data_export_rva: int | None = None
    stack_reserve = 0x100000
    callback_registration_import: dict[str, object] | None = None
    unhandled_filter_import: dict[str, object] | None = None
    rtl_unwind_import: dict[str, object] | None = None
    raise_exception_import: dict[str, object] | None = None
    exit_process_import: dict[str, object] | None = None
    factory_import: dict[str, object] | None = None
    factory_contract: SelectedMachineImportContract | None = None
    interface_method_catalogs: list[dict[str, object]] = []
    interface_profile_sha256s: list[str] = []
    original_import_inventory: list[dict[str, object]] = []
    if original_pe is not None:
        from spaghetti_extractor.roundtrip_fuzz.image_io import (
            write_spx_load_image_contract,
        )
        module_pe_sha256 = sha256_file(original_pe)
        load_contract = root / "load-image-contract.json"
        write_spx_load_image_contract(original_pe=original_pe, out=load_contract)
        interface_root = root / "interface"
        write_pe32_module_interface(
            image_id=original_pe.name,
            original_pe=original_pe,
            load_image_contract=load_contract,
            out=interface_root,
        )
        module_interface = interface_root / "module-interface.json"
        module_interface_sha256 = sha256_file(module_interface)
        interface_payload = json.loads(module_interface.read_text(encoding="utf-8"))
        original_import_inventory = [
            dict(row) for row in interface_payload["imports"]
        ]
        module_interface_identity = str(interface_payload["interface_sha256"])
        image_id = str(interface_payload["image_id"])
        module_kind = str(interface_payload["kind"])
        image_base = int(interface_payload["loader"]["preferred_base"])
        entry_rva = int(interface_payload["loader"]["entry_rva"])
        stack_reserve = int(interface_payload["loader"]["stack"]["reserve"])
        if interface_profile is not None:
            loaded_interface = load_external_interface_profile(
                Path(interface_profile)
            )
            selected_factories = load_machine_import_profile_set([
                Path(interface_profile)
            ]).contracts
            if (
                len(loaded_interface.factories) != 1
                or len(selected_factories) != 1
                or selected_factories[0].identity
                != loaded_interface.factories[0].identity
            ):
                raise ValueError(
                    "fixture interface profile has no single exact factory"
                )
            factory_contract = selected_factories[0]
            factory_rows = [
                row for row in interface_payload["imports"]
                if MachineImportIdentity.from_mapping(
                    row, context="fixture factory import"
                ) == factory_contract.identity
            ]
            if len(factory_rows) != 1:
                raise ValueError(
                    "fixture interface factory import is not loader-exact"
                )
            factory_import = dict(factory_rows[0])
            interface_profile_sha256s = [loaded_interface.sha256]
            interface_method_catalogs = [
                {
                    "interface_id": interface.interface_id,
                    "profile_id": loaded_interface.profile_id,
                    "profile_sha256": loaded_interface.sha256,
                    "vtable": interface.vtable,
                    "methods": [
                        method.target_json(
                            profile_id=loaded_interface.profile_id,
                            profile_sha256=loaded_interface.sha256,
                        )
                        for method in interface.methods
                    ],
                }
                for interface in loaded_interface.interfaces
            ]
        exit_imports = [
            row for row in interface_payload["imports"]
            if str(row["dll"]).lower() == "kernel32.dll"
            and row.get("symbol") == "ExitProcess"
        ]
        if len(exit_imports) != 1:
            raise ValueError("fixture process-termination import is not exact")
        exit_process_import = dict(exit_imports[0])
        if callback_target_rva is not None:
            callback_imports = [
                row for row in interface_payload["imports"]
                if str(row["dll"]).lower() == "kernel32.dll"
                and row.get("symbol") == "SetUnhandledExceptionFilter"
            ]
            if len(callback_imports) != 1:
                raise ValueError(
                    "fixture callback registration import is not exact"
                )
            callback_registration_import = dict(callback_imports[0])
        if include_export_ingress:
            unhandled_filter_imports = [
                row for row in interface_payload["imports"]
                if str(row["dll"]).lower() == "kernel32.dll"
                and row.get("symbol") == "UnhandledExceptionFilter"
            ]
            if len(unhandled_filter_imports) != 1:
                raise ValueError(
                    "fixture checked exception-filter service import is not exact"
                )
            unhandled_filter_import = dict(unhandled_filter_imports[0])
            rtl_unwind_imports = [
                row for row in interface_payload["imports"]
                if str(row["dll"]).lower() == "kernel32.dll"
                and row.get("symbol") == "RtlUnwind"
            ]
            if len(rtl_unwind_imports) != 1:
                raise ValueError(
                    "fixture checked unwind service import is not exact"
                )
            rtl_unwind_import = dict(rtl_unwind_imports[0])
        if exception_handler_rva is not None:
            exception_imports = [
                row for row in interface_payload["imports"]
                if str(row["dll"]).lower() == "kernel32.dll"
                and row.get("symbol") == "RaiseException"
            ]
            if len(exception_imports) != 1:
                raise ValueError(
                    "fixture host-import exception identity is not exact"
                )
            raise_exception_import = dict(exception_imports[0])
        tls_payload = interface_payload.get("tls")
        if isinstance(tls_payload, dict):
            tls_callbacks = [
                {"order": int(row["order"]), "rva": int(row["rva"])}
                for row in tls_payload["callbacks"]
            ]
            tls_template_bytes = int(tls_payload["template_size"])
            tls_zero_fill_bytes = int(tls_payload["zero_fill_size"])
        if include_export_ingress:
            if module_kind != "dll":
                raise ValueError("export-ingress fixture requires an original DLL")
            code_slots = [
                row for row in interface_payload["export_directory"]["slots"]
                if row["kind"] == "code"
            ]
            slots_by_rva: dict[int, list[dict[str, object]]] = {}
            for row in code_slots:
                slots_by_rva.setdefault(int(row["rva"]), []).append(row)
            for target_index, (target_rva, target_slots) in enumerate(
                sorted(slots_by_rva.items())
            ):
                aliases = [
                    {"name": name, "ordinal": int(row["ordinal"])}
                    for row in target_slots
                    for name in row["names"]
                ]
                names = {str(alias["name"]) for alias in aliases}
                suffix = (
                    "fixture-export"
                    if "fixture_export" in names else
                    "fixture-atomic"
                    if "fixture_atomic" in names else
                    "fixture-reentrant"
                    if "fixture_reentrant" in names else
                    "fixture-hardware-seh"
                    if "fixture_hardware_seh" in names else
                    "fixture-register-callback"
                    if "fixture_register_callback" in names else
                    "fixture-unhandled-filter"
                    if "fixture_unhandled_filter" in names else
                    "fixture-unwind"
                    if "fixture_unwind" in names else
                    "fixture-access-violation"
                    if "fixture_access_violation" in names else
                    "fixture-hardware-access-violation"
                    if "fixture_hardware_access_violation" in names else
                    "fixture-host-import-seh"
                    if "fixture_host_import_seh" in names else
                    "fixture-nonlocal"
                    if "fixture_nonlocal" in names else
                    "fixture-interface"
                    if "fixture_interface" in names else
                    "fixture-interface-stale"
                    if "fixture_interface_stale" in names else
                    "fixture-interface-record"
                    if "fixture_interface_record" in names else
                    "fixture-interface-callback"
                    if "fixture_interface_callback_flow" in names else
                    "fixture-interface-callback-target"
                    if "fixture_interface_callback" in names else
                    "fixture-seh"
                    if "fixture_seh" in names else
                    f"fixture-export-{target_index:04d}"
                )
                export_targets.append({
                    "rva": target_rva,
                    "aliases": aliases,
                    "unit_suffix": suffix,
                })
            if not export_targets:
                raise ValueError("export-ingress fixture has no code target")
            data_slots = [
                row for row in interface_payload["export_directory"]["slots"]
                if row["kind"] == "data" and "fixture_data" in row["names"]
            ]
            if len(data_slots) != 1:
                raise ValueError(
                    "export-ingress fixture requires one exact fixture_data slot"
                )
            data_export_rva = int(data_slots[0]["rva"])
    machine = root / "machine-ir.jsonl"
    entry_row = transfer_row()
    entry_row["id"] = (
        "semantic-transfer:fixture-entry"
        if include_export_ingress else "semantic-transfer:fixture"
    )
    entry_row["original"] = {
        "rva_start": entry_rva, "rva_end": entry_rva + 1, "size": 1,
    }
    entry_row["register_writes"] = []
    set_eax_return_semantics(entry_row, {"op": "const", "value": 1, "width": 32})
    rows = [entry_row]
    if include_export_ingress:
        export_entry_rvas = {
            int(target["rva"]) for target in export_targets
        }
        for target in export_targets:
            if target["unit_suffix"] in {
                "fixture-interface", "fixture-interface-stale",
                "fixture-interface-record",
                "fixture-interface-callback",
            }:
                if original_pe is None or factory_import is None:
                    raise ValueError(
                        "interface export has no checked loader factory"
                    )
                rows.extend(_fixture_interface_transfer_rows(
                    original_pe=original_pe,
                    target_rva=int(target["rva"]),
                    unit_suffix=str(target["unit_suffix"]),
                    factory_import=factory_import,
                    other_entry_rvas=export_entry_rvas,
                    image_base=image_base,
                    callback_target_rva=next(
                        (
                            int(row["rva"]) for row in export_targets
                            if row["unit_suffix"]
                            == "fixture-interface-callback-target"
                        ),
                        None,
                    ),
                ))
                continue
            if target["unit_suffix"] == "fixture-interface-callback-target":
                if original_pe is None:
                    raise ValueError(
                        "interface callback target has no original PE"
                    )
                rows.extend(_fixture_interface_callback_target_rows(
                    original_pe=original_pe,
                    target_rva=int(target["rva"]),
                    other_entry_rvas=export_entry_rvas,
                ))
                continue
            export_row = transfer_row()
            export_row["id"] = (
                f"semantic-transfer:{target['unit_suffix']}"
            )
            target_rva = int(target["rva"])
            export_row["original"] = {
                "rva_start": target_rva,
                "rva_end": target_rva + 1,
                "size": 1,
            }
            export_row["register_writes"] = []
            if target["unit_suffix"] in {
                "fixture-seh", "fixture-hardware-seh",
                "fixture-access-violation",
                "fixture-hardware-access-violation",
            }:
                fault = (
                    {
                        "kind": "access_violation",
                        "condition": {"op": "true"},
                        "operation": {
                            "op": "const", "value": 1, "width": 32,
                        },
                        "address": {
                            "op": "const", "value": 0x1BADB002,
                            "width": 32,
                        },
                    }
                    if target["unit_suffix"] in {
                        "fixture-access-violation",
                        "fixture-hardware-access-violation",
                    }
                    else {
                        "kind": "divide_error",
                        "condition": {"op": "true"},
                    }
                )
                fault["instruction_rva"] = target_rva
                export_row["faults"] = [fault]
                export_row["ordered_events"] = [{"family": "fault", **fault}]
                if target["unit_suffix"] in {
                    "fixture-seh", "fixture-access-violation",
                }:
                    # Preserve the physical ABI's original EDI in a clobbered
                    # machine register before exporting the continuable fault.
                    # The checked continuation consumes the host-projected EDI
                    # and restores this value before the boundary returns.
                    saved_edi = {
                        "register": "ecx",
                        "value": {
                            "op": "reg", "name": "edi", "width": 32,
                        },
                    }
                    classification = {
                        "status": "proposal_requires_lean_exact_byte_replay",
                        "proof_authority": False,
                        "checked_decoder": (
                            "SpaghettiExtractor.ISA.Formal.decodeInstructionExact"
                        ),
                        "checked_executor": (
                            "SpaghettiExtractor.ISA.Formal.executeInstruction"
                        ),
                    }
                    fault["instruction_rva"] = target_rva + 1
                    export_row["faults"] = [fault]
                    export_row["ordered_events"] = [
                        {"family": "fault", **fault}
                    ]
                    export_row["original"]["rva_end"] = target_rva + 2
                    export_row["original"]["size"] = 2
                    export_row["register_writes"] = [saved_edi]
                    export_row["instruction_effect_schedule"] = {
                        "format": (
                            "spaghetti-extractor-static-instruction-effects-v1"
                        ),
                        "status": "complete",
                        "proof_authority": False,
                        "blockers": [],
                        "ordering": "strict_contiguous_rva_order",
                        "rva_start": target_rva,
                        "rva_end": target_rva + 2,
                        "counts": {
                            "instructions": 2,
                            "ordinary_instructions": 2,
                            "x87_singletons": 0,
                            "blockers": 0,
                        },
                        "records": [{
                            "rva_start": target_rva,
                            "rva_end": target_rva + 1,
                            "instruction_class": "ordinary_symbolic_instruction",
                            "classification": classification,
                            "effects": {
                                "control": {
                                    "kind": "fallthrough",
                                    "target_rva": target_rva + 1,
                                },
                                "ordered_events": [],
                                "register_writes": [saved_edi],
                                "defined_flag_writes": [],
                                "undefined_flag_writes": [],
                                "undefined_flags": [],
                            },
                        }, {
                            "rva_start": target_rva + 1,
                            "rva_end": target_rva + 2,
                            "instruction_class": "ordinary_symbolic_instruction",
                            "classification": classification,
                            "effects": {
                                "control": {
                                    "kind": "return",
                                    "value": {
                                        "op": "const", "value": 0,
                                        "width": 32,
                                    },
                                },
                                "ordered_events": [
                                    {"family": "fault", **fault}
                                ],
                                "register_writes": [],
                                "defined_flag_writes": [],
                                "undefined_flag_writes": [],
                                "undefined_flags": [],
                            },
                        }],
                    }
                elif target["unit_suffix"] == "fixture-hardware-seh":
                    hardware_marker = {
                        "register": "ecx",
                        "value": {
                            "op": "const", "value": 0x48534548,
                            "width": 32,
                        },
                    }
                    classification = {
                        "status": "proposal_requires_lean_exact_byte_replay",
                        "proof_authority": False,
                        "checked_decoder": (
                            "SpaghettiExtractor.ISA.Formal.decodeInstructionExact"
                        ),
                        "checked_executor": (
                            "SpaghettiExtractor.ISA.Formal.executeInstruction"
                        ),
                    }
                    fault["instruction_rva"] = target_rva + 1
                    export_row["faults"] = [fault]
                    export_row["ordered_events"] = [
                        {"family": "fault", **fault}
                    ]
                    export_row["original"]["rva_end"] = target_rva + 2
                    export_row["original"]["size"] = 2
                    export_row["register_writes"] = [hardware_marker]
                    export_row["instruction_effect_schedule"] = {
                        "format": (
                            "spaghetti-extractor-static-instruction-effects-v1"
                        ),
                        "status": "complete",
                        "proof_authority": False,
                        "blockers": [],
                        "ordering": "strict_contiguous_rva_order",
                        "rva_start": target_rva,
                        "rva_end": target_rva + 2,
                        "counts": {
                            "instructions": 2,
                            "ordinary_instructions": 2,
                            "x87_singletons": 0,
                            "blockers": 0,
                        },
                        "records": [{
                            "rva_start": target_rva,
                            "rva_end": target_rva + 1,
                            "instruction_class": "ordinary_symbolic_instruction",
                            "classification": classification,
                            "effects": {
                                "control": {
                                    "kind": "fallthrough",
                                    "target_rva": target_rva + 1,
                                },
                                "ordered_events": [],
                                "register_writes": [hardware_marker],
                                "defined_flag_writes": [],
                                "undefined_flag_writes": [],
                                "undefined_flags": [],
                            },
                        }, {
                            "rva_start": target_rva + 1,
                            "rva_end": target_rva + 2,
                            "instruction_class": "ordinary_symbolic_instruction",
                            "classification": classification,
                            "effects": {
                                "control": {
                                    "kind": "return",
                                    "value": {
                                        "op": "const", "value": 0,
                                        "width": 32,
                                    },
                                },
                                "ordered_events": [
                                    {"family": "fault", **fault}
                                ],
                                "register_writes": [],
                                "defined_flag_writes": [],
                                "undefined_flag_writes": [],
                                "undefined_flags": [],
                            },
                        }],
                    }
            if target["unit_suffix"] == "fixture-register-callback":
                if (
                    callback_target_rva is None
                    or callback_registration_import is None
                ):
                    raise ValueError(
                        "callback registration export lacks exact call authority"
                    )
                callback_value = {
                    "op": "const",
                    "value": image_base + callback_target_rva,
                    "width": 32,
                }
                source_stack_pointer = {
                    "op": "reg", "name": "esp", "width": 32,
                }
                call_stack_pointer = {
                    "op": "sub32", "args": [
                        source_stack_pointer,
                        {"op": "const", "value": 4, "width": 32},
                    ],
                }
                stack_write = {
                    "family": "memory",
                    "kind": "write",
                    "width": 4,
                    "address": call_stack_pointer,
                    "value": callback_value,
                }
                call_event = {
                    "family": "external",
                    "kind": "external_call",
                    "instruction_rva": target_rva,
                    "target_rva": 0,
                    "return_rva": target_rva + 1,
                    "dll": str(callback_registration_import["dll"]),
                    "symbol": "SetUnhandledExceptionFilter",
                    "ordinal": None,
                    "register_inputs": {
                        name: (
                            call_stack_pointer
                            if name == "esp"
                            else {"op": "reg", "name": name, "width": 32}
                        )
                        for name in (
                            "eax", "ebx", "ecx", "edx",
                            "esi", "edi", "ebp", "esp",
                        )
                    },
                    "flag_inputs": {
                        name: {"op": "flag", "name": name}
                        for name in ("cf", "zf", "sf", "of", "pf", "df")
                    },
                    "arguments": [callback_value],
                    "stack_inputs": [{
                        "offset": 0,
                        "width": 4,
                        "value": callback_value,
                    }],
                }
                export_row["memory_events"] = [{
                    key: value for key, value in stack_write.items()
                    if key != "family"
                }]
                export_row["external_events"] = [call_event]
                export_row["ordered_events"] = [stack_write, call_event]
            if target["unit_suffix"] == "fixture-unhandled-filter":
                if unhandled_filter_import is None:
                    raise ValueError(
                        "exception-filter export lacks its exact service import"
                    )
                source_stack_pointer = {
                    "op": "reg", "name": "esp", "width": 32,
                }
                exception_pointers = {
                    "op": "load",
                    "width": 4,
                    "address": {
                        "op": "add32",
                        "args": [
                            source_stack_pointer,
                            {"op": "const", "value": 4, "width": 32},
                        ],
                    },
                }
                call_stack_pointer = {
                    "op": "sub32", "args": [
                        source_stack_pointer,
                        {"op": "const", "value": 4, "width": 32},
                    ],
                }
                stack_write = {
                    "family": "memory",
                    "kind": "write",
                    "width": 4,
                    "address": call_stack_pointer,
                    "value": exception_pointers,
                }
                call_event = {
                    "family": "external",
                    "kind": "external_call",
                    "instruction_rva": target_rva,
                    "target_rva": 0,
                    "return_rva": target_rva + 1,
                    "dll": str(unhandled_filter_import["dll"]),
                    "symbol": "UnhandledExceptionFilter",
                    "ordinal": None,
                    "register_inputs": {
                        name: (
                            call_stack_pointer
                            if name == "esp"
                            else {"op": "reg", "name": name, "width": 32}
                        )
                        for name in (
                            "eax", "ebx", "ecx", "edx",
                            "esi", "edi", "ebp", "esp",
                        )
                    },
                    "flag_inputs": {
                        name: {"op": "flag", "name": name}
                        for name in ("cf", "zf", "sf", "of", "pf", "df")
                    },
                    "arguments": [exception_pointers],
                    "stack_inputs": [{
                        "offset": 0,
                        "width": 4,
                        "value": exception_pointers,
                    }],
                }
                export_row["memory_events"] = [{
                    key: value for key, value in stack_write.items()
                    if key != "family"
                }]
                export_row["external_events"] = [call_event]
                export_row["ordered_events"] = [stack_write, call_event]
            if target["unit_suffix"] == "fixture-host-import-seh":
                if raise_exception_import is None:
                    raise ValueError(
                        "host-import SEH export lacks exact RaiseException identity"
                    )
                source_stack_pointer = {
                    "op": "reg", "name": "esp", "width": 32,
                }
                call_stack_pointer = {
                    "op": "sub32",
                    "args": [
                        source_stack_pointer,
                        {"op": "const", "value": 16, "width": 32},
                    ],
                }
                arguments = [
                    {
                        "op": "load",
                        "width": 4,
                        "address": {
                            "op": "add32",
                            "args": [
                                source_stack_pointer,
                                {
                                    "op": "const",
                                    "value": 4 + index * 4,
                                    "width": 32,
                                },
                            ],
                        },
                    }
                    for index in range(4)
                ]
                stack_writes = [
                    {
                        "family": "memory",
                        "kind": "write",
                        "width": 4,
                        "address": {
                            "op": "add32",
                            "args": [
                                call_stack_pointer,
                                {
                                    "op": "const",
                                    "value": index * 4,
                                    "width": 32,
                                },
                            ],
                        },
                        "value": value,
                    }
                    for index, value in enumerate(arguments)
                ]
                call_event = {
                    "family": "external",
                    "kind": "external_call",
                    "instruction_rva": target_rva,
                    "target_rva": 0,
                    "return_rva": target_rva + 1,
                    "dll": str(raise_exception_import["dll"]),
                    "symbol": "RaiseException",
                    "ordinal": None,
                    "register_inputs": {
                        name: (
                            call_stack_pointer
                            if name == "esp"
                            else {"op": "reg", "name": name, "width": 32}
                        )
                        for name in (
                            "eax", "ebx", "ecx", "edx",
                            "esi", "edi", "ebp", "esp",
                        )
                    },
                    "flag_inputs": {
                        name: {"op": "flag", "name": name}
                        for name in ("cf", "zf", "sf", "of", "pf", "df")
                    },
                    "arguments": arguments,
                    "stack_inputs": [
                        {"offset": index * 4, "width": 4, "value": value}
                        for index, value in enumerate(arguments)
                    ],
                    "native_exception_operations": ["divide_if"],
                }
                export_row["memory_events"] = [
                    {key: value for key, value in event.items() if key != "family"}
                    for event in stack_writes
                ]
                export_row["external_events"] = [call_event]
                export_row["ordered_events"] = [*stack_writes, call_event]
            if target["unit_suffix"] == "fixture-nonlocal":
                if any(value is None for value in nonlocal_targets):
                    raise ValueError(
                        "nonlocal export lacks exact callee and continuation RVAs"
                    )
                call_event = {
                    "family": "external",
                    "kind": "internal_call",
                    "instruction_rva": target_rva,
                    "target_rva": int(nonlocal_callee_rva),
                    "return_rva": int(nonlocal_continuation_rva),
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
                export_row["external_events"] = [call_event]
                export_row["ordered_events"] = [call_event]
                export_row["outcome"] = {
                    "kind": "fallthrough",
                    "target_rva": int(nonlocal_continuation_rva),
                }
            elif target["unit_suffix"] == "fixture-unwind":
                if (
                    any(value is None for value in unwind_targets)
                    or rtl_unwind_import is None
                ):
                    raise ValueError(
                        "unwind export lacks exact handler, continuation, or import"
                    )
                stack = {"op": "reg", "name": "esp", "width": 32}
                fs_head = {"op": "fs_base"}
                target_frame = {
                    "op": "sub32", "args": [
                        stack, {"op": "const", "value": 32, "width": 32},
                    ],
                }
                younger_frame = {
                    "op": "sub32", "args": [
                        stack, {"op": "const", "value": 64, "width": 32},
                    ],
                }
                handler = {
                    "op": "const",
                    "value": image_base + int(unwind_handler_rva),
                    "width": 32,
                }
                sentinel = {
                    "op": "const", "value": 0xFFFFFFFF, "width": 32,
                }
                registration_writes = [
                    {
                        "family": "memory", "kind": "write", "width": 4,
                        "address": target_frame, "value": sentinel,
                    },
                    {
                        "family": "memory", "kind": "write", "width": 4,
                        "address": {
                            "op": "add32", "args": [
                                target_frame,
                                {"op": "const", "value": 4, "width": 32},
                            ],
                        },
                        "value": handler,
                    },
                    {
                        "family": "memory", "kind": "write", "width": 4,
                        "address": younger_frame, "value": target_frame,
                    },
                    {
                        "family": "memory", "kind": "write", "width": 4,
                        "address": {
                            "op": "add32", "args": [
                                younger_frame,
                                {"op": "const", "value": 4, "width": 32},
                            ],
                        },
                        "value": handler,
                    },
                    {
                        "family": "memory", "kind": "write", "width": 4,
                        "address": fs_head, "value": younger_frame,
                    },
                ]
                arguments = [
                    target_frame,
                    {
                        "op": "const",
                        "value": image_base + int(unwind_continuation_rva),
                        "width": 32,
                    },
                    {"op": "const", "value": 0, "width": 32},
                    {"op": "const", "value": 0x554E5744, "width": 32},
                ]
                call_stack_pointer = {
                    "op": "sub32", "args": [
                        stack, {"op": "const", "value": 16, "width": 32},
                    ],
                }
                argument_writes = [
                    {
                        "family": "memory", "kind": "write", "width": 4,
                        "address": {
                            "op": "add32", "args": [
                                call_stack_pointer,
                                {"op": "const", "value": index * 4,
                                 "width": 32},
                            ],
                        },
                        "value": value,
                    }
                    for index, value in enumerate(arguments)
                ]
                call_event = {
                    "family": "external",
                    "kind": "external_call",
                    "instruction_rva": target_rva,
                    "target_rva": 0,
                    "return_rva": int(unwind_continuation_rva),
                    "dll": str(rtl_unwind_import["dll"]),
                    "symbol": "RtlUnwind",
                    "ordinal": None,
                    "register_inputs": {
                        name: (
                            call_stack_pointer if name == "esp" else
                            {"op": "reg", "name": name, "width": 32}
                        )
                        for name in (
                            "eax", "ebx", "ecx", "edx",
                            "esi", "edi", "ebp", "esp",
                        )
                    },
                    "flag_inputs": {
                        name: {"op": "flag", "name": name}
                        for name in ("cf", "zf", "sf", "of", "pf", "df")
                    },
                    "arguments": arguments,
                    "stack_inputs": [
                        {"offset": index * 4, "width": 4, "value": value}
                        for index, value in enumerate(arguments)
                    ],
                }
                ordered = [*registration_writes, *argument_writes, call_event]
                export_row["memory_events"] = [
                    {key: value for key, value in event.items()
                     if key != "family"}
                    for event in (*registration_writes, *argument_writes)
                ]
                export_row["external_events"] = [call_event]
                export_row["ordered_events"] = ordered
                export_row["outcome"] = {
                    "kind": "fallthrough",
                    "target_rva": int(unwind_continuation_rva),
                }
            elif target["unit_suffix"] == "fixture-atomic":
                if data_export_rva is None:
                    raise ValueError(
                        "atomic fixture lacks its exact data-export RVA"
                    )
                address = {
                    "op": "const",
                    "value": image_base + data_export_rva,
                    "width": 32,
                }
                observed = {"op": "load", "width": 4, "address": address}
                expected = {"op": "reg", "name": "eax", "width": 32}
                desired = {
                    "op": "add32", "args": [
                        expected,
                        {"op": "const", "value": 1, "width": 32},
                    ],
                }
                read_current = {
                    "kind": "read", "width": 4, "address": address,
                }
                atomic_read = {
                    "kind": "read", "width": 4, "address": address,
                }
                atomic_write = {
                    "kind": "write", "width": 4, "address": address,
                    "value": {
                        "op": "ite", "args": [
                            {"op": "eq", "args": [observed, expected]},
                            desired,
                            observed,
                        ],
                    },
                }
                ordered = [
                    {
                        "family": "memory", "instruction_rva": target_rva,
                        **read_current,
                    },
                    {
                        "family": "memory",
                        "instruction_rva": target_rva + 1,
                        **atomic_read,
                    },
                    {
                        "family": "memory",
                        "instruction_rva": target_rva + 1,
                        **atomic_write,
                    },
                ]
                memory_events = [read_current, atomic_read, atomic_write]
                export_row["original"]["rva_end"] = target_rva + 2
                export_row["original"]["size"] = 2
                export_row["memory_events"] = memory_events
                export_row["ordered_events"] = ordered
                export_row["memory_actions"] = build_memory_action_graph(
                    instructions=[{
                        "rva_start": target_rva + 1,
                        "mnemonic": "lock cmpxchg",
                        "operands": [{
                            "kind": "memory", "segment": None,
                            "base": None, "index": None, "scale": 1,
                            "displacement": image_base + data_export_rva,
                            "width_bits": 32,
                        }, {
                            "kind": "register", "name": "ecx",
                            "width_bits": 32,
                        }],
                    }],
                    memory_events=memory_events,
                    ordered_events=ordered,
                )
                branch = {
                    "kind": "branch",
                    "condition": {"op": "eq", "args": [observed, expected]},
                    "true_target_rva": target_rva + 2,
                    "false_target_rva": target_rva,
                }
                classification = {
                    "status": (
                        "proposal_requires_lean_exact_byte_replay"
                    ),
                    "proof_authority": False,
                    "checked_decoder": (
                        "SpaghettiExtractor.ISA.Formal.decodeInstructionExact"
                    ),
                    "checked_executor": (
                        "SpaghettiExtractor.ISA.Formal.executeInstruction"
                    ),
                }
                export_row["instruction_effect_schedule"] = {
                    "format": (
                        "spaghetti-extractor-static-instruction-effects-v1"
                    ),
                    "status": "complete",
                    "proof_authority": False,
                    "blockers": [],
                    "ordering": "strict_contiguous_rva_order",
                    "rva_start": target_rva,
                    "rva_end": target_rva + 2,
                    "counts": {
                        "instructions": 2,
                        "ordinary_instructions": 2,
                        "x87_singletons": 0,
                        "blockers": 0,
                    },
                    "records": [{
                        "rva_start": target_rva,
                        "rva_end": target_rva + 1,
                        "instruction_class": "ordinary_symbolic_instruction",
                        "classification": classification,
                        "effects": {
                            "control": {
                                "kind": "fallthrough",
                                "target_rva": target_rva + 1,
                            },
                            "ordered_events": [ordered[0]],
                            "register_writes": [{
                                "register": "eax", "value": observed,
                            }],
                            "defined_flag_writes": [],
                            "undefined_flag_writes": [],
                            "undefined_flags": [],
                        },
                    }, {
                        "rva_start": target_rva + 1,
                        "rva_end": target_rva + 2,
                        "instruction_class": "ordinary_symbolic_instruction",
                        "classification": classification,
                        "effects": {
                            "control": branch,
                            "ordered_events": ordered[1:],
                            "register_writes": [{
                                "register": "eax",
                                "value": {
                                    "op": "ite", "args": [
                                        {
                                            "op": "eq",
                                            "args": [observed, expected],
                                        },
                                        desired,
                                        observed,
                                    ],
                                },
                            }],
                            "defined_flag_writes": [],
                            "undefined_flag_writes": [],
                            "undefined_flags": [],
                        },
                    }],
                }
                export_row["outcome"] = branch
            else:
                result_value: dict[str, object]
                if target["unit_suffix"] == "fixture-reentrant":
                    # The checked exception-escape protocol resumes through this
                    # canonical unit after importing the host-modified EDI.  Keep
                    # that continuation behavior in the transfer semantics; the
                    # native runtime must not manufacture it in a fixture overlay.
                    result_value = {
                        "op": "ite",
                        "args": [
                            {
                                "op": "eq",
                                "args": [
                                    {
                                        "op": "reg", "name": "edi",
                                        "width": 32,
                                    },
                                    {
                                        "op": "const", "value": 0x13579BDF,
                                        "width": 32,
                                    },
                                ],
                            },
                            {
                                "op": "const", "value": 0x5E110001,
                                "width": 32,
                            },
                            {
                                "op": "const", "value": 0xC0DEC0DF,
                                "width": 32,
                            },
                        ],
                    }
                    continued = result_value["args"][0]
                    export_row["register_writes"] = [{
                        "register": "edi",
                        "value": {
                            "op": "ite",
                            "args": [
                                continued,
                                {
                                    "op": "reg", "name": "ecx",
                                    "width": 32,
                                },
                                {
                                    "op": "reg", "name": "edi",
                                    "width": 32,
                                },
                            ],
                        },
                    }]
                else:
                    result_value = {
                        "op": "call_response",
                        "call_index": 0,
                        "register": "eax",
                        "width": 32,
                    } if target["unit_suffix"] == (
                        "fixture-unhandled-filter"
                    ) else {
                        "op": "const",
                        "value": (
                            0xC0DEC0DE
                            if target["unit_suffix"] == "fixture-export" else
                            image_base + callback_target_rva
                            if (
                                target["unit_suffix"]
                                == "fixture-register-callback"
                                and callback_target_rva is not None
                            ) else 0
                        ),
                        "width": 32,
                    }
                if "instruction_effect_schedule" not in export_row:
                    set_eax_return_semantics(export_row, result_value)
                else:
                    export_row["outcome"] = {
                        "kind": "return", "value": result_value,
                    }
            rows.append(export_row)
            if target["unit_suffix"] == "fixture-atomic":
                atomic_return = transfer_row()
                atomic_return["id"] = (
                    "semantic-transfer:fixture-atomic-return"
                )
                atomic_return["original"] = {
                    "rva_start": target_rva + 2,
                    "rva_end": target_rva + 3,
                    "size": 1,
                }
                atomic_return["register_writes"] = []
                atomic_return["outcome"] = {
                    "kind": "return",
                    "value": {
                        "op": "reg", "name": "eax", "width": 32,
                    },
                }
                rows.append(atomic_return)
        if all(value is not None for value in nonlocal_targets):
            assert nonlocal_callee_rva is not None
            assert nonlocal_continuation_rva is not None
            occupied = {
                int(row["original"]["rva_start"]) for row in rows
            }
            if (
                nonlocal_callee_rva in occupied
                or nonlocal_continuation_rva in occupied
                or nonlocal_callee_rva == nonlocal_continuation_rva
            ):
                raise ValueError("fixture nonlocal unit RVA is ambiguous")
            nonlocal_callee = transfer_row()
            nonlocal_callee["id"] = (
                "semantic-transfer:fixture-nonlocal-callee"
            )
            nonlocal_callee["original"] = {
                "rva_start": nonlocal_callee_rva,
                "rva_end": nonlocal_callee_rva + 1,
                "size": 1,
            }
            nonlocal_callee["register_writes"] = []
            nonlocal_callee["outcome"] = {
                "kind": "nonlocal",
                "target": {
                    "op": "const", "value": nonlocal_continuation_rva,
                    "width": 32,
                },
                "value": {"op": "const", "value": 9, "width": 32},
            }
            nonlocal_continuation = transfer_row()
            nonlocal_continuation["id"] = (
                "semantic-transfer:fixture-nonlocal-continuation"
            )
            nonlocal_continuation["original"] = {
                "rva_start": nonlocal_continuation_rva,
                "rva_end": nonlocal_continuation_rva + 1,
                "size": 1,
            }
            nonlocal_continuation["register_writes"] = [{
                "register": "eax",
                "value": {
                    "op": "const", "value": 0x4E4F4E4C, "width": 32,
                },
            }, {
                "register": "esp",
                "value": {
                    "op": "add32",
                    "args": [
                        {"op": "reg", "name": "esp", "width": 32},
                        {"op": "const", "value": 4, "width": 32},
                    ],
                },
            }]
            nonlocal_continuation["outcome"] = {
                "kind": "return",
                "value": {
                    "op": "const", "value": 0x4E4F4E4C, "width": 32,
                },
            }
            rows.extend((nonlocal_callee, nonlocal_continuation))
        if all(value is not None for value in unwind_targets):
            assert unwind_handler_rva is not None
            assert unwind_continuation_rva is not None
            occupied = {
                int(row["original"]["rva_start"]) for row in rows
            }
            if (
                unwind_handler_rva in occupied
                or unwind_continuation_rva in occupied
                or unwind_handler_rva == unwind_continuation_rva
                or data_export_rva is None
            ):
                raise ValueError("fixture unwind unit RVA is ambiguous")
            handler_row = transfer_row()
            handler_row["id"] = (
                "semantic-transfer:fixture-guest-unwind-handler"
            )
            handler_row["original"] = {
                "rva_start": unwind_handler_rva,
                "rva_end": unwind_handler_rva + 1,
                "size": 1,
            }
            handler_stack = {
                "op": "reg", "name": "esp", "width": 32,
            }
            record = {
                "op": "load", "width": 4,
                "address": {
                    "op": "add32", "args": [
                        handler_stack,
                        {"op": "const", "value": 4, "width": 32},
                    ],
                },
            }
            flags = {
                "op": "load", "width": 4,
                "address": {
                    "op": "add32", "args": [
                        record,
                        {"op": "const", "value": 4, "width": 32},
                    ],
                },
            }
            counter = {
                "op": "const",
                "value": image_base + data_export_rva,
                "width": 32,
            }
            counter_write = {
                "kind": "write", "width": 4, "address": counter,
                "value": {
                    "op": "add32", "args": [
                        {"op": "load", "width": 4, "address": counter},
                        {"op": "const", "value": 1, "width": 32},
                    ],
                },
            }
            handler_row["memory_events"] = [counter_write]
            handler_row["ordered_events"] = [
                {"family": "memory", **counter_write},
            ]
            handler_row["register_writes"] = []
            set_eax_return_semantics(handler_row, {
                "op": "ite", "args": [
                    {
                        "op": "eq", "args": [
                            {
                                "op": "and32", "args": [
                                    flags,
                                    {"op": "const", "value": 2,
                                     "width": 32},
                                ],
                            },
                            {"op": "const", "value": 2, "width": 32},
                        ],
                    },
                    {"op": "const", "value": 0, "width": 32},
                    {"op": "const", "value": 1, "width": 32},
                ],
            })
            continuation_row = transfer_row()
            continuation_row["id"] = (
                "semantic-transfer:fixture-unwind-continuation"
            )
            continuation_row["original"] = {
                "rva_start": unwind_continuation_rva,
                "rva_end": unwind_continuation_rva + 1,
                "size": 1,
            }
            unlink = {
                "kind": "write", "width": 4,
                "address": {"op": "fs_base"},
                "value": {"op": "const", "value": 0xFFFFFFFF, "width": 32},
            }
            continuation_row["memory_events"] = [unlink]
            continuation_row["ordered_events"] = [
                {"family": "memory", **unlink},
            ]
            continuation_row["register_writes"] = []
            set_eax_return_semantics(continuation_row, {
                "op": "const", "value": 0x554E5744, "width": 32,
            })
            rows.extend((handler_row, continuation_row))
        if exception_handler_rva is not None and exception_resumption_rva is not None:
            for identity, rva in (
                ("semantic-transfer:fixture-guest-exception-handler", exception_handler_rva),
                (
                    "semantic-transfer:fixture-guest-exception-resumption",
                    exception_resumption_rva,
                ),
                (
                    "semantic-transfer:fixture-guest-finally-inner",
                    exception_finally_inner_rva,
                ),
                (
                    "semantic-transfer:fixture-guest-finally-outer",
                    exception_finally_outer_rva,
                ),
            ):
                assert rva is not None
                if rva in {
                    int(row["original"]["rva_start"]) for row in rows
                }:
                    raise ValueError("fixture guest exception unit RVA is ambiguous")
                exception_row = transfer_row()
                exception_row["id"] = identity
                exception_row["original"] = {
                    "rva_start": rva, "rva_end": rva + 1, "size": 1,
                }
                exception_row["register_writes"] = []
                result = 0
                if identity == (
                    "semantic-transfer:fixture-guest-exception-handler"
                ):
                    stack = {"op": "reg", "name": "esp", "width": 32}
                    record_cell = {
                        "op": "add32", "args": [
                            stack,
                            {"op": "const", "value": 4, "width": 32},
                        ],
                    }
                    context_cell = {
                        "op": "add32", "args": [
                            stack,
                            {"op": "const", "value": 12, "width": 32},
                        ],
                    }
                    record = {
                        "op": "load", "width": 4,
                        "address": record_cell,
                    }
                    context = {
                        "op": "load", "width": 4,
                        "address": context_cell,
                    }
                    exception_code = {
                        "op": "load", "width": 4, "address": record,
                    }
                    nested_record_cell = {
                        "op": "add32", "args": [
                            record,
                            {"op": "const", "value": 8, "width": 32},
                        ],
                    }
                    nested_record = {
                        "op": "load", "width": 4,
                        "address": nested_record_cell,
                    }
                    context_eax = {
                        "op": "add32", "args": [
                            context,
                            {"op": "const", "value": 44 * 4, "width": 32},
                        ],
                    }
                    context_eip = {
                        "op": "add32", "args": [
                            context,
                            {"op": "const", "value": 46 * 4, "width": 32},
                        ],
                    }
                    pinned_divide = {
                        "op": "and_bool", "args": [
                            {
                                "op": "eq", "args": [
                                    exception_code,
                                    {
                                        "op": "const", "value": 0xC0000094,
                                        "width": 32,
                                    },
                                ],
                            },
                            {
                                "op": "eq", "args": [
                                    {
                                        "op": "reg", "name": "ecx",
                                        "width": 32,
                                    },
                                    {
                                        "op": "const", "value": 0x48534548,
                                        "width": 32,
                                    },
                                ],
                            },
                        ],
                    }
                    current_eax = {
                        "op": "load", "width": 4,
                        "address": context_eax,
                    }
                    write = {
                        "kind": "write", "width": 4,
                        "address": {
                            "op": "ite", "args": [
                                pinned_divide, context_eip, context_eax,
                            ],
                        },
                        "value": {
                            "op": "ite", "args": [
                                pinned_divide,
                                {
                                    "op": "const",
                                    "value": image_base + exception_resumption_rva,
                                    "width": 32,
                                },
                                current_eax,
                            ],
                        },
                    }
                    memory_events = [
                        {"kind": "read", "width": 4, "address": record_cell},
                        {"kind": "read", "width": 4, "address": record},
                        {
                            "kind": "read", "width": 4,
                            "address": nested_record_cell,
                        },
                        {"kind": "read", "width": 4, "address": context_cell},
                        {"kind": "read", "width": 4, "address": context_eax},
                        write,
                    ]
                    exception_row["memory_events"] = memory_events
                    exception_row["ordered_events"] = [
                        {"family": "memory", "instruction_rva": rva, **event}
                        for event in memory_events
                    ]
                elif identity == (
                    "semantic-transfer:fixture-guest-exception-resumption"
                ):
                    result = 0xC0DEC0DF
                elif identity == (
                    "semantic-transfer:fixture-guest-finally-inner"
                ):
                    result = 0xF1A11E01
                elif identity == (
                    "semantic-transfer:fixture-guest-finally-outer"
                ):
                    result = 0xF1A11E02
                set_eax_return_semantics(
                    exception_row,
                    {"op": "const", "value": result, "width": 32},
                )
                rows.append(exception_row)
        for callback in tls_callbacks:
            if data_export_rva is None:
                raise ValueError("TLS fixture lacks its exact data-export RVA")
            callback_row = transfer_row()
            callback_row["id"] = (
                f"semantic-transfer:fixture-tls-{callback['order']:04d}"
            )
            callback_row["original"] = {
                "rva_start": callback["rva"],
                "rva_end": callback["rva"] + 1,
                "size": 1,
            }
            callback_row["register_writes"] = []
            stack_pointer = {"op": "reg", "name": "esp", "width": 32}
            module_base = {
                "op": "load", "width": 4,
                "address": {
                    "op": "add32", "args": [
                        stack_pointer,
                        {"op": "const", "value": 4, "width": 32},
                    ],
                },
            }
            reason = {
                "op": "load", "width": 4,
                "address": {
                    "op": "add32", "args": [
                        stack_pointer,
                        {"op": "const", "value": 8, "width": 32},
                    ],
                },
            }
            data_word = {
                "op": "add32", "args": [
                    module_base,
                    {
                        "op": "const", "value": data_export_rva + 4,
                        "width": 32,
                    },
                ],
            }
            current = {"op": "load", "width": 4, "address": data_word}
            attached = {
                "op": "eq", "args": [
                    reason, {"op": "const", "value": 1, "width": 32},
                ],
            }
            attached_value = (
                {"op": "const", "value": 1, "width": 32}
                if callback["order"] == 0 else
                {
                    "op": "add32", "args": [
                        {
                            "op": "mul32", "args": [
                                current,
                                {"op": "const", "value": 33, "width": 32},
                            ],
                        },
                        {
                            "op": "const", "value": callback["order"] + 1,
                            "width": 32,
                        },
                    ],
                }
            )
            write = {
                "kind": "write", "width": 4, "address": data_word,
                "value": {
                    "op": "ite", "args": [attached, attached_value, current],
                },
            }
            callback_row["memory_events"] = [write]
            callback_row["ordered_events"] = [{"family": "memory", **write}]
            callback_row["outcome"] = {
                "kind": "return",
                "value": {"op": "const", "value": 0, "width": 32},
            }
            rows.append(callback_row)
        if callback_target_rva is not None:
            if callback_target_rva in {
                int(row["original"]["rva_start"]) for row in rows
            }:
                raise ValueError("fixture callback target RVA is ambiguous")
            callback_row = transfer_row()
            callback_row["id"] = "semantic-transfer:fixture-callback"
            callback_row["original"] = {
                "rva_start": callback_target_rva,
                "rva_end": callback_target_rva + 1,
                "size": 1,
            }
            callback_row["register_writes"] = []
            callback_stack = {
                "op": "reg", "name": "esp", "width": 32,
            }
            exception_pointers = {
                "op": "load",
                "width": 4,
                "address": {
                    "op": "add32",
                    "args": [
                        callback_stack,
                        {"op": "const", "value": 4, "width": 32},
                    ],
                },
            }
            exception_record = {
                "op": "load", "width": 4,
                "address": exception_pointers,
            }
            exception_context = {
                "op": "load", "width": 4,
                "address": {
                    "op": "add32",
                    "args": [
                        exception_pointers,
                        {"op": "const", "value": 4, "width": 32},
                    ],
                },
            }
            callback_writes = [{
                "kind": "write",
                "width": 4,
                "address": {
                    "op": "add32",
                    "args": [
                        exception_record,
                        {"op": "const", "value": 4, "width": 32},
                    ],
                },
                "value": {
                    "op": "const", "value": 0x46584C54, "width": 32,
                },
            }, {
                "kind": "write",
                "width": 4,
                "address": {
                    "op": "add32",
                    "args": [
                        exception_context,
                        {"op": "const", "value": 156, "width": 32},
                    ],
                },
                "value": {
                    "op": "const", "value": 0x2468ACE0, "width": 32,
                },
            }]
            callback_row["memory_events"] = callback_writes
            callback_row["ordered_events"] = [
                {"family": "memory", **event}
                for event in callback_writes
            ]
            set_eax_return_semantics(
                callback_row,
                {"op": "const", "value": 1, "width": 32},
            )
            rows.append(callback_row)
    if original_pe is not None:
        _bind_exact_instruction_inventory(rows, original_pe)
    machine.write_text(
        "".join(
            json.dumps(as_machine_ir_unit(row), sort_keys=True) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )
    transfer = write_fixture_transfer_plan(
        machine,
        pe_sha256=module_pe_sha256,
    )
    transfer_manifest = root / "machine-ir-transfer-manifest.json"
    machine_manifest = root / "machine-ir-manifest.json"
    machine_manifest.write_bytes(transfer_manifest.read_bytes())
    transfer_payload = json.loads(transfer.read_text(encoding="utf-8"))
    checked_nonlocal_closure: dict[str, object] | None = None
    if all(value is not None for value in nonlocal_targets):
        nonlocal_export = next(
            target for target in export_targets
            if target["unit_suffix"] == "fixture-nonlocal"
        )
        nonlocal_root_rva = int(nonlocal_export["rva"])
        registers = list(ReferenceStateV1().registers)
        registers[7] = finite_reference_value_v1(references=(
            ReferenceAtomV1(
                "object", f"captured_stack:root:{nonlocal_root_rva:08x}"
            ),
        ))
        nonlocal_context = ExecutionClosureContextV1(
            roots=(nonlocal_root_rva,),
            catalog=ReferenceCatalogV1(
                guest_code_rvas=frozenset(
                    int(row["source"]["rva_start"])
                    for row in transfer_payload["transfers"]
                ),
            ),
            authority_bindings={"fixture_sha256": module_pe_sha256},
            initial_states={
                nonlocal_root_rva: ReferenceStateV1(
                    registers=tuple(registers)
                ),
            },
        )
        checked_nonlocal_closure = build_module_execution_closure_v1(
            transfer_plan_sha256=sha256_file(transfer),
            transfers=tuple(
                _transfer_from_payload(row)
                for row in transfer_payload["transfers"]
            ),
            context=nonlocal_context,
        )
        if (
            checked_nonlocal_closure["status"] != "complete"
            or len(checked_nonlocal_closure["nonlocal_transitions"]) != 1
            or sorted(
                row["kind"]
                for row in checked_nonlocal_closure["reachable_edges"]
            ) != ["internal_call", "nonlocal_control"]
        ):
            raise ValueError(
                "fixture nonlocal transition did not close through the reference "
                "kernel: "
                + json.dumps({
                    "status": checked_nonlocal_closure["status"],
                    "transfer_blockers": transfer_payload[
                        "semantic_blockers"
                    ],
                    "transfer_rvas": [
                        row["source"]["rva_start"]
                        for row in transfer_payload["transfers"]
                    ],
                    "blockers": checked_nonlocal_closure["blockers"],
                    "reachable_edges": checked_nonlocal_closure[
                        "reachable_edges"
                    ],
                    "nonlocal_transitions": checked_nonlocal_closure[
                        "nonlocal_transitions"
                    ],
                }, sort_keys=True)
            )
    seh_authorities: dict[str, dict[str, object]] = {}
    if include_export_ingress:
        seh_targets = [
            target for target in export_targets
            if target["unit_suffix"] in {
                "fixture-seh", "fixture-hardware-seh",
                "fixture-access-violation",
                "fixture-hardware-access-violation",
                "fixture-host-import-seh",
            }
        ]
        if len(seh_targets) != len({
            str(target["unit_suffix"]) for target in seh_targets
        }):
            raise ValueError("export-ingress fixture has duplicate SEH targets")
        main_target = next(
            (
                target for target in export_targets
                if target["unit_suffix"] == "fixture-export"
            ),
            None,
        )
        for seh_target in seh_targets:
            suffix = str(seh_target["unit_suffix"])
            seh_unit_id = f"semantic-transfer:{suffix}"
            seh_transfer = next(
                row for row in transfer_payload["transfers"]
                if row["identity"] == seh_unit_id
            )
            expected_operation = (
                "access_violation_if"
                if suffix in {
                    "fixture-access-violation",
                    "fixture-hardware-access-violation",
                } else "divide_if"
            )
            effect_ops = [effect["op"] for effect in seh_transfer["effects"]]
            host_import_exception = suffix == "fixture-host-import-seh"
            if host_import_exception:
                calls = [
                    call for call in seh_transfer["calls"]
                    if call.get("native_exception_operations")
                    == [expected_operation]
                ]
                if len(calls) != 1 or effect_ops.count("call") != 1:
                    raise ValueError(
                        "fixture host-import SEH transfer lacks one canonical "
                        "external-callee exception site"
                    )
                effect_index = next(
                    index for index, effect in enumerate(seh_transfer["effects"])
                    if effect["op"] == "call"
                )
                fault_sha256 = canonical_sha256_v3(
                    call_native_exception_fault_payload_v3(
                        call_kind=str(calls[0]["kind"]),
                        event_index=int(calls[0]["event_index"]),
                        instruction_rva=int(calls[0]["instruction_rva"]),
                        operation=expected_operation,
                        exception_index=0,
                    )
                )
            else:
                if effect_ops.count(expected_operation) != 1:
                    raise ValueError(
                        "fixture SEH transfer must contain its one canonical fault"
                    )
                effect_index = next(
                    index for index, effect in enumerate(seh_transfer["effects"])
                    if effect["op"] == expected_operation
                )
                exact_fault = next(
                    row for row in rows if row["id"] == seh_unit_id
                )["faults"][0]
                fault_sha256 = canonical_sha256_v3(exact_fault)
            transition_id = (
                "exceptional-transition-v3:"
                + canonical_sha256_v3({
                    "unit_id": seh_unit_id,
                    "fault_index": 0,
                    "fault_sha256": fault_sha256,
                })
            )
            handled = suffix in {
                "fixture-hardware-seh",
                "fixture-hardware-access-violation",
                "fixture-host-import-seh",
            }
            if handled and main_target is None:
                raise ValueError("hardware SEH fixture has no checked handler")
            disposition = "handled" if handled else "terminates"
            seh_authorities[suffix] = {
                "unit_id": seh_unit_id,
                "source_rva": int(seh_target["rva"]),
                "effect_index": effect_index,
                "fault_index": 0,
                "fault_sha256": fault_sha256,
                "transition_id": transition_id,
                "operation": expected_operation,
                "occurrence_kind": (
                    "call" if host_import_exception else "effect"
                ),
                "call_index": (
                    int(calls[0]["event_index"])
                    if host_import_exception else None
                ),
                "disposition": disposition,
                "handler_unit_id": (
                    (
                        "semantic-transfer:fixture-guest-exception-handler"
                        if exception_handler_rva is not None
                        else "semantic-transfer:fixture-export"
                    )
                    if handled else None
                ),
                "handler_rva": (
                    (
                        int(exception_handler_rva)
                        if exception_handler_rva is not None
                        else int(main_target["rva"])
                    )
                    if handled and main_target is not None else None
                ),
                "resumption_unit_id": (
                    "semantic-transfer:fixture-guest-exception-resumption"
                    if handled and exception_resumption_rva is not None
                    else (
                        "semantic-transfer:fixture-reentrant"
                        if handled else None
                    )
                ),
                "resumption_rva": (
                    int(exception_resumption_rva)
                    if handled and exception_resumption_rva is not None
                    else (
                        next(
                            int(target["rva"])
                            for target in export_targets
                            if target["unit_suffix"] == "fixture-reentrant"
                        )
                        if handled else None
                    )
                ),
                "unwind_unit_ids": (
                    [
                        "semantic-transfer:fixture-guest-finally-inner",
                        "semantic-transfer:fixture-guest-finally-outer",
                    ]
                    if handled else []
                ),
                "state_projection": (
                    {
                        "registers": [],
                        "flags": [],
                        "x87": (
                            ["all"]
                            if suffix == "fixture-hardware-seh"
                            else []
                        ),
                        "stack": [],
                        "exception_record": sorted({
                            "ExceptionCode", "ExceptionRecord",
                            *(
                                ["ExceptionAddress"]
                                if pin_numeric_exception_addresses
                                and suffix == "fixture-hardware-seh"
                                else []
                            ),
                        }),
                        "context": sorted({
                            "Eax",
                            *(
                                ["Eip"]
                                if pin_numeric_exception_addresses
                                and suffix == "fixture-hardware-seh"
                                else []
                            ),
                        }),
                    }
                    if handled else None
                ),
                "guard": {"op": "true"},
                "root_rvas": [int(seh_target["rva"])],
            }
    canonical_boundaries: list[dict[str, object]] = []
    if include_export_ingress:
        def checked_stack_arguments(words: int) -> list[dict[str, object]]:
            return [
                {
                    "id": f"argument-{index}",
                    "role": "parameter",
                    "storage_bits": 32,
                    "value_bits": 32,
                    "pass_mode": "direct",
                    "logical_path": [],
                    "fragments": [{
                        "logical_offset_bits": 0,
                        "width_bits": 32,
                        "location_offset_bits": 0,
                        "representation": "identity",
                        "specified": True,
                        "location": {
                            "kind": "stack",
                            "phase": "callee_entry",
                            "width_bits": 32,
                            "bank": None,
                            "name": None,
                            "stack_base": "callee-entry-esp",
                            "stack_offset_bytes": 4 + index * 4,
                            "memory_slot": None,
                        },
                    }],
                }
                for index in range(words)
            ]

        for target in export_targets:
            suffix = str(target["unit_suffix"])
            aliases = [
                str(alias["name"])
                for alias in target["aliases"]
                if alias.get("name") is not None
            ]
            subject_id = min(aliases) if aliases else (
                f"ordinal:{target['aliases'][0]['ordinal']}"
            )
            subject = {
                "kind": "export",
                "id": subject_id,
                "image_selector": image_id,
            }
            transport = PhysicalCallFrameV2.create(
                subject=subject,
                transfer_kind="direct",
                target="i686-pc-windows-gnu",
                abi_dialect="pe32-i386-gnu-v1",
                calling_convention=(
                    "cdecl"
                    if suffix == "fixture-host-import-seh" else "stdcall"
                ),
                arguments=(
                    checked_stack_arguments(4)
                    if suffix == "fixture-host-import-seh" else []
                ),
                results=[],
                stack={
                    "coordinate": "callee-entry-esp",
                    "alignment_bytes": 4,
                    "cleanup": (
                        "caller"
                        if suffix == "fixture-host-import-seh" else "callee"
                    ),
                    "cleanup_bytes": 0,
                    "reserved_bytes": 0,
                },
                preserved_state=["ebx", "ebp", "esi", "edi"],
                clobbered_state=["eax", "ecx", "edx", "eflags"],
                outcomes=(
                    ["normal", "exceptional"]
                    if suffix in seh_authorities else ["normal"]
                ),
            )
            canonical_boundaries.append(
                _fixture_checked_boundary_v1(
                    subject=subject, transport=transport
                )
            )
        canonical_boundaries.sort(key=lambda row: str(row["subject"]))
    interface_callback_boundaries: dict[str, dict[str, object]] = {}
    for interface in interface_method_catalogs:
        for method in interface["methods"]:
            target_core = {
                "profile_id": interface["profile_id"],
                "profile_sha256": interface["profile_sha256"],
                "interface_id": interface["interface_id"],
                "method": dict(method),
            }
            target = {
                **target_core,
                "method_contract_sha256": canonical_sha256_v3(target_core),
            }
            callback_boundary = interface_callback_boundary_catalog_v1(
                target, abi_dialect="pe32-i386-gnu-v1"
            )
            if callback_boundary is None:
                continue
            subject = str(callback_boundary["subject"])
            previous = interface_callback_boundaries.get(subject)
            if previous is not None and previous != callback_boundary:
                raise ValueError(
                    "fixture interface callback boundary is ambiguous"
                )
            interface_callback_boundaries[subject] = callback_boundary
    canonical_boundaries.extend(
        interface_callback_boundaries[key]
        for key in sorted(interface_callback_boundaries)
    )
    canonical_boundaries.sort(key=lambda row: str(row["subject"]))
    behavioral = root / "behavioral"
    write_spx_behavioral_c_package(transfer_plan=transfer, out=behavioral)
    environment = root / "environment"
    environment.mkdir()
    exit_profile = {
        "id": "fixture-process-termination-profile-v1",
        "abi_template": "pe32-stdcall-v1",
        "argument_words": 1,
        "arity": {"kind": "fixed", "words": 1},
        "disposition": "terminates",
        "result_register_relations": [],
        "memory_effect": "none",
        "memory_footprints": [],
        "world_effect": "process_termination",
        "out_pointer_relations": [],
        "out_interface_relations": [],
    }
    exit_identity = {
        "dll": "kernel32.dll", "symbol": "ExitProcess", "ordinal": None,
    }
    exit_iat_rva = (
        int(exit_process_import["iat_rva"])
        if exit_process_import is not None else 0x2000
    )
    original_semantic_imports: list[dict[str, object]] = [{
        "identity": exit_identity,
        "iat_rva": exit_iat_rva,
        "contract": {
            "profile_id": exit_profile["id"],
            "profile_sha256": canonical_sha256_v3(exit_profile),
            "entry_key": "machine_import_signatures",
            "entry_index": 0,
            "payload": exit_profile,
        },
        "boundary": _fixture_machine_import_boundary_v1(
            identity=exit_identity,
            profile=exit_profile,
            entry_index=0,
        ),
    }]
    if factory_contract is not None:
        if factory_import is None:
            raise ValueError("fixture factory contract has no loader import")
        original_semantic_imports.append({
            "import_kind": "ordinary",
            "identity": {
                "dll": factory_contract.identity.dll,
                "symbol": (
                    str(factory_contract.identity.value)
                    if factory_contract.identity.kind == "symbol" else None
                ),
                "ordinal": (
                    int(factory_contract.identity.value)
                    if factory_contract.identity.kind == "ordinal" else None
                ),
            },
            "iat_rva": int(factory_import["iat_rva"]),
            "descriptor_index": int(factory_import["descriptor_index"]),
            "cell_index": int(factory_import["cell_index"]),
            "contract": {
                "profile_id": factory_contract.profile_id,
                "profile_sha256": factory_contract.profile_sha256,
                "entry_key": factory_contract.entry_key,
                "entry_index": factory_contract.entry_index,
                "payload": factory_contract.contract,
            },
            "boundary": lower_machine_import_boundary_v1(
                factory_contract, abi_dialect="pe32-i386-gnu-v1"
            ),
        })
    if callback_registration_import is not None:
        callback_profile = {
            "id": "fixture-callback-registration-profile-v1",
            "abi_template": "pe32-stdcall-v1",
            "argument_words": 1,
            "arity": {"kind": "fixed", "words": 1},
            "disposition": "returns",
            "result_register_relations": [
                {"register": "eax", "relation": "exact"},
            ],
            "memory_effect": "none",
            "memory_footprints": [],
            "world_effect": "callback_registration",
            "callback_effect": "explicit",
            "out_interface_relations": [],
            "callback_protocol": {
                "format": "spaghetti-extractor-callback-protocol-v1",
                "id": "win32-unhandled-exception-filter",
                "action": "replace",
                "source": {
                    "kind": "argument_word",
                    "argument": 0,
                    "sentinels": [{"word": 0, "kind": "null"}],
                },
                "signature": {
                    "argument_words": 1,
                    "abi_template": "pe32-stdcall-v1",
                    "result": {"kind": "word", "register": "eax"},
                    "stack_cleanup_bytes": 4,
                },
                "lifetime": {"kind": "until_replaced_or_process_exit"},
                "delivery": {
                    "thread": "external_concurrent", "timing": "deferred",
                },
                "instance": {"kind": "singleton"},
                "previous_result": {
                    "register": "eax",
                    "nullable": True,
                    "sentinels": [{"word": 0, "kind": "null"}],
                },
                "cardinality": {
                    "minimum": 0,
                    "maximum": None,
                    "scope": "registration_generation",
                },
                "provider_behavior": None,
            },
        }
        callback_identity = {
            "dll": str(callback_registration_import["dll"]),
            "symbol": "SetUnhandledExceptionFilter",
            "ordinal": None,
        }
        callback_entry_index = len(original_semantic_imports)
        callback_contract = {
            "identity": callback_identity,
            "iat_rva": int(callback_registration_import["iat_rva"]),
            "descriptor_index": int(
                callback_registration_import.get("descriptor_index", 0)
            ),
            "cell_index": int(callback_registration_import.get("cell_index", 0)),
            "contract": {
                "profile_id": callback_profile["id"],
                "profile_sha256": canonical_sha256_v3(callback_profile),
                "entry_key": "machine_import_signatures",
                "entry_index": callback_entry_index,
                "payload": callback_profile,
            },
            "boundary": _fixture_machine_import_boundary_v1(
                identity=callback_identity,
                profile=callback_profile,
                entry_index=callback_entry_index,
            ),
        }
        original_semantic_imports.append(callback_contract)
        callback_boundary = machine_callback_boundary_catalog_v1(
            callback_contract, abi_dialect="pe32-i386-gnu-v1"
        )
        if callback_boundary is None:  # pragma: no cover - fixture invariant
            raise ValueError("fixture callback profile did not lower a boundary")
        canonical_boundaries.append(callback_boundary)
        canonical_boundaries.sort(key=lambda row: str(row["subject"]))
    if rtl_unwind_import is not None:
        rtl_unwind_profile = {
            "id": "fixture-rtl-unwind-profile-v1",
            "abi_template": "pe32-stdcall-v1",
            "argument_words": 4,
            "arity": {"kind": "fixed", "words": 4},
            "disposition": "nonlocal",
            "result_register_relations": [],
            "memory_effect": "checkedExternalService",
            "memory_footprints": [],
            "world_effect": "checkedExternalService",
            "out_pointer_relations": [],
            "out_interface_relations": [],
            "external_service_protocol": {
                "format": (
                    "spaghetti-extractor-checked-external-service-"
                    "protocol-v1"
                ),
                "id": "win32-rtl-unwind-v1",
                "kind": "nonlocal_unwind",
                "arguments": {
                    "target_frame": 0,
                    "target_instruction": 1,
                    "exception_record": 2,
                    "return_value": 3,
                },
                "behavior": {
                    "frame_selection": "registered_seh_ancestor",
                    "target_selection": "checked_guest_code_capability",
                    "exception_record": "nullable_checked_exception_record",
                    "return_value": "eax_word",
                    "unwind": "x86_seh_unwind",
                    "abandoned_lifetimes": "invalidate",
                    "outcome": "nonlocal",
                },
            },
        }
        rtl_unwind_identity = {
            "dll": str(rtl_unwind_import["dll"]),
            "symbol": "RtlUnwind",
            "ordinal": None,
        }
        rtl_unwind_entry_index = len(original_semantic_imports)
        original_semantic_imports.append({
            "identity": rtl_unwind_identity,
            "iat_rva": int(rtl_unwind_import["iat_rva"]),
            "descriptor_index": int(
                rtl_unwind_import.get("descriptor_index", 0)
            ),
            "cell_index": int(rtl_unwind_import.get("cell_index", 0)),
            "contract": {
                "profile_id": rtl_unwind_profile["id"],
                "profile_sha256": canonical_sha256_v3(rtl_unwind_profile),
                "entry_key": "machine_import_signatures",
                "entry_index": rtl_unwind_entry_index,
                "payload": rtl_unwind_profile,
            },
            "boundary": _fixture_machine_import_boundary_v1(
                identity=rtl_unwind_identity,
                profile=rtl_unwind_profile,
                entry_index=rtl_unwind_entry_index,
            ),
        })
    if unhandled_filter_import is not None:
        unhandled_filter_profile = {
            "id": "fixture-unhandled-exception-filter-profile-v1",
            "abi_template": "pe32-stdcall-v1",
            "argument_words": 1,
            "arity": {"kind": "fixed", "words": 1},
            "disposition": "returns",
            "result_register_relations": [
                {"register": "eax", "relation": "exact"},
            ],
            "memory_effect": "checkedExternalService",
            "memory_footprints": [{
                "access": "read",
                "base_argument": 0,
                "offset": 0,
                "size": {"kind": "fixed", "bytes": 8},
                "nullable": False,
            }],
            "world_effect": "checkedExternalService",
            "out_pointer_relations": [],
            "out_interface_relations": [],
            "external_service_protocol": {
                "format": (
                    "spaghetti-extractor-checked-external-service-"
                    "protocol-v1"
                ),
                "id": "win32-unhandled-exception-filter-v1",
                "kind": "unhandled_exception_filter",
                "arguments": {"exception_pointers": 0},
                "behavior": {
                    "active_filter": "invoke_once_on_same_thread",
                    "fallback": "loader_owned_unhandled_exception_policy",
                    "outcome": "normal",
                },
                "object_view": {
                    "kind": "win32_exception_pointers_v1",
                    "size_bytes": 8,
                    "exception_record_pointer_offset": 0,
                    "context_pointer_offset": 4,
                    "exception_record_view": "checked_exception_record_v1",
                    "context_view": "x86_context_v1",
                    "root_access": "read",
                    "referent_access": "read_write",
                    "lifetime": "during_call",
                },
                "registered_filter": {
                    "protocol_id": "win32-unhandled-exception-filter",
                    "absence": "host_fallback",
                    "result_register": "eax",
                },
            },
        }
        unhandled_filter_identity = {
            "dll": str(unhandled_filter_import["dll"]),
            "symbol": "UnhandledExceptionFilter",
            "ordinal": None,
        }
        unhandled_filter_entry_index = len(original_semantic_imports)
        original_semantic_imports.append({
            "identity": unhandled_filter_identity,
            "iat_rva": int(unhandled_filter_import["iat_rva"]),
            "descriptor_index": int(
                unhandled_filter_import.get("descriptor_index", 0)
            ),
            "cell_index": int(unhandled_filter_import.get("cell_index", 0)),
            "contract": {
                "profile_id": unhandled_filter_profile["id"],
                "profile_sha256": canonical_sha256_v3(
                    unhandled_filter_profile
                ),
                "entry_key": "machine_import_signatures",
                "entry_index": unhandled_filter_entry_index,
                "payload": unhandled_filter_profile,
            },
            "boundary": _fixture_machine_import_boundary_v1(
                identity=unhandled_filter_identity,
                profile=unhandled_filter_profile,
                entry_index=unhandled_filter_entry_index,
            ),
        })
    if raise_exception_import is not None:
        raise_profile = {
            "id": "fixture-semantic-raise-exception-profile-v1",
            "abi_template": "pe32-stdcall-v1",
            "argument_words": 4,
            "arity": {"kind": "fixed", "words": 4},
            "disposition": "returns",
            "result_register_relations": [],
            "memory_effect": "none",
            "memory_footprints": [],
            "world_effect": "none",
            "out_pointer_relations": [],
            "out_interface_relations": [],
        }
        raise_identity = {
            "dll": str(raise_exception_import["dll"]),
            "symbol": "RaiseException",
            "ordinal": None,
        }
        raise_entry_index = len(original_semantic_imports)
        original_semantic_imports.append({
            "identity": raise_identity,
            "iat_rva": int(raise_exception_import["iat_rva"]),
            "descriptor_index": int(
                raise_exception_import.get("descriptor_index", 0)
            ),
            "cell_index": int(raise_exception_import.get("cell_index", 0)),
            "contract": {
                "profile_id": raise_profile["id"],
                "profile_sha256": canonical_sha256_v3(raise_profile),
                "entry_key": "machine_import_signatures",
                "entry_index": raise_entry_index,
                "payload": raise_profile,
            },
            "boundary": _fixture_machine_import_boundary_v1(
                identity=raise_identity,
                profile=raise_profile,
                entry_index=raise_entry_index,
            ),
        })
    if original_import_inventory:
        def import_key(value: Mapping[str, object]) -> tuple[str, str, object]:
            return (
                str(value.get("dll", "")).lower(),
                "symbol" if value.get("symbol") is not None else "ordinal",
                (
                    value.get("symbol")
                    if value.get("symbol") is not None else value.get("ordinal")
                ),
            )

        exact_imports = {
            import_key(row): row for row in original_import_inventory
        }
        for row in original_semantic_imports:
            identity = row.get("identity")
            if not isinstance(identity, Mapping):
                raise ValueError("fixture machine import identity is malformed")
            physical = exact_imports.get(import_key(identity))
            if physical is None:
                raise ValueError(
                    f"fixture machine import {dict(identity)!r} has no exact IAT slot"
                )
            for field in ("descriptor_index", "cell_index", "iat_rva"):
                existing = row.get(field)
                if existing is not None and existing != physical.get(field):
                    raise ValueError(
                        f"fixture machine import {dict(identity)!r} has stale {field}"
                    )
                row[field] = physical[field]
            row["import_kind"] = "ordinary"
    else:
        for row in original_semantic_imports:
            row.setdefault("import_kind", "ordinary")
            row.setdefault("cell_index", 0)

    environment_intent_sha256 = canonical_sha256_v3({
        "id": "native-module-fixture-external-environment-intent-v1",
        "target": {
            "abi": "pe32-i686-mingw32",
            "data_layout": "pe32-ilp32-v1",
        },
        "semantic_imports": [
            row["identity"] for row in original_semantic_imports
        ],
    })
    runtime_profile_pack_sha256s = sorted({
        str(row["contract"]["profile_sha256"])
        for row in original_semantic_imports
        if "profile_sha256" in row["contract"]
    })
    exception_escape_target = next(
        (
            target for target in export_targets
            if target["unit_suffix"] == "fixture-reentrant"
        ),
        None,
    )
    checked_exception_protocols = []
    for row in seh_authorities.values():
        handled = row["disposition"] == "handled"
        if not handled and exception_escape_target is None:
            raise ValueError(
                "terminating fixture SEH authority has no external continuation"
            )
        checked_exception_protocols.append(
            bind_checked_exception_protocol_v1(
                occurrence={
                    "unit_id": row["unit_id"],
                    "source_rva": row["source_rva"],
                    "effect_index": row["effect_index"],
                    "fault_index": row["fault_index"],
                    "fault_sha256": row["fault_sha256"],
                    "occurrence_kind": row["occurrence_kind"],
                    "operation": row["operation"],
                    "call_index": row["call_index"],
                },
                handler=(
                    {
                        "unit_id": row["handler_unit_id"],
                        "rva": row["handler_rva"],
                    }
                    if handled else None
                ),
                resumption=(
                    {
                        "unit_id": row["resumption_unit_id"],
                        "rva": row["resumption_rva"],
                    }
                    if handled else {
                        "unit_id": "semantic-transfer:fixture-reentrant",
                        "rva": int(exception_escape_target["rva"]),
                    }
                ),
                unwind_unit_ids=sorted(row["unwind_unit_ids"]),
                state_projection=(
                    {
                        key: sorted(values)
                        for key, values in row["state_projection"].items()
                    }
                    if handled else {
                        "registers": ["edi"],
                        "flags": [],
                        "x87": [],
                        "stack": [],
                        "exception_record": ["ExceptionCode"],
                        "context": ["Edi"],
                    }
                ),
            )
        )
    checked_exception_protocols.sort(key=lambda row: row["protocol_id"])
    support_contracts = {
        str(row["identity"].get("symbol")): row
        for row in original_semantic_imports
        if isinstance(row.get("identity"), Mapping)
    }
    try:
        process_termination_support = support_contracts["ExitProcess"]
        exception_escape_support = support_contracts["RaiseException"]
    except KeyError as exc:
        raise ValueError(
            "fixture support import lacks its selected machine contract"
        ) from exc
    environment_core = {
        "format": RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT,
        "status": "complete",
        "bindings": {
            "module_pe_sha256": module_pe_sha256,
            "module_interface_sha256": module_interface_identity,
            "environment_intent_sha256": environment_intent_sha256,
            "runtime_profile_pack_sha256s": runtime_profile_pack_sha256s,
            "interface_profile_pack_sha256s": interface_profile_sha256s,
        },
        "target": {
            "abi": "pe32-i686-mingw32",
            "data_layout": "pe32-ilp32-v1",
        },
        "launch_policy": bind_launch_policy_v1(
            {
                "format": "spaghetti-extractor-pe32-launch-assumption-template-v1",
                "schema_version": 1,
                "assumptions": {
                    "argv": {
                        "contract": "windows-process-command-line-v1",
                        "encoding": "ansi-and-unicode-loader-views",
                    },
                    "environment": {
                        "contract": "windows-process-environment-v1",
                        "ownership": "external-world",
                    },
                    "fs": {
                        "contract": "pe32-user-thread-fs-v1",
                        "mapped_separately_from_image": True,
                        "minimum_accessible_bytes": 4096,
                        "range_contract": (
                            "private-non-image-thread-environment-range-v1"
                        ),
                        "teb_fields": "profiled-accesses-only",
                    },
                    "iat": {
                        "contract": "exact-pe-import-loader-binding-v1",
                        "resolution": "pinned-runtime-profile",
                    },
                    "initial_stack": {
                        "alignment_bytes": 4,
                        "contract": "private-non-image-stack-range-v2",
                        "mapped_separately_from_image": True,
                        "minimum_accessible_bytes_above": 65536,
                        "minimum_accessible_bytes_below": 8388608,
                    },
                    "relocations": {
                        "contract": "exact-pe32-base-relocation-v1",
                        "policy": "apply-if-relocated",
                    },
                },
                "feature_inventory": {
                    "direct_syscalls": [],
                    "executable_writes": [],
                    "threads": [],
                    "unknown_async_callbacks": [],
                    "unmodelled_seh": [],
                },
            },
            source_sha256="0" * 64,
            filename="fixture-launch.json",
        ),
        "canonical_boundaries": canonical_boundaries,
        "interface_method_catalogs": interface_method_catalogs,
        "machine_import_contracts": original_semantic_imports,
        "original_semantic_imports": original_semantic_imports,
        "generated_runtime_support_imports": [{
            "support": "process_termination",
            "identity": {
                "dll": "kernel32.dll", "symbol": "ExitProcess", "ordinal": None,
            },
            "contract": process_termination_support["contract"],
            "boundary": process_termination_support["boundary"],
        }, {
            "support": "exception_escape",
            "identity": {
                "dll": "kernel32.dll", "symbol": "RaiseException",
                "ordinal": None,
            },
            "contract": exception_escape_support["contract"],
            "boundary": exception_escape_support["boundary"],
        }],
        "loader_service_contracts": [],
        "static_authority_bindings": [],
        "checked_exception_protocols": checked_exception_protocols,
        "blockers": [],
        "authority": "checked_static_environment",
    }
    environment_path = environment / "resolved-external-environment.json"
    write_json(environment_path, {
        **environment_core,
        "resolved_environment_sha256": canonical_sha256_v3(environment_core),
    })
    resolved_environment = ResolvedExternalEnvironmentV1.load(environment_path)
    checked_transitions = derive_checked_exception_transitions_v1(
        transfers=tuple(
            _transfer_from_payload(row)
            for row in transfer_payload["transfers"]
        ),
        environment=resolved_environment,
    )
    checked_by_occurrence = {
        (row.unit_id, row.fault_index, row.fault_sha256): row
        for row in checked_transitions
    }
    for row in seh_authorities.values():
        checked = checked_by_occurrence.get((
            row["unit_id"], row["fault_index"], row["fault_sha256"],
        ))
        if (
            checked is None
            or not checked.authorizing
            or checked.disposition != row["disposition"]
            or checked.transition_sha256 is None
        ):
            raise ValueError(
                "fixture SEH contract disagrees with canonical exception semantics"
            )
        row["transition_sha256"] = checked.transition_sha256
        row["guard"] = checked.guard
    callback_escapes = []
    if callback_target_rva is not None:
        registration = next(
            target for target in export_targets
            if target["unit_suffix"] == "fixture-register-callback"
        )
        callback_escapes.append({
            "instruction_rva": int(registration["rva"]),
            "dll": image_id,
            "identity": "fixture-escaped-callback",
            "protocol_id": "win32-unhandled-exception-filter",
            "targets": [callback_target_rva],
            "action": "register",
            "lifetime": "until_replaced_or_process_exit",
            "delivery": {"thread": "foreign", "timing": "after_return"},
        })
    closure_core = {
        "format": MODULE_EXECUTION_CLOSURE_FORMAT,
        "status": "complete",
        "authorizes_execution": True,
        "bindings": {
            "executable_transfer_plan_sha256": sha256_file(transfer),
            "resolved_external_environment_sha256": sha256_file(environment_path),
        },
        "roots": sorted(int(row["original"]["rva_start"]) for row in rows),
        "reachable_units": [
            {
                "unit_id": str(row["id"]),
                "rva": int(row["original"]["rva_start"]),
            }
            for row in rows
        ],
        "reachable_edges": (
            []
            if checked_nonlocal_closure is None
            else checked_nonlocal_closure["reachable_edges"]
        ),
        "indirect_targets": [],
        "external_contracts": [],
        "runtime_providers": [],
        "callback_escapes": callback_escapes,
        "exception_continuations": sorted(
            seh_authorities.values(), key=lambda row: int(row["source_rva"])
        ),
        "nonlocal_transitions": (
            []
            if checked_nonlocal_closure is None
            else checked_nonlocal_closure["nonlocal_transitions"]
        ),
        "lifecycle_effects": [],
        "witnesses": [],
        "blockers": [],
        "metrics": {
            "reachable_units": len(rows),
            "reachable_edges": (
                0
                if checked_nonlocal_closure is None
                else len(checked_nonlocal_closure["reachable_edges"])
            ),
            "indirect_sites": 0,
            "function_contexts": 0,
        },
        "analysis_policy": {
            "reference_alternative_limit": 64,
            "call_string_limit": 1,
            "maximum_worklist_steps": 1_000_000,
            "boundary_exit_rvas": [],
        },
        "authority": "fixture exact execution closure",
    }
    closure = root / "module-execution-closure.json"
    write_json(closure, {
        **closure_core,
        "closure_sha256": canonical_sha256_v3(closure_core),
    })
    objects = root / "objects"
    if module_interface is not None:
        write_pe32_machine_object_authority_v2(
            module_interface=module_interface,
            out=objects,
        )
        authority_payload = json.loads(
            (objects / "machine-object-authority.json").read_text(
                encoding="utf-8"
            )
        )
        authority = MachineObjectAuthorityV2.parse(authority_payload)
    else:
        objects.mkdir()
        authority = MachineObjectAuthorityV2(
            machine_backend="x86-pe32-v1",
            bindings={"module_interface_sha256": module_interface_sha256},
            rules=[
                MachineObjectRuleV2(
                    identity="fixture-image-data",
                    kind="image",
                    domain=1,
                    object_id=1,
                    generation=1,
                    extent=0x1000,
                    permissions=3,
                    lifetime="image",
                    locator=LoaderRealizedLocatorV2(
                        "image_rva", image_id, 0x2000
                    ),
                    interior_pointers=True,
                    evidence_sha256="b" * 64,
                )
            ],
        )
        write_json(
            objects / "machine-object-authority.json", authority.to_payload()
        )

    pinned_layout = root / "pinned-layout"
    pinned_layout.mkdir()
    if pin_numeric_exception_addresses:
        seh_authority = seh_authorities.get("fixture-hardware-seh")
        if seh_authority is None:
            raise ValueError(
                "pinned numeric fixture lacks hardware exception authority"
            )
        pinned = PinnedCodeLayoutAuthorityV2.create(
            original_module_sha256=module_pe_sha256,
            resolved_external_environment_sha256=str(
                json.loads(environment_path.read_text(encoding="utf-8"))[
                    "resolved_environment_sha256"
                ]
            ),
            required_image_base=image_base,
            rva_bindings=sorted([{
                "source_rva": int(seh_authority["source_rva"]),
                "candidate_rva": int(seh_authority["source_rva"]),
            }, {
                "source_rva": int(seh_authority["resumption_rva"]),
                "candidate_rva": int(seh_authority["resumption_rva"]),
            }], key=lambda row: row["source_rva"]),
            observed_fields=["Eip", "ExceptionAddress"],
        )
        write_json(
            pinned_layout / "pinned-code-layout-authority-v2-0000.json",
            pinned.to_payload(),
        )

    return {
        "transfer": transfer,
        "machine_ir": machine,
        "machine_ir_manifest": machine_manifest,
        "behavioral": behavioral,
        "pinned_layout": pinned_layout,
        "execution_closure": closure,
        "environment": environment,
        "objects": objects,
        **({} if load_contract is None else {"load_contract": load_contract}),
        **({} if module_interface is None else {"module_interface": module_interface}),
    }
