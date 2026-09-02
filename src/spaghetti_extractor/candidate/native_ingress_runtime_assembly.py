# ruff: noqa: F401
"""Exact IA-32 PE-TLS ABI and table-driven native-ingress source emission."""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from ..transfer.exception_projection import (
    MAX_EXCEPTION_RECORD_CHAIN_V1,
    exception_record_projection_paths_v1,
)
from ..calls.frame import PhysicalCallFrameV2
from ..errors import ToolkitInputError
from ..transfer.exception_semantics import X87_EXCEPTION_PROJECTION_FIELDS_V1
from .native_ingress_runtime_abi import align_up as _align_up
from .native_ingress_runtime_model import compact_callback_runtime_v1
from .outcomes import pinned_continuation_portal_for_protocol_v1


def render_native_ingress_assembly(plan: Mapping[str, Any]) -> str:
    bridges = _bridge_rows(plan)
    compact_callbacks = compact_callback_runtime_v1(plan)
    handlers = sorted({
        str(row["gateway_handler_symbol"])
        for row in plan.get("seh_protocols", []) if isinstance(row, Mapping)
    })
    portals = {
        str(portal["candidate_symbol"])
        for protocol in plan.get("seh_protocols", [])
        if isinstance(protocol, Mapping)
        for portal in protocol.get("portals", [])
        if isinstance(portal, Mapping)
    }
    portals.update(
        symbol for protocol in plan.get("seh_protocols", [])
        if isinstance(protocol, Mapping)
        and (symbol := pinned_continuation_portal_for_protocol_v1(protocol))
        is not None
    )
    selected_handler = handlers[0] if handlers else None
    lines = [
        ".intel_syntax noprefix",
        ".text",
        ".extern _spx_native_ingress_prepare",
        ".extern _spx_native_ingress_dispatch",
        ".extern _spx_native_ingress_finish",
        ".extern _spx_native_callback_prepare",
        ".extern _spx_native_callback_dispatch",
        ".extern _spx_native_ingress_current_capture",
        ".extern _spx_native_ingress_recover_exception",
        ".extern _spx_native_seh_dispatch",
        ".extern _spx_native_capture_continued_exception",
        ".extern _spx_native_raise_exception_iat_pointer",
        "",
    ]
    for index, row in enumerate(bridges):
        symbol = row["symbol"]
        cleanup = row["cleanup_bytes"]
        lines.extend([
            f".globl _{symbol}",
            f"_{symbol}:",
            "    pushfd",
            "    pushad",
            "    mov eax, esp",
            "    push eax",
            f"    push {index}",
            "    call _spx_native_ingress_prepare",
            "    add esp, 8",
            "    test eax, eax",
            f"    jz .Lspx_ingress_fail_{index}",
            "    mov edi, esp",
            "    mov esp, eax",
            *(
                [
                    "    mov edx, DWORD PTR fs:0",
                    f"    push OFFSET FLAT:_{selected_handler}",
                    "    push edx",
                    "    mov DWORD PTR fs:0, esp",
                ]
                if selected_handler is not None else []
            ),
            f"    push {index}",
            "    call _spx_native_ingress_dispatch",
            "    add esp, 4",
            *(
                [
                    "    mov edx, DWORD PTR [esp]",
                    "    mov DWORD PTR fs:0, edx",
                    "    add esp, 8",
                ]
                if selected_handler is not None else []
            ),
            "    push eax",
            "    call _spx_native_ingress_finish",
            "    add esp, 4",
            "    test eax, eax",
            f"    jz .Lspx_ingress_trap_{index}",
            "    mov esp, eax",
            "    popad",
            "    popfd",
            f"    ret {cleanup}" if cleanup else "    ret",
            f".Lspx_ingress_fail_{index}:",
            "    mov DWORD PTR [esp + 28], 1",
            "    popad",
            "    popfd",
            f"    ret {cleanup}" if cleanup else "    ret",
            f".Lspx_ingress_trap_{index}:",
            "    mov esp, edi",
            "    mov DWORD PTR [esp + 28], 1",
            "    popad",
            "    popfd",
            f"    ret {cleanup}" if cleanup else "    ret",
            "",
        ])
    for domain in compact_callbacks.domains:
        family = next(
            row for row in compact_callbacks.families
            if row.identity == domain.bridge_family_id
        )
        lines.extend([
            ".p2align 2",
            f".globl _{domain.trampoline_table_symbol}",
            f"_{domain.trampoline_table_symbol}:",
        ])
        for target in domain.targets:
            # Spell both instructions explicitly.  GNU as otherwise selects a
            # short PUSH encoding for small indexes, which would destroy the
            # content-addressed ten-byte table stride.
            lines.extend([
                "    .byte 0x68",
                f"    .long {target.flat_index}",
                "    .byte 0xe9",
                f"    .long _{family.symbol} - . - 4",
            ])
        lines.append("")
    for family_index, family in enumerate(compact_callbacks.families):
        cleanup = family.cleanup_bytes
        lines.extend([
            f".globl _{family.symbol}",
            f"_{family.symbol}:",
            "    pushfd",
            "    pushad",
            "    mov eax, esp",
            # The trampoline metadata word precedes the physical caller's
            # return address.  Advance the captured entry coordinate so the
            # existing checked frame transducer sees the real native frame.
            "    add DWORD PTR [eax + 12], 4",
            "    mov edx, DWORD PTR [esp + 36]",
            "    push eax",
            "    push edx",
            "    call _spx_native_callback_prepare",
            "    add esp, 8",
            "    test eax, eax",
            f"    jz .Lspx_callback_fail_{family_index}",
            "    mov edi, esp",
            "    mov esp, eax",
            *(
                [
                    "    mov edx, DWORD PTR fs:0",
                    f"    push OFFSET FLAT:_{selected_handler}",
                    "    push edx",
                    "    mov DWORD PTR fs:0, esp",
                ]
                if selected_handler is not None else []
            ),
            "    call _spx_native_callback_dispatch",
            *(
                [
                    "    mov edx, DWORD PTR [esp]",
                    "    mov DWORD PTR fs:0, edx",
                    "    add esp, 8",
                ]
                if selected_handler is not None else []
            ),
            "    push eax",
            "    call _spx_native_ingress_finish",
            "    add esp, 4",
            "    test eax, eax",
            f"    jz .Lspx_callback_trap_{family_index}",
            "    mov esp, eax",
            "    popad",
            "    popfd",
            "    add esp, 4",
            f"    ret {cleanup}" if cleanup else "    ret",
            f".Lspx_callback_fail_{family_index}:",
            "    mov DWORD PTR [esp + 28], 1",
            "    popad",
            "    popfd",
            "    add esp, 4",
            f"    ret {cleanup}" if cleanup else "    ret",
            f".Lspx_callback_trap_{family_index}:",
            "    mov esp, edi",
            "    mov DWORD PTR [esp + 28], 1",
            "    popad",
            "    popfd",
            "    add esp, 4",
            f"    ret {cleanup}" if cleanup else "    ret",
            "",
        ])
    for symbol in handlers:
        lines.extend([
            f".globl _{symbol}",
            f"_{symbol}:",
            "    jmp _spx_native_seh_dispatch",
            "",
        ])
    lines.extend([
        ".globl _spx_native_exception_recovery",
        "_spx_native_exception_recovery:",
        "    mov edx, DWORD PTR [esp]",
        "    mov DWORD PTR fs:0, edx",
        "    add esp, 8",
        "    call _spx_native_ingress_current_capture",
        "    mov edi, eax",
        "    call _spx_native_ingress_recover_exception",
        "    push eax",
        "    call _spx_native_ingress_finish",
        "    add esp, 4",
        "    test eax, eax",
        "    jz .Lspx_exception_recovery_trap",
        "    mov esp, eax",
        "    popad",
        "    popfd",
        "    ret",
        ".Lspx_exception_recovery_trap:",
        "    test edi, edi",
        "    jz .Lspx_exception_recovery_fast_fail",
        "    mov esp, edi",
        "    mov DWORD PTR [esp + 28], 1",
        "    popad",
        "    popfd",
        "    ret",
        ".Lspx_exception_recovery_fast_fail:",
        "    int 0x29",
        "",
        ".globl _spx_native_raise_exception_gateway",
        "_spx_native_raise_exception_gateway:",
        "    push ebp",
        "    mov ebp, esp",
        "    push ebx",
        "    push esi",
        "    push edi",
        "    push DWORD PTR [ebp + 20]",
        "    push DWORD PTR [ebp + 16]",
        "    push DWORD PTR [ebp + 12]",
        "    push DWORD PTR [ebp + 8]",
        "    mov eax, DWORD PTR [_spx_native_raise_exception_iat_pointer]",
        "    call DWORD PTR [eax]",
        "    pushfd",
        "    pushad",
        "    mov eax, esp",
        "    push eax",
        "    call _spx_native_capture_continued_exception",
        "    add esp, 4",
        "    popad",
        "    popfd",
        "    pop edi",
        "    pop esi",
        "    pop ebx",
        "    pop ebp",
        "    ret",
        "",
    ])
    for symbol in sorted(portals):
        lines.extend([
            f".globl _{symbol}",
            f"_{symbol}:",
            "    int 0x29",
            "",
        ])
    return "\n".join(lines)


def _bridge_rows(plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    result = []
    for bridge in plan.get("bridges", []):
        if not isinstance(bridge, Mapping):
            raise ToolkitInputError("native ingress bridge inventory is malformed")
        matches = [
            row for row in plan.get("ingresses", [])
            if isinstance(row, Mapping) and row.get("bridge_symbol") == bridge.get("symbol")
        ]
        if not matches:
            raise ToolkitInputError("native ingress bridge has no descriptor")
        frames = {
            json.dumps({
                key: value
                for key, value in row["physical_frame"]["transport"].items()
                if key not in {"format", "id", "subject", "transfer_kind"}
            }, sort_keys=True, separators=(",", ":"))
            for row in matches
        }
        if len(frames) != 1:
            raise ToolkitInputError("one native ingress bridge has incompatible frames")
        lifecycle_transducers = {
            json.dumps(
                (
                    row.get("lifecycle_transducer") or {}
                ).get("bindings", []),
                sort_keys=True,
                separators=(",", ":"),
            )
            for row in matches
        }
        if len(lifecycle_transducers) != 1:
            raise ToolkitInputError(
                "one native ingress bridge has incompatible lifecycle transducers"
            )
        transport = PhysicalCallFrameV2.parse(matches[0]["physical_frame"]["transport"])
        capability_ids = sorted({
            str(row["capability_id"])
            for row in matches if row.get("capability_id") is not None
        })
        physical_frame_ids = sorted({
            str(row["physical_frame_id"])
            for row in matches
            if isinstance(row.get("physical_frame_id"), str)
            and row.get("physical_frame_id")
        })
        if not physical_frame_ids:
            raise ToolkitInputError(
                "native ingress bridge has no physical frame identity"
            )
        result.append({
            "symbol": str(bridge["symbol"]),
            "descriptor": sorted(matches, key=lambda row: (str(row["role"]), str(row.get("capability_id"))))[0],
            # A public/loader ingress makes the shared native address
            # permanently callable.  Otherwise any active capability that was
            # deliberately assigned that equal address authorizes the call.
            "capability_ids": capability_ids,
            "permanently_callable": any(
                row.get("capability_id") is None for row in matches
            ),
            "process_root": any(
                row.get("role") == "process_entry" for row in matches
            ),
            "cleanup_bytes": transport.stack.cleanup_bytes,
            "physical_frame_ids": physical_frame_ids,
        })
    return sorted(result, key=lambda row: row["symbol"])


def _uint(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ToolkitInputError(f"{label} is invalid")
    return value


def _preserved_mask(values: Sequence[str]) -> int:
    supported = {"ebx": 0x01, "esi": 0x02, "edi": 0x04, "ebp": 0x08,
                 "eflags": 0x10}
    ignored = {"esp"}
    unknown = sorted(set(values) - set(supported) - ignored)
    if unknown:
        raise ToolkitInputError(
            f"generic native ingress cannot restore preserved state {unknown!r}"
        )
    return sum(supported[value] for value in values if value in supported)


def _exception_record_projection_masks_v1(
    protocol: Mapping[str, Any],
) -> tuple[int, ...]:
    projections = protocol.get("projections")
    if not isinstance(projections, Mapping):
        raise ToolkitInputError("checked SEH projection inventory is malformed")
    values = frozenset(
        str(value).lower()
        for value in projections.get("exception_record", [])
    )
    paths, malformed, bounded = exception_record_projection_paths_v1(values)
    if malformed:
        raise ToolkitInputError(
            "generic native ingress cannot project exception-record fields "
            f"{list(malformed)!r}"
        )
    if bounded:
        raise ToolkitInputError(
            "generic native ingress exception-record depth exceeds its "
            f"checked bound: {list(bounded)!r}"
        )
    if any(
        path.depth != 0 and path.field == "exceptionaddress"
        for path in paths
    ):
        raise ToolkitInputError(
            "generic native ingress cannot project a nested numeric "
            "exception address"
        )
    record_bits = {
        "exceptioncode": 0,
        "exceptionflags": 1,
        "exceptionrecord": 2,
        "exceptionaddress": 3,
        "numberparameters": 4,
        **{
            f"exceptioninformation[{index}]": 5 + index
            for index in range(15)
        },
    }
    depth = max((path.depth for path in paths), default=0)
    masks = [0] * (depth + 1)
    for path in paths:
        masks[path.depth] |= 1 << record_bits[path.field]
    for parent_depth in range(depth):
        masks[parent_depth] |= 1 << record_bits["exceptionrecord"]
    if len(masks) > MAX_EXCEPTION_RECORD_CHAIN_V1:
        raise AssertionError("checked exception-record bound drifted")
    return tuple(masks)


def _seh_projection_masks(
    protocol: Mapping[str, Any],
) -> tuple[int, int, int, int, int, int]:
    projections = protocol.get("projections")
    if not isinstance(projections, Mapping):
        raise ToolkitInputError("checked SEH projection inventory is malformed")
    x87_names = {str(value).lower() for value in projections.get("x87", [])}
    x87_aliases = {
        "control": 0x01, "control_word": 0x01,
        "status": 0x02, "status_word": 0x02,
        "tags": 0x04, "tag_word": 0x04,
        "registers": 0x08, "stack": 0x0c,
        "instruction_pointer": 0x10, "error_offset": 0x10,
        "code_selector": 0x20, "error_selector": 0x20,
        "data_pointer": 0x40, "data_offset": 0x40,
        "data_selector": 0x80,
        "environment": 0xf7, "all": 0xff,
    }
    if set(x87_aliases) != set(X87_EXCEPTION_PROJECTION_FIELDS_V1):
        raise AssertionError("checked x87 projection vocabulary drifted")
    unsupported_x87 = sorted(x87_names - set(x87_aliases))
    if unsupported_x87:
        raise ToolkitInputError(
            f"generic native ingress cannot project x87 CONTEXT fields {unsupported_x87!r}"
        )
    x87_mask = 0
    for name in x87_names:
        x87_mask |= x87_aliases[name]
    registers = {
        str(value).lower()
        for field in ("registers", "context")
        for value in projections.get(field, [])
        if str(value).lower() in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"}
    }
    bits = {
        "edi": 0x01, "esi": 0x02, "ebx": 0x04, "edx": 0x08,
        "ecx": 0x10, "eax": 0x20, "ebp": 0x40,
    }
    register_mask = sum(bits[value] for value in registers)
    flags = any(
        str(value).lower() in {"eflags", "flags"}
        for field in ("flags", "context")
        for value in projections.get(field, [])
    )
    stack = any(
        str(value).lower() == "esp"
        for field in ("stack", "context")
        for value in projections.get(field, [])
    )
    supported_context = {
        "contextflags", "eax", "ebx", "ecx", "edx", "esi", "edi",
        "ebp", "esp", "eflags", "eip",
    }
    unsupported_context = sorted(
        str(value) for value in projections.get("context", [])
        if str(value).lower() not in supported_context
    )
    if unsupported_context:
        raise ToolkitInputError(
            f"generic native ingress cannot project CONTEXT fields {unsupported_context!r}"
        )
    record_masks = _exception_record_projection_masks_v1(protocol)
    record_names = {
        str(value).lower()
        for value in projections.get("exception_record", [])
    }
    context_bits = {
        "contextflags": 0,
        "edi": 1,
        "esi": 2,
        "ebx": 3,
        "edx": 4,
        "ecx": 5,
        "eax": 6,
        "ebp": 7,
        "eflags": 8,
        "esp": 9,
        "eip": 10,
    }
    context_names = {
        str(value).lower() for value in projections.get("context", [])
    }
    numeric_address = (
        "exceptionaddress" in record_names or "eip" in context_names
    )
    if numeric_address and (
        protocol.get("address_policy") != "pinned_original_layout"
        or not protocol.get("pinned_layout_authority_id")
    ):
        raise ToolkitInputError(
            "numeric exception address projection requires pinned layout authority"
        )
    if protocol.get("handler_rva") is not None and (
        record_names or context_names
    ) and protocol.get("resumption_rva") is None:
        raise ToolkitInputError(
            "checked exception objects require an authorized guest resumption"
        )
    context_mask = sum(1 << context_bits[name] for name in context_names)
    return (
        register_mask,
        int(flags),
        int(stack),
        x87_mask,
        record_masks[0],
        context_mask,
    )
