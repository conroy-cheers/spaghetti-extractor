# ruff: noqa: F401
"""Exact IA-32 PE-TLS ABI and table-driven native-ingress source emission."""

from __future__ import annotations

import json
from typing import Any, Mapping

from ..transfer.exception_projection import MAX_EXCEPTION_RECORD_CHAIN_V1
from ..artifacts.artifact_set import canonical_sha256_v3
from ..calls.frame import PhysicalCallFrameV2
from ..errors import ToolkitInputError
from .native_ingress_runtime_abi import (
    DIAGNOSTIC_REGION_OFFSET,
    EXCEPTION_CHAIN_SCRATCH_BYTES,
    FRAME_REGION_OFFSET,
    INGRESS_FRAME_BYTES,
    MACHINE_STATE_BYTES,
    MAX_CAPABILITY_GENERATIONS,
    RUNTIME_CONTEXT_OFFSET,
    RUNTIME_THREAD_STATE_BYTES,
    RUNTIME_THREAD_STATE_OFFSET,
    STATE_PAIR_BYTES,
    STATE_REGION_OFFSET,
    THREAD_HEADER_BYTES,
)
from .native_ingress_runtime_model import (
    _CAPABILITY_LIFETIME_MODES,
    physical_frame_transducer_v1,
    _checked_lifecycle_bindings_v1,
    _capability_lifetime,
    checked_unwind_effect_catalog_v1,
    require_realized_native_outcome_v1,
    NativeIngressSupportABI,
)
from .native_ingress_runtime_compact import (
    compact_callback_capability_source_v1,
    compact_callback_capture_prefix_source_v1,
    compact_callback_entry_source_v1,
    compact_callback_table_declarations_v1,
    compact_callback_table_values_v1,
    merge_compact_callback_lifetimes_v1,
    prepare_compact_callback_source_v1,
)
from .native_ingress_runtime_capabilities import (
    capability_authorization_source_v1,
)
from .native_ingress_runtime_assembly import (
    _bridge_rows,
    _exception_record_projection_masks_v1,
    _preserved_mask,
    _seh_projection_masks,
)
from .native_ingress_runtime_exception import (
    exception_memory_access_source_v1,
    exception_object_helpers_source_v1,
    exception_recovery_source_v1,
    process_termination_branch_source_v1,
)
from .native_ingress_runtime_x87_source import native_x87_and_unwind_source_v1

def render_native_ingress_source(plan: Mapping[str, Any]) -> str:
    NativeIngressSupportABI.parse(plan)
    bridges = _bridge_rows(plan)
    compact = prepare_compact_callback_source_v1(plan, bridges)
    compact_callbacks = compact.runtime
    compact_lifetimes = compact.lifetimes
    runtime_bridges = compact.bridge_rows
    physical_frame_ids = sorted({
        identity
        for row in runtime_bridges
        for identity in row["physical_frame_ids"]
    })
    physical_frame_selectors = {
        identity: index + 1
        for index, identity in enumerate(physical_frame_ids)
    }
    capabilities = sorted({
        str(row["capability_id"])
        for row in plan.get("ingresses", [])
        if isinstance(row, Mapping) and row.get("capability_id") is not None
    } | set(compact_lifetimes))
    capability_index = {identity: index for index, identity in enumerate(capabilities)}
    seh_protocols = [
        row for row in plan.get("seh_protocols", []) if isinstance(row, Mapping)
    ]
    process_termination_branch = process_termination_branch_source_v1(
        seh_protocols
    )
    unwind_effect_catalog = checked_unwind_effect_catalog_v1(plan)
    portal_declarations: list[str] = []
    seh_rows: list[str] = []
    seh_rows_by_protocol_id: dict[str, list[int]] = {}
    unwind_effect_rvas: list[int] = []
    referenced_unwind_effects: set[str] = set()
    for protocol_index, protocol in enumerate(seh_protocols):
        protocol_id = protocol.get("id")
        if not isinstance(protocol_id, str) or not protocol_id:
            raise ToolkitInputError("native ingress SEH protocol identity is missing")
        if protocol_id in seh_rows_by_protocol_id:
            raise ToolkitInputError("native ingress SEH protocol identity is duplicated")
        unwind_effect_ids = protocol.get("unwind_effect_ids", [])
        if not isinstance(unwind_effect_ids, list) or any(
            not isinstance(identity, str) or not identity
            for identity in unwind_effect_ids
        ):
            raise ToolkitInputError(
                "native ingress SEH unwind-effect inventory is malformed"
            )
        unwind_first = len(unwind_effect_rvas)
        for identity in unwind_effect_ids:
            rva = unwind_effect_catalog.get(identity)
            if rva is None:
                raise ToolkitInputError(
                    "native ingress SEH names an unresolved unwind effect"
                )
            referenced_unwind_effects.add(identity)
            unwind_effect_rvas.append(rva)
        seh_rows_by_protocol_id[protocol_id] = []
        exception = protocol["exception"]
        (
            register_mask,
            flags_projection,
            stack_projection,
            x87_projection,
            exception_record_projection,
            context_projection,
        ) = _seh_projection_masks(protocol)
        record_masks = _exception_record_projection_masks_v1(protocol)
        padded_nested_record_masks = [
            *record_masks[1:],
            *([0] * (MAX_EXCEPTION_RECORD_CHAIN_V1 - len(record_masks))),
        ]
        escape_code = {
            "continue_search": 0,
            "terminate_process_root": 1,
            "escape_callable_root": 2,
        }[str(protocol["escape_disposition"])]
        access = exception.get("access_violation")
        operation_parameter = (
            0xFFFFFFFF if access is None else int(access["operation_parameter"])
        )
        address_parameter = (
            0xFFFFFFFF if access is None else int(access["address_parameter"])
        )
        for portal in protocol.get("portals", []):
            seh_rows_by_protocol_id[protocol_id].append(len(seh_rows))
            symbol = str(portal["candidate_symbol"])
            portal_declarations.append(f"extern const uint8_t {symbol}[];")
            seh_rows.append(
                "  { %dU, 0x%08xU, 0x%08xU, 0x%08xU, %dU, %dU, %s, %s, %dU, 0x%08xU, 0x%02xU, %dU, %dU, 0x%02xU, 0x%08xU, { %s }, %dU, 0x%08xU, 0x%08xU, 0x%08xU, %dU, %dU, %s, %dU }," % (
                    protocol_index,
                    int(exception["code"]),
                    int(exception["flags_mask"]),
                    int(exception["flags_value"]),
                    int(exception["parameter_count"]),
                    1 if exception["continuable"] else 0,
                    "0U" if protocol.get("handler_rva") is None else f"0x{int(protocol['handler_rva']):08x}U",
                    "0U" if protocol.get("resumption_rva") is None else f"0x{int(protocol['resumption_rva']):08x}U",
                    escape_code,
                    int(portal["source_rva"]),
                    register_mask,
                    flags_projection,
                    stack_projection,
                    x87_projection,
                    exception_record_projection,
                    ", ".join(
                        f"0x{mask:08x}U"
                        for mask in padded_nested_record_masks
                    ),
                    len(record_masks),
                    context_projection,
                    operation_parameter,
                    address_parameter,
                    unwind_first,
                    len(unwind_effect_ids),
                    symbol,
                    1 if protocol.get("address_policy") == "pinned_original_layout" else 0,
                )
            )
    if referenced_unwind_effects != set(unwind_effect_catalog):
        raise ToolkitInputError(
            "native ingress unwind-effect catalog is not exactly referenced"
        )
    portal_declaration_text = "\n".join(sorted(set(portal_declarations)))
    raise_pointer_declaration = (
        "uint32_t *spx_native_raise_exception_iat_pointer = "
        "(uint32_t *)(uintptr_t)1U;"
    )
    seh_table = "\n".join(seh_rows) or (
        "  { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, "
        "0U, { 0U, 0U, 0U }, 1U, 0U, 0xffffffffU, 0xffffffffU, 0U, 0U, "
        "0, 0 },"
    )
    unwind_effect_table = "\n".join(
        f"  0x{rva:08x}U," for rva in unwind_effect_rvas
    ) or "  0U,"
    descriptor_rows = []
    descriptor_lifecycle_modes: list[int] = []
    lifecycle_borrows: list[dict[str, Any]] = []
    bridge_capability_indexes: list[int] = []
    bridge_seh_indexes: list[int] = []
    bridge_physical_frame_selectors: list[int] = []
    physical_stack_ranges: list[dict[str, Any]] = []
    for bridge_index, row in enumerate(runtime_bridges):
        descriptor = row["descriptor"]
        transport = PhysicalCallFrameV2.parse(descriptor["physical_frame"]["transport"])
        transducer, transducer_issues = physical_frame_transducer_v1(
            descriptor["physical_frame"]
        )
        if transducer_issues:
            raise ToolkitInputError(
                "native ingress physical frame cannot be represented by the "
                "complete capture ABI"
            )
        provided_transducer = descriptor.get("physical_transducer")
        if provided_transducer is not None:
            if not isinstance(provided_transducer, Mapping):
                raise ToolkitInputError(
                    "native ingress physical transducer is malformed"
                )
            provided_core = {
                key: value for key, value in provided_transducer.items()
                if key != "transducer_sha256"
            }
            if (
                provided_core != transducer
                or provided_transducer.get("transducer_sha256")
                != canonical_sha256_v3(transducer)
            ):
                raise ToolkitInputError(
                    "native ingress physical transducer is stale"
                )
        stack_first = len(physical_stack_ranges)
        physical_stack_ranges.extend(transducer["stack_ranges"])
        lifecycle_protocol = descriptor.get("lifecycle_protocol")
        lifecycle_mode = 0
        process_root = int(row["process_root"])
        if (
            isinstance(lifecycle_protocol, Mapping)
            and lifecycle_protocol.get("kind")
            == "reviewed_pe32_loader_lifecycle_v1"
        ):
            lifecycle_mode = {
                "process_entry": 0,
                "dll_entry": 1,
                "tls_callback": 2,
            }.get(str(lifecycle_protocol.get("role")), 0)
        lifecycle_first = len(lifecycle_borrows)
        lifecycle_transducer = descriptor.get("lifecycle_transducer")
        if lifecycle_transducer is not None:
            if not isinstance(lifecycle_transducer, Mapping):
                raise ToolkitInputError(
                    "native ingress lifecycle transducer is malformed"
                )
            lifecycle_core = {
                key: value for key, value in lifecycle_transducer.items()
                if key != "transducer_sha256"
            }
            if lifecycle_transducer.get("transducer_sha256") != (
                canonical_sha256_v3(lifecycle_core)
            ):
                raise ToolkitInputError(
                    "native ingress lifecycle transducer is stale"
                )
            lifecycle_borrows.extend(_checked_lifecycle_bindings_v1(
                lifecycle_transducer,
                physical_frame_id=descriptor["physical_frame"].get("id"),
            ))
        outcome = next(
            item for item in plan.get("outcome_protocols", [])
            if item.get("id") == descriptor["outcome_protocol_id"]
        )
        require_realized_native_outcome_v1(outcome)
        outcome_mask = sum(
            1 << {"normal": 0, "no_return": 1, "exceptional": 2, "nonlocal": 3}[name]
            for name in outcome["outcomes"]
        )
        outcome_seh_ids = outcome.get("seh_protocol_ids", [])
        if not isinstance(outcome_seh_ids, list) or any(
            not isinstance(identity, str) or identity not in seh_rows_by_protocol_id
            for identity in outcome_seh_ids
        ):
            raise ToolkitInputError(
                "native ingress outcome protocol has invalid SEH authority"
            )
        if ("exceptional" in outcome["outcomes"]) != bool(outcome_seh_ids):
            raise ToolkitInputError(
                "native ingress exceptional outcome and SEH authority disagree"
            )
        seh_first = len(bridge_seh_indexes)
        for identity in outcome_seh_ids:
            bridge_seh_indexes.extend(seh_rows_by_protocol_id[identity])
        seh_count = len(bridge_seh_indexes) - seh_first
        capability_ids = row["capability_ids"]
        physical_frame_first = len(bridge_physical_frame_selectors)
        bridge_physical_frame_selectors.extend(
            physical_frame_selectors[identity]
            for identity in row["physical_frame_ids"]
        )
        descriptor_lifecycle_modes.append(lifecycle_mode)
        physical_subject = descriptor["physical_frame"]["transport"].get(
            "subject", {}
        )
        exception_filter_callback = (
            descriptor.get("role") == "callback"
            and isinstance(physical_subject, Mapping)
            and physical_subject.get("kind") == "callback"
            and physical_subject.get("id")
            == "win32-unhandled-exception-filter"
        )
        capability_first = len(bridge_capability_indexes)
        bridge_capability_indexes.extend(
            capability_index[identity] for identity in capability_ids
        )
        descriptor_rows.append(
            "  { %dU, 0x%08xU, %dU, %dU, %dU, %dU, %dU, 0x%08xU, %dU, %dU, %dU, %dU, %dU, %dU, %dU, %dU, %dU, %dU, %dU }," % (
                bridge_index,
                int(descriptor["target_rva"]),
                int(transport.stack.cleanup_bytes),
                outcome_mask,
                capability_first,
                len(capability_ids),
                1 if row["permanently_callable"] else 0,
                _preserved_mask(transport.preserved_state),
                lifecycle_mode,
                seh_first,
                seh_count,
                stack_first,
                len(transducer["stack_ranges"]),
                lifecycle_first,
                len(lifecycle_borrows) - lifecycle_first,
                physical_frame_first,
                len(row["physical_frame_ids"]),
                process_root,
                1 if exception_filter_callback else 0,
            )
        )
    capability_lifetimes: dict[str, tuple[str, str | None]] = {}
    for row in plan.get("ingresses", []):
        if not isinstance(row, Mapping) or row.get("capability_id") is None:
            continue
        identity = str(row["capability_id"])
        lifetime = _capability_lifetime(str(
            row.get("capability_lifetime")
            or "until_replaced_or_process_exit"
        ))
        prior = capability_lifetimes.setdefault(identity, lifetime)
        if prior != lifetime:
            raise ToolkitInputError(
                f"native ingress capability {identity!r} has conflicting lifetimes"
            )
    merge_compact_callback_lifetimes_v1(
        capability_lifetimes, compact_lifetimes
    )
    capability_lifetime_ranges: list[tuple[int, int, int, str | None]] = []
    for index, identity in enumerate(capabilities):
        lifetime, end_event = capability_lifetimes[identity]
        mode = _CAPABILITY_LIFETIME_MODES[lifetime]
        if (
            capability_lifetime_ranges
            and capability_lifetime_ranges[-1][0]
            + capability_lifetime_ranges[-1][1] == index
            and capability_lifetime_ranges[-1][2:] == (mode, end_event)
        ):
            first, count, observed_mode, observed_event = (
                capability_lifetime_ranges[-1]
            )
            capability_lifetime_ranges[-1] = (
                first, count + 1, observed_mode, observed_event
            )
        else:
            capability_lifetime_ranges.append((index, 1, mode, end_event))
    capability_lifetime_table = "\n".join(
        "  { %dU, %dU, %dU, %s }," % (
            first,
            count,
            mode,
            "0" if event is None else json.dumps(event, ensure_ascii=True),
        )
        for first, count, mode, event in capability_lifetime_ranges
    ) or "  { 0U, 0U, 0U, 0 },"
    descriptor_table = "\n".join(descriptor_rows) or (
        "  { 0U, 0U, 0U, 0U, 0U, 0U, 1U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U },"
    )
    physical_frame_selector_table = "\n".join(
        f"  {selector}U," for selector in bridge_physical_frame_selectors
    ) or "  0U,"
    register_codes = {
        name: index for index, name in enumerate(
            ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        )
    }
    lifecycle_borrow_table = "\n".join(
        "  { %dU, %d, %dU, %dU, %dU }, /* %s */" % (
            1 if row["location"]["kind"] == "register" else 2,
            register_codes[str(row["location"]["name"])]
            if row["location"]["kind"] == "register"
            else int(row["location"]["stack_offset_bytes"]),
            (int(row["location"]["width_bits"]) + 7) // 8,
            0 if row["nullable"] else 1,
            1 if row["transition"] == "borrow_shared" else 2,
            str(row["binding_id"]),
        )
        for row in lifecycle_borrows
    ) or "  { 0U, 0, 0U, 0U, 0U },"
    if any(
        row["direction"] not in {"input", "output"}
        for row in physical_stack_ranges
    ):
        raise ToolkitInputError(
            "native ingress physical stack range has unsupported access"
        )
    physical_stack_range_table = "\n".join(
        "  { %d, %dU, %dU }, /* %s:%s */" % (
            int(row["offset_bytes"]), int(row["extent_bytes"]),
            1 if row["direction"] == "input" else 2,
            str(row["direction"]), str(row["slot_id"]),
        )
        for row in physical_stack_ranges
    ) or "  { 0, 0U, 0U },"
    bridge_capability_table = "\n".join(
        f"  {index}U," for index in bridge_capability_indexes
    ) or "  0U,"
    (
        compact_capability_table,
        compact_global_target_table,
        compact_target_rva_table,
        compact_global_target_count,
        compact_assignment_table,
        compact_descriptor_table,
        compact_descriptor_range_count,
    ) = compact_callback_table_values_v1(
        compact_callbacks, capability_index,
        compact.target_descriptor_indexes,
    )
    compact_table_declarations = compact_callback_table_declarations_v1(
        capability_rows=compact_capability_table,
        global_rows=compact_global_target_table,
        target_rva_rows=compact_target_rva_table,
        assignment_rows=compact_assignment_table,
        descriptor_rows=compact_descriptor_table,
        descriptor_range_count=compact_descriptor_range_count,
        global_count=compact_global_target_count,
    )
    interface_callback_argument_rows: list[str] = []
    for domain in compact_callbacks.domains:
        raw_arguments = domain.payload.get(
            "interface_callback_arguments", []
        )
        if not isinstance(raw_arguments, list):
            raise ToolkitInputError(
                "native interface callback argument catalog is malformed"
            )
        normalized_arguments: list[tuple[int, str, str]] = []
        for raw_argument in raw_arguments:
            if not isinstance(raw_argument, Mapping):
                raise ToolkitInputError(
                    "native interface callback argument is malformed"
                )
            argument_index = raw_argument.get("argument_index")
            profile_sha256 = raw_argument.get("profile_sha256")
            interface_id = raw_argument.get("interface_id")
            if (
                raw_argument.get("kind") != "interface_object"
                or not isinstance(argument_index, int)
                or isinstance(argument_index, bool)
                or not 0 <= argument_index < 64
                or not isinstance(profile_sha256, str)
                or len(profile_sha256) != 64
                or not isinstance(interface_id, str)
                or not interface_id
            ):
                raise ToolkitInputError(
                    "native interface callback argument authority is malformed"
                )
            normalized_arguments.append((
                argument_index, profile_sha256, interface_id,
            ))
        if normalized_arguments != sorted(set(normalized_arguments)):
            raise ToolkitInputError(
                "native interface callback arguments are non-canonical"
            )
        for argument_index, profile_sha256, interface_id in (
            normalized_arguments
        ):
            interface_callback_argument_rows.append(
                "  { %dU, %dU, %dU, %s, %s }," % (
                    domain.flat_first,
                    len(domain.targets),
                    argument_index,
                    json.dumps(profile_sha256),
                    json.dumps(interface_id),
                )
            )
    interface_callback_argument_table = "\n".join(
        interface_callback_argument_rows
    ) or '  { 0U, 0U, 0U, "", "" },'
    bridge_seh_table = "\n".join(
        f"  {index}U," for index in bridge_seh_indexes
    ) or "  0U,"
    loader_lifecycle_present = any(descriptor_lifecycle_modes)
    return f'''#include "native-ingress-runtime.h"

#include <stddef.h>
#include <stdint.h>

extern uint32_t spx_behavioral_function_owner(
    uint32_t source_rva, uint32_t *owner_rva) __attribute__((weak));
extern uint32_t spx_native_runtime_bind_interface_callback_argument(
    const char *profile_sha256, const char *interface_id,
    uint32_t object, uint32_t generation);
extern uint32_t spx_native_runtime_unbind_interface_callback_argument(
    const char *profile_sha256, const char *interface_id,
    uint32_t object, uint32_t generation, uint32_t binding_kind);

typedef struct spx_native_ingress_descriptor {{
  uint32_t bridge_index, target_rva, cleanup_bytes, outcome_mask;
  uint32_t capability_first, capability_count, permanently_callable;
  uint32_t preserved_mask, lifecycle_mode, seh_first, seh_count;
  uint32_t stack_range_first, stack_range_count;
  uint32_t lifecycle_first, lifecycle_count;
  uint32_t physical_frame_first, physical_frame_count;
  uint32_t process_root, exception_filter_callback;
}} spx_native_ingress_descriptor;
typedef struct spx_native_interface_callback_argument {{
  uint32_t flat_first, target_count, argument_index;
  const char *profile_sha256, *interface_id;
}} spx_native_interface_callback_argument;
typedef struct spx_native_compact_descriptor_range {{
  uint32_t flat_first, target_count, descriptor_index;
}} spx_native_compact_descriptor_range;

typedef struct spx_native_physical_stack_range {{
  int32_t offset_bytes;
  uint32_t extent_bytes, access_mask;
}} spx_native_physical_stack_range;

typedef struct spx_native_lifecycle_borrow {{
  uint32_t source_kind;
  int32_t source;
  uint32_t width_bytes, nonnull, transition;
}} spx_native_lifecycle_borrow;

typedef struct spx_native_ingress_frame {{
  uint32_t parent_index, bridge_index, stack_mark, generation;
  spx_native_physical_capture *capture;
  spx_machine_state *input, *output;
  uint32_t outcome, host_stack_base, host_stack_limit;
  void *outgoing_mark, *x87_mark;
  uint32_t runtime_initialized_mark, runtime_nested_depth_mark;
  uint32_t exception_active, exception_seh_index;
  uint32_t exception_record, exception_context, exception_handler_frame;
}} spx_native_ingress_frame;

typedef struct spx_native_thread_header {{
  uint32_t magic, abi_version, depth, reserved_stack;
  uint32_t generation, exceptional, exception_code, exception_flags;
  uint32_t exception_address, exception_parameter_count, exception_parameters[15];
  uint32_t seh_descriptor_index, exception_frame_index;
  uint32_t image_generation, thread_generation;
}} spx_native_thread_header;

typedef struct spx_native_capability_generation {{
  uint32_t generation, active, escaped, owner_thread, owner_ingress;
}} spx_native_capability_generation;

typedef struct spx_native_capability_state {{
  volatile uint32_t lock;
  spx_native_capability_generation generations[{MAX_CAPABILITY_GENERATIONS}];
}} spx_native_capability_state;
typedef struct spx_native_capability_lifetime_range {{
  uint32_t capability_first, capability_count, lifetime_mode;
  const char *end_event;
}} spx_native_capability_lifetime_range;

typedef struct spx_native_seh_descriptor {{
  uint32_t protocol_index, code, flags_mask, flags_value, parameter_count;
  uint32_t continuable, handler_rva, resumption_rva, escape_disposition;
  uint32_t source_rva, register_projection_mask, flags_projection;
  uint32_t stack_projection, x87_projection_mask;
  uint32_t exception_record_projection_mask;
  uint32_t nested_exception_record_projection_masks[{MAX_EXCEPTION_RECORD_CHAIN_V1 - 1}];
  uint32_t exception_record_count, context_projection_mask;
  uint32_t operation_parameter, address_parameter;
  uint32_t unwind_first, unwind_count;
  const uint8_t *portal;
  uint32_t pinned_address_projection;
}} spx_native_seh_descriptor;

static uint32_t spx_native_checked_exception_address(
    const spx_native_seh_descriptor *seh, uint32_t rva);

{portal_declaration_text}
extern void spx_native_exception_recovery(void);
extern void spx_native_seh_gateway(void);

uint32_t *spx_native_tls_index_cell_pointer = (uint32_t *)(uintptr_t)1U;
uint8_t *spx_native_module_base_pointer = (uint8_t *)(uintptr_t)1U;
{raise_pointer_declaration}

static const spx_native_ingress_descriptor spx_native_ingress_descriptors[] = {{
{descriptor_table}
}};
static const uint32_t spx_native_ingress_descriptor_storage_count = {len(runtime_bridges)}U;
static const uint32_t spx_native_static_ingress_descriptor_count = {len(bridges)}U;
static const uint32_t spx_native_compact_callback_target_count = {len(compact_callbacks.targets)}U;
static const uint32_t spx_native_ingress_descriptor_count =
    {len(bridges) + len(compact_callbacks.targets)}U;
static const spx_native_physical_stack_range spx_native_stack_ranges[] = {{
{physical_stack_range_table}
}};
static const uint32_t spx_native_stack_range_count = {len(physical_stack_ranges)}U;
static const spx_native_lifecycle_borrow spx_native_lifecycle_borrows[] = {{
{lifecycle_borrow_table}
}};
static const uint32_t spx_native_lifecycle_borrow_count = {len(lifecycle_borrows)}U;
static const uint32_t spx_native_bridge_capability_indexes[] = {{
{bridge_capability_table}
}};
{compact_table_declarations}
static const spx_native_interface_callback_argument
spx_native_interface_callback_arguments[] = {{
{interface_callback_argument_table}
}};
static const uint32_t spx_native_interface_callback_argument_count =
    {len(interface_callback_argument_rows)}U;
static const uint32_t spx_native_bridge_seh_indexes[] = {{
{bridge_seh_table}
}};
static const uint32_t spx_native_bridge_physical_frame_selectors[] = {{
{physical_frame_selector_table}
}};
static spx_native_capability_state
spx_native_capabilities[{max(1, len(capabilities))}U];
static const spx_native_capability_lifetime_range
spx_native_capability_lifetime_ranges[] = {{
{capability_lifetime_table}
}};
static const uint32_t spx_native_capability_count = {len(capabilities)}U;
static const uint32_t spx_native_capability_lifetime_range_count =
    {len(capability_lifetime_ranges)}U;
static volatile uint32_t spx_native_next_capability_generation = 1U;
static volatile uint32_t spx_native_image_generation = 1U;
static volatile uint32_t spx_native_image_active = {0 if loader_lifecycle_present else 1}U;
static volatile uint32_t spx_native_next_thread_generation = 1U;
static const spx_native_seh_descriptor spx_native_seh_descriptors[] = {{
{seh_table}
}};
static const uint32_t spx_native_seh_descriptor_count = {len(seh_rows)}U;
static const uint32_t spx_native_unwind_effect_rvas[] = {{
{unwind_effect_table}
}};
static const uint32_t spx_native_unwind_effect_count = {len(unwind_effect_rvas)}U;

static const spx_native_ingress_descriptor *spx_native_ingress_descriptor_for(
    uint32_t bridge_index) {{
  uint32_t flat_target_index, descriptor_index, low, high;
  if (bridge_index >= spx_native_ingress_descriptor_count) return 0;
  if (bridge_index < spx_native_static_ingress_descriptor_count)
    descriptor_index = bridge_index;
  else {{
    flat_target_index =
        bridge_index - spx_native_static_ingress_descriptor_count;
    if (flat_target_index >= spx_native_compact_callback_target_count)
      return 0;
    low = 0U;
    high = spx_native_compact_descriptor_range_count;
    while (low < high) {{
      const uint32_t middle = low + (high - low) / 2U;
      const spx_native_compact_descriptor_range *range =
          &spx_native_compact_descriptor_ranges[middle];
      if (flat_target_index < range->flat_first)
        high = middle;
      else if (flat_target_index - range->flat_first >= range->target_count)
        low = middle + 1U;
      else {{
        descriptor_index = range->descriptor_index;
        goto descriptor_selected;
      }}
    }}
    return 0;
  }}
descriptor_selected:
  if (descriptor_index >= spx_native_ingress_descriptor_storage_count)
    return 0;
  return &spx_native_ingress_descriptors[descriptor_index];
}}

static uint32_t spx_native_ingress_target_rva(
    uint32_t bridge_index,
    const spx_native_ingress_descriptor *descriptor) {{
  uint32_t flat_target_index;
  if (descriptor == 0 || bridge_index >= spx_native_ingress_descriptor_count)
    return 0U;
  if (bridge_index < spx_native_static_ingress_descriptor_count)
    return descriptor->target_rva;
  flat_target_index =
      bridge_index - spx_native_static_ingress_descriptor_count;
  if (flat_target_index >= spx_native_compact_callback_target_count)
    return 0U;
  return spx_native_compact_target_rvas[flat_target_index];
}}

static const spx_native_capability_lifetime_range *
spx_native_capability_lifetime_for(uint32_t capability_index) {{
  uint32_t low = 0U, high = spx_native_capability_lifetime_range_count;
  if (capability_index >= spx_native_capability_count) return 0;
  while (low < high) {{
    const uint32_t middle = low + (high - low) / 2U;
    const spx_native_capability_lifetime_range *range =
        &spx_native_capability_lifetime_ranges[middle];
    if (capability_index < range->capability_first)
      high = middle;
    else if (capability_index - range->capability_first >=
             range->capability_count)
      low = middle + 1U;
    else
      return range;
  }}
  return 0;
}}

static uint32_t spx_native_capability_expire_thread(uint32_t owner_thread);
static uint32_t spx_native_capability_expire_process(void);
static uint32_t spx_native_capability_expire_ingress(uint32_t owner_ingress);
static uint32_t spx_native_abandon_top_frame(
    uint8_t *base, spx_native_thread_header *header);
static uint32_t spx_native_abandon_frames_above(
    uint8_t *base, spx_native_thread_header *header,
    uint32_t retained_index);

{compact_callback_capture_prefix_source_v1()}

static uint8_t *spx_native_thread_base(void) {{
  void **slots;
  uint32_t index;
  if (spx_native_tls_index_cell_pointer == 0) return 0;
  index = *spx_native_tls_index_cell_pointer;
  __asm__ volatile ("movl %%fs:0x2c,%0" : "=r" (slots));
  if (slots == 0 || slots[index] == 0) return 0;
  return (uint8_t *)slots[index] + SPX_NATIVE_TLS_RUNTIME_OFFSET;
}}

void *spx_native_module_tls_base_current(void) {{
  void **slots;
  uint32_t index;
  if (spx_native_tls_index_cell_pointer == 0) return 0;
  index = *spx_native_tls_index_cell_pointer;
  __asm__ volatile ("movl %%fs:0x2c,%0" : "=r" (slots));
  return slots == 0 ? 0 : slots[index];
}}

void *spx_native_runtime_context_current(void) {{
  uint8_t *base = spx_native_thread_base();
  return base == 0 ? 0 : base + SPX_NATIVE_RUNTIME_CONTEXT_OFFSET;
}}

void *spx_module_runtime_thread_state_current(void) {{
  uint8_t *base = spx_native_thread_base();
  return base == 0 ? 0 : base + {RUNTIME_THREAD_STATE_OFFSET}U;
}}

void *spx_native_outgoing_frame_current(void) {{
  void **state = (void **)spx_module_runtime_thread_state_current();
  return state == 0 ? 0 : state[0];
}}

void *spx_native_x87_frame_current(void) {{
  void **state = (void **)spx_module_runtime_thread_state_current();
  return state == 0 ? 0 : state[2];
}}

volatile uint32_t *spx_native_runtime_diagnostic_slot(uint32_t index) {{
  uint8_t *base = spx_native_thread_base();
  if (base == 0 || index >= 4U) return 0;
  return (volatile uint32_t *)(void *)(
      base + {DIAGNOSTIC_REGION_OFFSET}U + index * 4U);
}}

static spx_native_ingress_frame *spx_native_frame_at(
    uint8_t *base, uint32_t index) {{
  return (spx_native_ingress_frame *)(void *)(
      base + {FRAME_REGION_OFFSET}U + index * {INGRESS_FRAME_BYTES}U);
}}

static uint32_t spx_native_frame_for_establisher(
    uint8_t *base, const spx_native_thread_header *header,
    const void *establisher, uint32_t *frame_index) {{
  uint32_t index;
  uintptr_t observed;
  if (base == 0 || header == 0 || establisher == 0 || frame_index == 0)
    return 0U;
  observed = (uintptr_t)establisher;
  for (index = 0U; index < header->depth; ++index) {{
    const spx_native_ingress_frame *frame = spx_native_frame_at(base, index);
    uintptr_t expected = (uintptr_t)(
        base + SPX_PRIVATE_STACK_OFFSET + frame->stack_mark - 8U);
    if (observed == expected) {{
      *frame_index = index;
      return 1U;
    }}
  }}
  return 0U;
}}

static spx_machine_state *spx_native_state_at(
    uint8_t *base, uint32_t index, uint32_t output) {{
  return (spx_machine_state *)(void *)(base + {STATE_REGION_OFFSET}U +
      index * {STATE_PAIR_BYTES}U + output * {MACHINE_STATE_BYTES}U);
}}

{exception_memory_access_source_v1()}

static void spx_native_read_stack_bounds(
    uint32_t *stack_base, uint32_t *stack_limit) {{
  __asm__ volatile ("movl %%fs:0x4,%0" : "=r" (*stack_base));
  __asm__ volatile ("movl %%fs:0x8,%0" : "=r" (*stack_limit));
}}

static void spx_native_write_stack_bounds(
    uint32_t stack_base, uint32_t stack_limit) {{
  __asm__ volatile ("movl %0,%%fs:0x4" : : "r" (stack_base) : "memory");
  __asm__ volatile ("movl %0,%%fs:0x8" : : "r" (stack_limit) : "memory");
}}

uint32_t spx_native_outgoing_stack_enter_host(void) {{
  uint8_t *base = spx_native_thread_base();
  spx_native_thread_header *header;
  spx_native_ingress_frame *frame;
  if (base == 0) return 0U;
  header = (spx_native_thread_header *)(void *)base;
  if (header->magic != SPX_NATIVE_THREAD_MAGIC || header->depth == 0U)
    return 0U;
  frame = spx_native_frame_at(base, header->depth - 1U);
  if (frame->host_stack_base <= frame->host_stack_limit) return 0U;
  spx_native_write_stack_bounds(
      frame->host_stack_base, frame->host_stack_limit);
  return 1U;
}}

uint32_t spx_native_host_stack_bounds_current(
    uint32_t *stack_base, uint32_t *stack_limit) {{
  uint8_t *base = spx_native_thread_base();
  spx_native_thread_header *header;
  spx_native_ingress_frame *frame;
  if (base == 0 || stack_base == 0 || stack_limit == 0) return 0U;
  header = (spx_native_thread_header *)(void *)base;
  if (header->magic != SPX_NATIVE_THREAD_MAGIC || header->depth == 0U)
    return 0U;
  frame = spx_native_frame_at(base, header->depth - 1U);
  if (frame->host_stack_base <= frame->host_stack_limit) return 0U;
  *stack_base = frame->host_stack_base;
  *stack_limit = frame->host_stack_limit;
  return 1U;
}}

uint32_t spx_native_outgoing_stack_leave_host(void) {{
  uint8_t *base = spx_native_thread_base();
  spx_native_thread_header *header;
  uint32_t private_stack_limit, private_stack_base;
  if (base == 0) return 0U;
  header = (spx_native_thread_header *)(void *)base;
  if (header->magic != SPX_NATIVE_THREAD_MAGIC || header->depth == 0U)
    return 0U;
  private_stack_limit = (uint32_t)(uintptr_t)(
      base + SPX_PRIVATE_STACK_OFFSET);
  private_stack_base = private_stack_limit + SPX_PRIVATE_STACK_BYTES;
  if (private_stack_base <= private_stack_limit) return 0U;
  spx_native_write_stack_bounds(private_stack_base, private_stack_limit);
  return 1U;
}}

uint32_t spx_native_checked_unwind_inspect(
    uint32_t target_frame, spx_native_checked_unwind_snapshot *snapshot) {{
  uint32_t current, count = 0U, index;
  if (snapshot == 0 || target_frame == 0U ||
      (target_frame & 3U) != 0U)
    return 0U;
  if (spx_native_captured_stack_memory_access(
          target_frame, 8U, 0U) != 1U ||
      !spx_native_runtime_guest_seh_chain_head(&current))
    return 0U;
  snapshot->head = current;
  snapshot->target_frame = target_frame;
  snapshot->frame_count = 0U;
  while (current != target_frame) {{
    uint32_t next, handler, handler_rva, owner;
    if (count >= SPX_NATIVE_CHECKED_UNWIND_FRAME_LIMIT ||
        current == 0U || current == 0xffffffffU ||
        (current & 3U) != 0U ||
        spx_native_captured_stack_memory_access(
            current, 8U, 0U) != 1U)
      return 0U;
    for (index = 0U; index < count; ++index)
      if (snapshot->frames[index].establisher == current) return 0U;
    next = *(volatile const uint32_t *)(uintptr_t)current;
    handler = *(volatile const uint32_t *)(uintptr_t)(current + 4U);
    if (spx_native_module_base_pointer == 0 ||
        spx_native_module_base_pointer == (uint8_t *)(uintptr_t)1U ||
        handler < (uint32_t)(uintptr_t)spx_native_module_base_pointer)
      return 0U;
    handler_rva = handler -
        (uint32_t)(uintptr_t)spx_native_module_base_pointer;
    if (spx_behavioral_function_owner == 0 ||
        !spx_behavioral_function_owner(handler_rva, &owner)) return 0U;
    snapshot->frames[count].establisher = current;
    snapshot->frames[count].handler_rva = handler_rva;
    ++count;
    if (next != target_frame && next <= current) return 0U;
    current = next;
  }}
  snapshot->frame_count = count;
  return 1U;
}}

spx_call_status spx_native_checked_unwind_commit(
    const spx_native_checked_unwind_snapshot *snapshot,
    uint32_t exception_record_count,
    const uint32_t exception_record_words[][20],
    spx_runtime *runtime, spx_machine_state *state) {{
  spx_native_checked_unwind_snapshot observed;
  uint32_t records[SPX_EXCEPTION_RECORD_CHAIN_CAPACITY][20];
  uint32_t context[179], handler_frame[5];
  uint32_t index, word;
  if (snapshot == 0 || exception_record_words == 0 || runtime == 0 ||
      state == 0 || snapshot->frame_count >
          SPX_NATIVE_CHECKED_UNWIND_FRAME_LIMIT ||
      exception_record_count == 0U ||
      exception_record_count > SPX_EXCEPTION_RECORD_CHAIN_CAPACITY ||
      !spx_native_checked_unwind_inspect(snapshot->target_frame, &observed) ||
      observed.head != snapshot->head ||
      observed.frame_count != snapshot->frame_count)
    return SPX_CALL_UNIMPLEMENTED;
  for (index = 0U; index < snapshot->frame_count; ++index)
    if (observed.frames[index].establisher !=
            snapshot->frames[index].establisher ||
        observed.frames[index].handler_rva !=
            snapshot->frames[index].handler_rva)
      return SPX_CALL_UNIMPLEMENTED;
  for (index = 0U; index < snapshot->frame_count; ++index) {{
    spx_machine_state handler_state = *state;
    spx_call_status status;
    uint32_t expected_head = snapshot->frames[index].establisher;
    uint32_t next_head = index + 1U < snapshot->frame_count
        ? snapshot->frames[index + 1U].establisher
        : snapshot->target_frame;
    uint32_t observed_head = 0U;
    if (!spx_native_runtime_guest_seh_chain_head(&observed_head) ||
        observed_head != expected_head)
      return SPX_CALL_UNIMPLEMENTED;
    for (uint32_t depth = 0U; depth < exception_record_count; ++depth) {{
      for (word = 0U; word < 20U; ++word)
        records[depth][word] = exception_record_words[depth][word];
      records[depth][2] = depth + 1U < exception_record_count
          ? (uint32_t)(uintptr_t)&records[depth + 1U][0] : 0U;
    }}
    records[0][1] |= 0x00000002U; /* EXCEPTION_UNWINDING */
    for (word = 0U; word < 179U; ++word) context[word] = 0U;
    for (word = 0U; word < 5U; ++word) handler_frame[word] = 0U;
    context[0] = 0x00010003U;
    context[39] = state->edi; context[40] = state->esi;
    context[41] = state->ebx; context[42] = state->edx;
    context[43] = state->ecx; context[44] = state->eax;
    context[45] = state->ebp; context[48] = state->eflags;
    context[49] = state->esp;
    handler_frame[1] = (uint32_t)(uintptr_t)&records[0][0];
    handler_frame[2] = expected_head;
    handler_frame[3] = (uint32_t)(uintptr_t)context;
    handler_frame[4] = 0U;
    if (spx_native_runtime_bind_unwind_handler_objects(
            (uint32_t)(uintptr_t)&records[0][0],
            exception_record_count,
            (uint32_t)(uintptr_t)context,
            (uint32_t)(uintptr_t)handler_frame) != SPX_CALL_OK)
      return SPX_CALL_UNIMPLEMENTED;
    handler_state.esp = (uint32_t)(uintptr_t)handler_frame;
    status = spx_native_runtime_run_at_rva(
        snapshot->frames[index].handler_rva,
        &handler_state, &handler_state);
    if (spx_native_runtime_unbind_unwind_handler_objects(
            (uint32_t)(uintptr_t)&records[0][0],
            exception_record_count,
            (uint32_t)(uintptr_t)context,
            (uint32_t)(uintptr_t)handler_frame) != SPX_CALL_OK &&
        status == SPX_CALL_OK)
      status = SPX_CALL_UNIMPLEMENTED;
    if (!spx_native_runtime_guest_seh_chain_head(&observed_head) ||
        status != SPX_CALL_OK || handler_state.eax != 0U ||
        observed_head != expected_head)
      return status == SPX_CALL_OK ? SPX_CALL_UNIMPLEMENTED : status;
    if (!spx_native_runtime_set_guest_seh_chain_head(next_head))
      return SPX_CALL_UNIMPLEMENTED;
  }}
  if (!spx_native_runtime_guest_seh_chain_head(&observed.head))
    return SPX_CALL_UNIMPLEMENTED;
  return observed.head == snapshot->target_frame ? SPX_CALL_OK
      : SPX_CALL_UNIMPLEMENTED;
}}

{native_x87_and_unwind_source_v1()}

static uint32_t spx_native_raise_exception(
    const spx_native_seh_descriptor *seh,
    spx_native_thread_header *header) {{
  uint8_t *base = spx_native_thread_base();
  spx_native_ingress_frame *frame;
  spx_call_status status;
  if (base == 0 || header->depth == 0U) return 0U;
  frame = spx_native_frame_at(base, header->depth - 1U);
  if (spx_native_apply_checked_unwind(seh, frame) != SPX_CALL_OK) return 0U;
{process_termination_branch}
  if (spx_native_raise_exception_iat_pointer == 0 ||
      spx_native_raise_exception_iat_pointer == (uint32_t *)(uintptr_t)1U)
    return 0U;
  if (*spx_native_raise_exception_iat_pointer == 0U) return 0U;
  /* The gateway installed by this ingress must not consume an exception that
   * the checked protocol is deliberately transporting to an outer host frame. */
  header->exceptional = 3U;
  spx_native_raise_exception_gateway(
      seh->code, seh->continuable != 0U ? 0U : 1U,
      header->exception_parameter_count, header->exception_parameters);
  if (seh->continuable == 0U || header->exceptional != 4U) return 0U;
  if (seh->resumption_rva == 0U) return 0U;
  status = spx_native_runtime_run_at_rva(
      seh->resumption_rva, frame->output, frame->output);
  header->exceptional = 0U;
  return status == SPX_CALL_OK ? 1U : 0U;
}}

void spx_native_capture_continued_exception(
    const spx_native_physical_capture *capture) {{
  uint8_t *base = spx_native_thread_base();
  spx_native_thread_header *header;
  spx_native_ingress_frame *frame;
  const spx_native_seh_descriptor *seh;
  if (base == 0 || capture == 0) return;
  header = (spx_native_thread_header *)(void *)base;
  if (header->depth == 0U ||
      header->seh_descriptor_index >= spx_native_seh_descriptor_count)
    return;
  frame = spx_native_frame_at(base, header->depth - 1U);
  seh = &spx_native_seh_descriptors[header->seh_descriptor_index];
  if (seh->register_projection_mask & 0x01U) frame->output->edi = capture->edi;
  if (seh->register_projection_mask & 0x02U) frame->output->esi = capture->esi;
  if (seh->register_projection_mask & 0x04U) frame->output->ebx = capture->ebx;
  if (seh->register_projection_mask & 0x08U) frame->output->edx = capture->edx;
  if (seh->register_projection_mask & 0x10U) frame->output->ecx = capture->ecx;
  if (seh->register_projection_mask & 0x20U) frame->output->eax = capture->eax;
  if (seh->register_projection_mask & 0x40U) frame->output->ebp = capture->ebp;
  if (seh->flags_projection != 0U) frame->output->eflags = capture->eflags;
  if (seh->stack_projection != 0U) frame->output->esp = capture->entry_esp + 4U;
  if (seh->x87_projection_mask != 0U)
    spx_native_capture_current_x87(frame->output, seh->x87_projection_mask);
  header->exceptional = 4U;
}}

static void spx_native_import_capture(
    spx_machine_state *state, const spx_native_physical_capture *capture,
    uint32_t target_rva) {{
  *state = (spx_machine_state){{0}};
  state->eax = capture->eax; state->ebx = capture->ebx;
  state->ecx = capture->ecx; state->edx = capture->edx;
  state->esi = capture->esi; state->edi = capture->edi;
  state->ebp = capture->ebp; state->esp = capture->entry_esp + 4U;
  __asm__ volatile ("movl %%fs:0x18,%0" : "=r" (state->fs_base));
  state->eflags = capture->eflags; state->df = (capture->eflags >> 10) & 1U;
  state->cf = capture->eflags & 1U; state->pf = (capture->eflags >> 2) & 1U;
  state->zf = (capture->eflags >> 6) & 1U;
  state->sf = (capture->eflags >> 7) & 1U;
  state->of = (capture->eflags >> 11) & 1U;
  state->original_rva = target_rva;
}}

static void spx_native_export_capture(
    spx_native_physical_capture *capture, const spx_machine_state *state) {{
  capture->eax = state->eax; capture->ebx = state->ebx;
  capture->ecx = state->ecx; capture->edx = state->edx;
  capture->esi = state->esi; capture->edi = state->edi;
  capture->ebp = state->ebp;
  capture->eflags = (capture->eflags & ~0x0cd5U) |
      (state->cf & 1U) | ((state->pf & 1U) << 2) |
      ((state->zf & 1U) << 6) | ((state->sf & 1U) << 7) |
      ((state->df & 1U) << 10) | ((state->of & 1U) << 11);
}}

static void spx_native_restore_capture(
    spx_native_physical_capture *capture, const spx_machine_state *state) {{
  capture->eax = state->eax; capture->ebx = state->ebx;
  capture->ecx = state->ecx; capture->edx = state->edx;
  capture->esi = state->esi; capture->edi = state->edi;
  capture->ebp = state->ebp;
  capture->entry_esp = state->esp - 4U;
  capture->eflags = state->eflags;
}}

{capability_authorization_source_v1(MAX_CAPABILITY_GENERATIONS)}

void *spx_native_ingress_prepare(
    uint32_t bridge_index, spx_native_physical_capture *capture) {{
  uint8_t *base = spx_native_thread_base();
  spx_native_thread_header *header;
  spx_native_ingress_frame *frame;
  const spx_native_ingress_descriptor *descriptor;
  uint32_t index, stack_mark, capability_offset, capability_active;
  uint32_t private_stack_base, private_stack_limit;
  uint32_t host_stack_base, host_stack_limit;
  uint32_t capture_address, scratch_address;
  if (base == 0 || capture == 0 || bridge_index >= spx_native_ingress_descriptor_count)
    return 0;
  header = (spx_native_thread_header *)(void *)base;
  if (header->magic == 0U) {{
    header->magic = SPX_NATIVE_THREAD_MAGIC;
    header->abi_version = SPX_NATIVE_THREAD_ABI_VERSION;
    header->reserved_stack = 0U;
    header->generation = 1U;
    header->image_generation = __atomic_load_n(
        &spx_native_image_generation, __ATOMIC_ACQUIRE);
    header->thread_generation = __atomic_add_fetch(
        &spx_native_next_thread_generation, 1U, __ATOMIC_RELAXED);
    if (header->thread_generation == 0U)
      header->thread_generation = __atomic_add_fetch(
          &spx_native_next_thread_generation, 1U, __ATOMIC_RELAXED);
  }}
  if (header->magic != SPX_NATIVE_THREAD_MAGIC ||
      header->abi_version != SPX_NATIVE_THREAD_ABI_VERSION ||
      header->depth >= SPX_NATIVE_MAX_INGRESS_DEPTH)
    return 0;
  if (header->depth == 0U)
    spx_native_runtime_reset_guest_seh_chain();
  descriptor = spx_native_ingress_descriptor_for(bridge_index);
  if (descriptor == 0) return 0;
  if (descriptor->lifecycle_mode == 0U && descriptor->process_root == 0U &&
      (__atomic_load_n(&spx_native_image_active, __ATOMIC_ACQUIRE) == 0U ||
       header->image_generation != __atomic_load_n(
           &spx_native_image_generation, __ATOMIC_ACQUIRE)))
    return 0;
  if (descriptor->permanently_callable == 0U) {{
    capability_active = 0U;
    if (bridge_index >= spx_native_static_ingress_descriptor_count) {{
      const uint32_t flat_target_index =
          bridge_index - spx_native_static_ingress_descriptor_count;
      if (flat_target_index >= spx_native_compact_callback_target_count)
        return 0;
      capability_active = spx_native_capability_authorize(
          spx_native_compact_capability_indexes[flat_target_index],
          (uint32_t)(uintptr_t)base);
    }} else {{
      for (capability_offset = 0U;
           capability_offset < descriptor->capability_count;
           ++capability_offset) {{
        const uint32_t capability = spx_native_bridge_capability_indexes[
            descriptor->capability_first + capability_offset];
        if (capability_active == 0U)
          capability_active = spx_native_capability_authorize(
              capability, (uint32_t)(uintptr_t)base);
      }}
    }}
    if (capability_active == 0U) return 0;
  }}
  private_stack_limit = (uint32_t)(uintptr_t)(
      base + SPX_PRIVATE_STACK_OFFSET);
  private_stack_base = private_stack_limit + SPX_PRIVATE_STACK_BYTES;
  if (private_stack_base <= private_stack_limit ||
      SPX_PRIVATE_STACK_BYTES < SPX_PRIVATE_STACK_SLICE_BYTES)
    return 0;
  spx_native_read_stack_bounds(&host_stack_base, &host_stack_limit);
  if (host_stack_base <= host_stack_limit) return 0;
  capture_address = (uint32_t)(uintptr_t)capture;
  if (header->depth == 0U) {{
    /* A root owns the complete qualified stack reserve.  Fixed 64-KiB slices
     * made the rest of that reserve unreachable and caused ordinary generated
     * C recursion to cross the TEB limit long before the qualified bound. */
    scratch_address = private_stack_base - SPX_EXCEPTION_CHAIN_SCRATCH_BYTES;
  }} else {{
    /* Synchronous same-thread reentry arrives on the already active private
     * stack.  Continue its natural downward growth below the immutable capture
     * instead of jumping to a disjoint slice above the suspended caller. */
    if (host_stack_base != private_stack_base ||
        host_stack_limit != private_stack_limit ||
        capture_address > private_stack_base ||
        capture_address < private_stack_limit + SPX_PRIVATE_STACK_SLICE_BYTES)
      return 0;
    scratch_address = capture_address - SPX_EXCEPTION_CHAIN_SCRATCH_BYTES;
  }}
  if (scratch_address < private_stack_limit ||
      scratch_address >= private_stack_base)
    return 0;
  stack_mark = scratch_address - private_stack_limit;
  index = header->depth++;
  frame = spx_native_frame_at(base, index);
  frame->parent_index = index == 0U ? 0xffffffffU : index - 1U;
  frame->bridge_index = bridge_index; frame->stack_mark = stack_mark;
  frame->generation = header->generation++; frame->capture = capture;
  frame->input = spx_native_state_at(base, index, 0U);
  frame->output = spx_native_state_at(base, index, 1U);
  frame->outcome = 0U;
  frame->exception_active = 0U;
  frame->exception_seh_index = 0U;
  frame->exception_record = 0U;
  frame->exception_context = 0U;
  frame->exception_handler_frame = 0U;
  frame->outgoing_mark = spx_native_outgoing_frame_current();
  frame->x87_mark = spx_native_x87_frame_current();
  spx_native_runtime_execution_mark(
      &frame->runtime_initialized_mark,
      &frame->runtime_nested_depth_mark);
  spx_native_import_capture(
      frame->input, capture,
      spx_native_ingress_target_rva(bridge_index, descriptor));
  spx_native_capture_current_x87(frame->input, 0xffU);
  *frame->output = *frame->input;
  frame->host_stack_base = host_stack_base;
  frame->host_stack_limit = host_stack_limit;
  /* TEB stack bounds describe the one contiguous private stack used by guest
   * execution, native callees, SEH, and synchronous callback reentry. */
  spx_native_write_stack_bounds(private_stack_base, private_stack_limit);
  return (void *)(uintptr_t)scratch_address;
}}

static spx_call_status spx_native_loader_reason(
    const spx_native_ingress_frame *frame, uint32_t *reason) {{
  uint32_t reason_address;
  if (frame->input->esp > 0xffffffffU - 8U ||
      frame->host_stack_base < 4U)
    return SPX_CALL_MEMORY_FAULT;
  reason_address = frame->input->esp + 8U;
  if (reason_address < frame->host_stack_limit ||
      reason_address > frame->host_stack_base - 4U)
    return SPX_CALL_MEMORY_FAULT;
  *reason = *(const uint32_t *)(uintptr_t)reason_address;
  return *reason <= 3U ? SPX_CALL_OK : SPX_CALL_UNIMPLEMENTED;
}}

static uint32_t spx_native_validate_physical_stack_ranges(
    const spx_native_ingress_descriptor *descriptor,
    const spx_native_ingress_frame *frame) {{
  uint32_t offset;
  if (descriptor->stack_range_first > spx_native_stack_range_count ||
      descriptor->stack_range_count >
          spx_native_stack_range_count - descriptor->stack_range_first)
    return 0U;
  for (offset = 0U; offset < descriptor->stack_range_count; ++offset) {{
    const spx_native_physical_stack_range *range = &spx_native_stack_ranges[
        descriptor->stack_range_first + offset];
    int64_t start64 = (int64_t)(uint64_t)frame->input->esp +
        (int64_t)range->offset_bytes;
    uint32_t start, end;
    if (range->extent_bytes == 0U || start64 < 0 || start64 > 0xffffffffLL)
      return 0U;
    start = (uint32_t)start64;
    if (start > 0xffffffffU - range->extent_bytes) return 0U;
    end = start + range->extent_bytes;
    if (start < frame->host_stack_limit || end > frame->host_stack_base)
      return 0U;
  }}
  return 1U;
}}

uint32_t spx_native_physical_frame_memory_access(
    uint32_t address, uint32_t width, uint32_t write_access) {{
  uint8_t *base = spx_native_thread_base();
  spx_native_thread_header *header;
  spx_native_ingress_frame *frame;
  const spx_native_ingress_descriptor *descriptor;
  uint32_t address_end, offset, overlaps = 0U, allowed = 0U;
  const uint32_t requested = write_access != 0U ? 2U : 1U;
  if (base == 0 || width == 0U || address > 0xffffffffU - width)
    return 0U;
  address_end = address + width;
  header = (spx_native_thread_header *)(void *)base;
  if (header->magic != SPX_NATIVE_THREAD_MAGIC || header->depth == 0U)
    return 0U;
  frame = spx_native_frame_at(base, header->depth - 1U);
  if (frame->bridge_index >= spx_native_ingress_descriptor_count ||
      frame->input == 0)
    return 0U;
  descriptor = spx_native_ingress_descriptor_for(frame->bridge_index);
  if (descriptor == 0) return 2U;
  if (descriptor->stack_range_first > spx_native_stack_range_count ||
      descriptor->stack_range_count >
          spx_native_stack_range_count - descriptor->stack_range_first)
    return 2U;
  for (offset = 0U; offset < descriptor->stack_range_count; ++offset) {{
    const spx_native_physical_stack_range *range = &spx_native_stack_ranges[
        descriptor->stack_range_first + offset];
    const int64_t start64 = (int64_t)(uint64_t)frame->input->esp +
        (int64_t)range->offset_bytes;
    uint32_t start, end;
    if (range->extent_bytes == 0U || start64 < 0 ||
        start64 > 0xffffffffLL)
      return 2U;
    start = (uint32_t)start64;
    if (start > 0xffffffffU - range->extent_bytes) return 2U;
    end = start + range->extent_bytes;
    if (address < end && start < address_end) {{
      overlaps = 1U;
      if (address >= start && address_end <= end &&
          (range->access_mask & requested) != 0U)
        allowed = 1U;
    }}
  }}
  return allowed != 0U ? 1U : overlaps != 0U ? 2U : 0U;
}}

uint32_t spx_native_captured_stack_memory_access(
    uint32_t address, uint32_t width, uint32_t write_access) {{
  uint8_t *base = spx_native_thread_base();
  spx_native_thread_header *header;
  spx_native_ingress_frame *frame;
  uint32_t end, low, logical_top;
  (void)write_access;
  if (base == 0 || width == 0U || address > 0xffffffffU - width)
    return 0U;
  end = address + width;
  header = (spx_native_thread_header *)(void *)base;
  if (header->magic != SPX_NATIVE_THREAD_MAGIC || header->depth == 0U)
    return 0U;
  frame = spx_native_frame_at(base, header->depth - 1U);
  if (frame->bridge_index >= spx_native_ingress_descriptor_count ||
      frame->input == 0 || frame->host_stack_base <= frame->host_stack_limit)
    return 0U;
  logical_top = frame->input->esp;
  low = logical_top > SPX_PRIVATE_STACK_BYTES
      ? logical_top - SPX_PRIVATE_STACK_BYTES : 0U;
  if (low < frame->host_stack_limit) low = frame->host_stack_limit;
  /* The exact physical frame transducer separately owns the return address,
   * arguments, and writeback cells at and above logical_top.  This dynamic
   * invocation object is only the downward-growing callee stack. */
  return address >= low && end <= logical_top ? 1U : 0U;
}}

static uint32_t spx_native_lifecycle_borrow_value(
    const spx_native_lifecycle_borrow *binding,
    const spx_native_ingress_frame *frame, uint32_t *value) {{
  uint32_t address;
  int64_t address64;
  if (binding == 0 || frame == 0 || value == 0 ||
      binding->width_bytes == 0U || binding->width_bytes > 4U)
    return 0U;
  if (binding->source_kind == 1U) {{
    switch ((uint32_t)binding->source) {{
      case 0U: *value = frame->input->eax; break;
      case 1U: *value = frame->input->ebx; break;
      case 2U: *value = frame->input->ecx; break;
      case 3U: *value = frame->input->edx; break;
      case 4U: *value = frame->input->esi; break;
      case 5U: *value = frame->input->edi; break;
      case 6U: *value = frame->input->ebp; break;
      case 7U: *value = frame->input->esp; break;
      default: return 0U;
    }}
    if (binding->width_bytes < 4U)
      *value &= (1U << (binding->width_bytes * 8U)) - 1U;
    return 1U;
  }}
  if (binding->source_kind != 2U || frame->capture == 0) return 0U;
  address64 = (int64_t)(uint64_t)frame->capture->entry_esp + binding->source;
  if (address64 < 0 || address64 > 0xffffffffLL) return 0U;
  address = (uint32_t)address64;
  if (frame->host_stack_base < binding->width_bytes ||
      address < frame->host_stack_limit ||
      address > frame->host_stack_base - binding->width_bytes)
    return 0U;
  *value = binding->width_bytes == 1U
      ? *(const uint8_t *)(uintptr_t)address
      : binding->width_bytes == 2U
      ? *(const uint16_t *)(uintptr_t)address
      : *(const uint32_t *)(uintptr_t)address;
  return 1U;
}}

static spx_call_status spx_native_preflight_boundary_lifecycle(
    const spx_native_ingress_descriptor *descriptor,
    const spx_native_ingress_frame *frame) {{
  uint32_t offset;
  if (descriptor->lifecycle_first > spx_native_lifecycle_borrow_count ||
      descriptor->lifecycle_count >
          spx_native_lifecycle_borrow_count - descriptor->lifecycle_first)
    return SPX_CALL_UNIMPLEMENTED;
  for (offset = 0U; offset < descriptor->lifecycle_count; ++offset) {{
    const spx_native_lifecycle_borrow *binding =
        &spx_native_lifecycle_borrows[descriptor->lifecycle_first + offset];
    uint32_t value;
    if ((binding->transition != 1U && binding->transition != 2U) ||
        !spx_native_lifecycle_borrow_value(binding, frame, &value) ||
        (binding->nonnull != 0U && value == 0U))
      return SPX_CALL_UNIMPLEMENTED;
  }}
  return SPX_CALL_OK;
}}

static spx_call_status spx_native_preflight_loader_lifecycle(
    const spx_native_ingress_descriptor *descriptor,
    const spx_native_thread_header *header,
    const spx_native_ingress_frame *frame) {{
  uint32_t active, generation, reason;
  spx_call_status status;
  if (descriptor->lifecycle_mode == 0U) return SPX_CALL_OK;
  status = spx_native_loader_reason(frame, &reason);
  if (status != SPX_CALL_OK) return status;
  active = __atomic_load_n(&spx_native_image_active, __ATOMIC_ACQUIRE);
  generation = __atomic_load_n(
      &spx_native_image_generation, __ATOMIC_ACQUIRE);
  if (reason == 1U) return SPX_CALL_OK; /* DLL_PROCESS_ATTACH */
  /* TLS callbacks still run after DllMain during detach.  They observe the
   * checked order, but only DllMain owns the image/thread generation cut. */
  if (descriptor->lifecycle_mode == 2U && (reason == 0U || reason == 3U))
    return SPX_CALL_OK;
  return active != 0U && header->image_generation == generation
      ? SPX_CALL_OK : SPX_CALL_UNIMPLEMENTED;
}}

static spx_call_status spx_native_apply_loader_lifecycle(
    const spx_native_ingress_descriptor *descriptor,
    spx_native_thread_header *header, spx_native_ingress_frame *frame,
    spx_call_status status) {{
  uint32_t reason, owner_thread;
  if (status != SPX_CALL_OK || descriptor->lifecycle_mode == 0U)
    return status;
  status = spx_native_loader_reason(frame, &reason);
  if (status != SPX_CALL_OK) return status;
  owner_thread = (uint32_t)(uintptr_t)spx_native_thread_base();
  if (reason == 1U) {{ /* DLL_PROCESS_ATTACH */
    header->image_generation = __atomic_load_n(
        &spx_native_image_generation, __ATOMIC_ACQUIRE);
    if (header->thread_generation == 0U)
      header->thread_generation = __atomic_add_fetch(
          &spx_native_next_thread_generation, 1U, __ATOMIC_RELAXED);
    __atomic_store_n(&spx_native_image_active, 1U, __ATOMIC_RELEASE);
  }} else if (reason == 2U) {{ /* DLL_THREAD_ATTACH */
    if (header->thread_generation == 0U)
      header->thread_generation = __atomic_add_fetch(
          &spx_native_next_thread_generation, 1U, __ATOMIC_RELAXED);
  }} else if (reason == 3U && descriptor->lifecycle_mode == 1U) {{
    /* DLL_THREAD_DETACH is committed once at DllMain. */
    (void)spx_native_capability_expire_thread(owner_thread);
    header->thread_generation = 0U;
  }} else if (reason == 0U && descriptor->lifecycle_mode == 1U) {{
    /* DLL_PROCESS_DETACH is applied once at the reviewed DllMain boundary.
     * TLS callback bridges observe ordering but do not repeat image teardown. */
    (void)spx_native_capability_expire_process();
    __atomic_store_n(&spx_native_image_active, 0U, __ATOMIC_RELEASE);
    (void)__atomic_add_fetch(
        &spx_native_image_generation, 1U, __ATOMIC_ACQ_REL);
  }}
  return status;
}}

static uint32_t spx_native_output_frame_valid(
    const spx_native_ingress_descriptor *descriptor,
    const spx_native_ingress_frame *frame) {{
  uint32_t expected_esp;
  if (descriptor == 0 || frame == 0 || frame->input == 0 ||
      frame->output == 0 ||
      frame->input->esp > 0xffffffffU - 4U ||
      frame->input->esp + 4U >
          0xffffffffU - descriptor->cleanup_bytes)
    return 0U;
  expected_esp = frame->input->esp + 4U + descriptor->cleanup_bytes;
  return
      (!(descriptor->preserved_mask & 0x01U) ||
       frame->output->ebx == frame->input->ebx) &&
      (!(descriptor->preserved_mask & 0x02U) ||
       frame->output->esi == frame->input->esi) &&
      (!(descriptor->preserved_mask & 0x04U) ||
       frame->output->edi == frame->input->edi) &&
      (!(descriptor->preserved_mask & 0x08U) ||
       frame->output->ebp == frame->input->ebp) &&
      (!(descriptor->preserved_mask & 0x10U) ||
       frame->output->eflags == frame->input->eflags) &&
      frame->output->esp == expected_esp;
}}

static uint32_t spx_native_materialize_normal_return_frame(
    const spx_native_ingress_descriptor *descriptor,
    spx_native_ingress_frame *frame) {{
  if (descriptor == 0 || frame == 0 || frame->input == 0 ||
      frame->output == 0 ||
      frame->input->esp > 0xffffffffU - 4U ||
      frame->input->esp + 4U >
          0xffffffffU - descriptor->cleanup_bytes)
    return 0U;
  /* Canonical return outcomes carry the logical result.  The checked
   * physical frame, not a semantic provider, owns RET and ABI cleanup. */
  frame->output->esp =
      frame->input->esp + 4U + descriptor->cleanup_bytes;
  return 1U;
}}

uint32_t spx_native_ingress_dispatch(uint32_t bridge_index) {{
  uint8_t *base = spx_native_thread_base();
  spx_native_thread_header *header;
  spx_native_ingress_frame *frame;
  const spx_native_ingress_descriptor *descriptor;
  spx_call_status status;
  uint32_t exception_filter_root = 0U, exception_filter_bound = 0U;
  uint32_t interface_binding_count = 0U;
  uint32_t interface_binding_kinds[{max(1, len(interface_callback_argument_rows))}U];
  uint32_t interface_binding_objects[{max(1, len(interface_callback_argument_rows))}U];
  uint32_t interface_binding_rows[{max(1, len(interface_callback_argument_rows))}U];
  if (base == 0 || bridge_index >= spx_native_ingress_descriptor_count) return 1U;
  header = (spx_native_thread_header *)(void *)base;
  if (header->depth == 0U) return 1U;
  frame = spx_native_frame_at(base, header->depth - 1U);
  if (frame->bridge_index != bridge_index) return 1U;
  descriptor = spx_native_ingress_descriptor_for(bridge_index);
  if (descriptor == 0) return 1U;
  status = spx_native_validate_physical_stack_ranges(descriptor, frame)
      ? spx_native_preflight_loader_lifecycle(descriptor, header, frame)
      : SPX_CALL_MEMORY_FAULT;
  if (status == SPX_CALL_OK)
    status = spx_native_preflight_boundary_lifecycle(descriptor, frame);
  if (status == SPX_CALL_OK && descriptor->exception_filter_callback != 0U &&
      spx_native_runtime_exception_filter_callback_expected() != 0U) {{
    if (descriptor->cleanup_bytes != 4U ||
        frame->input->esp > 0xffffffffU - 8U ||
        frame->input->esp + 4U < frame->host_stack_limit ||
        frame->input->esp + 8U > frame->host_stack_base) {{
      status = SPX_CALL_MEMORY_FAULT;
    }} else {{
      exception_filter_root = *(const uint32_t *)(uintptr_t)(
          frame->input->esp + 4U);
      status = spx_native_runtime_bind_exception_filter_callback(
          exception_filter_root);
      if (status == SPX_CALL_OK) exception_filter_bound = 1U;
    }}
  }}
  if (status == SPX_CALL_OK &&
      bridge_index >= spx_native_static_ingress_descriptor_count) {{
    const uint32_t flat_target_index =
        bridge_index - spx_native_static_ingress_descriptor_count;
    uint32_t row_index;
    for (row_index = 0U;
         row_index < spx_native_interface_callback_argument_count;
         ++row_index) {{
      const spx_native_interface_callback_argument *argument =
          &spx_native_interface_callback_arguments[row_index];
      uint32_t address, object, binding_kind;
      if (flat_target_index < argument->flat_first ||
          flat_target_index - argument->flat_first >= argument->target_count)
        continue;
      /* The checked frame uses callee-entry-esp-v1: offset zero is the
       * physical return address and argument zero begins at offset four. */
      if (argument->argument_index > 0x3ffffffeU ||
          frame->input->esp >
              0xffffffffU - 4U - argument->argument_index * 4U) {{
        status = SPX_CALL_MEMORY_FAULT;
        break;
      }}
      address = frame->input->esp + 4U + argument->argument_index * 4U;
      if (frame->host_stack_base < 4U ||
          address < frame->host_stack_limit ||
          address > frame->host_stack_base - 4U) {{
        status = SPX_CALL_MEMORY_FAULT;
        break;
      }}
      object = *(const uint32_t *)(uintptr_t)address;
      binding_kind = spx_native_runtime_bind_interface_callback_argument(
          argument->profile_sha256, argument->interface_id,
          object, frame->generation);
      if (binding_kind == 0U) {{
        status = SPX_CALL_UNIMPLEMENTED;
        break;
      }}
      interface_binding_kinds[interface_binding_count] = binding_kind;
      interface_binding_objects[interface_binding_count] = object;
      interface_binding_rows[interface_binding_count] = row_index;
      ++interface_binding_count;
    }}
  }}
  if (status == SPX_CALL_OK)
    status = spx_native_runtime_run_at_rva(
        spx_native_ingress_target_rva(bridge_index, descriptor),
        frame->input, frame->output);
  while (interface_binding_count != 0U) {{
    const spx_native_interface_callback_argument *argument;
    uint32_t binding_status;
    --interface_binding_count;
    argument = &spx_native_interface_callback_arguments[
        interface_binding_rows[interface_binding_count]];
    binding_status = spx_native_runtime_unbind_interface_callback_argument(
        argument->profile_sha256, argument->interface_id,
        interface_binding_objects[interface_binding_count],
        frame->generation,
        interface_binding_kinds[interface_binding_count]);
    if (binding_status == 0U && status == SPX_CALL_OK)
      status = SPX_CALL_UNIMPLEMENTED;
  }}
  if (exception_filter_bound != 0U &&
      spx_native_runtime_unbind_exception_filter_callback(
          exception_filter_root) != SPX_CALL_OK && status == SPX_CALL_OK)
    status = SPX_CALL_UNIMPLEMENTED;
  if (status == SPX_CALL_OK) {{
    uint32_t native_value = 0U;
    uint32_t realization = spx_native_realize_registered_code_result(
        spx_native_ingress_target_rva(bridge_index, descriptor),
        frame->output->eax, &native_value);
    if (realization == 1U)
      frame->output->eax = native_value;
    else if (realization == 2U)
      status = SPX_CALL_UNIMPLEMENTED;
  }}
  if (status != SPX_CALL_OK && descriptor->seh_count != 0U) {{
    uint32_t exception_code =
        status == SPX_CALL_DIVIDE_ERROR ? 0xc0000094U :
        status == SPX_CALL_MEMORY_FAULT ? 0xc0000005U : 0U;
    if (exception_code != 0U) {{
      uint32_t i;
      for (i = 0U; i < descriptor->seh_count; ++i) {{
        uint32_t seh_index = spx_native_bridge_seh_indexes[
            descriptor->seh_first + i];
        const spx_native_seh_descriptor *seh = &spx_native_seh_descriptors[seh_index];
        if (seh->code == exception_code &&
            seh->source_rva == frame->output->original_rva &&
            seh->exception_record_count == 1U) {{
          header->exceptional = 2U; header->exception_code = exception_code;
          header->exception_flags = seh->continuable != 0U ? 0U : 1U;
          header->exception_address = spx_native_checked_exception_address(
              seh, seh->source_rva);
          if (header->exception_address == 0U) continue;
          header->exception_parameter_count = seh->parameter_count;
          for (uint32_t parameter = 0U;
               parameter < header->exception_parameter_count; ++parameter)
            header->exception_parameters[parameter] = 0U;
          if (status == SPX_CALL_MEMORY_FAULT &&
              seh->operation_parameter < header->exception_parameter_count &&
              seh->address_parameter < header->exception_parameter_count) {{
            volatile uint32_t *reason = spx_native_runtime_diagnostic_slot(0U);
            volatile uint32_t *address = spx_native_runtime_diagnostic_slot(1U);
            volatile uint32_t *operation =
                spx_native_runtime_diagnostic_slot(2U);
            if (reason == 0 || address == 0 || operation == 0 ||
                (*reason != 0x3001U && *reason != 0x3002U &&
                 *reason != 0x3003U))
              break;
            header->exception_parameters[seh->operation_parameter] =
                *reason == 0x3001U ? 0U :
                *reason == 0x3002U ? 1U : *operation;
            header->exception_parameters[seh->address_parameter] = *address;
          }}
          header->seh_descriptor_index = seh_index;
          header->exception_frame_index = header->depth - 1U;
          if (seh->handler_rva != 0U)
            status = (spx_call_status)spx_native_ingress_recover_exception();
          else if (spx_native_raise_exception(seh, header) != 0U)
            status = SPX_CALL_OK;
          break;
        }}
      }}
    }}
  }}
  /* A no-return-only target returning normally is a protocol violation.  The
   * outcome inventory is authority, not descriptive metadata. */
  if (status == SPX_CALL_OK && (descriptor->outcome_mask & 0x01U) == 0U)
    status = SPX_CALL_UNIMPLEMENTED;
  if (status == SPX_CALL_OK &&
      !spx_native_materialize_normal_return_frame(descriptor, frame))
    status = SPX_CALL_UNIMPLEMENTED;
  if (status == SPX_CALL_OK &&
      !spx_native_output_frame_valid(descriptor, frame))
    status = SPX_CALL_UNIMPLEMENTED;
  status = spx_native_apply_loader_lifecycle(
      descriptor, header, frame, status);
  frame->outcome = status == SPX_CALL_OK ? 1U : 0U;
  return (uint32_t)status;
}}

{compact_callback_entry_source_v1()}

{exception_object_helpers_source_v1()}

{exception_recovery_source_v1()}

spx_native_physical_capture *spx_native_ingress_current_capture(void) {{
  uint8_t *base = spx_native_thread_base();
  spx_native_thread_header *header;
  spx_native_ingress_frame *frame;
  if (base == 0) return 0;
  header = (spx_native_thread_header *)(void *)base;
  if (header->depth == 0U) return 0;
  frame = spx_native_frame_at(
      base,
      header->exceptional != 0U && header->exception_frame_index < header->depth
          ? header->exception_frame_index : header->depth - 1U);
  if (frame->bridge_index >= spx_native_ingress_descriptor_count)
    return 0;
  return frame->capture;
}}

uint32_t spx_native_captured_stack_rule_base(
    uint32_t physical_frame_selector, uint32_t offset, uint32_t extent,
    uint32_t *object_base, uint32_t *generation) {{
  uint8_t *base = spx_native_thread_base();
  spx_native_thread_header *header;
  spx_native_ingress_frame *frame;
  const spx_native_ingress_descriptor *descriptor;
  uint32_t index, stack_base, end;
  if (base == 0 || physical_frame_selector == 0U || extent == 0U ||
      object_base == 0 || generation == 0)
    return 0U;
  header = (spx_native_thread_header *)(void *)base;
  if (header->depth == 0U) return 0U;
  frame = spx_native_frame_at(base, header->depth - 1U);
  if (frame->bridge_index >= spx_native_ingress_descriptor_count ||
      frame->capture == 0 || frame->generation == 0U)
    return 0U;
  descriptor = spx_native_ingress_descriptor_for(frame->bridge_index);
  if (descriptor == 0) return 0U;
  for (index = 0U; index < descriptor->physical_frame_count; ++index)
    if (spx_native_bridge_physical_frame_selectors[
            descriptor->physical_frame_first + index] ==
        physical_frame_selector)
      break;
  if (index == descriptor->physical_frame_count ||
      frame->capture->entry_esp > 0xffffffffU - 4U)
    return 0U;
  stack_base = frame->capture->entry_esp + 4U;
  if (stack_base > 0xffffffffU - offset) return 0U;
  stack_base += offset;
  if (stack_base < frame->host_stack_limit ||
      extent > 0xffffffffU - stack_base)
    return 0U;
  end = stack_base + extent;
  if (end > frame->host_stack_base) return 0U;
  *object_base = stack_base;
  *generation = frame->generation;
  return 1U;
}}

spx_native_physical_capture *spx_native_ingress_finish(uint32_t status) {{
  uint8_t *base = spx_native_thread_base();
  spx_native_thread_header *header;
  spx_native_ingress_frame *frame;
  spx_native_physical_capture *capture;
  uint32_t cleanup_bytes, callback_prefix, exceptional_return, return_target, i;
  if (base == 0) return 0;
  header = (spx_native_thread_header *)(void *)base;
  if (header->depth == 0U) return 0;
  frame = spx_native_frame_at(base, header->depth - 1U);
  capture = frame->capture;
  {{
    const spx_native_ingress_descriptor *descriptor =
        spx_native_ingress_descriptor_for(frame->bridge_index);
    if (descriptor == 0) return 0;
    cleanup_bytes = descriptor->cleanup_bytes;
  }}
  exceptional_return = frame->outcome == 4U;
  /* Faithful execution owns the machine stack below entry ESP and therefore
   * legitimately overwrites the PUSHAD record used to enter this bridge.
   * Reconstitute that physical record from the immutable imported state before
   * applying the checked result projection and returning on the host stack. */
  spx_native_restore_capture(capture, frame->input);
  callback_prefix = spx_native_compact_capture_prefix(capture);
  if (status == (uint32_t)SPX_CALL_OK) {{
    spx_native_export_capture(capture, frame->output);
    spx_native_restore_current_x87(frame->output);
  }} else {{
    capture->eax = status;
    spx_native_restore_current_x87(frame->input);
  }}
  (void)spx_native_capability_expire_ingress(frame->generation);
  frame->exception_active = 0U;
  header->depth--;
  spx_native_write_stack_bounds(
      frame->host_stack_base, frame->host_stack_limit);
  if (exceptional_return && (cleanup_bytes != 0U || callback_prefix != 0U)) {{
    uint8_t *source = (uint8_t *)(void *)capture;
    uint8_t *target = source + callback_prefix + cleanup_bytes;
    return_target = *(uint32_t *)(void *)(
        source + sizeof(*capture) + callback_prefix);
    for (i = sizeof(*capture); i != 0U; --i) target[i - 1U] = source[i - 1U];
    *(uint32_t *)(void *)(target + sizeof(*capture)) = return_target;
    capture = (spx_native_physical_capture *)(void *)target;
  }}
  return capture;
}}

uint32_t spx_native_capability_publish(
    uint32_t capability_index, uint32_t generation, uint32_t escaped) {{
  spx_native_capability_state *cap;
  const spx_native_capability_lifetime_range *lifetime;
  uint32_t slot, selected = {MAX_CAPABILITY_GENERATIONS}U;
  uint8_t *thread_base;
  if (capability_index >= spx_native_capability_count || generation == 0U) return 0U;
  cap = &spx_native_capabilities[capability_index];
  lifetime = spx_native_capability_lifetime_for(capability_index);
  if (lifetime == 0) return 0U;
  thread_base = spx_native_thread_base();
  if (escaped == 0U && thread_base == 0) return 0U;
  spx_native_capability_lock(cap);
  if (lifetime->lifetime_mode != 2U) {{
    for (slot = 0U; slot < {MAX_CAPABILITY_GENERATIONS}U; ++slot)
      if (cap->generations[slot].active == 0U) {{ selected = slot; break; }}
  }} else {{
    selected = 0U;
  }}
  if (selected == {MAX_CAPABILITY_GENERATIONS}U) {{
    spx_native_capability_unlock(cap);
    return 0U;
  }}
  cap->generations[selected].generation = generation;
  cap->generations[selected].escaped = escaped != 0U;
  cap->generations[selected].owner_thread =
      escaped != 0U ? 0U : (uint32_t)(uintptr_t)thread_base;
  if (thread_base != 0) {{
    spx_native_thread_header *header =
        (spx_native_thread_header *)(void *)thread_base;
    cap->generations[selected].owner_ingress = header->depth == 0U
        ? 0U : spx_native_frame_at(
            thread_base, header->depth - 1U)->generation;
  }} else {{
    cap->generations[selected].owner_ingress = 0U;
  }}
  cap->generations[selected].active = 1U;
  spx_native_capability_unlock(cap);
  return 1U;
}}

uint32_t spx_native_capability_revoke(
    uint32_t capability_index, uint32_t generation) {{
  spx_native_capability_state *cap;
  uint32_t slot, revoked = 0U;
  if (capability_index >= spx_native_capability_count) return 0U;
  cap = &spx_native_capabilities[capability_index];
  spx_native_capability_lock(cap);
  for (slot = 0U; slot < {MAX_CAPABILITY_GENERATIONS}U; ++slot)
    if (cap->generations[slot].active != 0U &&
        cap->generations[slot].generation == generation) {{
      cap->generations[slot].active = 0U; revoked = 1U; break;
    }}
  spx_native_capability_unlock(cap);
  return revoked;
}}

uint32_t spx_native_capability_commit(
    uint32_t capability_index, uint32_t generation) {{
  spx_native_capability_state *cap;
  uint32_t slot, committed = 0U;
  if (capability_index >= spx_native_capability_count || generation == 0U)
    return 0U;
  cap = &spx_native_capabilities[capability_index];
  spx_native_capability_lock(cap);
  for (slot = 0U; slot < {MAX_CAPABILITY_GENERATIONS}U; ++slot)
    if (cap->generations[slot].generation == generation &&
        cap->generations[slot].owner_ingress != 0U) {{
      cap->generations[slot].owner_ingress = 0U;
      committed = 1U;
      break;
    }}
  spx_native_capability_unlock(cap);
  return committed;
}}

uint32_t spx_native_capability_activate(
    uint32_t capability_index, uint32_t escaped) {{
  uint32_t generation;
  if (__atomic_load_n(&spx_native_image_active, __ATOMIC_ACQUIRE) == 0U)
    return 0U;
  generation = __atomic_add_fetch(
      &spx_native_next_capability_generation, 1U, __ATOMIC_RELAXED);
  if (generation == 0U)
    generation = __atomic_add_fetch(
        &spx_native_next_capability_generation, 1U, __ATOMIC_RELAXED);
  return spx_native_capability_publish(
      capability_index, generation, escaped) != 0U ? generation : 0U;
}}

uint32_t spx_native_capability_is_active(uint32_t capability_index) {{
  spx_native_capability_state *cap;
  uint32_t slot, active = 0U;
  if (capability_index >= spx_native_capability_count) return 0U;
  cap = &spx_native_capabilities[capability_index];
  spx_native_capability_lock(cap);
  for (slot = 0U; slot < {MAX_CAPABILITY_GENERATIONS}U; ++slot)
    if (cap->generations[slot].active != 0U) {{ active = 1U; break; }}
  spx_native_capability_unlock(cap);
  return active;
}}

{compact_callback_capability_source_v1()}

uint32_t spx_native_capability_replace(
    uint32_t old_capability_index, uint32_t new_capability_index,
    uint32_t escaped) {{
  uint32_t generation;
  if (old_capability_index >= spx_native_capability_count ||
      new_capability_index >= spx_native_capability_count)
    return 0U;
  {{
    const spx_native_capability_lifetime_range *lifetime =
        spx_native_capability_lifetime_for(new_capability_index);
    if (lifetime == 0 || lifetime->lifetime_mode != 2U)
      return 0U;
  }}
  generation = spx_native_capability_activate(new_capability_index, escaped);
  if (generation == 0U) return 0U;
  if (old_capability_index != new_capability_index) {{
    spx_native_capability_state *old_cap =
        &spx_native_capabilities[old_capability_index];
    uint32_t slot;
    spx_native_capability_lock(old_cap);
    for (slot = 0U; slot < {MAX_CAPABILITY_GENERATIONS}U; ++slot)
      old_cap->generations[slot].active = 0U;
    spx_native_capability_unlock(old_cap);
  }}
  return generation;
}}

static uint32_t spx_native_text_equal(const char *left, const char *right) {{
  uint32_t index = 0U;
  if (left == 0 || right == 0) return 0U;
  while (left[index] != 0 && left[index] == right[index]) ++index;
  return left[index] == right[index];
}}

uint32_t spx_native_capability_expire_event(const char *event_id) {{
  uint32_t index, slot, expired = 0U;
  if (event_id == 0) return 0U;
  for (index = 0U; index < spx_native_capability_count; ++index) {{
    spx_native_capability_state *cap = &spx_native_capabilities[index];
    const spx_native_capability_lifetime_range *lifetime =
        spx_native_capability_lifetime_for(index);
    if (lifetime != 0 && lifetime->lifetime_mode == 3U &&
        spx_native_text_equal(lifetime->end_event, event_id) != 0U) {{
      spx_native_capability_lock(cap);
      for (slot = 0U; slot < {MAX_CAPABILITY_GENERATIONS}U; ++slot)
        if (cap->generations[slot].active != 0U) {{
          cap->generations[slot].active = 0U; ++expired;
        }}
      spx_native_capability_unlock(cap);
    }}
  }}
  return expired;
}}

static uint32_t spx_native_capability_expire_thread(uint32_t owner_thread) {{
  uint32_t index, slot, expired = 0U;
  if (owner_thread == 0U) return 0U;
  for (index = 0U; index < spx_native_capability_count; ++index) {{
    spx_native_capability_state *cap = &spx_native_capabilities[index];
    spx_native_capability_lock(cap);
    for (slot = 0U; slot < {MAX_CAPABILITY_GENERATIONS}U; ++slot) {{
      spx_native_capability_generation *generation = &cap->generations[slot];
      if (generation->active != 0U && generation->escaped == 0U &&
          generation->owner_thread == owner_thread) {{
        generation->active = 0U; ++expired;
      }}
    }}
    spx_native_capability_unlock(cap);
  }}
  return expired;
}}

static uint32_t spx_native_capability_expire_ingress(uint32_t owner_ingress) {{
  uint32_t index, slot, expired = 0U;
  if (owner_ingress == 0U) return 0U;
  for (index = 0U; index < spx_native_capability_count; ++index) {{
    spx_native_capability_state *cap = &spx_native_capabilities[index];
    spx_native_capability_lock(cap);
    for (slot = 0U; slot < {MAX_CAPABILITY_GENERATIONS}U; ++slot) {{
      spx_native_capability_generation *generation = &cap->generations[slot];
      if (generation->owner_ingress == owner_ingress) {{
        if (generation->active != 0U) {{
          generation->active = 0U;
          ++expired;
        }}
        generation->owner_ingress = 0U;
      }}
    }}
    spx_native_capability_unlock(cap);
  }}
  return expired;
}}

static uint32_t spx_native_abandon_top_frame(
    uint8_t *base, spx_native_thread_header *header) {{
  spx_native_ingress_frame *abandoned;
  if (base == 0 || header == 0 || header->depth == 0U) return 0U;
  abandoned = spx_native_frame_at(base, header->depth - 1U);
  if (spx_native_runtime_restore_execution(
          abandoned->runtime_initialized_mark,
          abandoned->runtime_nested_depth_mark,
          abandoned->outgoing_mark, abandoned->x87_mark) == 0U)
    return 0U;
  (void)spx_native_capability_expire_ingress(abandoned->generation);
  abandoned->exception_active = 0U;
  header->depth--;
  if (header->depth == 0U)
    spx_native_write_stack_bounds(
        abandoned->host_stack_base, abandoned->host_stack_limit);
  return 1U;
}}

static uint32_t spx_native_abandon_frames_above(
    uint8_t *base, spx_native_thread_header *header,
    uint32_t retained_index) {{
  if (base == 0 || header == 0 || retained_index >= header->depth)
    return 0U;
  while (header->depth - 1U > retained_index)
    if (spx_native_abandon_top_frame(base, header) == 0U) return 0U;
  return 1U;
}}

static uint32_t spx_native_capability_expire_process(void) {{
  uint32_t index, slot, expired = 0U;
  for (index = 0U; index < spx_native_capability_count; ++index) {{
    spx_native_capability_state *cap = &spx_native_capabilities[index];
    spx_native_capability_lock(cap);
    for (slot = 0U; slot < {MAX_CAPABILITY_GENERATIONS}U; ++slot)
      if (cap->generations[slot].active != 0U) {{
        cap->generations[slot].active = 0U; ++expired;
      }}
    spx_native_capability_unlock(cap);
  }}
  return expired;
}}

int32_t spx_native_seh_dispatch(
    const void *record_value, void *establisher, void *context_value,
    void *dispatcher) {{
  const uint32_t *record = (const uint32_t *)record_value;
  uint32_t *context = (uint32_t *)context_value;
  uint8_t *base = spx_native_thread_base();
  spx_native_thread_header *header;
  const spx_native_ingress_descriptor *descriptor;
  const spx_native_ingress_frame *fault_frame;
  uint32_t frame_index, index, offset;
  (void)dispatcher;
  if (base == 0 || record == 0 || context == 0)
    return 1; /* ExceptionContinueSearch */
  header = (spx_native_thread_header *)(void *)base;
  if ((record[1] & 0x66U) != 0U) {{
    if (header->depth == 0U ||
        spx_native_frame_for_establisher(
            base, header, establisher, &frame_index) == 0U ||
        frame_index != header->depth - 1U)
      return 1;
    if (spx_native_abandon_top_frame(base, header) == 0U) return 1;
    header->exceptional = 0U;
    return 1; /* ExceptionContinueSearch after checked invalidation. */
  }}
  if (header->exceptional == 3U)
    return 1; /* A checked escaping exception belongs to the outer host. */
  if (header->depth == 0U ||
      spx_native_frame_for_establisher(
          base, header, establisher, &frame_index) == 0U)
    return 1;
  fault_frame = spx_native_frame_at(base, header->depth - 1U);
  if (fault_frame->bridge_index >= spx_native_ingress_descriptor_count)
    return 1;
  {{
    const spx_native_ingress_frame *handler_frame =
        spx_native_frame_at(base, frame_index);
    if (handler_frame->bridge_index >= spx_native_ingress_descriptor_count)
      return 1;
    descriptor = spx_native_ingress_descriptor_for(
        handler_frame->bridge_index);
    if (descriptor == 0) return 1;
  }}
  for (offset = 0U; offset < descriptor->seh_count; ++offset) {{
    index = spx_native_bridge_seh_indexes[descriptor->seh_first + offset];
    const spx_native_seh_descriptor *seh = &spx_native_seh_descriptors[index];
    if (record[0] == seh->code &&
        (record[1] & seh->flags_mask) == seh->flags_value &&
        seh->exception_record_count != 0U &&
        seh->exception_record_count <= SPX_EXCEPTION_RECORD_CHAIN_CAPACITY &&
        (seh->exception_record_count > 1U
             ? record[2] != 0U
             : (((seh->exception_record_projection_mask & 0x004U) == 0U) ||
                record[2] == 0U)) &&
        record[4] == seh->parameter_count &&
        fault_frame->output->original_rva == seh->source_rva &&
        seh->handler_rva != 0U &&
        ((seh->continuable != 0U) == ((record[1] & 1U) == 0U)))
      break;
  }}
  if (offset == descriptor->seh_count) return 1;
  if (spx_native_seh_descriptors[index].exception_record_count > 1U &&
      spx_native_copy_exception_chain(
          base, spx_native_frame_at(base, frame_index),
          &spx_native_seh_descriptors[index], record) == 0U)
    return 1;
  header->exceptional = 1U; header->exception_code = record[0];
  header->exception_flags = record[1];
  header->exception_address = spx_native_checked_exception_address(
      &spx_native_seh_descriptors[index],
      spx_native_seh_descriptors[index].source_rva);
  if (header->exception_address == 0U) return 1;
  header->exception_parameter_count = record[4] > 15U ? 15U : record[4];
  for (uint32_t i = 0; i < header->exception_parameter_count; ++i)
    header->exception_parameters[i] = record[5U + i];
  header->seh_descriptor_index = index;
  header->exception_frame_index = frame_index;
  if (frame_index < header->depth) {{
    spx_native_ingress_frame *frame =
        spx_native_frame_at(base, frame_index);
    const spx_native_seh_descriptor *seh = &spx_native_seh_descriptors[index];
    if (seh->register_projection_mask & 0x01U) frame->output->edi = context[39];
    if (seh->register_projection_mask & 0x02U) frame->output->esi = context[40];
    if (seh->register_projection_mask & 0x04U) frame->output->ebx = context[41];
    if (seh->register_projection_mask & 0x08U) frame->output->edx = context[42];
    if (seh->register_projection_mask & 0x10U) frame->output->ecx = context[43];
    if (seh->register_projection_mask & 0x20U) frame->output->eax = context[44];
    if (seh->register_projection_mask & 0x40U) frame->output->ebp = context[45];
    if (seh->flags_projection != 0U) frame->output->eflags = context[48];
    if (seh->stack_projection != 0U) frame->output->esp = context[49];
    if (seh->x87_projection_mask != 0U)
      spx_native_import_context_x87(
          frame->output, context, seh->x87_projection_mask);
    frame->output->original_rva = spx_native_seh_descriptors[index].source_rva;
  }}
  context[46] = (uint32_t)(uintptr_t)spx_native_exception_recovery;
  context[49] = (uint32_t)(uintptr_t)establisher;
  return 0; /* ExceptionContinueExecution at the checked recovery portal. */
}}

_Static_assert(sizeof(spx_native_physical_capture) == 36U, "capture ABI drift");
_Static_assert(sizeof(spx_native_ingress_frame) == {INGRESS_FRAME_BYTES}U, "ingress frame ABI drift");
_Static_assert(sizeof(spx_native_thread_header) <= {THREAD_HEADER_BYTES}U, "thread header ABI drift");
_Static_assert({RUNTIME_CONTEXT_OFFSET}U < SPX_NATIVE_TLS_CONTROL_BYTES,
    "runtime context is outside PE TLS control storage");
_Static_assert({RUNTIME_THREAD_STATE_OFFSET + RUNTIME_THREAD_STATE_BYTES}U <=
    {RUNTIME_CONTEXT_OFFSET}U, "runtime thread state overlaps semantic context");
'''
