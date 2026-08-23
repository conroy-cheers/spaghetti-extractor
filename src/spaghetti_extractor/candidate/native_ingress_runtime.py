"""Exact IA-32 PE-TLS ABI and table-driven native-ingress source emission."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping, Sequence

from ..calls.frame import PhysicalCallFrameV2
from ..errors import ToolkitInputError


THREAD_MAGIC = 0x53505854
THREAD_ABI_VERSION = 1
THREAD_HEADER_BYTES = 128
INGRESS_FRAME_BYTES = 40
MAX_INGRESS_DEPTH = 64
FRAME_REGION_OFFSET = THREAD_HEADER_BYTES
FRAME_REGION_BYTES = INGRESS_FRAME_BYTES * MAX_INGRESS_DEPTH
STATE_REGION_OFFSET = 0x1000
MACHINE_STATE_BYTES = 252
STATE_PAIR_BYTES = MACHINE_STATE_BYTES * 2
STATE_REGION_BYTES = STATE_PAIR_BYTES * MAX_INGRESS_DEPTH
DIAGNOSTIC_REGION_OFFSET = 0x9000
DIAGNOSTIC_REGION_BYTES = 0x1000
ENGINE_THREAD_STATE_OFFSET = 0xA000
ENGINE_THREAD_STATE_BYTES = 0x10
RUNTIME_CONTEXT_OFFSET = 0xB000
MINIMUM_RUNTIME_CONTROL_BYTES = 0x80000
ENGINE_STACK_FRAME_BYTES = 0x10000

_CAPABILITY_LIFETIME_MODES = {
    "during_call": 0,
    "one_shot_or_process_exit": 1,
    "until_replaced_or_process_exit": 2,
    "until_resource_event_or_process_exit": 3,
}


def _capability_lifetime(value: object) -> tuple[str, str | None]:
    """Normalize the checked lifetime identity retained by callback authority."""

    if not isinstance(value, str) or not value:
        raise ToolkitInputError("native ingress capability lifetime is missing")
    kind, separator, end_event = value.partition(":")
    if kind not in _CAPABILITY_LIFETIME_MODES:
        raise ToolkitInputError(
            f"native ingress capability lifetime {value!r} is unsupported"
        )
    if kind == "until_resource_event_or_process_exit":
        if not separator or not end_event:
            raise ToolkitInputError(
                "resource-event callback lifetime lacks its checked end event"
            )
        return kind, end_event
    if separator:
        raise ToolkitInputError(
            f"native ingress capability lifetime {kind!r} cannot name an end event"
        )
    return kind, None


@dataclass(frozen=True)
class NativeIngressSupportABI:
    runtime_offset: int
    runtime_control_bytes: int
    engine_stack_offset: int
    engine_stack_bytes: int

    @classmethod
    def parse(cls, plan: Mapping[str, Any]) -> "NativeIngressSupportABI":
        layout = plan.get("tls_layout")
        if not isinstance(layout, Mapping):
            raise ToolkitInputError("native ingress plan lacks a TLS layout")
        regions = layout.get("runtime_regions")
        if not isinstance(regions, Mapping):
            raise ToolkitInputError("native ingress TLS regions are malformed")
        stack = regions.get("engine_stack")
        if not isinstance(stack, Mapping):
            raise ToolkitInputError("native ingress plan lacks a private engine stack")
        result = cls(
            _uint(layout.get("runtime_offset"), "runtime TLS offset"),
            _uint(layout.get("runtime_control_bytes"), "runtime TLS control size"),
            _uint(stack.get("offset"), "private engine stack offset"),
            _uint(stack.get("extent"), "private engine stack size"),
        )
        if result.runtime_control_bytes < MINIMUM_RUNTIME_CONTROL_BYTES:
            raise ToolkitInputError("native ingress TLS control region is below the exact runtime ABI")
        if result.engine_stack_offset < result.runtime_control_bytes:
            raise ToolkitInputError("native ingress private stack overlaps runtime control state")
        if result.engine_stack_bytes < ENGINE_STACK_FRAME_BYTES:
            raise ToolkitInputError("native ingress private stack cannot hold one checked frame")
        return result


def exact_tls_regions(*, control_bytes: int, stack_bytes: int) -> dict[str, dict[str, Any]]:
    if control_bytes < MINIMUM_RUNTIME_CONTROL_BYTES:
        raise ToolkitInputError("runtime TLS control size is below the native ingress ABI")
    stack_offset = _align_up(control_bytes, 16)
    return {
        "thread_header": {"offset": 0, "extent": THREAD_HEADER_BYTES},
        "ingress_frames": {
            "offset": FRAME_REGION_OFFSET,
            "extent": FRAME_REGION_BYTES,
            "element_bytes": INGRESS_FRAME_BYTES,
            "capacity": MAX_INGRESS_DEPTH,
        },
        "captured_machine_states": {
            "offset": STATE_REGION_OFFSET,
            "extent": STATE_REGION_BYTES,
            "element_bytes": STATE_PAIR_BYTES,
            "capacity": MAX_INGRESS_DEPTH,
        },
        "diagnostics_and_outcomes": {
            "offset": DIAGNOSTIC_REGION_OFFSET,
            "extent": DIAGNOSTIC_REGION_BYTES,
        },
        "engine_thread_state": {
            "offset": ENGINE_THREAD_STATE_OFFSET,
            "extent": ENGINE_THREAD_STATE_BYTES,
        },
        "runtime_context": {
            "offset": RUNTIME_CONTEXT_OFFSET,
            "extent": control_bytes - RUNTIME_CONTEXT_OFFSET,
        },
        "engine_stack": {
            "offset": stack_offset,
            "extent": stack_bytes,
            "growth": "bounded_slices_x86_down",
            "slice_bytes": ENGINE_STACK_FRAME_BYTES,
        },
    }


def render_native_ingress_header(plan: Mapping[str, Any]) -> str:
    abi = NativeIngressSupportABI.parse(plan)
    return f'''#ifndef SPX_NATIVE_INGRESS_RUNTIME_H
#define SPX_NATIVE_INGRESS_RUNTIME_H

#include "native-runtime.h"

#define SPX_NATIVE_THREAD_MAGIC 0x{THREAD_MAGIC:08x}U
#define SPX_NATIVE_THREAD_ABI_VERSION {THREAD_ABI_VERSION}U
#define SPX_NATIVE_TLS_RUNTIME_OFFSET {abi.runtime_offset}U
#define SPX_NATIVE_TLS_CONTROL_BYTES {abi.runtime_control_bytes}U
#define SPX_NATIVE_ENGINE_STACK_OFFSET {abi.engine_stack_offset}U
#define SPX_NATIVE_ENGINE_STACK_BYTES {abi.engine_stack_bytes}U
#define SPX_NATIVE_ENGINE_STACK_SLICE_BYTES {ENGINE_STACK_FRAME_BYTES}U
#define SPX_NATIVE_MAX_INGRESS_DEPTH {MAX_INGRESS_DEPTH}U
#define SPX_NATIVE_RUNTIME_CONTEXT_OFFSET {RUNTIME_CONTEXT_OFFSET}U

typedef struct spx_native_physical_capture {{
  uint32_t edi, esi, ebp, entry_esp, ebx, edx, ecx, eax, eflags;
}} spx_native_physical_capture;

extern uint32_t *spx_native_tls_index_cell_pointer;
void *spx_native_ingress_prepare(
    uint32_t bridge_index, spx_native_physical_capture *capture);
uint32_t spx_native_ingress_dispatch(uint32_t bridge_index);
spx_native_physical_capture *spx_native_ingress_finish(uint32_t status);
uint32_t spx_native_ingress_recover_exception(void);
int32_t spx_native_seh_dispatch(
    const void *record, void *establisher, void *context, void *dispatcher);
uint32_t spx_native_capability_publish(
    uint32_t capability_index, uint32_t generation, uint32_t escaped);
uint32_t spx_native_capability_revoke(
    uint32_t capability_index, uint32_t generation);
uint32_t spx_native_capability_activate(
    uint32_t capability_index, uint32_t escaped);
uint32_t spx_native_capability_replace(
    uint32_t old_capability_index, uint32_t new_capability_index,
    uint32_t escaped);
uint32_t spx_native_capability_expire_event(const char *event_id);
volatile uint32_t *spx_native_runtime_diagnostic_slot(uint32_t index);
void *spx_native_engine_thread_state_current(void);
void *spx_native_outgoing_frame_current(void);
void *spx_native_x87_frame_current(void);

#endif
'''


def render_native_ingress_source(plan: Mapping[str, Any]) -> str:
    NativeIngressSupportABI.parse(plan)
    bridges = _bridge_rows(plan)
    capabilities = sorted({
        str(row["capability_id"])
        for row in plan.get("ingresses", [])
        if isinstance(row, Mapping) and row.get("capability_id") is not None
    })
    capability_index = {identity: index for index, identity in enumerate(capabilities)}
    seh_protocols = [
        row for row in plan.get("seh_protocols", []) if isinstance(row, Mapping)
    ]
    portal_declarations: list[str] = []
    seh_rows: list[str] = []
    for protocol_index, protocol in enumerate(seh_protocols):
        exception = protocol["exception"]
        register_mask, flags_projection, stack_projection, x87_projection = (
            _seh_projection_masks(protocol)
        )
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
            symbol = str(portal["candidate_symbol"])
            portal_declarations.append(f"extern const uint8_t {symbol}[];")
            seh_rows.append(
                "  { %dU, 0x%08xU, 0x%08xU, 0x%08xU, %dU, %dU, %s, %s, %dU, 0x%08xU, 0x%02xU, %dU, %dU, 0x%02xU, 0x%08xU, 0x%08xU, %s }," % (
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
                    operation_parameter,
                    address_parameter,
                    symbol,
                )
            )
    portal_declaration_text = "\n".join(sorted(set(portal_declarations)))
    raise_pointer_declaration = (
        "uint32_t *spx_native_raise_exception_iat_pointer = "
        "(uint32_t *)(uintptr_t)1U;"
    )
    seh_table = "\n".join(seh_rows) or (
        "  { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, "
        "0xffffffffU, 0xffffffffU, 0 },"
    )
    descriptor_rows = []
    bridge_capability_indexes: list[int] = []
    for bridge_index, row in enumerate(bridges):
        descriptor = row["descriptor"]
        transport = PhysicalCallFrameV2.parse(descriptor["physical_frame"]["transport"])
        outcome = next(
            item for item in plan.get("outcome_protocols", [])
            if item.get("id") == descriptor["outcome_protocol_id"]
        )
        outcome_mask = sum(
            1 << {"normal": 0, "no_return": 1, "exceptional": 2, "nonlocal": 3}[name]
            for name in outcome["outcomes"]
        )
        capability_ids = row["capability_ids"]
        capability_first = len(bridge_capability_indexes)
        bridge_capability_indexes.extend(
            capability_index[identity] for identity in capability_ids
        )
        descriptor_rows.append(
            "  { %dU, 0x%08xU, %dU, %dU, %dU, %dU, %dU, 0x%08xU }," % (
                bridge_index,
                int(descriptor["target_rva"]),
                int(transport.stack.cleanup_bytes),
                outcome_mask,
                capability_first,
                len(capability_ids),
                1 if row["permanently_callable"] else 0,
                _preserved_mask(transport.preserved_state),
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
    capability_rows = "\n".join(
        '  {{ 0U, 0U, 0U, {mode}U, {event} }}, /* {identity} */'.format(
            mode=_CAPABILITY_LIFETIME_MODES[capability_lifetimes[identity][0]],
            event=(
                "0"
                if capability_lifetimes[identity][1] is None
                else json.dumps(capability_lifetimes[identity][1], ensure_ascii=True)
            ),
            identity=identity,
        )
        for identity in capabilities
    ) or "  { 0U, 0U, 0U, 0U, 0 },"
    descriptor_table = "\n".join(descriptor_rows) or (
        "  { 0U, 0U, 0U, 0U, 0U, 0U, 1U, 0U },"
    )
    bridge_capability_table = "\n".join(
        f"  {index}U," for index in bridge_capability_indexes
    ) or "  0U,"
    return f'''#include "native-ingress-runtime.h"

#include <stddef.h>
#include <stdint.h>

typedef struct spx_native_ingress_descriptor {{
  uint32_t bridge_index, target_rva, cleanup_bytes, outcome_mask;
  uint32_t capability_first, capability_count, permanently_callable;
  uint32_t preserved_mask;
}} spx_native_ingress_descriptor;

typedef struct spx_native_ingress_frame {{
  uint32_t parent_index, bridge_index, stack_mark, generation;
  spx_native_physical_capture *capture;
  spx_machine_state *input, *output;
  uint32_t outcome, host_stack_base, host_stack_limit;
}} spx_native_ingress_frame;

typedef struct spx_native_thread_header {{
  uint32_t magic, abi_version, depth, stack_bump;
  uint32_t generation, exceptional, exception_code, exception_flags;
  uint32_t exception_address, exception_parameter_count, exception_parameters[15];
  uint32_t seh_descriptor_index;
}} spx_native_thread_header;

typedef struct spx_native_capability_state {{
  volatile uint32_t generation, active, escaped;
  uint32_t lifetime_mode;
  const char *end_event;
}} spx_native_capability_state;

typedef struct spx_native_seh_descriptor {{
  uint32_t protocol_index, code, flags_mask, flags_value, parameter_count;
  uint32_t continuable, handler_rva, resumption_rva, escape_disposition;
  uint32_t source_rva, register_projection_mask, flags_projection;
  uint32_t stack_projection, x87_projection_mask;
  uint32_t operation_parameter, address_parameter;
  const uint8_t *portal;
}} spx_native_seh_descriptor;

{portal_declaration_text}
extern void spx_native_exception_recovery(void);

uint32_t *spx_native_tls_index_cell_pointer = (uint32_t *)(uintptr_t)1U;
{raise_pointer_declaration}

static const spx_native_ingress_descriptor spx_native_ingress_descriptors[] = {{
{descriptor_table}
}};
static const uint32_t spx_native_ingress_descriptor_count = {len(bridges)}U;
static const uint32_t spx_native_bridge_capability_indexes[] = {{
{bridge_capability_table}
}};
static spx_native_capability_state spx_native_capabilities[] = {{
{capability_rows}
}};
static const uint32_t spx_native_capability_count = {len(capabilities)}U;
static volatile uint32_t spx_native_next_capability_generation = 1U;
static const spx_native_seh_descriptor spx_native_seh_descriptors[] = {{
{seh_table}
}};
static const uint32_t spx_native_seh_descriptor_count = {len(seh_rows)}U;

static uint8_t *spx_native_thread_base(void) {{
  void **slots;
  uint32_t index;
  if (spx_native_tls_index_cell_pointer == 0) return 0;
  index = *spx_native_tls_index_cell_pointer;
  __asm__ volatile ("movl %%fs:0x2c,%0" : "=r" (slots));
  if (slots == 0 || slots[index] == 0) return 0;
  return (uint8_t *)slots[index] + SPX_NATIVE_TLS_RUNTIME_OFFSET;
}}

void *spx_native_runtime_context_current(void) {{
  uint8_t *base = spx_native_thread_base();
  return base == 0 ? 0 : base + SPX_NATIVE_RUNTIME_CONTEXT_OFFSET;
}}

void *spx_native_engine_thread_state_current(void) {{
  uint8_t *base = spx_native_thread_base();
  return base == 0 ? 0 : base + {ENGINE_THREAD_STATE_OFFSET}U;
}}

void *spx_native_outgoing_frame_current(void) {{
  void **state = (void **)spx_native_engine_thread_state_current();
  return state == 0 ? 0 : state[0];
}}

void *spx_native_x87_frame_current(void) {{
  void **state = (void **)spx_native_engine_thread_state_current();
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

static spx_machine_state *spx_native_state_at(
    uint8_t *base, uint32_t index, uint32_t output) {{
  return (spx_machine_state *)(void *)(base + {STATE_REGION_OFFSET}U +
      index * {STATE_PAIR_BYTES}U + output * {MACHINE_STATE_BYTES}U);
}}

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

extern void spx_native_raise_exception_gateway(
    uint32_t code, uint32_t flags, uint32_t count,
    const uint32_t *parameters);

typedef struct __attribute__((packed, aligned(4))) spx_native_fnsave_image {{
  uint16_t control_word, reserved_02;
  uint16_t status_word, reserved_06;
  uint16_t tag_word, reserved_0a;
  uint32_t instruction_pointer;
  uint16_t code_selector, last_opcode;
  uint32_t data_pointer;
  uint16_t data_selector, reserved_1a;
  uint8_t physical_registers[8][10];
}} spx_native_fnsave_image;

static void spx_native_import_x87_parts(
    spx_machine_state *state, uint32_t mask,
    uint16_t control_word, uint16_t status_word, uint16_t tag_word,
    uint32_t instruction_pointer, uint16_t code_selector,
    uint32_t data_pointer, uint16_t data_selector,
    const uint8_t physical_registers[8][10]) {{
  uint32_t logical, byte_index;
  if ((mask & 0x01U) != 0U) state->x87_control = control_word;
  if ((mask & 0x02U) != 0U) {{
    state->x87_status = status_word;
    state->x87_pending_exception = (uint8_t)((status_word >> 7U) & 1U);
  }}
  if ((mask & 0x10U) != 0U)
    state->x87_instruction_pointer = instruction_pointer;
  if ((mask & 0x20U) != 0U) state->x87_code_selector = code_selector;
  if ((mask & 0x40U) != 0U) state->x87_data_pointer = data_pointer;
  if ((mask & 0x80U) != 0U) state->x87_data_selector = data_selector;
  if ((mask & 0x0cU) == 0U) return;
  for (logical = 0U; logical < 8U; ++logical) {{
    uint32_t physical = (((uint32_t)status_word >> 11U) + logical) & 7U;
    uint8_t tag = (uint8_t)((tag_word >> (physical * 2U)) & 3U);
    if ((mask & 0x04U) != 0U) {{
      state->x87_stack[logical].tag = tag;
      state->x87_stack[logical].empty = tag == 3U ? 1U : 0U;
    }}
    if ((mask & 0x08U) != 0U)
      for (byte_index = 0U; byte_index < 10U; ++byte_index)
        state->x87_stack[logical].value_bytes[byte_index] =
            physical_registers[physical][byte_index];
  }}
}}

static void spx_native_import_context_x87(
    spx_machine_state *state, const uint32_t *context, uint32_t mask) {{
  const uint8_t (*registers)[10] =
      (const uint8_t (*)[10])(const void *)(context + 14U);
  spx_native_import_x87_parts(
      state, mask, (uint16_t)context[7], (uint16_t)context[8],
      (uint16_t)context[9], context[10], (uint16_t)context[11],
      context[12], (uint16_t)context[13], registers);
}}

static void spx_native_capture_current_x87(
    spx_machine_state *state, uint32_t mask) {{
  spx_native_fnsave_image image;
  __asm__ volatile ("fnsave %0\\n\\tfrstor %0" : "=m" (image));
  spx_native_import_x87_parts(
      state, mask, image.control_word, image.status_word, image.tag_word,
      image.instruction_pointer, image.code_selector, image.data_pointer,
      image.data_selector, image.physical_registers);
}}

static uint32_t spx_native_raise_exception(
    const spx_native_seh_descriptor *seh,
    spx_native_thread_header *header) {{
  uint8_t *base = spx_native_thread_base();
  spx_native_ingress_frame *frame;
  spx_call_status status;
  if (spx_native_raise_exception_iat_pointer == 0 ||
      spx_native_raise_exception_iat_pointer == (uint32_t *)(uintptr_t)1U)
    return 0U;
  if (*spx_native_raise_exception_iat_pointer == 0U) return 0U;
  if (base == 0 || header->depth == 0U) return 0U;
  /* The gateway installed by this ingress must not consume an exception that
   * the checked protocol is deliberately transporting to an outer host frame. */
  header->exceptional = 3U;
  spx_native_raise_exception_gateway(
      seh->code, seh->continuable != 0U ? 0U : 1U,
      header->exception_parameter_count, header->exception_parameters);
  if (seh->continuable == 0U || header->exceptional != 4U) return 0U;
  frame = spx_native_frame_at(base, header->depth - 1U);
  status = SPX_CALL_OK;
  if (seh->resumption_rva != 0U)
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

void *spx_native_ingress_prepare(
    uint32_t bridge_index, spx_native_physical_capture *capture) {{
  uint8_t *base = spx_native_thread_base();
  spx_native_thread_header *header;
  spx_native_ingress_frame *frame;
  const spx_native_ingress_descriptor *descriptor;
  uint32_t index, stack_mark, capability_offset, capability_active;
  uint32_t engine_stack_base, engine_stack_limit;
  if (base == 0 || capture == 0 || bridge_index >= spx_native_ingress_descriptor_count)
    return 0;
  header = (spx_native_thread_header *)(void *)base;
  if (header->magic == 0U) {{
    header->magic = SPX_NATIVE_THREAD_MAGIC;
    header->abi_version = SPX_NATIVE_THREAD_ABI_VERSION;
    header->stack_bump = 0U;
    header->generation = 1U;
  }}
  if (header->magic != SPX_NATIVE_THREAD_MAGIC ||
      header->abi_version != SPX_NATIVE_THREAD_ABI_VERSION ||
      header->depth >= SPX_NATIVE_MAX_INGRESS_DEPTH ||
      header->stack_bump > SPX_NATIVE_ENGINE_STACK_BYTES - SPX_NATIVE_ENGINE_STACK_SLICE_BYTES)
    return 0;
  descriptor = &spx_native_ingress_descriptors[bridge_index];
  if (descriptor->permanently_callable == 0U) {{
    capability_active = 0U;
    for (capability_offset = 0U;
         capability_offset < descriptor->capability_count;
         ++capability_offset) {{
      const uint32_t capability = spx_native_bridge_capability_indexes[
          descriptor->capability_first + capability_offset];
      spx_native_capability_state *cap = &spx_native_capabilities[capability];
      if (cap->lifetime_mode == 1U) {{
        uint32_t expected = 1U;
        capability_active |= __atomic_compare_exchange_n(
            &cap->active, &expected, 0U, 0, __ATOMIC_ACQ_REL,
            __ATOMIC_ACQUIRE);
      }} else {{
        capability_active |= __atomic_load_n(
            &cap->active, __ATOMIC_ACQUIRE);
      }}
    }}
    if (capability_active == 0U) return 0;
  }}
  index = header->depth++;
  stack_mark = header->stack_bump;
  header->stack_bump += SPX_NATIVE_ENGINE_STACK_SLICE_BYTES;
  frame = spx_native_frame_at(base, index);
  frame->parent_index = index == 0U ? 0xffffffffU : index - 1U;
  frame->bridge_index = bridge_index; frame->stack_mark = stack_mark;
  frame->generation = header->generation++; frame->capture = capture;
  frame->input = spx_native_state_at(base, index, 0U);
  frame->output = spx_native_state_at(base, index, 1U);
  frame->outcome = 0U;
  spx_native_import_capture(frame->input, capture, descriptor->target_rva);
  *frame->output = *frame->input;
  spx_native_read_stack_bounds(
      &frame->host_stack_base, &frame->host_stack_limit);
  engine_stack_limit = (uint32_t)(uintptr_t)(
      base + SPX_NATIVE_ENGINE_STACK_OFFSET);
  engine_stack_base = engine_stack_limit + SPX_NATIVE_ENGINE_STACK_BYTES;
  /* Windows validates every x86 SEH registration record against the TEB stack
   * interval.  The checked private stack and an outer host handler must both
   * remain valid while an ingress is active, including nested ingress. */
  spx_native_write_stack_bounds(
      frame->host_stack_base > engine_stack_base
          ? frame->host_stack_base : engine_stack_base,
      frame->host_stack_limit < engine_stack_limit
          ? frame->host_stack_limit : engine_stack_limit);
  return base + SPX_NATIVE_ENGINE_STACK_OFFSET + header->stack_bump;
}}

uint32_t spx_native_ingress_dispatch(uint32_t bridge_index) {{
  uint8_t *base = spx_native_thread_base();
  spx_native_thread_header *header;
  spx_native_ingress_frame *frame;
  const spx_native_ingress_descriptor *descriptor;
  spx_call_status status;
  if (base == 0 || bridge_index >= spx_native_ingress_descriptor_count) return 1U;
  header = (spx_native_thread_header *)(void *)base;
  if (header->depth == 0U) return 1U;
  frame = spx_native_frame_at(base, header->depth - 1U);
  if (frame->bridge_index != bridge_index) return 1U;
  descriptor = &spx_native_ingress_descriptors[bridge_index];
  status = spx_native_runtime_run_at_rva(
      descriptor->target_rva, frame->input, frame->output);
  if (status != SPX_CALL_OK && spx_native_seh_descriptor_count != 0U) {{
    uint32_t exception_code =
        status == SPX_CALL_DIVIDE_ERROR ? 0xc0000094U :
        status == SPX_CALL_MEMORY_FAULT ? 0xc0000005U : 0U;
    if (exception_code != 0U) {{
      uint32_t i;
      for (i = 0U; i < spx_native_seh_descriptor_count; ++i) {{
        const spx_native_seh_descriptor *seh = &spx_native_seh_descriptors[i];
        if (seh->code == exception_code &&
            seh->source_rva == frame->output->original_rva) {{
          header->exceptional = 2U; header->exception_code = exception_code;
          header->exception_flags = seh->continuable != 0U ? 0U : 1U;
          header->exception_address = (uint32_t)(uintptr_t)seh->portal;
          header->exception_parameter_count = seh->parameter_count;
          for (uint32_t parameter = 0U;
               parameter < header->exception_parameter_count; ++parameter)
            header->exception_parameters[parameter] = 0U;
          if (status == SPX_CALL_MEMORY_FAULT &&
              seh->operation_parameter < header->exception_parameter_count &&
              seh->address_parameter < header->exception_parameter_count) {{
            volatile uint32_t *reason = spx_native_runtime_diagnostic_slot(0U);
            volatile uint32_t *address = spx_native_runtime_diagnostic_slot(1U);
            if (reason == 0 || address == 0 ||
                (*reason != 0x3001U && *reason != 0x3002U))
              break;
            header->exception_parameters[seh->operation_parameter] =
                *reason == 0x3001U ? 0U : 1U;
            header->exception_parameters[seh->address_parameter] = *address;
          }}
          header->seh_descriptor_index = i;
          if (seh->handler_rva != 0U)
            status = (spx_call_status)spx_native_ingress_recover_exception();
          else if (spx_native_raise_exception(seh, header) != 0U)
            status = SPX_CALL_OK;
          break;
        }}
      }}
    }}
  }}
  if (status == SPX_CALL_OK &&
      (((descriptor->preserved_mask & 0x01U) && frame->output->ebx != frame->input->ebx) ||
       ((descriptor->preserved_mask & 0x02U) && frame->output->esi != frame->input->esi) ||
       ((descriptor->preserved_mask & 0x04U) && frame->output->edi != frame->input->edi) ||
       ((descriptor->preserved_mask & 0x08U) && frame->output->ebp != frame->input->ebp) ||
       ((descriptor->preserved_mask & 0x10U) && frame->output->eflags != frame->input->eflags) ||
       frame->output->esp != frame->input->esp + 4U + descriptor->cleanup_bytes))
    status = SPX_CALL_UNIMPLEMENTED;
  frame->outcome = status == SPX_CALL_OK ? 1U : 0U;
  return (uint32_t)status;
}}

uint32_t spx_native_ingress_recover_exception(void) {{
  uint8_t *base = spx_native_thread_base();
  spx_native_thread_header *header;
  spx_native_ingress_frame *frame;
  const spx_native_seh_descriptor *seh;
  spx_call_status status;
  if (base == 0) return (uint32_t)SPX_CALL_UNIMPLEMENTED;
  header = (spx_native_thread_header *)(void *)base;
  if (header->depth == 0U || header->exceptional == 0U ||
      header->seh_descriptor_index >= spx_native_seh_descriptor_count)
    return (uint32_t)SPX_CALL_UNIMPLEMENTED;
  frame = spx_native_frame_at(base, header->depth - 1U);
  seh = &spx_native_seh_descriptors[header->seh_descriptor_index];
  if (seh->handler_rva == 0U) return (uint32_t)SPX_CALL_UNIMPLEMENTED;
  status = spx_native_runtime_run_at_rva(
      seh->handler_rva, frame->output, frame->output);
  if (status == SPX_CALL_OK && seh->resumption_rva != 0U)
    status = spx_native_runtime_run_at_rva(
        seh->resumption_rva, frame->output, frame->output);
  frame->outcome = status == SPX_CALL_OK
      ? (header->exceptional == 1U ? 4U : 1U) : 0U;
  header->exceptional = 0U;
  return (uint32_t)status;
}}

spx_native_physical_capture *spx_native_ingress_finish(uint32_t status) {{
  uint8_t *base = spx_native_thread_base();
  spx_native_thread_header *header;
  spx_native_ingress_frame *frame;
  spx_native_physical_capture *capture;
  uint32_t cleanup_bytes, exceptional_return, return_target, i;
  if (base == 0) return 0;
  header = (spx_native_thread_header *)(void *)base;
  if (header->depth == 0U) return 0;
  frame = spx_native_frame_at(base, header->depth - 1U);
  capture = frame->capture;
  cleanup_bytes = spx_native_ingress_descriptors[
      frame->bridge_index].cleanup_bytes;
  exceptional_return = frame->outcome == 4U;
  if (status == (uint32_t)SPX_CALL_OK) spx_native_export_capture(capture, frame->output);
  else capture->eax = status;
  header->stack_bump = frame->stack_mark;
  header->depth--;
  spx_native_write_stack_bounds(
      frame->host_stack_base, frame->host_stack_limit);
  if (exceptional_return && cleanup_bytes != 0U) {{
    uint8_t *source = (uint8_t *)(void *)capture;
    uint8_t *target = source + cleanup_bytes;
    return_target = *(uint32_t *)(void *)(source + sizeof(*capture));
    for (i = sizeof(*capture); i != 0U; --i) target[i - 1U] = source[i - 1U];
    *(uint32_t *)(void *)(target + sizeof(*capture)) = return_target;
    capture = (spx_native_physical_capture *)(void *)target;
  }}
  return capture;
}}

uint32_t spx_native_capability_publish(
    uint32_t capability_index, uint32_t generation, uint32_t escaped) {{
  spx_native_capability_state *cap;
  if (capability_index >= spx_native_capability_count || generation == 0U) return 0U;
  cap = &spx_native_capabilities[capability_index];
  __atomic_store_n(&cap->generation, generation, __ATOMIC_RELAXED);
  __atomic_store_n(&cap->escaped, escaped != 0U, __ATOMIC_RELAXED);
  __atomic_store_n(&cap->active, 1U, __ATOMIC_RELEASE);
  return 1U;
}}

uint32_t spx_native_capability_revoke(
    uint32_t capability_index, uint32_t generation) {{
  spx_native_capability_state *cap;
  if (capability_index >= spx_native_capability_count) return 0U;
  cap = &spx_native_capabilities[capability_index];
  if (__atomic_load_n(&cap->generation, __ATOMIC_ACQUIRE) != generation) return 0U;
  __atomic_store_n(&cap->active, 0U, __ATOMIC_RELEASE);
  return 1U;
}}

uint32_t spx_native_capability_activate(
    uint32_t capability_index, uint32_t escaped) {{
  uint32_t generation = __atomic_add_fetch(
      &spx_native_next_capability_generation, 1U, __ATOMIC_RELAXED);
  if (generation == 0U)
    generation = __atomic_add_fetch(
        &spx_native_next_capability_generation, 1U, __ATOMIC_RELAXED);
  return spx_native_capability_publish(
      capability_index, generation, escaped) != 0U ? generation : 0U;
}}

uint32_t spx_native_capability_replace(
    uint32_t old_capability_index, uint32_t new_capability_index,
    uint32_t escaped) {{
  uint32_t generation;
  if (old_capability_index >= spx_native_capability_count ||
      new_capability_index >= spx_native_capability_count)
    return 0U;
  if (spx_native_capabilities[new_capability_index].lifetime_mode != 2U)
    return 0U;
  generation = spx_native_capability_activate(new_capability_index, escaped);
  if (generation == 0U) return 0U;
  if (old_capability_index != new_capability_index)
    __atomic_store_n(
        &spx_native_capabilities[old_capability_index].active,
        0U, __ATOMIC_RELEASE);
  return generation;
}}

static uint32_t spx_native_text_equal(const char *left, const char *right) {{
  uint32_t index = 0U;
  if (left == 0 || right == 0) return 0U;
  while (left[index] != 0 && left[index] == right[index]) ++index;
  return left[index] == right[index];
}}

uint32_t spx_native_capability_expire_event(const char *event_id) {{
  uint32_t index, expired = 0U;
  if (event_id == 0) return 0U;
  for (index = 0U; index < spx_native_capability_count; ++index) {{
    spx_native_capability_state *cap = &spx_native_capabilities[index];
    if (cap->lifetime_mode == 3U &&
        spx_native_text_equal(cap->end_event, event_id) != 0U)
      expired += __atomic_exchange_n(
          &cap->active, 0U, __ATOMIC_ACQ_REL) != 0U;
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
  uint32_t index;
  (void)dispatcher;
  if (base == 0 || record == 0 || context == 0)
    return 1; /* ExceptionContinueSearch */
  header = (spx_native_thread_header *)(void *)base;
  if ((record[1] & 0x66U) != 0U) {{
    if (header->depth != 0U) {{
      spx_native_ingress_frame *abandoned =
          spx_native_frame_at(base, header->depth - 1U);
      header->stack_bump = abandoned->stack_mark;
      header->depth--;
      spx_native_write_stack_bounds(
          abandoned->host_stack_base, abandoned->host_stack_limit);
    }}
    header->exceptional = 0U;
    return 1; /* ExceptionContinueSearch after checked invalidation. */
  }}
  if (header->exceptional == 3U)
    return 1; /* A checked escaping exception belongs to the outer host. */
  if (header->depth == 0U) return 1;
  for (index = 0U; index < spx_native_seh_descriptor_count; ++index) {{
    const spx_native_seh_descriptor *seh = &spx_native_seh_descriptors[index];
    const spx_native_ingress_frame *frame =
        spx_native_frame_at(base, header->depth - 1U);
    if (record[0] == seh->code &&
        (record[1] & seh->flags_mask) == seh->flags_value &&
        record[4] == seh->parameter_count &&
        frame->output->original_rva == seh->source_rva &&
        seh->handler_rva != 0U &&
        ((seh->continuable != 0U) == ((record[1] & 1U) == 0U)))
      break;
  }}
  if (index == spx_native_seh_descriptor_count) return 1;
  header->exceptional = 1U; header->exception_code = record[0];
  header->exception_flags = record[1];
  header->exception_address = (uint32_t)(uintptr_t)
      spx_native_seh_descriptors[index].portal;
  header->exception_parameter_count = record[4] > 15U ? 15U : record[4];
  for (uint32_t i = 0; i < header->exception_parameter_count; ++i)
    header->exception_parameters[i] = record[5U + i];
  header->seh_descriptor_index = index;
  if (header->depth != 0U) {{
    spx_native_ingress_frame *frame =
        spx_native_frame_at(base, header->depth - 1U);
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
_Static_assert({ENGINE_THREAD_STATE_OFFSET + ENGINE_THREAD_STATE_BYTES}U <=
    {RUNTIME_CONTEXT_OFFSET}U, "engine thread state overlaps semantic context");
'''


def render_native_ingress_assembly(plan: Mapping[str, Any]) -> str:
    bridges = _bridge_rows(plan)
    handlers = sorted({
        str(row["gateway_handler_symbol"])
        for row in plan.get("seh_protocols", []) if isinstance(row, Mapping)
    })
    portals = sorted({
        str(portal["candidate_symbol"])
        for protocol in plan.get("seh_protocols", [])
        if isinstance(protocol, Mapping)
        for portal in protocol.get("portals", [])
        if isinstance(portal, Mapping)
    })
    selected_handler = handlers[0] if handlers else None
    lines = [
        ".intel_syntax noprefix",
        ".text",
        ".extern _spx_native_ingress_prepare",
        ".extern _spx_native_ingress_dispatch",
        ".extern _spx_native_ingress_finish",
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
            "    int3",
            "    ud2",
            "",
        ])
    for symbol in handlers:
        lines.extend([
            f".globl _{symbol}",
            f"_{symbol}:",
            "    jmp _spx_native_seh_dispatch",
            "",
        ])
    if handlers:
        lines.extend([
            ".globl _spx_native_exception_recovery",
            "_spx_native_exception_recovery:",
            "    mov edx, DWORD PTR [esp]",
            "    mov DWORD PTR fs:0, edx",
            "    add esp, 8",
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
            "    int3",
            "    ud2",
            "",
        ])
        lines.extend([
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
    for symbol in portals:
        lines.extend([
            f".globl _{symbol}",
            f"_{symbol}:",
            "    int3",
            "    ret",
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
        transport = PhysicalCallFrameV2.parse(matches[0]["physical_frame"]["transport"])
        capability_ids = sorted({
            str(row["capability_id"])
            for row in matches if row.get("capability_id") is not None
        })
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
            "cleanup_bytes": transport.stack.cleanup_bytes,
        })
    return sorted(result, key=lambda row: row["symbol"])


def _uint(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ToolkitInputError(f"{label} is invalid")
    return value


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


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


def _seh_projection_masks(
    protocol: Mapping[str, Any],
) -> tuple[int, int, int, int]:
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
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags"
    }
    unsupported_context = sorted(
        str(value) for value in projections.get("context", [])
        if str(value).lower() not in supported_context
    )
    if unsupported_context:
        raise ToolkitInputError(
            f"generic native ingress cannot project CONTEXT fields {unsupported_context!r}"
        )
    return register_mask, int(flags), int(stack), x87_mask


__all__ = [
    "ENGINE_STACK_FRAME_BYTES",
    "MINIMUM_RUNTIME_CONTROL_BYTES",
    "NativeIngressSupportABI",
    "exact_tls_regions",
    "render_native_ingress_assembly",
    "render_native_ingress_header",
    "render_native_ingress_source",
]
