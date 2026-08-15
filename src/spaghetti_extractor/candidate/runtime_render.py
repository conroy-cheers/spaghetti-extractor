"""Native runtime header, tables, and front-half C rendering."""

from __future__ import annotations

import json

from .runtime_model import NativeRuntimePlan
from .runtime_render_core import _native_runtime_source_core
from .runtime_render_entry import _native_runtime_source_entry


def _native_runtime_header() -> str:
    return r'''#ifndef STAGE_B_NATIVE_RUNTIME_H
#define STAGE_B_NATIVE_RUNTIME_H

#include "state-machine-interpreter.h"

typedef enum stage_b_native_terminal_kind {
  STAGE_B_NATIVE_TERMINAL_RETURNED = 0,
  STAGE_B_NATIVE_TERMINAL_UNIMPLEMENTED = 1,
  STAGE_B_NATIVE_TERMINAL_DIVIDE_ERROR = 2,
  STAGE_B_NATIVE_TERMINAL_MEMORY_FAULT = 3,
  STAGE_B_NATIVE_TERMINAL_EXTERNAL_FAULT = 4,
  STAGE_B_NATIVE_TERMINAL_UNDEFINED_VALUE = 5,
  STAGE_B_NATIVE_TERMINAL_INVALID_IMAGE = 6,
  STAGE_B_NATIVE_TERMINAL_CONCURRENT_ENTRY = 7
} stage_b_native_terminal_kind;

extern const char stage_b_native_interpreter_manifest_sha256[65];
extern const char stage_b_native_engine_manifest_sha256[65];
extern const char stage_b_native_state_machine_sha256[65];
extern volatile stage_b_native_terminal_kind stage_b_native_terminal_status;
extern volatile stage_b_call_status stage_b_native_terminal_call_status;
extern stage_b_machine_state stage_b_native_terminal_state;
extern stage_b_runtime stage_b_native_runtime_instance;
void stage_b_native_terminate(stage_b_native_terminal_kind status)
    __attribute__((noreturn));

stage_b_call_status stage_b_native_runtime_run_at_rva(
    uint32_t entry_rva, const stage_b_machine_state *input,
    stage_b_machine_state *output);
stage_b_call_status stage_b_native_runtime_run_nested_callback(
    uint32_t callback_rva, uint32_t stack_cleanup_bytes,
    const stage_b_machine_state *input, stage_b_machine_state *output);
stage_b_call_status stage_b_native_runtime_run_captured(
    const stage_b_machine_state *captured, stage_b_machine_state *output);
void stage_b_native_runtime_coordinate(
    const stage_b_machine_state *captured) __attribute__((noreturn));
#ifdef STAGE_B_NATIVE_DIAGNOSTIC_FAILURE_TRAP
void stage_b_native_runtime_write_diagnostic(
    uint32_t status, uint32_t failure_rva,
    const stage_b_machine_state *state);
#endif

#endif
'''


def _native_runtime_source(plan: NativeRuntimePlan) -> str:
    transfer_rows = "\n".join(
        f"  0x{rva:08x}U," for rva in plan.transfer_rvas
    )
    implementation_rows = "\n".join(
        "  {{ 0x{rva:08x}U, {class_code}U, {entry_rva}, {replacement}, {cluster} }},".format(
            rva=dispatch.rva,
            class_code=dispatch.class_code,
            entry_rva=(
                "0U"
                if dispatch.component_entry_rva is None
                else f"0x{dispatch.component_entry_rva:08x}U"
            ),
            replacement=(
                "0"
                if dispatch.replacement_id is None
                else json.dumps(dispatch.replacement_id, ensure_ascii=True)
            ),
            cluster=(
                "0"
                if dispatch.cluster_id is None
                else json.dumps(dispatch.cluster_id, ensure_ascii=True)
            ),
        )
        for dispatch in plan.implementation_dispatches
    )
    portable_dispatch_count = sum(
        dispatch.implementation_class == "selected_portable_component"
        for dispatch in plan.implementation_dispatches
    )
    recovered_data_rows = "\n".join(
        f"  {{ 0x{start:08x}U, 0x{end:08x}U }},"
        for start, end in plan.recovered_executable_data_ranges
    ) or "  { 0U, 0U },"
    callback_rows = "\n".join(
        f"  {{ 0x{rva:08x}U, {cleanup}U }},"
        for rva, cleanup in plan.callback_abis
    ) or "  { 0U, 0U },"
    undefined_rows = "\n".join(
        f"  {{ 0x{policy.slot:08x}U, {policy.policy_code}U, "
        f"{policy.input_location_code}U }},"
        for policy in plan.undefined_policies
    ) or "  { 0U, 2U, 0U },"
    register_codes = {
        name: index
        for index, name in enumerate(
            ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        )
    }
    callable_resolver_table = "  { 0U, 0U, 0U, 0U },"
    callable_route_table = "  { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U },"
    callable_argument_table = "  { 0U, 0U, 0U },"
    callable_footprint_table = "  { 0U, 0U, 0U, 0U, 0U },"
    callable_binding_rows = "  0U,"
    callable_binding_count = 0
    action_codes = {
        "add_result_range": 1,
        "release_argument_range": 2,
        "add_result_pointee_ranges": 3,
        "add_argument_pointee_ranges": 4,
        "add_argument_interface_ranges": 5,
    }
    size_codes = {
        None: 0,
        "fixed": 1,
        "argument": 2,
        "product": 3,
        "bounded_zero_run": 4,
    }
    diagnostic_iat_rvas = (0, 0, 0)
    diagnostic_writer_available = 0
    authorized_external_site_rows = "\n".join(
        f"  0x{rva:08x}U," for rva in plan.authorized_external_site_rvas
    ) or "  0U,"
    external_range_rows = "\n".join(
        "  {{ 0x{rva:08x}U, 0x{target_iat_rva:08x}U, {action}U, {argument_base_offset}U, "
        "{argument_count}U, {register}U, {argument}U, "
        "{size_kind}U, {size_value}U, {size_argument}U, "
        "{size_right_argument}U, {minimum_size}U, {nullable}U, "
        "{termination_unit_bytes}U, {termination_zero_units}U, "
        "{termination_max_units}U, "
        "{pointee_offset}U, {max_elements}U, {element_unit_bytes}U, "
        "{element_max_units}U }},".format(
            rva=rule.instruction_rva,
            target_iat_rva=rule.target_iat_rva or 0,
            action=action_codes[rule.action],
            argument_base_offset=rule.argument_base_offset,
            argument_count=rule.argument_count,
            register=register_codes.get(rule.register or "", 0),
            argument=rule.argument or 0,
            size_kind=size_codes[rule.size_kind],
            size_value=rule.size_value,
            size_argument=rule.size_argument or 0,
            size_right_argument=rule.size_right_argument or 0,
            minimum_size=rule.minimum_size,
            nullable=1 if rule.nullable else 0,
            termination_unit_bytes=rule.termination_unit_bytes,
            termination_zero_units=rule.termination_zero_units,
            termination_max_units=rule.termination_max_units,
            pointee_offset=rule.pointee_offset,
            max_elements=rule.max_elements,
            element_unit_bytes=rule.element_unit_bytes,
            element_max_units=rule.element_max_units,
        )
        for rule in plan.external_range_rules
    ) or (
        "  { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, "
        "0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U },"
    )
    x87_declaration = (
        r'''extern stage_b_call_status stage_b_native_execute_typed_x87_operation(
    stage_b_runtime *runtime, const stage_b_typed_x87_operation *program,
    const stage_b_machine_state *input, stage_b_machine_state *output);
'''
        if plan.has_typed_x87_handler
        else ""
    )
    return (f'''#include "native-runtime.h"

#include <stdint.h>

#define STAGE_B_NATIVE_IMAGE_SCN_MEM_EXECUTE 0x20000000U
#define STAGE_B_NATIVE_MAX_PE_SECTIONS 96U
#define STAGE_B_NATIVE_MAX_EXTERNAL_RANGES 8192U
#define STAGE_B_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS 64U
#define STAGE_B_NATIVE_MAX_EXTERNAL_TRACE_EVENTS 128U
#define STAGE_B_NATIVE_MAX_TRANSFER_TRACE_EVENTS 1024U
#define STAGE_B_NATIVE_DIAGNOSTIC_WRITER_AVAILABLE {diagnostic_writer_available}U
#define STAGE_B_NATIVE_DIAGNOSTIC_CREATE_FILE_IAT_RVA 0x{diagnostic_iat_rvas[0]:08x}U
#define STAGE_B_NATIVE_DIAGNOSTIC_WRITE_FILE_IAT_RVA 0x{diagnostic_iat_rvas[1]:08x}U
#define STAGE_B_NATIVE_DIAGNOSTIC_CLOSE_HANDLE_IAT_RVA 0x{diagnostic_iat_rvas[2]:08x}U

extern const unsigned char __ImageBase[];
volatile uint32_t stage_b_native_diagnostic_reason;
volatile uint32_t stage_b_native_diagnostic_value;
volatile uint32_t stage_b_native_diagnostic_aux;
volatile uint32_t stage_b_native_diagnostic_detail;
extern stage_b_call_status stage_b_dispatch_external_call(
    stage_b_runtime *runtime, const stage_b_call_event *event,
    const stage_b_machine_state *input, stage_b_machine_state *output);
extern const stage_b_region_override *stage_b_region_override_lookup(
    uint32_t entry_rva) __attribute__((weak));
extern const stage_b_region_override stage_b_region_overrides[]
    __attribute__((weak));
extern const uint32_t stage_b_region_override_count __attribute__((weak));
extern const uint32_t stage_b_program_transfer_count __attribute__((weak));
{x87_declaration}

_Static_assert(sizeof(uintptr_t) == 4U, "native runtime requires i686 pointers");

volatile stage_b_native_terminal_kind stage_b_native_terminal_status =
    STAGE_B_NATIVE_TERMINAL_UNIMPLEMENTED;
volatile stage_b_call_status stage_b_native_terminal_call_status =
    STAGE_B_CALL_UNIMPLEMENTED;
stage_b_machine_state stage_b_native_terminal_state;

static const uint32_t stage_b_native_transfer_rvas[] = {{
{transfer_rows}
}};
static const uint32_t stage_b_native_transfer_count = {len(plan.transfer_rvas)}U;

typedef struct stage_b_native_implementation_dispatch {{
  uint32_t rva, implementation_class;
  uint32_t component_entry_rva;
  const char *replacement_id, *cluster_id;
}} stage_b_native_implementation_dispatch;
static const stage_b_native_implementation_dispatch
stage_b_native_implementation_dispatches[] = {{
{implementation_rows}
}};
static const uint32_t stage_b_native_implementation_dispatch_count =
    {len(plan.implementation_dispatches)}U;
static const uint32_t stage_b_native_portable_dispatch_count =
    {portable_dispatch_count}U;

typedef struct stage_b_native_noncode_range {{
  uint32_t rva_start, rva_end;
}} stage_b_native_noncode_range;
static const stage_b_native_noncode_range stage_b_native_noncode_ranges[] = {{
{recovered_data_rows}
}};
static const uint32_t stage_b_native_noncode_range_count = {len(plan.recovered_executable_data_ranges)}U;

typedef struct stage_b_native_callback_abi {{
  uint32_t rva, stack_cleanup_bytes;
}} stage_b_native_callback_abi;
static const stage_b_native_callback_abi stage_b_native_callback_abis[] = {{
{callback_rows}
}};
static const uint32_t stage_b_native_callback_abi_count = {len(plan.callback_abis)}U;

typedef struct stage_b_native_undefined_policy {{
  uint32_t slot, policy, input_location;
}} stage_b_native_undefined_policy;
static const stage_b_native_undefined_policy stage_b_native_undefined_policies[] = {{
{undefined_rows}
}};
static const uint32_t stage_b_native_undefined_policy_count = {len(plan.undefined_policies)}U;

static const uint32_t stage_b_native_authorized_external_sites[] = {{
{authorized_external_site_rows}
}};
static const uint32_t stage_b_native_authorized_external_site_count = {len(plan.authorized_external_site_rvas)}U;

typedef struct stage_b_native_external_range_rule {{
  uint32_t instruction_rva, target_iat_rva, action;
  uint32_t argument_base_offset, argument_count;
  uint32_t register_index, argument;
  uint32_t size_kind, size_value, size_argument, size_right_argument;
  uint32_t minimum_size, nullable;
  uint32_t termination_unit_bytes, termination_zero_units, termination_max_units;
  uint32_t pointee_offset, max_elements, element_unit_bytes, element_max_units;
}} stage_b_native_external_range_rule;
static const stage_b_native_external_range_rule stage_b_native_external_range_rules[] = {{
{external_range_rows}
}};
static const uint32_t stage_b_native_external_range_rule_count = {len(plan.external_range_rules)}U;

typedef struct stage_b_native_callable_resolver {{
  uint32_t instruction_rva, capability_id, result_register, nullable;
}} stage_b_native_callable_resolver;
static const stage_b_native_callable_resolver stage_b_native_callable_resolvers[] = {{
{callable_resolver_table}
}};
static const uint32_t stage_b_native_callable_resolver_count = 0U;
static const uint32_t stage_b_native_callable_binding_capabilities[] = {{
{callable_binding_rows}
}};
static const uint32_t stage_b_native_callable_binding_count = {callable_binding_count}U;

typedef struct stage_b_native_callable_argument {{
  uint32_t kind, register_index, value;
}} stage_b_native_callable_argument;
static const stage_b_native_callable_argument stage_b_native_callable_arguments[] = {{
{callable_argument_table}
}};
static const uint32_t stage_b_native_callable_argument_count = 0U;

typedef struct stage_b_native_callable_footprint {{
  uint32_t access, base_argument, offset, size, nullable;
}} stage_b_native_callable_footprint;
static const stage_b_native_callable_footprint stage_b_native_callable_footprints[] = {{
{callable_footprint_table}
}};
static const uint32_t stage_b_native_callable_footprint_count = 0U;

typedef struct stage_b_native_callable_route {{
  uint32_t source_rva, instruction_rva, capability_id, abi_contract_id;
  uint32_t stack_result_delta, preserved_register_mask;
  uint32_t argument_offset, argument_count;
  uint32_t footprint_offset, footprint_count;
}} stage_b_native_callable_route;
static const stage_b_native_callable_route stage_b_native_callable_routes[] = {{
{callable_route_table}
}};
static const uint32_t stage_b_native_callable_route_count = 0U;

typedef struct stage_b_native_callable_binding {{
  uint32_t capability_id, target_word, bound;
}} stage_b_native_callable_binding;

typedef struct stage_b_native_external_range {{
  uint32_t start, size, producer_rva, producer_action, generation;
}} stage_b_native_external_range;

typedef struct stage_b_native_external_lifecycle_event {{
  uint32_t sequence, operation, status, instruction_rva;
  uint32_t start, size, producer_rva, producer_action, generation;
}} stage_b_native_external_lifecycle_event;

typedef struct stage_b_native_external_trace_event {{
  uint32_t sequence, phase, instruction_rva, target_rva, target_iat_rva;
  uint32_t kind, status, eax, esp, eflags;
}} stage_b_native_external_trace_event;

typedef struct stage_b_native_transfer_trace_event {{
  uint32_t sequence, rva, df, esp;
}} stage_b_native_transfer_trace_event;

typedef struct stage_b_native_context {{
  uint32_t image_base;
  uint32_t image_size;
  uint32_t headers_size;
  uint32_t section_table;
  uint32_t section_count;
  uint32_t stack_low;
  uint32_t stack_high;
  volatile uint32_t active;
  uint32_t initialized;
  uint32_t process_world_initialized;
  uint32_t owner_fs_base;
  uint32_t nested_depth;
  uint32_t undefined_fault;
  uint32_t undefined_fault_slot;
  uint32_t undefined_fault_rva;
  uint32_t last_undefined_fault;
  stage_b_native_external_range external_ranges[STAGE_B_NATIVE_MAX_EXTERNAL_RANGES];
  uint32_t external_range_count;
  stage_b_native_external_lifecycle_event external_lifecycle_events[
      STAGE_B_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS];
  uint32_t external_lifecycle_count;
  uint32_t external_lifecycle_next;
  uint32_t external_lifecycle_sequence;
  stage_b_native_external_trace_event external_trace_events[
      STAGE_B_NATIVE_MAX_EXTERNAL_TRACE_EVENTS];
  uint32_t external_trace_count;
  uint32_t external_trace_next;
  uint32_t external_trace_sequence;
  stage_b_native_transfer_trace_event transfer_trace_events[
      STAGE_B_NATIVE_MAX_TRANSFER_TRACE_EVENTS];
  uint32_t transfer_trace_count;
  uint32_t transfer_trace_next;
  uint32_t transfer_trace_sequence;
  stage_b_native_callable_binding callable_bindings[{max(1, callable_binding_count)}U];
}} stage_b_native_context;

#define STAGE_B_NATIVE_THREAD_ENVIRONMENT_BYTES 0x1000U

static stage_b_native_context stage_b_native_context_value;

static uint16_t stage_b_native_u16(uint32_t address) {{
  const volatile uint8_t *p = (const volatile uint8_t *)(uintptr_t)address;
  return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}}

static uint32_t stage_b_native_u32(uint32_t address) {{
  const volatile uint8_t *p = (const volatile uint8_t *)(uintptr_t)address;
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
      ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}}

static uint32_t stage_b_native_range_end(
    uint32_t start, uint32_t width, uint32_t *end) {{
  if (width == 0U || start > 0xffffffffU - width) return 0U;
  *end = start + width;
  return 1U;
}}

static uint32_t stage_b_native_inside(
    uint32_t start, uint32_t end, uint32_t region_start, uint32_t region_size) {{
  uint32_t region_end;
  if (region_size == 0U ||
      !stage_b_native_range_end(region_start, region_size, &region_end))
    return 0U;
  return start >= region_start && end <= region_end;
}}

static uint32_t stage_b_native_inside_external_range(
    const stage_b_native_context *context, uint32_t start, uint32_t end) {{
  uint32_t i;
  for (i = 0U; i < context->external_range_count; ++i)
    if (stage_b_native_inside(
            start, end, context->external_ranges[i].start,
            context->external_ranges[i].size))
      return 1U;
  return 0U;
}}

static void stage_b_native_diagnose_external_range(
    const stage_b_native_context *context, uint32_t address) {{
  uint32_t i, nearest_start = 0U, nearest_end = 0U, has_preceding = 0U;
  if (context == 0) return;
  for (i = 0U; i < context->external_range_count; ++i) {{
    uint32_t start = context->external_ranges[i].start;
    uint32_t end;
    if (!stage_b_native_range_end(
            start, context->external_ranges[i].size, &end))
      continue;
    if ((start <= address &&
         (has_preceding == 0U || start > nearest_start)) ||
        (start > address && has_preceding == 0U &&
         (nearest_start == 0U || start < nearest_start))) {{
      nearest_start = start;
      nearest_end = end;
      has_preceding = start <= address;
    }}
  }}
  stage_b_native_diagnostic_aux = nearest_start;
  stage_b_native_diagnostic_detail = nearest_end;
}}

#ifdef STAGE_B_NATIVE_DIAGNOSTIC_FAILURE_TRAP
typedef uint32_t (__attribute__((stdcall)) *stage_b_native_create_file_a_fn)(
    const char *, uint32_t, uint32_t, void *, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__attribute__((stdcall)) *stage_b_native_write_file_fn)(
    uint32_t, const void *, uint32_t, uint32_t *, void *);
typedef uint32_t (__attribute__((stdcall)) *stage_b_native_close_handle_fn)(
    uint32_t);

typedef struct stage_b_native_diagnostic_header {{
  uint32_t magic, version, status, failure_rva;
  uint32_t reason, value, aux, detail;
  uint32_t external_range_count, external_lifecycle_count;
  uint32_t external_lifecycle_next, external_lifecycle_sequence;
  uint32_t external_trace_count, external_trace_next, external_trace_sequence;
  uint32_t transfer_trace_count, transfer_trace_next, transfer_trace_sequence;
  uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp, eflags, fs_base;
  uint32_t stack_word_count;
  uint32_t stack_words[16];
}} stage_b_native_diagnostic_header;

static uint32_t stage_b_native_diagnostic_iat_target(uint32_t iat_rva) {{
  const stage_b_native_context *context = &stage_b_native_context_value;
  if (iat_rva > context->image_size || context->image_size - iat_rva < 4U ||
      context->image_base > 0xffffffffU - iat_rva)
    return 0U;
  return stage_b_native_u32(context->image_base + iat_rva);
}}

static uint32_t stage_b_native_diagnostic_write(
    stage_b_native_write_file_fn write_file, uint32_t handle,
    const void *data, uint32_t size) {{
  uint32_t written = 0U;
  return write_file != 0 &&
      write_file(handle, data, size, &written, 0) != 0U && written == size;
}}

void stage_b_native_runtime_write_diagnostic(
    uint32_t status, uint32_t failure_rva,
    const stage_b_machine_state *state) {{
  const stage_b_native_context *context = &stage_b_native_context_value;
  stage_b_native_create_file_a_fn create_file;
  stage_b_native_write_file_fn write_file;
  stage_b_native_close_handle_fn close_handle;
  stage_b_native_diagnostic_header header;
  uint32_t handle, range_bytes, lifecycle_bytes, external_trace_bytes;
  uint32_t transfer_trace_bytes;
  if (STAGE_B_NATIVE_DIAGNOSTIC_WRITER_AVAILABLE == 0U) return;
  create_file = (stage_b_native_create_file_a_fn)(uintptr_t)
      stage_b_native_diagnostic_iat_target(
          STAGE_B_NATIVE_DIAGNOSTIC_CREATE_FILE_IAT_RVA);
  write_file = (stage_b_native_write_file_fn)(uintptr_t)
      stage_b_native_diagnostic_iat_target(
          STAGE_B_NATIVE_DIAGNOSTIC_WRITE_FILE_IAT_RVA);
  close_handle = (stage_b_native_close_handle_fn)(uintptr_t)
      stage_b_native_diagnostic_iat_target(
          STAGE_B_NATIVE_DIAGNOSTIC_CLOSE_HANDLE_IAT_RVA);
  if (create_file == 0 || write_file == 0 || close_handle == 0) return;
  handle = create_file(
      "spaghetti-extractor-diagnostic.bin", 0x40000000U, 0U, 0,
      2U, 0x00000080U, 0U);
  if (handle == 0U || handle == 0xffffffffU) return;
  header.magic = 0x31444553U;
  header.version = 4U;
  header.status = status;
  header.failure_rva = failure_rva;
  header.reason = stage_b_native_diagnostic_reason;
  header.value = stage_b_native_diagnostic_value;
  header.aux = stage_b_native_diagnostic_aux;
  header.detail = stage_b_native_diagnostic_detail;
  header.external_range_count = context->external_range_count;
  header.external_lifecycle_count = context->external_lifecycle_count;
  header.external_lifecycle_next = context->external_lifecycle_next;
  header.external_lifecycle_sequence = context->external_lifecycle_sequence;
  header.external_trace_count = context->external_trace_count;
  header.external_trace_next = context->external_trace_next;
  header.external_trace_sequence = context->external_trace_sequence;
  header.transfer_trace_count = context->transfer_trace_count;
  header.transfer_trace_next = context->transfer_trace_next;
  header.transfer_trace_sequence = context->transfer_trace_sequence;
  header.eax = state != 0 ? state->eax : 0U;
  header.ebx = state != 0 ? state->ebx : 0U;
  header.ecx = state != 0 ? state->ecx : 0U;
  header.edx = state != 0 ? state->edx : 0U;
  header.esi = state != 0 ? state->esi : 0U;
  header.edi = state != 0 ? state->edi : 0U;
  header.ebp = state != 0 ? state->ebp : 0U;
  header.esp = state != 0 ? state->esp : 0U;
  header.eflags = state != 0 ? state->eflags : 0U;
  header.fs_base = state != 0 ? state->fs_base : 0U;
  header.stack_word_count = 0U;
  if (state != 0) {{
    uint32_t i;
    for (i = 0U; i < 16U; ++i) {{
      uint32_t offset = i * 4U;
      uint32_t address, end;
      if (state->esp > 0xffffffffU - offset) break;
      address = state->esp + offset;
      if (!stage_b_native_range_end(address, 4U, &end) ||
          address < context->stack_low || end > context->stack_high)
        break;
      header.stack_words[i] = stage_b_native_u32(address);
      ++header.stack_word_count;
    }}
    for (i = header.stack_word_count; i < 16U; ++i)
      header.stack_words[i] = 0U;
  }} else {{
    uint32_t i;
    for (i = 0U; i < 16U; ++i) header.stack_words[i] = 0U;
  }}
  range_bytes = context->external_range_count *
      (uint32_t)sizeof(stage_b_native_external_range);
  lifecycle_bytes = context->external_lifecycle_count *
      (uint32_t)sizeof(stage_b_native_external_lifecycle_event);
  external_trace_bytes = context->external_trace_count *
      (uint32_t)sizeof(stage_b_native_external_trace_event);
  transfer_trace_bytes = context->transfer_trace_count *
      (uint32_t)sizeof(stage_b_native_transfer_trace_event);
  if (!stage_b_native_diagnostic_write(
          write_file, handle, &header, (uint32_t)sizeof(header)) ||
      (range_bytes != 0U && !stage_b_native_diagnostic_write(
          write_file, handle, context->external_ranges, range_bytes)) ||
      (lifecycle_bytes != 0U && !stage_b_native_diagnostic_write(
          write_file, handle, context->external_lifecycle_events,
          lifecycle_bytes)) ||
      (external_trace_bytes != 0U && !stage_b_native_diagnostic_write(
          write_file, handle, context->external_trace_events,
          external_trace_bytes)) ||
      (transfer_trace_bytes != 0U && !stage_b_native_diagnostic_write(
          write_file, handle, context->transfer_trace_events,
          transfer_trace_bytes))) {{
    close_handle(handle);
    return;
  }}
  close_handle(handle);
}}

void stage_b_native_runtime_write_external_probe(
    const stage_b_call_event *event,
    const stage_b_machine_state *state) {{
  uint32_t saved_last_error;
  uint32_t saved_reason = stage_b_native_diagnostic_reason;
  uint32_t saved_value = stage_b_native_diagnostic_value;
  uint32_t saved_aux = stage_b_native_diagnostic_aux;
  uint32_t saved_detail = stage_b_native_diagnostic_detail;
  if (event == 0 || state == 0) return;
  __asm__ volatile ("movl %%fs:0x34, %0" : "=r" (saved_last_error));
  stage_b_native_diagnostic_reason = 0x4001U;
  stage_b_native_diagnostic_value = event->target_rva;
  stage_b_native_diagnostic_aux = (uint32_t)event->kind;
  stage_b_native_diagnostic_detail = event->return_rva;
  stage_b_native_runtime_write_diagnostic(
      (uint32_t)STAGE_B_CALL_OK, event->instruction_rva, state);
  stage_b_native_diagnostic_reason = saved_reason;
  stage_b_native_diagnostic_value = saved_value;
  stage_b_native_diagnostic_aux = saved_aux;
  stage_b_native_diagnostic_detail = saved_detail;
  __asm__ volatile ("movl %0, %%fs:0x34" : : "r" (saved_last_error) : "memory");
}}
#endif

static uint32_t stage_b_native_inside_thread_environment(
    const stage_b_native_context *context, uint32_t start, uint32_t end) {{
  uint32_t teb_end;
  return context->owner_fs_base != 0U &&
      stage_b_native_range_end(
          context->owner_fs_base,
          STAGE_B_NATIVE_THREAD_ENVIRONMENT_BYTES,
          &teb_end) &&
      start >= context->owner_fs_base && end <= teb_end;
}}

static uint32_t stage_b_native_validate_image(stage_b_native_context *context) {{
  uint32_t base = (uint32_t)(uintptr_t)&__ImageBase;
  uint32_t pe_offset, pe, optional, section_table, section_bytes, section_end;
  uint32_t image_size, headers_size;
  uint16_t section_count, optional_size;
  if (base == 0U || base > 0xffffffffU - 0x40U ||
      stage_b_native_u16(base) != 0x5a4dU)
    return 0U;
  pe_offset = stage_b_native_u32(base + 0x3cU);
  if (pe_offset < 0x40U || pe_offset > 0x00100000U ||
      base > 0xffffffffU - pe_offset ||
      base + pe_offset > 0xffffffffU - 24U)
    return 0U;
  pe = base + pe_offset;
  if (stage_b_native_u32(pe) != 0x00004550U) return 0U;
  section_count = stage_b_native_u16(pe + 6U);
  optional_size = stage_b_native_u16(pe + 20U);
  if (section_count == 0U || section_count > STAGE_B_NATIVE_MAX_PE_SECTIONS ||
      optional_size < 64U)
    return 0U;
  optional = pe + 24U;
  if (optional > 0xffffffffU - 64U) return 0U;
  if (stage_b_native_u16(optional) != 0x010bU) return 0U;
  image_size = stage_b_native_u32(optional + 56U);
  headers_size = stage_b_native_u32(optional + 60U);
  if (image_size == 0U || headers_size == 0U || headers_size > image_size ||
      base > 0xffffffffU - image_size)
    return 0U;
  if (optional > 0xffffffffU - optional_size) return 0U;
  section_table = optional + optional_size;
  section_bytes = (uint32_t)section_count * 40U;
  if (!stage_b_native_range_end(section_table, section_bytes, &section_end) ||
      section_end > base + headers_size)
    return 0U;
  context->image_base = base;
  context->image_size = image_size;
  context->headers_size = headers_size;
  context->section_table = section_table;
  context->section_count = section_count;
  return 1U;
}}

static uint32_t stage_b_native_validate_stack(
    stage_b_native_context *context, const stage_b_machine_state *captured) {{
  uint32_t teb = captured->fs_base;
  uint32_t stack_high, stack_low;
  if (teb == 0U || teb > 0xffffffffU - 12U) return 0U;
  stack_high = stage_b_native_u32(teb + 4U);
  stack_low = stage_b_native_u32(teb + 8U);
  if (stack_low >= stack_high || captured->esp < stack_low ||
      captured->esp > stack_high)
    return 0U;
  context->stack_low = stack_low;
  context->stack_high = stack_high;
  return 1U;
}}

static uint32_t stage_b_native_string_equal(
    const char *left, const char *right) {{
  if (left == 0 || right == 0) return left == right;
  while (*left != '\\0' && *left == *right) {{ ++left; ++right; }}
  return *left == *right;
}}

static uint32_t stage_b_native_override_table_valid(void) {{
  uint32_t i, matched = 0U;
  if ((uintptr_t)&stage_b_region_override_count == 0U ||
      (uintptr_t)stage_b_region_overrides == 0U)
    return stage_b_native_portable_dispatch_count == 0U;
  if (stage_b_region_override_count != stage_b_native_portable_dispatch_count)
    return 0U;
  for (i = 0U; i < stage_b_region_override_count; ++i) {{
    const stage_b_region_override *observed = &stage_b_region_overrides[i];
    uint32_t j, found = 0U;
    for (j = 0U; j < stage_b_native_implementation_dispatch_count; ++j) {{
      const stage_b_native_implementation_dispatch *expected =
          &stage_b_native_implementation_dispatches[j];
      if (expected->implementation_class != 1U || expected->rva != observed->entry_rva)
        continue;
      if (found != 0U || observed->function == 0 ||
          observed->fallback_on_unimplemented != 0U ||
          !stage_b_native_string_equal(
              observed->replacement_id, expected->replacement_id) ||
          !stage_b_native_string_equal(
              observed->cluster_id, expected->cluster_id))
        return 0U;
      found = 1U;
    }}
    if (found == 0U) return 0U;
    ++matched;
  }}
  return matched == stage_b_native_portable_dispatch_count;
}}

static uint32_t stage_b_native_transfer_table_valid(void) {{
  uint32_t i;
  if ((uintptr_t)&stage_b_program_transfer_count == 0U ||
      stage_b_program_transfer_count != stage_b_native_transfer_count ||
      stage_b_native_transfer_count == 0U ||
      stage_b_native_implementation_dispatch_count !=
          stage_b_native_transfer_count ||
      !stage_b_native_override_table_valid())
    return 0U;
  for (i = 0U; i < stage_b_native_transfer_count; ++i) {{
    uint32_t rva = stage_b_native_transfer_rvas[i];
    const stage_b_native_implementation_dispatch *expected =
        &stage_b_native_implementation_dispatches[i];
    const stage_b_region_override *override;
    if ((i != 0U && stage_b_native_transfer_rvas[i - 1U] >= rva) ||
        expected->rva != rva ||
        rva >= stage_b_native_context_value.image_size ||
        stage_b_program_lookup(rva) == 0)
      return 0U;
    override = (
        stage_b_region_override_lookup == 0
        ? (const stage_b_region_override *)0
        : stage_b_region_override_lookup(rva));
    if (expected->implementation_class == 0U) {{
      if (override != 0 || expected->replacement_id != 0 ||
          expected->cluster_id != 0)
        return 0U;
    }} else if (expected->implementation_class == 1U) {{
      if (override == 0 || override->entry_rva != rva ||
          override->function == 0 || override->fallback_on_unimplemented != 0U ||
          !stage_b_native_string_equal(
              override->replacement_id, expected->replacement_id) ||
          !stage_b_native_string_equal(
              override->cluster_id, expected->cluster_id))
        return 0U;
    }} else if (expected->implementation_class == 2U) {{
      if (override != 0 || expected->replacement_id == 0 ||
          expected->cluster_id == 0 || expected->component_entry_rva == 0U ||
          expected->component_entry_rva == rva)
        return 0U;
    }} else {{
      return 0U;
    }}
  }}
''' + _native_runtime_source_core(plan) + _native_runtime_source_entry(plan))


def _native_runtime_bindings_source(plan: NativeRuntimePlan) -> str:
    return f'''#include "native-runtime.h"

const char stage_b_native_interpreter_manifest_sha256[65] =
    "{plan.interpreter_manifest_sha256}";
const char stage_b_native_engine_manifest_sha256[65] =
    "{plan.native_engine_manifest_sha256}";
const char stage_b_native_state_machine_sha256[65] =
    "{plan.state_machine_sha256}";
'''
