"""Freestanding C and assembly rendering for a checked engine plan."""

from __future__ import annotations

from collections.abc import Mapping
import json

from ..errors import ToolkitInputError
from .engine_model import (
    NativeEnginePlan,
    _FNSAVE_IMAGE_SIZE,
    _FRAME_OFFSETS,
    _MACHINE_STATE_SIZE,
    _STATE_OFFSETS,
    _X87_CHECKED_DECODER,
    _X87_CHECKED_EXECUTOR,
    _X87_FRAME_OFFSETS,
    _X87_REPLAY_INLINE_BODY_SIZE,
    _X87_REPLAY_INLINE_CAPTURE_OFFSET,
    _X87_REPLAY_INLINE_INSTRUCTION_OFFSET,
    _X87_REPLAY_INLINE_RETURN_OFFSET,
    _X87_VALUE_EMPTY_OFFSET,
    _X87_VALUE_SIZE,
    _X87_VALUE_TAG_OFFSET,
)
from .engine_x87 import (
    _capture_pushad_registers,
    _capture_split_flags,
    _render_typed_x87_instruction,
    _restore_pushes,
)


def _native_callback_lifetime_kind(value: object) -> str:
    if isinstance(value, Mapping):
        raw_kind = value.get("kind")
    else:
        raw_kind = value
    if not isinstance(raw_kind, str) or not raw_kind:
        raise ToolkitInputError("native callback capability lifetime is missing")
    kind = raw_kind.split(":", 1)[0]
    aliases = {
        "during_native_call": "during_call",
        "until_class_unregistered_or_process_exit": (
            "until_resource_event_or_process_exit"
        ),
    }
    kind = aliases.get(kind, kind)
    if kind not in {
        "during_call",
        "one_shot_or_process_exit",
        "until_replaced_or_process_exit",
        "until_resource_event_or_process_exit",
    }:
        raise ToolkitInputError(
            f"native callback capability lifetime {raw_kind!r} is unsupported"
        )
    return kind


def _wrapper_header() -> str:
    return """#ifndef SPX_NATIVE_ENGINE_WRAPPER_H
#define SPX_NATIVE_ENGINE_WRAPPER_H

#include <stddef.h>
#include "state-machine-runtime.h"

/* Intel 32-bit protected-mode FNSAVE/FRSTOR image.  The register array is
 * physical R0..R7 and tag_word is the complete architectural tag word. */
typedef struct __attribute__((packed, aligned(4))) spx_x87_fnsave_image {
  uint16_t control_word, reserved_02;
  uint16_t status_word, reserved_06;
  uint16_t tag_word, reserved_0a;
  uint32_t instruction_pointer;
  uint16_t code_selector, last_opcode;
  uint32_t data_pointer;
  uint16_t data_selector, reserved_1a;
  uint8_t physical_registers[8][10];
} spx_x87_fnsave_image;

typedef struct spx_native_bridge_frame {
  struct spx_native_bridge_frame *parent;
  const spx_machine_state *input;
  spx_machine_state *output;
  uint32_t private_esp;
  uint32_t call_target;
  spx_call_status status;
  uint32_t saved_continuation;
  uint32_t continuation_replaced;
  spx_x87_fnsave_image input_x87;
  spx_x87_fnsave_image output_x87;
} spx_native_bridge_frame;

typedef struct spx_native_x87_frame {
  struct spx_native_x87_frame *parent;
  const spx_machine_state *input;
  spx_machine_state *output;
  uint32_t private_esp;
  spx_call_status status;
  spx_x87_fnsave_image input_x87;
  spx_x87_fnsave_image output_x87;
} spx_native_x87_frame;

extern volatile uint32_t spx_native_diagnostic_reason;
extern volatile uint32_t spx_native_diagnostic_value;
extern volatile uint32_t spx_native_diagnostic_aux;
extern volatile uint32_t spx_native_diagnostic_detail;
extern spx_runtime spx_native_runtime_instance;

spx_call_status spx_native_runtime_run_at_rva(
    uint32_t entry_rva, const spx_machine_state *input,
    spx_machine_state *output);
spx_call_status spx_native_runtime_capture_external_call(
    const spx_call_event *event, const spx_machine_state *input,
    spx_external_call_snapshot *snapshot);
spx_call_status spx_native_runtime_record_external_result(
    const spx_call_event *event,
    const spx_external_call_snapshot *snapshot,
    const spx_machine_state *output);
#endif
"""


def _wrapper_source(
    plan: NativeEnginePlan,
    native_ingress_plan: dict,
) -> str:
    declarations = ["extern void spx_native_bridge(void);"]
    callback_declarations: list[str] = []
    ingress_callback_symbols = {
        int(row["target_rva"]): str(row["bridge_symbol"])
        for row in (native_ingress_plan or {}).get("ingresses", [])
        if isinstance(row, dict) and row.get("role") == "callback"
    }
    ingress_capability_ids = sorted({
        str(row["capability_id"])
        for row in (native_ingress_plan or {}).get("ingresses", [])
        if isinstance(row, dict) and row.get("capability_id") is not None
    })
    ingress_capability_index = {
        identity: index for index, identity in enumerate(ingress_capability_ids)
    }
    callback_capability_indexes = {
        int(row["target_rva"]): ingress_capability_index[str(row["capability_id"])]
        for row in (native_ingress_plan or {}).get("ingresses", [])
        if isinstance(row, dict) and row.get("role") == "callback"
    }
    callback_lifetimes = {
        (registration.instruction_rva, registration.logical_target_rva): (
            _native_callback_lifetime_kind(registration.lifetime)
        )
        for registration in plan.code_capability_registrations
    }
    missing_callback_ingresses = sorted({
        binding.code_target_rva for binding in plan.code_capability_bindings
        if binding.code_target_rva not in ingress_callback_symbols
    })
    if missing_callback_ingresses:
        raise ToolkitInputError(
            "native ingress plan lacks callback capabilities for "
            + ", ".join(f"0x{rva:08x}" for rva in missing_callback_ingresses)
        )
    callback_declarations.extend(
        f"extern void {symbol}(void);"
        for symbol in sorted(set(ingress_callback_symbols.values()))
    )
    x87_declarations = [
        f"extern void spx_native_x87_bridge_{operation.id:04d}(void);"
        for operation in plan.x87_operations
    ]
    table = [
        (
            f"  {{ 0x{site.instruction_rva:08x}U, "
            f"0x{(site.iat_va or 0):08x}U, "
            f"{1 if site.site_kind != 'direct_import' else 0}U, "
            f"{1 if site.disposition == 'tail_jump' else 0}U, "
            f"{2 if site.callback_source_kind == 'argument_pointee' else 1 if site.callback_argument_offset is not None else 0}U, "
            f"{site.callback_argument_index or 0}U, "
            f"{site.callback_argument_offset or 0}U, "
            f"{site.callback_pointee_offset}U, "
            f"{1 if site.callback_nullable else 0}U }},"
        )
        for site in plan.external_sites
    ]
    state_assertions = [
        f'_Static_assert(offsetof(spx_machine_state, {field}) == {offset}U, '
        f'"assembly offset for {field} is stale");'
        for field, offset in _STATE_OFFSETS.items()
        if field != "x87_stack"
    ]
    state_assertions.extend([
        f'_Static_assert(offsetof(spx_machine_state, x87_stack) == '
        f'{_STATE_OFFSETS["x87_stack"]}U, '
        '"assembly offset for x87_stack is stale");',
        f'_Static_assert(sizeof(spx_x87_value) == {_X87_VALUE_SIZE}U, '
        '"assembly x87-value stride is stale");',
        f'_Static_assert(offsetof(spx_x87_value, empty) == '
        f'{_X87_VALUE_EMPTY_OFFSET}U, '
        '"assembly x87 empty offset is stale");',
        f'_Static_assert(offsetof(spx_x87_value, tag) == '
        f'{_X87_VALUE_TAG_OFFSET}U, '
        '"assembly x87 tag offset is stale");',
    ])
    frame_assertions = [
        f'_Static_assert(offsetof(spx_native_bridge_frame, {field}) == {offset}U, '
        f'"assembly bridge-frame offset for {field} is stale");'
        for field, offset in _FRAME_OFFSETS.items()
    ]
    x87_frame_assertions = [
        f'_Static_assert(offsetof(spx_native_x87_frame, {field}) == {offset}U, '
        f'"assembly x87-frame offset for {field} is stale");'
        for field, offset in _X87_FRAME_OFFSETS.items()
    ]
    code_capability_table = [
        (
            f"  {{ 0x{binding.instruction_rva:08x}U, "
            f"{binding.argument_index}U, 0x{binding.original_rva:08x}U, "
            f"{ingress_callback_symbols[binding.code_target_rva]}, "
            f"{callback_capability_indexes.get(binding.code_target_rva, 0xffffffff)}U, "
            f"{0 if callback_lifetimes.get((binding.instruction_rva, binding.original_rva)) == 'during_call' else 1}U }},"
        )
        for binding in plan.code_capability_bindings
    ]
    x87_table = [
        (
            f"  {{ 0x{operation.image_base:08x}U, 0x{operation.rva_start:08x}U, "
            f"0x{operation.rva_end:08x}U, {operation.operation.source_size}U, "
            f"{json.dumps(operation.operation.identity)}, "
            f"{json.dumps(operation.contract_sha256)}, "
            f"spx_native_x87_bridge_{operation.id:04d} }},"
        )
        for operation in plan.x87_operations
    ]
    bridge_dispatch = [
        "static void spx_native_dispatch_bridge(void) {",
        "  spx_native_bridge();",
        "}",
    ]
    thread_state = [
        '#include "native-ingress-runtime.h"',
        "typedef struct spx_native_engine_thread_state {",
        "  spx_native_bridge_frame *current_outgoing;",
        "  void *reserved;",
        "  spx_native_x87_frame *current_x87;",
        "} spx_native_engine_thread_state;",
        "static spx_native_engine_thread_state *spx_native_engine_thread_state_get(void) {",
        "  return (spx_native_engine_thread_state *)spx_native_engine_thread_state_current();",
        "}",
        "#define spx_native_current_outgoing (spx_native_engine_thread_state_get()->current_outgoing)",
        "#define spx_native_current_x87 (spx_native_engine_thread_state_get()->current_x87)",
        "#define spx_native_diagnostic_reason (*spx_native_runtime_diagnostic_slot(0U))",
        "#define spx_native_diagnostic_value (*spx_native_runtime_diagnostic_slot(1U))",
        "#define spx_native_diagnostic_aux (*spx_native_runtime_diagnostic_slot(2U))",
        "#define spx_native_diagnostic_detail (*spx_native_runtime_diagnostic_slot(3U))",
        '_Static_assert(sizeof(spx_native_engine_thread_state) == 12U, "PE TLS engine state ABI changed");',
    ]
    return "\n".join([
        '#include "native-engine-wrapper.h"',
        "",
        *declarations,
        *callback_declarations,
        *x87_declarations,
        "extern const unsigned char __ImageBase[];",
        "",
        *thread_state,
        "",
        *state_assertions,
        *frame_assertions,
        *x87_frame_assertions,
        f'_Static_assert(sizeof(spx_machine_state) == {_MACHINE_STATE_SIZE}U, '
        '"assembly machine-state size is stale");',
        f'_Static_assert(sizeof(spx_x87_fnsave_image) == {_FNSAVE_IMAGE_SIZE}U, '
        '"FNSAVE image must be 108 bytes in i686 mode");',
        '_Static_assert(offsetof(spx_x87_fnsave_image, control_word) == 0U, '
        '"FNSAVE control offset changed");',
        '_Static_assert(offsetof(spx_x87_fnsave_image, status_word) == 4U, '
        '"FNSAVE status offset changed");',
        '_Static_assert(offsetof(spx_x87_fnsave_image, tag_word) == 8U, '
        '"FNSAVE tag offset changed");',
        '_Static_assert(offsetof(spx_x87_fnsave_image, physical_registers) == 28U, '
        '"FNSAVE physical-register offset changed");',
        '_Static_assert(SPX_CALL_OK == 0, "assembly status encoding is stale");',
        "",
        "typedef void (*spx_native_assembly_fn)(void);",
        "typedef struct spx_native_bridge_entry {",
        "  uint32_t instruction_rva;",
        "  uint32_t iat_va;",
        "  uint32_t dynamic_target, tail_jump;",
        "  uint32_t callback_registration, callback_argument_index;",
        "  uint32_t callback_argument_offset, callback_pointee_offset;",
        "  uint32_t callback_nullable;",
        "} spx_native_bridge_entry;",
        "typedef struct spx_native_code_capability {",
        "  uint32_t instruction_rva, argument_index, original_rva;",
        "  spx_native_assembly_fn bridge;",
        "  uint32_t capability_index, escaped;",
        "} spx_native_code_capability;",
        "typedef struct spx_native_x87_entry {",
        "  uint32_t image_base, rva_start, rva_end, source_size;",
        "  const char *operation_identity, *contract_sha256;",
        "  spx_native_assembly_fn bridge;",
        "} spx_native_x87_entry;",
        "",
        "static const spx_native_bridge_entry spx_native_bridges[] = {",
        *table,
        "};",
        f"static const uint32_t spx_native_bridge_count = {len(table)}U;",
        "",
        "static const spx_native_code_capability spx_native_code_capabilities[] = {",
        *code_capability_table,
        "};",
        f"static const uint32_t spx_native_code_capability_count = {len(code_capability_table)}U;",
        "",
        "static const spx_native_x87_entry spx_native_x87_entries[] = {",
        *x87_table,
        "};",
        f"static const uint32_t spx_native_x87_count = {len(x87_table)}U;",
        "",
        "static const spx_native_bridge_entry *spx_native_bridge_entry_for(",
        "    uint32_t instruction_rva) {",
        "  uint32_t i;",
        "  for (i = 0; i < spx_native_bridge_count; ++i)",
        "    if (spx_native_bridges[i].instruction_rva == instruction_rva)",
        "      return &spx_native_bridges[i];",
        "  return (const spx_native_bridge_entry *)0;",
        "}",
        "",
        "static const spx_native_code_capability *",
        "spx_native_code_capability_for(",
        "    uint32_t instruction_rva, uint32_t argument_index,",
        "    uint32_t observed_target) {",
        "  const uint32_t image_base = (uint32_t)(uintptr_t)&__ImageBase;",
        "  uint32_t i;",
        "  for (i = 0; i < spx_native_code_capability_count; ++i) {",
        "    const spx_native_code_capability *capability =",
        "        &spx_native_code_capabilities[i];",
        "    if (capability->instruction_rva == instruction_rva &&",
        "        capability->argument_index == argument_index &&",
        "        image_base + capability->original_rva == observed_target)",
        "      return capability;",
        "  }",
        "  return (const spx_native_code_capability *)0;",
        "}",
        "",
        "static __attribute__((unused)) const spx_native_x87_entry *",
        "spx_native_x87_entry_for(",
        "    uint32_t rva) {",
        "  uint32_t i;",
        "  for (i = 0; i < spx_native_x87_count; ++i)",
        "    if (spx_native_x87_entries[i].rva_start == rva)",
        "      return &spx_native_x87_entries[i];",
        "  return (const spx_native_x87_entry *)0;",
        "}",
        "",
        *bridge_dispatch,
        "",
        "static __attribute__((unused)) uint32_t spx_native_bytes_equal(",
        "    const uint8_t *left, const uint8_t *right, uint32_t count) {",
        "  uint32_t i;",
        "  if (left == 0 || right == 0) return 0U;",
        "  for (i = 0; i < count; ++i) if (left[i] != right[i]) return 0U;",
        "  return 1U;",
        "}",
        "",
        "static __attribute__((unused)) uint32_t spx_native_string_equal(",
        "    const char *left, const char *right) {",
        "  if (left == 0 || right == 0) return 0U;",
        "  while (*left != '\\0' && *right != '\\0')",
        "    if (*left++ != *right++) return 0U;",
        "  return *left == *right;",
        "}",
        "",
        "static uint32_t spx_native_fixed_flat_read_u32(",
        "    uint32_t address, uint32_t *value) {",
        "  const volatile uint8_t *bytes;",
        "  if (value == 0 || address > 0xffffffffU - 3U) return 0U;",
        "  bytes = (const volatile uint8_t *)(uintptr_t)address;",
        "  *value = (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U) |",
        "      ((uint32_t)bytes[2] << 16U) | ((uint32_t)bytes[3] << 24U);",
        "  return 1U;",
        "}",
        "",
        "static uint32_t spx_native_fixed_flat_write_u32(",
        "    uint32_t address, uint32_t value) {",
        "  volatile uint8_t *bytes;",
        "  if (address > 0xffffffffU - 3U) return 0U;",
        "  bytes = (volatile uint8_t *)(uintptr_t)address;",
        "  bytes[0] = (uint8_t)value;",
        "  bytes[1] = (uint8_t)(value >> 8U);",
        "  bytes[2] = (uint8_t)(value >> 16U);",
        "  bytes[3] = (uint8_t)(value >> 24U);",
        "  return 1U;",
        "}",
        "",
        "static __attribute__((unused)) uint32_t spx_native_state_to_fnsave(",
        "    const spx_machine_state *state, spx_x87_fnsave_image *image) {",
        "  uint32_t i, j, top; uint16_t tags = 0U;",
        "  if (state == 0 || image == 0 || state->x87_last_opcode > 0x7ffU)",
        "    return 1U;",
        "  top = (state->x87_status >> 11U) & 7U;",
        "  if (((state->x87_status >> 7) & 1U) !=",
        "      (uint32_t)(state->x87_pending_exception & 1U)) return 1U;",
        "  for (i = 0; i < 8U; ++i) {",
        "    const uint32_t physical = (top + i) & 7U;",
        "    const uint32_t tag = state->x87_stack[i].tag;",
        "    const uint32_t empty = state->x87_stack[i].empty;",
        "    if (tag > 3U || empty > 1U || ((tag == 3U) != (empty != 0U)))",
        "      return 1U;",
        "    tags = (uint16_t)(tags | (uint16_t)(tag << (2U * physical)));",
        "  }",
        "  for (i = 0; i < sizeof(*image); ++i) ((uint8_t *)image)[i] = 0U;",
        "  image->control_word = state->x87_control;",
        "  image->status_word = state->x87_status;",
        "  image->tag_word = tags;",
        "  image->instruction_pointer = state->x87_instruction_pointer;",
        "  image->code_selector = state->x87_code_selector;",
        "  image->last_opcode = state->x87_last_opcode;",
        "  image->data_pointer = state->x87_data_pointer;",
        "  image->data_selector = state->x87_data_selector;",
        "  for (i = 0; i < 8U; ++i) for (j = 0; j < 10U; ++j)",
        "    image->physical_registers[(top + i) & 7U][j] =",
        "      state->x87_stack[i].value_bytes[j];",
        "  return 0U;",
        "}",
        "",
        "static __attribute__((unused)) uint32_t spx_native_fnsave_to_state(",
        "    const spx_x87_fnsave_image *image, spx_machine_state *state) {",
        "  uint32_t i, j, top;",
        "  if (image == 0 || state == 0 || image->last_opcode > 0x7ffU) return 1U;",
        "  top = (image->status_word >> 11U) & 7U;",
        "  state->x87_control = image->control_word;",
        "  state->x87_status = image->status_word;",
        "  state->x87_pending_exception = (uint8_t)((image->status_word >> 7) & 1U);",
        "  state->x87_last_opcode = image->last_opcode;",
        "  state->x87_instruction_pointer = image->instruction_pointer;",
        "  state->x87_code_selector = image->code_selector;",
        "  state->x87_data_pointer = image->data_pointer;",
        "  state->x87_data_selector = image->data_selector;",
        "  for (i = 0; i < 8U; ++i) {",
        "    const uint32_t physical = (top + i) & 7U;",
        "    const uint8_t tag =",
        "      (uint8_t)((image->tag_word >> (2U * physical)) & 3U);",
        "    state->x87_stack[i].tag = tag;",
        "    state->x87_stack[i].empty = tag == 3U ? 1U : 0U;",
        "    for (j = 0; j < 10U; ++j)",
        "      state->x87_stack[i].value_bytes[j] =",
        "        image->physical_registers[physical][j];",
        "  }",
        "  return 0U;",
        "}",
        "",
        "static void spx_native_pack_flags(spx_machine_state *state) {",
        "  /* The supported machine model carries exactly these six flags.",
        "   * Do not replay unmodeled control bits such as TF, NT, RF, or VM. */",
        "  state->eflags = 2U |",
        "      ((state->cf & 1U) << 0) | ((state->pf & 1U) << 2) |",
        "      ((state->zf & 1U) << 6) | ((state->sf & 1U) << 7) |",
        "      ((state->df & 1U) << 10) | ((state->of & 1U) << 11);",
        "}",
        "",
        "static uint32_t spx_native_original_iat_target(uint32_t iat_va) {",
        "  const uint32_t image_base = (uint32_t)(uintptr_t)&__ImageBase;",
        "  uint32_t nt_offset, preferred_base, iat_address;",
        "  if (image_base == 0U ||",
        "      *(volatile const uint16_t *)(uintptr_t)image_base != 0x5a4dU)",
        "    return 0U;",
        "  nt_offset = *(volatile const uint32_t *)(uintptr_t)(image_base + 0x3cU);",
        "  if (nt_offset > 0x100000U ||",
        "      *(volatile const uint32_t *)(uintptr_t)(image_base + nt_offset) !=",
        "          0x00004550U ||",
        "      *(volatile const uint16_t *)(uintptr_t)(image_base + nt_offset + 0x18U) !=",
        "          0x010bU)",
        "    return 0U;",
        "  preferred_base = *(volatile const uint32_t *)(uintptr_t)(",
        "      image_base + nt_offset + 0x34U);",
        "  iat_address = iat_va + (image_base - preferred_base);",
        "  return *(volatile const uint32_t *)(uintptr_t)iat_address;",
        "}",
        "",
        *(
            _x87_handler_source_lines()
            if plan.x87_operations
            else []
        ),
        "spx_call_status spx_dispatch_external_call(",
        "    spx_runtime *runtime,",
        "    const spx_call_event *event,",
        "    const spx_machine_state *input,",
        "    spx_machine_state *output) {",
        "  spx_native_bridge_frame frame;",
        "  spx_external_call_snapshot external_snapshot;",
        "  const spx_native_bridge_entry *entry;",
        "  const spx_native_code_capability *code_capability = 0;",
        "  uint32_t callback_argument_address = 0U;",
        "  uint32_t callback_container_address = 0U;",
        "  uint32_t callback_argument_original = 0U;",
        "  uint32_t callback_argument_patched = 0U;",
        "  uint32_t callback_capability_generation = 0U;",
        "  uint32_t preserved_ebx, preserved_esi, preserved_edi, preserved_ebp;",
        "  if (runtime != &spx_native_runtime_instance ||",
        "      event == 0 || input == 0 || output == 0)",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  spx_native_diagnostic_reason = 0U;",
        "  spx_native_diagnostic_value = 0U;",
        "  spx_native_diagnostic_aux = 0U;",
        "  spx_native_diagnostic_detail = 0U;",
        "  entry = spx_native_bridge_entry_for(event->instruction_rva);",
        "  if (entry == 0) return SPX_CALL_UNIMPLEMENTED;",
        "  if ((entry->dynamic_target && event->kind != SPX_CALL_INDIRECT) ||",
        "      (!entry->dynamic_target && event->kind != SPX_CALL_EXTERNAL_IMPORT))",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  if (entry->dynamic_target != 0U && entry->iat_va != 0U &&",
        "      event->target_rva != spx_native_original_iat_target(entry->iat_va)) {",
        "    spx_native_diagnostic_reason = 0x1003U;",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  }",
        "  preserved_ebx = input->ebx;",
        "  preserved_esi = input->esi;",
        "  preserved_edi = input->edi;",
        "  preserved_ebp = input->ebp;",
        "  if (spx_native_runtime_capture_external_call(",
        "          event, input, &external_snapshot) != SPX_CALL_OK)",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  if (input->df != 0U) {",
        "    spx_native_diagnostic_reason = 0x1006U;",
        "    spx_native_diagnostic_value = input->df;",
        "    spx_native_diagnostic_aux = event->instruction_rva;",
        "    spx_native_diagnostic_detail = event->target_rva;",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  }",
        "  frame.parent = spx_native_current_outgoing;",
        "  frame.output = output;",
        "  frame.private_esp = 0U;",
        "  frame.call_target = entry->dynamic_target",
        "      ? event->target_rva : spx_native_original_iat_target(entry->iat_va);",
        "  frame.status = SPX_CALL_UNIMPLEMENTED;",
        "  frame.saved_continuation = 0U;",
        "  frame.continuation_replaced = entry->tail_jump != 0U;",
        "  if (frame.call_target == 0U) return SPX_CALL_UNIMPLEMENTED;",
        "  if (entry->tail_jump != 0U) {",
        "    if (runtime->context == 0)",
        "      return SPX_CALL_UNIMPLEMENTED;",
        "    if (spx_native_fixed_flat_read_u32(",
        "            input->esp, &frame.saved_continuation) == 0U ||",
        "        frame.saved_continuation == 0U)",
        "      return SPX_CALL_MEMORY_FAULT;",
        "  }",
        "  if (entry->callback_registration != 0U) {",
        "    if (input->esp > 0xffffffffU - entry->callback_argument_offset)",
        "      return SPX_CALL_MEMORY_FAULT;",
        "    callback_argument_address =",
        "        input->esp + entry->callback_argument_offset;",
        "    if (entry->callback_registration == 2U) {",
        "      if (spx_native_fixed_flat_read_u32(",
        "              callback_argument_address,",
        "              &callback_container_address) == 0U ||",
        "          callback_container_address == 0U ||",
        "          callback_container_address >",
        "              0xffffffffU - entry->callback_pointee_offset)",
        "        return SPX_CALL_MEMORY_FAULT;",
        "      callback_argument_address =",
        "          callback_container_address + entry->callback_pointee_offset;",
        "    } else if (entry->callback_registration != 1U) {",
        "      return SPX_CALL_UNIMPLEMENTED;",
        "    }",
        "    if (spx_native_fixed_flat_read_u32(",
        "            callback_argument_address, &callback_argument_original) == 0U)",
        "      return SPX_CALL_MEMORY_FAULT;",
        "    if (callback_argument_original == 0U) {",
        "      if (entry->callback_nullable == 0U)",
        "        return SPX_CALL_UNIMPLEMENTED;",
        "    } else {",
        "      code_capability = spx_native_code_capability_for(",
        "          entry->instruction_rva, entry->callback_argument_index,",
        "          callback_argument_original);",
        "      if (code_capability == 0)",
        "        return SPX_CALL_UNIMPLEMENTED;",
        "      if (code_capability->capability_index != 0xffffffffU) {",
        "        callback_capability_generation = spx_native_capability_activate(",
        "            code_capability->capability_index, code_capability->escaped);",
        "        if (callback_capability_generation == 0U)",
        "          return SPX_CALL_UNIMPLEMENTED;",
        "      }",
        "      if (spx_native_fixed_flat_write_u32(",
        "              callback_argument_address,",
        "              (uint32_t)(uintptr_t)code_capability->bridge) == 0U)",
        "        return SPX_CALL_MEMORY_FAULT;",
        "      callback_argument_patched = 1U;",
        "    }",
        "  }",
        "  *output = *input;",
        "  spx_native_pack_flags(output);",
        *(
            [
                "  if (spx_native_state_to_fnsave(input, &frame.input_x87) != 0U)",
                "    return SPX_CALL_UNIMPLEMENTED;",
            ]
            if plan.x87_operations
            else []
        ),
        "  frame.input = output;",
        "  spx_native_current_outgoing = &frame;",
        "  spx_native_dispatch_bridge();",
        "  if (callback_argument_patched != 0U &&",
        "      spx_native_fixed_flat_write_u32(",
        "          callback_argument_address, callback_argument_original) == 0U)",
        "    frame.status = SPX_CALL_MEMORY_FAULT;",
        "  if (spx_native_current_outgoing != &frame)",
        "    frame.status = SPX_CALL_UNIMPLEMENTED;",
        "  spx_native_current_outgoing = frame.parent;",
        "  if (callback_capability_generation != 0U &&",
        "      code_capability != 0 && code_capability->escaped == 0U &&",
        "      spx_native_capability_revoke(code_capability->capability_index,",
        "          callback_capability_generation) == 0U)",
        "    frame.status = SPX_CALL_UNIMPLEMENTED;",
        "  if (entry->tail_jump != 0U && frame.continuation_replaced != 0U)",
        "    frame.status = SPX_CALL_UNIMPLEMENTED;",
        "  if (frame.status == SPX_CALL_OK && entry->iat_va != 0U &&",
        "      (output->ebx != preserved_ebx || output->esi != preserved_esi ||",
        "       output->edi != preserved_edi || output->ebp != preserved_ebp)) {",
        "    spx_native_diagnostic_reason = 0x1005U;",
        "    frame.status = SPX_CALL_UNIMPLEMENTED;",
        "  }",
        "  if (frame.status == SPX_CALL_OK) {",
        "    output->df = 0U;",
        "    output->eflags &= ~(1U << 10);",
        "  }",
        *(
            [
                "  if (frame.status == SPX_CALL_OK &&",
                "      spx_native_fnsave_to_state(&frame.output_x87, output) != 0U)",
                "    frame.status = SPX_CALL_UNIMPLEMENTED;",
            ]
            if plan.x87_operations
            else []
        ),
        "  if (frame.status == SPX_CALL_OK)",
        "    frame.status = spx_native_runtime_record_external_result(",
        "        event, &external_snapshot, output);",
        "  return frame.status;",
        "}",
        "",
    ])


def _x87_handler_source_lines() -> list[str]:
    return [
        "spx_call_status spx_native_execute_typed_x87_operation(",
        "    spx_runtime *runtime, const spx_typed_x87_operation *program,",
        "    const spx_machine_state *input, spx_machine_state *output) {",
        "  const spx_native_x87_entry *entry;",
        "  spx_native_x87_frame frame;",
        "  if (runtime != &spx_native_runtime_instance || program == 0 ||",
        "      input == 0 || output == 0)",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  entry = spx_native_x87_entry_for(program->rva_start);",
        "  if (entry == 0 || entry->image_base != program->image_base ||",
        "      entry->rva_end != program->rva_end ||",
        "      entry->source_size != program->source_size ||",
        "      !spx_native_string_equal(entry->operation_identity,",
        "          program->operation_identity) ||",
        "      !spx_native_string_equal(entry->contract_sha256,",
        "          program->contract_sha256) ||",
        f"      !spx_native_string_equal(program->checked_decoder, {json.dumps(_X87_CHECKED_DECODER)}) ||",
        f"      !spx_native_string_equal(program->checked_executor, {json.dumps(_X87_CHECKED_EXECUTOR)}))",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  frame.parent = spx_native_current_x87;",
        "  frame.input = output;",
        "  frame.output = output;",
        "  frame.private_esp = 0U;",
        "  frame.status = SPX_CALL_UNIMPLEMENTED;",
        "  *output = *input;",
        "  spx_native_pack_flags(output);",
        "  if (spx_native_state_to_fnsave(input, &frame.input_x87) != 0U)",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  spx_native_current_x87 = &frame;",
        "  entry->bridge();",
        "  if (spx_native_current_x87 != &frame)",
        "    frame.status = SPX_CALL_UNIMPLEMENTED;",
        "  spx_native_current_x87 = frame.parent;",
        "  if (frame.status == SPX_CALL_OK &&",
        "      spx_native_fnsave_to_state(&frame.output_x87, output) != 0U)",
        "    frame.status = SPX_CALL_UNIMPLEMENTED;",
        "  return frame.status;",
        "}",
        "",
    ]


def _bridge_assembly(plan: NativeEnginePlan) -> str:
    termination_iat = (
        f"0x{plan.termination_import.iat_va:08x}"
        if plan.termination_import is not None
        else None
    )
    lines = [
        "    .intel_syntax noprefix",
        "    .text",
        "",
        "    .extern _spx_native_outgoing_frame_current",
        "    .extern _spx_native_x87_frame_current",
        "_spx_native_halt:",
        "    .globl _spx_native_termination",
        "_spx_native_termination:",
        *(
            [
                "    push eax",
                "    push 0",
                f"    jmp DWORD PTR ds:{termination_iat}",
            ]
            if termination_iat is not None
            else [
                "    ud2",
                "    jmp _spx_native_halt",
            ]
        ),
        "",
        "    .globl _spx_native_terminate",
        "_spx_native_terminate:",
        *(
            [f"    jmp DWORD PTR ds:{termination_iat}"]
            if termination_iat is not None
            else [
                "    ud2",
                "    jmp _spx_native_terminate",
            ]
        ),
        "",
        "/* The data-driven bridge preserves its private C frame, restores the",
        " * complete logical ABI state, enters the checked target with CALL stack",
        " * semantics, captures the result, and resumes C dispatch. */",
        "    .globl _spx_native_bridge",
        "_spx_native_bridge:",
        "    push ebp",
        "    push ebx",
        "    push esi",
        "    push edi",
        "    call _spx_native_outgoing_frame_current",
        "    test eax, eax",
        "    je _spx_native_bridge_unavailable",
        f"    mov DWORD PTR [eax + {_FRAME_OFFSETS['private_esp']}], esp",
        f"    mov ecx, DWORD PTR [eax + {_FRAME_OFFSETS['input']}]",
        f"    mov edx, DWORD PTR [eax + {_FRAME_OFFSETS['call_target']}]",
        *(
            [f"    frstor [eax + {_FRAME_OFFSETS['input_x87']}]" ]
            if plan.x87_operations
            else []
        ),
        f"    mov esp, DWORD PTR [ecx + {_STATE_OFFSETS['esp']}]",
        f"    cmp DWORD PTR [eax + {_FRAME_OFFSETS['continuation_replaced']}], 0",
        "    jne _spx_native_bridge_tail",
        "    sub esp, 8",
        "    mov DWORD PTR [esp], edx",
        "    mov DWORD PTR [esp + 4], OFFSET FLAT:_spx_native_capture",
        "    jmp _spx_native_bridge_restore",
        "_spx_native_bridge_tail:",
        "    mov ebx, DWORD PTR [esp]",
        f"    cmp ebx, DWORD PTR [eax + {_FRAME_OFFSETS['saved_continuation']}]",
        "    jne _spx_native_bridge_tail_unavailable",
        "    mov DWORD PTR [esp], OFFSET FLAT:_spx_native_capture",
        "    sub esp, 4",
        "    mov DWORD PTR [esp], edx",
        "_spx_native_bridge_restore:",
        *_restore_pushes("ecx"),
        "    popad",
        "    popfd",
        "    ret",
        "_spx_native_bridge_tail_unavailable:",
        f"    mov esp, DWORD PTR [eax + {_FRAME_OFFSETS['private_esp']}]",
        "_spx_native_bridge_unavailable:",
        "    pop edi",
        "    pop esi",
        "    pop ebx",
        "    pop ebp",
        "    ret",
        "",
        "    .globl _spx_native_capture",
        "_spx_native_capture:",
        "    pushfd",
        "    pushad",
        "    call _spx_native_outgoing_frame_current",
        "    test eax, eax",
        "    je _spx_native_halt",
        *(
            [f"    fnsave [eax + {_FRAME_OFFSETS['output_x87']}]" ]
            if plan.x87_operations
            else []
        ),
        f"    mov edx, DWORD PTR [eax + {_FRAME_OFFSETS['output']}]",
        *_capture_pushad_registers("edx"),
        f"    cmp DWORD PTR [eax + {_FRAME_OFFSETS['continuation_replaced']}], 0",
        "    je _spx_native_capture_continuation_ready",
        f"    mov ebx, DWORD PTR [eax + {_FRAME_OFFSETS['saved_continuation']}]",
        "    mov DWORD PTR [ecx - 4], ebx",
        f"    mov DWORD PTR [eax + {_FRAME_OFFSETS['continuation_replaced']}], 0",
        "_spx_native_capture_continuation_ready:",
        f"    mov DWORD PTR [edx + {_STATE_OFFSETS['esp']}], ecx",
        "    mov ecx, DWORD PTR [esp + 32]",
        f"    mov DWORD PTR [edx + {_STATE_OFFSETS['eflags']}], ecx",
        *_capture_split_flags("edx"),
        f"    cmp DWORD PTR [eax + {_FRAME_OFFSETS['call_target']}], 0",
        "    je _spx_native_capture_preserve_status",
        f"    mov DWORD PTR [eax + {_FRAME_OFFSETS['status']}], 0",
        "_spx_native_capture_preserve_status:",
        f"    mov esp, DWORD PTR [eax + {_FRAME_OFFSETS['private_esp']}]",
        "    cld",
        "    pop edi",
        "    pop esi",
        "    pop ebx",
        "    pop ebp",
        "    ret",
    ]
    if plan.x87_operations:
        lines.extend([
            "",
            "/* Typed x87 operations use reviewed mnemonic and operand rendering. */",
        ])
    for replay in plan.x87_operations:
        lines.extend([
            "",
            f"    .globl _spx_native_x87_bridge_{replay.id:04d}",
            f"_spx_native_x87_bridge_{replay.id:04d}:",
            "    push ebp",
            "    push ebx",
            "    push esi",
            "    push edi",
            "    call _spx_native_x87_frame_current",
            f"    mov DWORD PTR [eax + {_X87_FRAME_OFFSETS['private_esp']}], esp",
            f"    frstor [eax + {_X87_FRAME_OFFSETS['input_x87']}]",
            f"    mov eax, DWORD PTR [eax + {_X87_FRAME_OFFSETS['input']}]",
            f"    mov ebx, DWORD PTR [eax + {_STATE_OFFSETS['ebx']}]",
            f"    mov ecx, DWORD PTR [eax + {_STATE_OFFSETS['ecx']}]",
            f"    mov esi, DWORD PTR [eax + {_STATE_OFFSETS['esi']}]",
            f"    mov edi, DWORD PTR [eax + {_STATE_OFFSETS['edi']}]",
            f"    mov ebp, DWORD PTR [eax + {_STATE_OFFSETS['ebp']}]",
            f"    mov esp, DWORD PTR [eax + {_STATE_OFFSETS['esp']}]",
            f"    push DWORD PTR [eax + {_STATE_OFFSETS['eflags']}]",
            f"    push DWORD PTR [eax + {_STATE_OFFSETS['eax']}]",
            f"    mov edx, DWORD PTR [eax + {_STATE_OFFSETS['edx']}]",
            "    pop eax",
            "    popfd",
            f"    .if (. - _spx_native_x87_bridge_{replay.id:04d}) "
            f"> {_X87_REPLAY_INLINE_INSTRUCTION_OFFSET}",
            '    .error "x87 replay prologue exceeds its fixed bridge slot"',
            "    .endif",
            f"    .fill {_X87_REPLAY_INLINE_INSTRUCTION_OFFSET} - "
            f"(. - _spx_native_x87_bridge_{replay.id:04d}), 1, 0x90",
            f"    .if (. - _spx_native_x87_bridge_{replay.id:04d}) "
            f"!= {_X87_REPLAY_INLINE_INSTRUCTION_OFFSET}",
            '    .error "x87 replay instruction offset changed"',
            "    .endif",
            f"    .globl _spx_native_x87_instruction_{replay.id:04d}",
            f"_spx_native_x87_instruction_{replay.id:04d}:",
            f"    {_render_typed_x87_instruction(replay)}",
            f"    .if (. - _spx_native_x87_bridge_{replay.id:04d}) "
            f"> {_X87_REPLAY_INLINE_CAPTURE_OFFSET}",
            '    .error "x87 replay instruction exceeds its fixed bridge slot"',
            "    .endif",
            f"    .fill {_X87_REPLAY_INLINE_CAPTURE_OFFSET} - "
            f"(. - _spx_native_x87_bridge_{replay.id:04d}), 1, 0x90",
            f"    .if (. - _spx_native_x87_bridge_{replay.id:04d}) "
            f"!= {_X87_REPLAY_INLINE_CAPTURE_OFFSET}",
            '    .error "x87 replay capture offset changed"',
            "    .endif",
            f"_spx_native_x87_capture_{replay.id:04d}:",
            "    pushfd",
            "    push eax",
            "    call _spx_native_x87_frame_current",
            f"    fnsave [eax + {_X87_FRAME_OFFSETS['output_x87']}]",
            f"    mov edx, DWORD PTR [eax + {_X87_FRAME_OFFSETS['output']}]",
            "    mov ecx, DWORD PTR [esp]",
            f"    mov DWORD PTR [edx + {_STATE_OFFSETS['eax']}], ecx",
            f"    setc BYTE PTR [edx + {_STATE_OFFSETS['cf']}]",
            f"    setp BYTE PTR [edx + {_STATE_OFFSETS['pf']}]",
            f"    setz BYTE PTR [edx + {_STATE_OFFSETS['zf']}]",
            f"    sets BYTE PTR [edx + {_STATE_OFFSETS['sf']}]",
            f"    seto BYTE PTR [edx + {_STATE_OFFSETS['of']}]",
            "    mov ebx, DWORD PTR [esp + 4]",
            f"    mov ecx, DWORD PTR [eax + {_X87_FRAME_OFFSETS['input']}]",
            f"    mov ecx, DWORD PTR [ecx + {_STATE_OFFSETS['eflags']}]",
            "    and ecx, 0xfffff32a",
            "    and ebx, 0x00000cd5",
            "    or ecx, ebx",
            f"    mov DWORD PTR [edx + {_STATE_OFFSETS['eflags']}], ecx",
            f"    mov DWORD PTR [eax + {_X87_FRAME_OFFSETS['status']}], 0",
            f"    mov esp, DWORD PTR [eax + {_X87_FRAME_OFFSETS['private_esp']}]",
            "    cld",
            "    pop edi",
            "    pop esi",
            "    pop ebx",
            "    pop ebp",
            f"    .if (. - _spx_native_x87_bridge_{replay.id:04d}) "
            f"> {_X87_REPLAY_INLINE_RETURN_OFFSET}",
            '    .error "x87 replay capture exceeds its fixed bridge slot"',
            "    .endif",
            f"    .fill {_X87_REPLAY_INLINE_RETURN_OFFSET} - "
            f"(. - _spx_native_x87_bridge_{replay.id:04d}), 1, 0x90",
            f"    .if (. - _spx_native_x87_bridge_{replay.id:04d}) "
            f"!= {_X87_REPLAY_INLINE_RETURN_OFFSET}",
            '    .error "x87 replay return offset changed"',
            "    .endif",
            f"_spx_native_x87_return_{replay.id:04d}:",
            "    ret",
            f"    .fill {_X87_REPLAY_INLINE_BODY_SIZE} - "
            f"(. - _spx_native_x87_bridge_{replay.id:04d}), 1, 0x90",
            f"    .if (. - _spx_native_x87_bridge_{replay.id:04d}) "
            f"!= {_X87_REPLAY_INLINE_BODY_SIZE}",
            '    .error "x87 replay bridge size changed"',
            "    .endif",
        ])
    return "\n".join(lines).rstrip() + "\n"
