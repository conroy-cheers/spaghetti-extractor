"""Static x87 and checked-unwind portion of the IA-32 ingress runtime."""

from __future__ import annotations


def native_x87_and_unwind_source_v1() -> str:
    return '''extern void spx_native_raise_exception_gateway(
    uint32_t code, uint32_t flags, uint32_t count,
    const uint32_t *parameters);

typedef struct __attribute__((packed, aligned(4))) spx_native_fnsave_image {
  uint16_t control_word, reserved_02;
  uint16_t status_word, reserved_06;
  uint16_t tag_word, reserved_0a;
  uint32_t instruction_pointer;
  uint16_t code_selector, last_opcode;
  uint32_t data_pointer;
  uint16_t data_selector, reserved_1a;
  uint8_t physical_registers[8][10];
} spx_native_fnsave_image;

static void spx_native_import_x87_parts(
    spx_machine_state *state, uint32_t mask,
    uint16_t control_word, uint16_t status_word, uint16_t tag_word,
    uint32_t instruction_pointer, uint16_t code_selector, uint16_t last_opcode,
    uint32_t data_pointer, uint16_t data_selector,
    const uint8_t physical_registers[8][10]) {
  uint32_t logical, byte_index;
  if ((mask & 0x01U) != 0U) state->x87_control = control_word;
  if ((mask & 0x02U) != 0U) {
    state->x87_status = status_word;
    state->x87_pending_exception = (uint8_t)((status_word >> 7U) & 1U);
  }
  if ((mask & 0x10U) != 0U)
    state->x87_instruction_pointer = instruction_pointer;
  if ((mask & 0x20U) != 0U) {
    state->x87_code_selector = code_selector;
    state->x87_last_opcode = last_opcode & 0x07ffU;
  }
  if ((mask & 0x40U) != 0U) state->x87_data_pointer = data_pointer;
  if ((mask & 0x80U) != 0U) state->x87_data_selector = data_selector;
  if ((mask & 0x0cU) == 0U) return;
  for (logical = 0U; logical < 8U; ++logical) {
    uint32_t physical = (((uint32_t)status_word >> 11U) + logical) & 7U;
    uint8_t tag = (uint8_t)((tag_word >> (physical * 2U)) & 3U);
    if ((mask & 0x04U) != 0U) {
      state->x87_stack[logical].tag = tag;
      state->x87_stack[logical].empty = tag == 3U ? 1U : 0U;
    }
    if ((mask & 0x08U) != 0U)
      for (byte_index = 0U; byte_index < 10U; ++byte_index)
        state->x87_stack[logical].value_bytes[byte_index] =
            physical_registers[logical][byte_index];
  }
}

static void spx_native_import_context_x87(
    spx_machine_state *state, const uint32_t *context, uint32_t mask) {
  const uint8_t (*registers)[10] =
      (const uint8_t (*)[10])(const void *)(context + 14U);
  spx_native_import_x87_parts(
      state, mask, (uint16_t)context[7], (uint16_t)context[8],
      (uint16_t)context[9], context[10], (uint16_t)context[11],
      (uint16_t)(context[11] >> 16U),
      context[12], (uint16_t)context[13], registers);
}

static void spx_native_capture_current_x87(
    spx_machine_state *state, uint32_t mask) {
  spx_native_fnsave_image image;
  __asm__ volatile ("fnsave %0\\n\\tfrstor %0" : "=m" (image));
  spx_native_import_x87_parts(
      state, mask, image.control_word, image.status_word, image.tag_word,
      image.instruction_pointer, image.code_selector, image.last_opcode,
      image.data_pointer, image.data_selector, image.physical_registers);
}

static void spx_native_restore_current_x87(const spx_machine_state *state) {
  spx_native_fnsave_image image;
  uint32_t logical, byte_index;
  if (state == 0) return;
  __asm__ volatile ("fnsave %0" : "=m" (image));
  image.control_word = state->x87_control;
  image.status_word = (uint16_t)((state->x87_status & ~(1U << 7U)) |
      ((uint16_t)(state->x87_pending_exception & 1U) << 7U));
  image.tag_word = 0U;
  image.instruction_pointer = state->x87_instruction_pointer;
  image.code_selector = state->x87_code_selector;
  image.last_opcode = state->x87_last_opcode & 0x07ffU;
  image.data_pointer = state->x87_data_pointer;
  image.data_selector = state->x87_data_selector;
  for (logical = 0U; logical < 8U; ++logical) {
    uint32_t physical = (((uint32_t)image.status_word >> 11U) + logical) & 7U;
    uint16_t tag = state->x87_stack[logical].empty != 0U
        ? 3U : (uint16_t)(state->x87_stack[logical].tag & 3U);
    image.tag_word |= (uint16_t)(tag << (physical * 2U));
    for (byte_index = 0U; byte_index < 10U; ++byte_index)
      image.physical_registers[logical][byte_index] =
          state->x87_stack[logical].value_bytes[byte_index];
  }
  __asm__ volatile ("frstor %0" : : "m" (image));
}

static spx_call_status spx_native_apply_checked_unwind(
    const spx_native_seh_descriptor *seh,
    spx_native_ingress_frame *frame) {
  uint32_t offset;
  spx_call_status status;
  if (seh == 0 || frame == 0 ||
      seh->unwind_first > spx_native_unwind_effect_count ||
      seh->unwind_count >
          spx_native_unwind_effect_count - seh->unwind_first)
    return SPX_CALL_UNIMPLEMENTED;
  for (offset = 0U; offset < seh->unwind_count; ++offset) {
    uint32_t rva = spx_native_unwind_effect_rvas[
        seh->unwind_first + offset];
    status = spx_native_runtime_run_at_rva(rva, frame->output, frame->output);
    if (status != SPX_CALL_OK) return status;
  }
  return SPX_CALL_OK;
}'''
