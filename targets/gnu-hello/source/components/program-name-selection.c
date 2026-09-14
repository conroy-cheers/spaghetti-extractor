#include "portable-component-implementation.h"

static int ref_is_null(spx_ref_v1 value) {
  return value.domain == UINT64_C(0) && value.object == UINT64_C(0) &&
         value.generation == UINT64_C(0) && value.offset == UINT64_C(0) &&
         value.extent == UINT64_C(0) && value.permissions == UINT32_C(0);
}

static int read_byte(
    const spx_view_v1 *value, uint64_t index, uint8_t expected) {
  uint8_t observed = 0U;
  return spx_view_read_u8(value, index, &observed) == SPX_REF_OK &&
         observed == expected;
}

void gnu_hello_program_name_selection(
    spx_program_name_selection_context_v2 *context,
    const spx_view_v1 *program,
    const spx_view_v1 *wrapper_prefix) {
  spx_ref_v1 selected;
  spx_ref_v1 separator;
  spx_ref_v1 basename;
  int64_t separator_offset = 0;

  SPX_PROOF_BEGIN(select);
  selected = program->base;
  separator = context->services->find_last_character(
      context->services->context, program, UINT8_C(47));
  if (ref_is_null(separator) ||
      spx_ref_difference(separator, program->base, &separator_offset) != SPX_REF_OK ||
      separator_offset < INT64_C(0) ||
      spx_ref_derive(separator, UINT64_C(1), UINT32_C(0), &basename) != SPX_REF_OK) {
    context->state.program_name = selected;
    return;
  }

  if (separator_offset >= INT64_C(6) &&
      separator_offset < INT64_C(2147483647)) {
    spx_ref_v1 prefix_start;
    spx_view_v1 candidate = *program;
    uint8_t prefix_equal;

    if (spx_ref_derive(
            program->base, (uint64_t)separator_offset - UINT64_C(6),
            UINT32_C(0), &prefix_start) == SPX_REF_OK) {
      candidate.base = prefix_start;
      candidate.extent = UINT64_C(7);
      prefix_equal = context->services->memory_equal(
          context->services->context, &candidate, wrapper_prefix, UINT32_C(7));
      if (prefix_equal != UINT8_C(0)) {
        selected = basename;
        if (read_byte(program, (uint64_t)separator_offset + UINT64_C(1), UINT8_C(108)) &&
            read_byte(program, (uint64_t)separator_offset + UINT64_C(2), UINT8_C(116)) &&
            read_byte(program, (uint64_t)separator_offset + UINT64_C(3), UINT8_C(45))) {
          (void)spx_ref_derive(
              separator, UINT64_C(4), UINT32_C(0), &selected);
        }
      }
    }
  }
  context->state.program_name = selected;
}
