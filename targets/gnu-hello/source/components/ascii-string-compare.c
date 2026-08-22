#include "portable-component-inductive.h"

static int32_t gnu_hello_ascii_string_compare_difference(
    uint32_t left,
    uint32_t right) {
  uint32_t difference = left - right;

  if (difference <= UINT32_C(2147483647)) {
    return (int32_t)difference;
  }
  return (-2147483647 - 1) +
      (int32_t)(difference - UINT32_C(2147483648));
}

static spx_ascii_string_compare_compare_control_v1
gnu_hello_ascii_string_compare_scan(
    spx_ascii_string_compare_compare_state_v1 *state,
    spx_ascii_string_compare_context_v2 *context,
    const spx_bytes_view_v2 *left,
    const spx_bytes_view_v2 *right) {
  uint8_t left_byte = 0U;
  uint8_t right_byte = 0U;
  uint32_t left_lower;
  uint32_t right_lower;

  if (left->read_u8(left->context, state->offset, &left_byte) != 0U ||
      right->read_u8(right->context, state->offset, &right_byte) != 0U) {
    state->result = 0;
    return (spx_ascii_string_compare_compare_control_v1) {
      SPX_ASCII_STRING_COMPARE_COMPARE_CONTROL_COMPLETE,
      SPX_ASCII_STRING_COMPARE_COMPARE_PHASE_SCAN,
      SPX_ASCII_STRING_COMPARE_COMPARE_COMPLETION_RETURN
    };
  }

  left_lower = context->services->lower_ascii(
      context->services->context, (uint32_t)left_byte) & UINT32_C(255);
  right_lower = context->services->lower_ascii(
      context->services->context, (uint32_t)right_byte) & UINT32_C(255);
  if (left_lower == 0U || left_lower != right_lower) {
    state->result =
        gnu_hello_ascii_string_compare_difference(left_lower, right_lower);
    return (spx_ascii_string_compare_compare_control_v1) {
      SPX_ASCII_STRING_COMPARE_COMPARE_CONTROL_COMPLETE,
      SPX_ASCII_STRING_COMPARE_COMPARE_PHASE_SCAN,
      SPX_ASCII_STRING_COMPARE_COMPARE_COMPLETION_RETURN
    };
  }
  return (spx_ascii_string_compare_compare_control_v1) {
    SPX_ASCII_STRING_COMPARE_COMPARE_CONTROL_RUNNING,
    SPX_ASCII_STRING_COMPARE_COMPARE_PHASE_SCAN,
    SPX_ASCII_STRING_COMPARE_COMPARE_COMPLETION_RETURN
  };
}

spx_ascii_string_compare_compare_control_v1
gnu_hello_ascii_string_compare_initialize(
    spx_ascii_string_compare_compare_state_v1 *state,
    spx_ascii_string_compare_context_v2 *context,
    const spx_bytes_view_v2 *left,
    const spx_bytes_view_v2 *right) {
  state->offset = 0U;
  state->result = 0;
  return gnu_hello_ascii_string_compare_scan(state, context, left, right);
}

spx_ascii_string_compare_compare_control_v1
gnu_hello_ascii_string_compare_step(
    spx_ascii_string_compare_compare_state_v1 *state,
    uint32_t phase_id,
    spx_ascii_string_compare_context_v2 *context,
    const spx_bytes_view_v2 *left,
    const spx_bytes_view_v2 *right) {
  (void)phase_id;
  state->offset += 1U;
  return gnu_hello_ascii_string_compare_scan(state, context, left, right);
}

int32_t gnu_hello_ascii_string_compare_finish(
    const spx_ascii_string_compare_compare_state_v1 *state,
    uint32_t completion_id,
    spx_ascii_string_compare_context_v2 *context,
    const spx_bytes_view_v2 *left,
    const spx_bytes_view_v2 *right) {
  (void)completion_id;
  (void)context;
  (void)left;
  (void)right;
  return state->result;
}
