#include "portable-component-inductive.h"

spx_bounded_string_length_length_control_v1
gnu_hello_bounded_string_length_initialize(
    spx_bounded_string_length_length_state_v1 *state,
    spx_bounded_string_length_context_v2 *context,
    const spx_bytes_view_v2 *buffer,
    uint32_t maximum) {
  (void)context;
  (void)buffer;
  state->length = 0U;
  return (spx_bounded_string_length_length_control_v1) {
    maximum == 0U
        ? SPX_BOUNDED_STRING_LENGTH_LENGTH_CONTROL_COMPLETE
        : SPX_BOUNDED_STRING_LENGTH_LENGTH_CONTROL_RUNNING,
    SPX_BOUNDED_STRING_LENGTH_LENGTH_PHASE_SCAN,
    SPX_BOUNDED_STRING_LENGTH_LENGTH_COMPLETION_RETURN
  };
}

spx_bounded_string_length_length_control_v1
gnu_hello_bounded_string_length_step(
    spx_bounded_string_length_length_state_v1 *state,
    uint32_t phase_id,
    spx_bounded_string_length_context_v2 *context,
    const spx_bytes_view_v2 *buffer,
    uint32_t maximum) {
  uint8_t byte = 0U;
  (void)phase_id;
  (void)context;
  if (buffer->read_u8(buffer->context, state->length, &byte) != 0U || byte == 0U) {
    return (spx_bounded_string_length_length_control_v1) {
      SPX_BOUNDED_STRING_LENGTH_LENGTH_CONTROL_COMPLETE,
      SPX_BOUNDED_STRING_LENGTH_LENGTH_PHASE_SCAN,
      SPX_BOUNDED_STRING_LENGTH_LENGTH_COMPLETION_RETURN
    };
  }
  state->length += 1U;
  return (spx_bounded_string_length_length_control_v1) {
    state->length >= maximum
        ? SPX_BOUNDED_STRING_LENGTH_LENGTH_CONTROL_COMPLETE
        : SPX_BOUNDED_STRING_LENGTH_LENGTH_CONTROL_RUNNING,
    SPX_BOUNDED_STRING_LENGTH_LENGTH_PHASE_SCAN,
    SPX_BOUNDED_STRING_LENGTH_LENGTH_COMPLETION_RETURN
  };
}

uint32_t gnu_hello_bounded_string_length_finish(
    const spx_bounded_string_length_length_state_v1 *state,
    uint32_t completion_id,
    spx_bounded_string_length_context_v2 *context,
    const spx_bytes_view_v2 *buffer,
    uint32_t maximum) {
  (void)completion_id;
  (void)context;
  (void)buffer;
  (void)maximum;
  return state->length;
}
