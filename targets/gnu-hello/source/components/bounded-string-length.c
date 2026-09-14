#include "portable-component-implementation.h"

uint32_t gnu_hello_bounded_string_length(
    spx_bounded_string_length_context_v5 *context,
    const spx_bytes_view_v2 *buffer,
    uint32_t maximum) {
  uint32_t length = 0U;
  uint8_t byte = 0U;
  (void)context;

  SPX_PROOF_BEGIN(length);
  if (maximum != 0U) {
    for (;;) {
      SPX_PROOF_SYNC(scan, length < maximum, buffer, maximum, length);
      if (buffer->read_u8(buffer->context, length, &byte) != 0U || byte == 0U)
        break;
      length += 1U;
      if (length >= maximum)
        break;
    }
  }
  return length;
}
