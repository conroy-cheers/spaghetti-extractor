#include "spaghetti-component-abi.h"

#include <stdint.h>

uint32_t gnu_hello_bounded_string_length(
    const stage_b_ro_bytes_v1 *value, uint32_t maximum) {
  uint32_t length = 0U;
  uint8_t byte = 0U;

  while (length < maximum) {
    if (value->read_u8(value->context, length, &byte) != 0U)
      return 0U;
    if (byte == 0U)
      break;
    ++length;
  }
  return length;
}
