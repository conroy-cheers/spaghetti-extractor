#include "spaghetti-component-abi.h"

#include <stdint.h>

uint32_t gnu_hello_memory_regions_equal(
    const spx_ro_bytes_v1 *left,
    const spx_ro_bytes_v1 *right,
    uint32_t count) {
  uint32_t index;

  for (index = 0U; index < count; ++index) {
    uint8_t left_byte = 0U;
    uint8_t right_byte = 0U;
    if (left->read_u8(left->context, index, &left_byte) != 0U ||
        right->read_u8(right->context, index, &right_byte) != 0U) {
      return 0U;
    }
    if (left_byte != right_byte) {
      return 0U;
    }
  }
  return 1U;
}
