#include <stdint.h>

#include "spaghetti-component-abi.h"

static uint8_t byte_at(const spx_c_string_v1 *value, uint32_t index) {
  uint8_t result = 0U;
  (void)value->read_u8(value->context, index, &result);
  return result;
}

uint32_t gnu_hello_last_path_component(const spx_c_string_v1 *value) {
  uint32_t cursor = 0U;
  uint32_t component = 0U;
  uint32_t saw_separator = 0U;
  uint8_t first = byte_at(value, 0U);

  if ((((uint32_t)(first | 0x20U) - (uint32_t)'a') < 26U) &&
      byte_at(value, 1U) == (uint8_t)':') {
    cursor = 2U;
  }
  while (byte_at(value, cursor) == (uint8_t)'/' ||
         byte_at(value, cursor) == (uint8_t)'\\') {
    ++cursor;
  }
  component = cursor;
  while (byte_at(value, cursor) != 0U) {
    uint8_t current = byte_at(value, cursor);
    if (current == (uint8_t)'/' || current == (uint8_t)'\\') {
      saw_separator = 1U;
    } else if (saw_separator != 0U) {
      component = cursor;
      saw_separator = 0U;
    }
    ++cursor;
  }
  return component;
}
