#include "portable-component-implementation.h"

static uint8_t byte_at(const spx_bytes_view_v2 *value, uint32_t index) {
  uint8_t result = 0U;
  (void)value->read_u8(value->context, index, &result);
  return result;
}

static uint32_t is_separator(uint8_t value) {
  return value == (uint8_t)'/' || value == (uint8_t)'\\';
}

uint32_t gnu_hello_last_path_component(
    spx_last_path_component_context_v5 *context,
    const spx_bytes_view_v2 *value) {
  uint8_t current;
  uint32_t component = 0U;
  uint32_t cursor = 0U;
  uint32_t saw_separator = 0U;
  (void)context;

  SPX_PROOF_BEGIN(find);
  current = byte_at(value, 0U);
  if ((((uint32_t)(current | 0x20U) - (uint32_t)'a') < 26U) &&
      byte_at(value, 1U) == (uint8_t)':')
    cursor = 2U;
  current = byte_at(value, cursor);
  if (is_separator(current) != 0U) {
    for (;;) {
      SPX_PROOF_SYNC(
          skip_prefix,
          cursor < value->extent,
          value, component, cursor, saw_separator);
      cursor += 1U;
      current = byte_at(value, cursor);
      if (is_separator(current) == 0U)
        break;
    }
  }
  component = cursor;
  if (current == 0U)
    return component;

  for (;;) {
    SPX_PROOF_SYNC(
        scan,
        cursor < value->extent,
        value, component, cursor, saw_separator);
    current = byte_at(value, cursor);
    if (is_separator(current) != 0U) {
      saw_separator = 1U;
    } else if (saw_separator != 0U) {
      component = cursor;
      saw_separator = 0U;
    }
    cursor += 1U;
    if (byte_at(value, cursor) == 0U)
      return component;
  }
}
