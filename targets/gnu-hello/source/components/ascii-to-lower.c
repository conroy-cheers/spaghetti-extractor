#include "portable-component-implementation.h"

uint32_t gnu_hello_ascii_to_lower(
    spx_ascii_to_lower_context_v2 *context,
    uint32_t value) {
  (void)context;
  if (value >= (uint32_t)'A' && value <= (uint32_t)'Z')
    return value + UINT32_C(0x20);
  return value;
}
