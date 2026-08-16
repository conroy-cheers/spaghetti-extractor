#include "portable-component-implementation.h"

uint8_t gnu_hello_memory_regions_equal(
    spx_memory_regions_equal_context_v2 *context,
    const spx_bytes_view_v2 *left,
    const spx_bytes_view_v2 *right,
    uint32_t count) {
  uint32_t comparison = context->services->compare_memory(
      context->services->context, left, right, count);
  return comparison == UINT32_C(0) ? UINT32_C(1) : UINT32_C(0);
}
