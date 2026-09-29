#include "portable-component-implementation.h"
uint8_t regions_equal(spx_memory_regions_equal_context_v5 *context,
    const spx_view_v5 *left, const spx_view_v5 *right, uint32_t count) {
  (void)context;
  if (count>left->extent || count>right->extent) return 0;
  for (uint32_t i=0; i<count; ++i) {
    uint8_t a,b;
    if (spx_view_read_u8(left,i,&a) || spx_view_read_u8(right,i,&b)) return 0;
    if (a!=b) return 0;
  }
  return 1;
}
