#include "portable-component-implementation.h"

uint32_t component_g_increment(
    spx_g_context_v2 *context,
    uint32_t value) {
  (void)context;
  return value + UINT32_C(1);
}
