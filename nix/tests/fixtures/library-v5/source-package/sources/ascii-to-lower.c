#include "portable-component-implementation.h"
uint32_t spx_ascii_to_lower(
    spx_ascii_to_lower_context_v5 *context, uint32_t value) {
  (void)context;
  return value >= 'A' && value <= 'Z' ? value + 32u : value;
}
