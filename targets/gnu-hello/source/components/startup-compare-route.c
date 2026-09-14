#include "portable-component-implementation.h"

uint32_t gnu_hello_startup_compare_route(
    spx_startup_compare_route_context_v2 *context,
    uint32_t left,
    uint32_t right) {
  SPX_PROOF_BEGIN(compare);
  (void)context;
  return left == right;
}
