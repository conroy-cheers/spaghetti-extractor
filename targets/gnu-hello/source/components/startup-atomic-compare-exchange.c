#include "portable-component-implementation.h"
#include "spx-atomics.h"

uint32_t gnu_hello_startup_atomic_compare_exchange(
    spx_startup_atomic_compare_exchange_context_v2 *context,
    spx_atomic_object *object,
    uint32_t desired) {
  spx_atomic_observation observation = {0};
  SPX_PROOF_BEGIN(compare_exchange);
  (void)context;
  (void)spx_atomic_compare_exchange(object, 0U, desired, &observation);
  return !observation.exchanged;
}
