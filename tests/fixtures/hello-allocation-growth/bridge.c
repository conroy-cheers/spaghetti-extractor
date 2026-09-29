#include "portable-component-implementation.h"
#include "allocation-objects.h"
#include "runtime.h"

static struct {
  const struct allocation_adapter *adapter;
  uint32_t *destination;
  struct spx_opaque_allocation_count_v5 count;
  struct spx_opaque_allocation_block_v5 old, result;
} active;

struct spx_opaque_allocation_block_v5 *allocation_resize(void *unused,
    struct spx_opaque_allocation_block_v5 *block, uint32_t bytes) {
  (void)unused;
  *active.destination = active.count.value;
  active.result.address = active.adapter->resize(active.adapter->context,
      block ? block->address : 0, bytes, active.count.value);
  return active.result.address ? &active.result : 0;
}
void allocation_allocation_failed(void *unused, uint32_t published_count) {
  (void)unused;
  *active.destination = active.count.value;
  active.adapter->failed(active.adapter->context, published_count);
}
#include "comparison-service-bridge.h"
uint32_t fixture_source_growth(const struct allocation_adapter *adapter,
    uint32_t old, uint32_t *count, uint32_t additional, uint32_t maximum, uint32_t width) {
  active.adapter = adapter; active.destination = count;
  active.count.value = *count; active.old.address = old;
  struct spx_opaque_allocation_block_v5 *result = bridge_allocation_grow(
      old ? &active.old : 0, &active.count, additional, maximum, width);
  *count = active.count.value;
  return result ? result->address : 0;
}
