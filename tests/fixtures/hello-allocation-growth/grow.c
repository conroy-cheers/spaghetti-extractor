#include "portable-component-implementation.h"
#include "allocation-objects.h"

struct spx_opaque_allocation_block_v5 *allocation_grow(
    spx_allocation_grow_context_v5 *context,
    struct spx_opaque_allocation_block_v5 *block,
    struct spx_opaque_allocation_count_v5 *count,
    uint32_t additional, uint32_t maximum, uint32_t width) {
  const uint32_t limit = UINT32_C(2147483647);
  const uint32_t previous = count->value;
  uint64_t expanded = (uint64_t)previous + previous / 2U;
  uint32_t next = expanded > limit ? limit : (uint32_t)expanded;
  if (maximum <= limit && next > maximum)
    next = maximum;
  uint64_t product = (uint64_t)next * width;
  uint32_t adjusted = product > limit ? limit : product < 64U ? 64U : 0U;
  if (adjusted != 0U) {
    next = adjusted / width;
    product = (uint64_t)next * width;
  }
  /* Null allocation publishes zero before either terminal failure or realloc.
   * Rechecking maximum after the small-allocation adjustment would also change
   * the original behavior: its second limit check occurs only in this branch. */
  if (block == 0)
    count->value = 0;
  if ((uint64_t)previous + additional > next) {
    expanded = (uint64_t)previous + additional;
    product = expanded * width;
    if (expanded > limit || (maximum <= limit && expanded > maximum) || product > limit) {
      context->services->allocation_failed(context->services->context, count->value);
      return 0; /* The admitted failure service does not return. */
    }
    next = (uint32_t)expanded;
  }
  block = context->services->resize(context->services->context, block, (uint32_t)product);
  count->value = next;
  return block;
}
