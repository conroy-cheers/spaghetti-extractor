#ifndef HELLO_ALLOCATION_RUNTIME_H
#define HELLO_ALLOCATION_RUNTIME_H
#include <stdint.h>

/* Target addresses name blocks; the allocator owns their contents and lifetime.
 * The count at the interaction is observable even when allocation never returns.
 * This fixture bridge admits synchronous, nonreentrant calls. */
struct allocation_adapter {
  void *context;
  uint32_t (*resize)(void *, uint32_t, uint32_t, uint32_t);
  void (*failed)(void *, uint32_t);
};
uint32_t fixture_source_growth(const struct allocation_adapter *, uint32_t,
    uint32_t *, uint32_t, uint32_t, uint32_t);
#endif
