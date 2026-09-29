#ifndef HELLO_REALLOCATE_RUNTIME_H
#define HELLO_REALLOCATE_RUNTIME_H
#include <stdint.h>

/* PE32 transport belongs to the adapter, not the authored implementation.
 * The allocator supplies existing contents, aliases and lifetime transitions. */
struct reallocate_adapter {
    void *context;
    uint32_t (*resize)(void *, uint32_t, uint32_t);
    uint32_t (*errno_address)(void *);
    uint32_t (*load)(void *, uint32_t);
    void (*store)(void *, uint32_t, uint32_t);
};
uint32_t fixture_source_reallocate(const struct reallocate_adapter *, uint32_t, uint32_t);
#endif
