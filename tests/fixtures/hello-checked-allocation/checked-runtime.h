#ifndef HELLO_CHECKED_ALLOCATION_RUNTIME_H
#define HELLO_CHECKED_ALLOCATION_RUNTIME_H
#include <stdint.h>
/* Explicit private fixture transport. Public component operations remain typed. */
enum { CHECKED_ALLOCATE, CHECKED_ALLOCATE_INDEXED, CHECKED_RESIZE, CHECKED_RESIZE_INDEXED,
    CHECKED_RESIZE_ARRAY, CHECKED_RESIZE_ARRAY_INDEXED, CHECKED_ZEROED, CHECKED_ZEROED_INDEXED };
struct checked_adapter {
    void *context;
    uint32_t (*lower)(void *, uint32_t operation, uint32_t block, uint32_t a, uint32_t b);
    void (*failed)(void *);
};
uint32_t fixture_checked_allocation(const struct checked_adapter *, uint32_t operation,
    uint32_t block, uint32_t a, uint32_t b);
#endif
