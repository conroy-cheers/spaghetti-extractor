#include "services.h"
#include "portable-component-implementation.h"
#include <stdlib.h>

typedef struct spx_opaque_allocation_block_v5 Block;
static Block *allocate(void *context, uint32_t size) {
    (void)context;
    ++hello_runtime.allocations; hello_runtime.allocated_bytes = size;
    return (Block *)malloc(size);
}
static void failed(void *context) { (void)context; hello_allocation_failed(); }
void *hello_allocate(uint32_t size) {
    spx_checked_allocation_services_v5 services = {.allocate=allocate, .allocation_failed=failed};
    spx_checked_allocation_context_v5 context = {.services=&services};
    return checked_allocate(&context, size);
}
