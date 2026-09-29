#include "portable-component-implementation.h"
#include "allocation-objects.h"
#include "checked-runtime.h"
#include <stdlib.h>

typedef struct spx_opaque_allocation_block_v5 Block;
struct bridge_context { const struct checked_adapter *adapter; Block result; };
static Block *lower(void *opaque, uint32_t operation, Block *old, uint32_t a, uint32_t b) {
    struct bridge_context *context = opaque;
    uint32_t address = context->adapter->lower(context->adapter->context, operation, old?old->address:0, a, b);
    if (!address) return 0;
    if (old && old->address == address) return old;
    context->result.address = address;
    return &context->result;
}
static Block *adapter_allocate(void *c, uint32_t bytes) {return lower(c,CHECKED_ALLOCATE,0,bytes,1);}
static Block *adapter_allocate_indexed(void *c, uint32_t bytes) {return lower(c,CHECKED_ALLOCATE_INDEXED,0,bytes,1);}
static Block *adapter_resize(void *c, Block *b, uint32_t bytes) {return lower(c,CHECKED_RESIZE,b,bytes,1);}
static Block *adapter_resize_indexed(void *c, Block *b, uint32_t bytes) {return lower(c,CHECKED_RESIZE_INDEXED,b,bytes,1);}
static Block *adapter_resize_array(void *c, Block *b, uint32_t n, uint32_t w) {return lower(c,CHECKED_RESIZE_ARRAY,b,n,w);}
static Block *adapter_resize_array_indexed(void *c, Block *b, uint32_t n, uint32_t w) {return lower(c,CHECKED_RESIZE_ARRAY_INDEXED,b,n,w);}
static Block *adapter_allocate_zeroed(void *c, uint32_t n, uint32_t w) {return lower(c,CHECKED_ZEROED,0,n,w);}
static Block *adapter_allocate_zeroed_indexed(void *c, uint32_t n, uint32_t w) {return lower(c,CHECKED_ZEROED_INDEXED,0,n,w);}
static void adapter_allocation_failed(void *c) {
    const struct checked_adapter *adapter = ((struct bridge_context *)c)->adapter;
    adapter->failed(adapter->context);
    abort(); /* Returning is outside the admitted failure contract. */
}
#include "comparison-service-bridge.h"
uint32_t fixture_checked_allocation(const struct checked_adapter *adapter, uint32_t operation,
    uint32_t old, uint32_t a, uint32_t b) {
    struct bridge_context bridge = {.adapter=adapter};
    Block block = {.address=old};
    const spx_checked_allocation_services_v5 services = spx_checked_allocation_bind_services(&bridge);
    spx_checked_allocation_context_v5 context = {.services=&services};
    Block *result=0, *input=old?&block:0;
    spx_checked_allocation_services_begin();
    switch(operation) {
    case CHECKED_ALLOCATE: result=checked_allocate(&context,a);break;
    case CHECKED_ALLOCATE_INDEXED: result=checked_allocate_indexed(&context,a);break;
    case CHECKED_RESIZE: result=checked_resize(&context,input,a);break;
    case CHECKED_RESIZE_INDEXED: result=checked_resize_indexed(&context,input,a);break;
    case CHECKED_RESIZE_ARRAY: result=checked_resize_array(&context,input,a,b);break;
    case CHECKED_RESIZE_ARRAY_INDEXED: result=checked_resize_array_indexed(&context,input,a,b);break;
    case CHECKED_ZEROED: result=checked_allocate_zeroed(&context,a,b);break;
    case CHECKED_ZEROED_INDEXED: result=checked_allocate_zeroed_indexed(&context,a,b);break;
    default: abort();
    }
    spx_checked_allocation_services_end();
    return result?result->address:0;
}
