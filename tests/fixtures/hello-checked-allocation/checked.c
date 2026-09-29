#include "portable-component-implementation.h"

typedef struct spx_opaque_allocation_block_v5 Block;
typedef spx_checked_allocation_context_v5 Context;

/* The shared machine tail belongs to this component, not to a public helper API. */
static Block *checked(Context *context, Block *block) {
    if (block == 0)
        context->services->allocation_failed(context->services->context);
    return block;
}
Block *checked_allocate(Context *context, uint32_t bytes) {
    return checked(context, context->services->allocate(context->services->context, bytes));
}
Block *checked_allocate_indexed(Context *context, uint32_t bytes) {
    return checked(context, context->services->allocate_indexed(context->services->context, bytes));
}
Block *checked_resize(Context *context, Block *block, uint32_t bytes) {
    return checked(context, context->services->resize(context->services->context, block, bytes));
}
Block *checked_resize_indexed(Context *context, Block *block, uint32_t bytes) {
    return checked(context, context->services->resize_indexed(context->services->context, block, bytes));
}
Block *checked_resize_array(Context *context, Block *block, uint32_t count, uint32_t width) {
    return checked(context, context->services->resize_array(context->services->context, block, count, width));
}
Block *checked_resize_array_indexed(Context *context, Block *block, uint32_t count, uint32_t width) {
    return checked(context, context->services->resize_array_indexed(context->services->context, block, count, width));
}
Block *checked_allocate_zeroed(Context *context, uint32_t count, uint32_t width) {
    return checked(context, context->services->allocate_zeroed(context->services->context, count, width));
}
Block *checked_allocate_zeroed_indexed(Context *context, uint32_t count, uint32_t width) {
    return checked(context, context->services->allocate_zeroed_indexed(context->services->context, count, width));
}
