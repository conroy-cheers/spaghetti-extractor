#include "portable-component-implementation.h"

struct spx_opaque_allocation_block_v5 *allocation_reallocate(
    spx_allocation_reallocate_context_v5 *context,
    struct spx_opaque_allocation_block_v5 *block, uint32_t bytes)
{
    const spx_allocation_reallocate_services_v5 *services = context->services;
    void *environment = services->context;
    if (bytes <= UINT32_C(2147483647)) {
        if (bytes == 0U)
            bytes = 1U;
        block = services->raw_resize(environment, block, bytes);
        if (block != 0)
            return block;
    }
    spx_view_v5 error = services->errno_cell(environment);
    (void)error.write(error.access_context, error.base, 0U, 4U, 12U);
    return 0;
}
