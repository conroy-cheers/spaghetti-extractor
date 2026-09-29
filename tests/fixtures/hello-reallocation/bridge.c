#include "portable-component-implementation.h"
#include "allocation-objects.h"
#include "reallocate-runtime.h"

typedef struct spx_opaque_allocation_block_v5 Block;
struct bridge_context { const struct reallocate_adapter *adapter; Block result; };
static Block *resize(void *opaque,Block *old,uint32_t bytes)
{
    struct bridge_context *context = opaque;
    const struct reallocate_adapter *adapter = context->adapter;
    uint32_t address = adapter->resize(adapter->context,old?old->address:0,bytes);
    if (!address) return 0;
    if (old && address == old->address) return old;
    context->result.address = address;
    return &context->result;
}
static uint32_t read_error(void *opaque,spx_ref_v5 reference,uint64_t offset,uint32_t width,uint64_t *value)
{
    const struct reallocate_adapter *adapter = opaque;
    if (offset || width != 4 || !value) return SPX_REF_FAULT;
    *value = adapter->load(adapter->context,(uint32_t)reference.object);
    return SPX_REF_OK;
}
static uint32_t write_error(void *opaque,spx_ref_v5 reference,uint64_t offset,uint32_t width,uint64_t value)
{
    const struct reallocate_adapter *adapter = opaque;
    if (offset || width != 4) return SPX_REF_FAULT;
    adapter->store(adapter->context,(uint32_t)reference.object,(uint32_t)value);
    return SPX_REF_OK;
}
static spx_view_v5 errno_cell(void *opaque)
{
    const struct reallocate_adapter *adapter = ((struct bridge_context *)opaque)->adapter;
    uint32_t address = adapter->errno_address(adapter->context);
    return (spx_view_v5){.base={.object=address,.extent=4,.permissions=3},.extent=4,
        .element_width=1,.access_context=(void *)adapter,.read=read_error,.write=write_error};
}
uint32_t fixture_source_reallocate(const struct reallocate_adapter *adapter,uint32_t old,uint32_t bytes)
{
    struct bridge_context bridge = {.adapter=adapter};
    Block block = {.address=old};
    const spx_allocation_reallocate_services_v5 services = {
        .context=&bridge,.raw_resize=resize,.errno_cell=errno_cell
    };
    spx_allocation_reallocate_context_v5 context = {.services=&services};
    Block *result = allocation_reallocate(&context,old?&block:0,bytes);
    return result?result->address:0;
}
