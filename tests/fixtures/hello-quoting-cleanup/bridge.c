#include "portable-component-implementation.h"
#include "cleanup-runtime.h"

uint32_t fixture_quote_cleanup(struct spx_opaque_quote_state_v5 *state,
    const struct cleanup_adapter *adapter)
{
    const spx_quote_cleanup_services_v5 services = {
        .context = adapter->context, .release_buffer = adapter->release_buffer,
        .release_table = adapter->release_table
    };
    spx_quote_cleanup_context_v5 context = { .services = &services, .state = { .slots = state } };
    return quote_cleanup(&context);
}
