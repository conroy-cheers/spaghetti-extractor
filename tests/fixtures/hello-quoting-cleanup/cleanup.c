#include "portable-component-implementation.h"
#include "quote-objects.h"

uint32_t quote_cleanup(spx_quote_cleanup_context_v5 *context)
{
    struct spx_opaque_quote_state_v5 *state = context->state.slots;
    struct spx_opaque_quote_table_v5 *slots = state->table;
    const spx_quote_cleanup_services_v5 *services = context->services;
    void *environment = services->context;

    for (uint32_t index = 1U; index < state->count; ++index)
        services->release_buffer(environment, slots[index].buffer);

    if (slots[0].buffer != state->initial_buffer) {
        services->release_buffer(environment, slots[0].buffer);
        state->initial_table[0].size = 256U;
        state->initial_table[0].buffer = state->initial_buffer;
    }
    if (slots != state->initial_table) {
        services->release_table(environment, slots);
        state->table = state->initial_table;
    }
    state->count = 1U;
    return 0U;
}
