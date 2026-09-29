#include "portable-component-implementation.h"
#include "quote-objects.h"

/* Runtime-owned storage uses a call-scoped byte view. The errno contract
 * supplies a readable/writable word; neither helper retains that view. */
static uint32_t read_word(spx_view_v5 cell)
{
    uint64_t value = 0;
    (void)cell.read(cell.access_context, cell.base, 0U, 4U, &value);
    return (uint32_t)value;
}

static void write_word(spx_view_v5 cell, uint32_t value)
{
    (void)cell.write(cell.access_context, cell.base, 0U, 4U, value);
}

/* The byte count remains a 32-bit target value. Object identities and storage
 * are portable pointers supplied by the surrounding representation contract. */
struct spx_opaque_quote_bytes_v5 *quote_slots(
    spx_quote_slots_context_v5 *context, uint32_t slot_index,
    struct spx_opaque_quote_bytes_v5 *argument, uint32_t argument_size,
    struct spx_opaque_quote_options_v5 *options)
{
    struct spx_opaque_quote_state_v5 *state = context->state.slots;
    const spx_quote_slots_services_v5 *services = context->services;
    void *environment = services->context;
    uint32_t saved_errno = read_word(services->errno_cell(environment));
    struct spx_opaque_quote_table_v5 *slots = state->table;

    if (slot_index >= UINT32_C(2147483647)) {
        services->invalid_slot(environment);
        return 0; /* The admitted invalid-slot service does not return. */
    }

    if (state->count <= slot_index) {
        uint32_t preallocated = slots == state->initial_table;
        struct spx_opaque_quote_word_v5 new_count = { state->count };
        slots = services->grow_slots(environment, preallocated ? 0 : slots,
            &new_count, slot_index - state->count + 1U, UINT32_C(2147483647));
        state->table = slots;
        if (preallocated)
            slots[0] = state->initial_table[0];
        services->clear_slots(environment, slots, state->count,
            new_count.value - state->count);
        state->count = new_count.value;
    }

    struct spx_opaque_quote_table_v5 *slot = &slots[slot_index];
    uint32_t size = slot->size;
    struct spx_opaque_quote_bytes_v5 *buffer = slot->buffer;
    uint32_t flags = options->flags | 1U;
    uint32_t required = services->quote_buffer(environment, buffer, size,
        argument, argument_size, options->style, flags, &options->mask,
        options->left_quote, options->right_quote);

    if (size <= required) {
        size = required + 1U;
        slot->size = size;
        if (buffer != state->initial_buffer)
            services->release_buffer(environment, buffer);
        buffer = services->allocate_buffer(environment, size);
        slot->buffer = buffer;
        (void)services->quote_buffer(environment, buffer, size,
            argument, argument_size, options->style, flags, &options->mask,
            options->left_quote, options->right_quote);
    }

    write_word(services->errno_cell(environment), saved_errno);
    return buffer;
}
