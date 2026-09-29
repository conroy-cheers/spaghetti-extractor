#include "portable-component-implementation.h"
#include "cleanup-state.h"

void lifted_cleanup_dispose(spx_cleanup_dispose_context_v5 *context,
                            struct spx_opaque_cleanup_state_v5 *state,
                            uint32_t slot) {
    struct spx_opaque_cleanup_sprite_v5 *sprite =
        state->banks[state->current_bank].slots[slot];
    if (!sprite)
        return;
    if (sprite->surface) {
        context->services->release(context->services->context, state, sprite->surface);
        /* A service may change the current bank or its slot. The machine code
         * reloads both before clearing the surface and choosing what to free. */
        state->banks[state->current_bank].slots[slot]->surface = 0;
    }
    context->services->free_sprite(context->services->context, state,
        state->banks[state->current_bank].slots[slot]);
    state->banks[state->current_bank].slots[slot] = 0;
}
