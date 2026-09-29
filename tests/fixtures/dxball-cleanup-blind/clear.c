#include "portable-component-implementation.h"
#include "cleanup-state.h"

void lifted_cleanup_clear(spx_cleanup_clear_context_v5 *context,
                          struct spx_opaque_cleanup_state_v5 *state) {
    for (uint32_t bank = 0; bank < 3; ++bank) {
        state->banks[bank].count = 0;
        context->services->select(context->services->context, state, bank);
        for (uint32_t slot = 0; slot < 255; ++slot)
            context->services->dispose(context->services->context, state, slot);
    }
}
