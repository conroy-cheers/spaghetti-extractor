#include "portable-component-implementation.h"
#include "cleanup-state.h"

void lifted_cleanup_select(spx_cleanup_select_context_v5 *context,
                           struct spx_opaque_cleanup_state_v5 *state,
                           uint32_t bank) {
    (void)context;
    state->current_bank = bank;
}
