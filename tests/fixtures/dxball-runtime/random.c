#include "portable-component-implementation.h"
#include "runtime-state.h"
#include <stdlib.h>

void lifted_runtime_set_seed(spx_runtime_support_context_v5 *context, runtime_state *state, uint32_t seed) {
    (void)context;
    state->random_seed = seed;
}

uint32_t lifted_runtime_next(spx_runtime_support_context_v5 *context, runtime_state *state) {
    (void)context;
    state->random_seed = state->random_seed * 214013 + 2531011;
    return (state->random_seed >> 16) & 32767;
}

uint32_t lifted_runtime_random(spx_runtime_support_context_v5 *context, runtime_state *state, uint32_t limit) {
    uint32_t value = lifted_runtime_next(context, state);
    if (!limit) {
        context->services->fault(context->services->context, state, UINT32_C(0xc0000094));
        abort();
    }
    uint32_t magnitude = limit < UINT32_C(0x80000000) ? limit : 0u - limit;
    return value % magnitude;
}

void lifted_runtime_seed(spx_runtime_support_context_v5 *context, runtime_state *state) {
    state->random_seed = context->services->ticks(context->services->context, state) % 300;
}
