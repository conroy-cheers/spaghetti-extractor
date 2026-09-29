#include "portable-component-implementation.h"
#include "runtime-state.h"
#include <stdlib.h>

void lifted_runtime_clock_init(spx_runtime_support_context_v5 *context, runtime_state *state, uint32_t platform_history) {
    runtime_version_query version = {148, platform_history};
    context->services->version(context->services->context, state, &version);
    state->counter_enabled = version.platform != 1;
}

uint32_t lifted_runtime_now(spx_runtime_support_context_v5 *context, runtime_state *state, runtime_sample *history) {
    const spx_runtime_support_services_v5 *services = context->services;
    void *user = services->context;
    if (state->counter_enabled) {
        runtime_sample sample = *history;
        if (!state->counter_divisor) {
            if (!services->frequency(user, state, &sample)) return services->ticks(user, state);
            state->counter_divisor = sample.low / 1000;
        }
        services->counter(user, state, &sample);
        if (!state->counter_divisor) {
            services->fault(user, state, UINT32_C(0xc0000094));
            abort();
        }
        return sample.low / state->counter_divisor;
    }
    return services->ticks(user, state);
}

uint32_t lifted_runtime_elapsed(spx_runtime_support_context_v5 *context, runtime_state *state, uint32_t previous, uint32_t delay) {
    uint32_t now = context->services->now(context->services->context, state);
    return now < previous || now >= previous + delay;
}

void lifted_runtime_wait(spx_runtime_support_context_v5 *context, runtime_state *state, uint32_t count) {
    if (!count || count >= UINT32_C(0x80000000)) return;
    const spx_runtime_support_services_v5 *services = context->services;
    void *user = services->context;
    bootstrap_state *bootstrap = state->bootstrap;
    shell_state *application = bootstrap->application;
    if (application->scene->refresh_ok) {
        do services->vertical_blank(user, state, application->graphics, 1); while (--count);
    } else {
        do {
            uint32_t now = services->now(user, state);
            while (now >= bootstrap->last_refresh && now < bootstrap->last_refresh + 17)
                now = services->now(user, state);
            bootstrap->last_refresh = services->now(user, state);
        } while (--count);
    }
}
