#include "portable-component-implementation.h"
#include "flow-state.h"

void lifted_flow_enter(spx_game_flow_context_v5 *context, flow_state *state) {
    if (state->scene <= 4)
        context->services->scene_enter(context->services->context, state, state->scene);
}

void lifted_flow_leave(spx_game_flow_context_v5 *context, flow_state *state, uint32_t reason) {
    if (state->scene <= 4)
        context->services->scene_leave(context->services->context, state, state->scene, reason);
}

void lifted_flow_key(spx_game_flow_context_v5 *context, flow_state *state, uint32_t key) {
    if (state->scene <= 4)
        context->services->scene_key(context->services->context, state, state->scene, key);
}

void lifted_flow_redraw(spx_game_flow_context_v5 *context, flow_state *state) {
    if (state->scene <= 4)
        context->services->scene_redraw(context->services->context, state, state->scene);
}

void lifted_flow_restore(spx_game_flow_context_v5 *context, flow_state *state) {
    const spx_game_flow_services_v5 *services = context->services;
    void *user = services->context;
    if (services->surface_restore(user, state, state->primary)) return;
    if (services->surface_restore(user, state, state->back)) return;
    services->restore_banks(user, state->sprites);
    lifted_flow_redraw(context, state);
}

void lifted_flow_check_surfaces(spx_game_flow_context_v5 *context, flow_state *state) {
    if (state->windowed) {
        if (state->refresh_needed == 1) {
            lifted_flow_restore(context, state);
            state->refresh_needed = 0;
        }
    } else {
        if (context->services->surface_status(context->services->context, state, state->primary) == UINT32_C(0x887601c2))
            lifted_flow_restore(context, state);
        if (state->refresh_needed == 1) state->refresh_needed = 0;
    }
}

uint32_t lifted_flow_frame(spx_game_flow_context_v5 *context, flow_state *state) {
    const spx_game_flow_services_v5 *services = context->services;
    void *user = services->context;
    if (state->first_frame) {
        services->initialize(user, state);
        lifted_flow_enter(context, state);
        state->first_frame = 0;
        state->refresh_needed = 0;
    }
    lifted_flow_check_surfaces(context, state);
    if (state->audio_enabled && (services->audio_status(user, state, state->audio) & 2))
        services->audio_restore(user, state, state->audio);
    if (state->scene <= 4) services->scene_update(user, state, state->scene);
    if (state->transition_pending) {
        lifted_flow_leave(context, state, 1);
        state->scene = state->next_scene;
        lifted_flow_enter(context, state);
        state->transition_pending = 0;
    }
    return 1;
}

void lifted_flow_shutdown(spx_game_flow_context_v5 *context, flow_state *state, uint32_t reason) {
    /* Preserve the binary's first-frame test, including its unusual direction. */
    if (state->first_frame) lifted_flow_leave(context, state, reason);
    if (state->overlay) {
        context->services->release(context->services->context, state, state->overlay);
        state->overlay = NULL;
    }
}
