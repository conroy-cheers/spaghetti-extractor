#include "portable-component-implementation.h"
#include "bootstrap-state.h"
#include <stdlib.h>

void lifted_bootstrap_clear(spx_application_bootstrap_context_v5 *context,
                            bootstrap_state *state, font_surface *surface, uint32_t color) {
    font_rect rectangle = {0, 0, 640, 480};
    context->services->fill(context->services->context, state, surface, &rectangle, 100, 0x400, color);
}

void lifted_bootstrap_palette(spx_application_bootstrap_context_v5 *context, bootstrap_state *state) {
    shell_state *application = state->application;
    title_state *title = application->scene->animation;
    for (unsigned i = 0; i < 256; ++i)
        for (unsigned channel = 0; channel < 3; ++channel)
            title->palettes->current[i][channel] = title->palettes->staged[i][channel] = 0;
    if (!context->services->create_palette(context->services->context, state, application->graphics, 4))
        context->services->attach_palette(context->services->context, state, title->primary, application->palette);
}

void lifted_bootstrap_initialize(spx_application_bootstrap_context_v5 *context, bootstrap_state *state) {
    const spx_application_bootstrap_services_v5 *services = context->services;
    void *user = services->context;
    shell_state *application = state->application;
    scene_state *scene = application->scene;
    title_state *title = scene->animation;
    flow_state *flow = title->flow;
    display_surface descriptor = {.size=108, .flags=7, .height=480, .width=640, .caps=0x840};
    if (services->create_overlay(user, state, application->graphics, &descriptor)) {
        services->terminate(user, state, 1);
        abort();
    }
    flow->transition_pending = 0;
    flow->scene = flow->next_scene = 4;
    services->scores_initialize(user, state);
    services->scores_load(user, state);
    asset_name boards = {"default.bds"};
    services->boards_load(user, state, &boards);
    services->seed_random(user, state);
    lifted_bootstrap_clear(context, state, title->primary, 0);
    lifted_bootstrap_palette(context, state);
    uint32_t start = services->now(user, state);
    for (unsigned i = 0; i < 32; ++i)
        services->vertical_blank(user, state, application->graphics, 1);
    uint32_t end = services->now(user, state);
    scene->refresh_ok = end - start > 400;
    if (title->fast == 1) scene->refresh_ok = 0;
    if (!scene->no_hardware && !scene->refresh_ok) title->fast = 1;
    state->last_refresh = services->now(user, state);
}
