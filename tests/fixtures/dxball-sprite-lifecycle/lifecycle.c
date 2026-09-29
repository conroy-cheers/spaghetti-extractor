#include <stdlib.h>
#include "portable-component-implementation.h"
#include "asset-state.h"

static font_sprite *selected(asset_state *state, uint32_t slot) {
    return state->objects->banks[state->objects->current_bank].slots[slot];
}

uint32_t lifted_sprite_capture(spx_sprite_lifecycle_context_v5 *context,
        asset_state *state, font_state *drawing, uint32_t slot,
        uint32_t x, uint32_t y, uint32_t width, uint32_t height) {
    const spx_sprite_lifecycle_services_v5 *services = context->services;
    void *user = services->context;
    services->dispose(user, state->objects, slot);
    font_sprite *sprite = services->allocate_sprite(user, state);
    if (!sprite) exit(1);
    state->objects->banks[state->objects->current_bank].slots[slot] = sprite;
    asset_set_word(sprite, 8, width); asset_set_word(sprite, 12, height);
    sprite->retained[32] = 0; asset_set_word(sprite, 40, 0);
    asset_set_word(sprite, 20, 0); asset_set_word(sprite, 24, 0);
    asset_set_word(sprite, 28, width); asset_set_word(sprite, 32, height);
    uint32_t result = services->create(user, state, sprite, 0x840);
    if (result) return result;
    services->color_key(user, state, selected(state, slot)->surface);
    asset_view view;
    while (services->describe(user, state, selected(state, slot)->surface, &view)) {}
    asset_set_word(selected(state, slot), 16, view.pitch);
    font_rect source = {x, y, x + width, y + height};
    return services->copy(user, state, drawing, selected(state, slot), &source);
}

void lifted_sprite_restore(spx_sprite_lifecycle_context_v5 *context, asset_state *state) {
    const spx_sprite_lifecycle_services_v5 *services = context->services;
    void *user = services->context;
    for (uint32_t bank = 0; bank < 3; ++bank) {
        struct cleanup_bank *row = &state->objects->banks[bank];
        if (row->retained[0] != 1) continue;
        for (uint32_t slot = 0; slot < 255; ++slot) {
            font_sprite *sprite = row->slots[slot];
            if (sprite && sprite->surface)
                services->restore_surface(user, state, sprite->surface);
        }
        /* Reload the serialized filename. The load boundary retains the live
         * bank identity so an adapter can preserve its alias during callbacks. */
        services->reload(user, state, bank);
    }
}
