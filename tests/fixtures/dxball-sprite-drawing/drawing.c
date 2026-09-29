#include "portable-component-implementation.h"
#include "font-state.h"

void lifted_sprite_destination(spx_sprite_drawing_context_v5 *context,
                               font_state *state, font_surface *surface) {
    (void)context;
    state->destination = surface;
}

static uint32_t draw(spx_sprite_drawing_context_v5 *context, font_state *state,
                     uint32_t slot, uint32_t x, uint32_t y, uint32_t flags) {
    font_sprite *sprite = state->objects->banks[state->objects->current_bank].slots[slot];
    return context->services->blit_fast(context->services->context, state, sprite, x, y, flags);
}

uint32_t lifted_sprite_transparent(spx_sprite_drawing_context_v5 *context,
                                  font_state *state, uint32_t slot, uint32_t x, uint32_t y) {
    return draw(context, state, slot, x, y, 0x11);
}

uint32_t lifted_sprite_opaque(spx_sprite_drawing_context_v5 *context,
                             font_state *state, uint32_t slot, uint32_t x, uint32_t y) {
    return draw(context, state, slot, x, y, 0x10);
}
