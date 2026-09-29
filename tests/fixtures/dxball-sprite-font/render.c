#include "portable-component-implementation.h"
#include "font-state.h"

uint32_t lifted_font_glyph(spx_font_render_context_v5 *context, font_state *state,
                           uint32_t character, uint32_t x, uint32_t y) {
    uint32_t slot = context->services->find(context->services->context, state, character);
    if (!slot)
        return 0;
    font_sprite *glyph = state->objects->banks[state->bank].slots[slot];
    font_rect destination = {x, y - font_height(glyph) - font_baseline(glyph),
                             x + font_width(glyph), y - font_baseline(glyph)};
    font_rect source = {font_word(glyph, 20), font_word(glyph, 24),
                        font_word(glyph, 28), font_word(glyph, 32)};
    context->services->blit(context->services->context, state, &destination, glyph->surface, &source);
    return font_width(state->objects->banks[state->bank].slots[slot]);
}

uint32_t lifted_font_line(spx_font_render_context_v5 *context, font_state *state,
                          uint32_t x, uint32_t y, uint32_t length, font_bytes *text) {
    uint32_t advance = 0;
    for (uint32_t i = 0; font_signed(i) < font_signed(length); ++i) {
        x += advance;
        advance = lifted_font_glyph(context, state, text->data[i], x, y);
        if (advance)
            advance += state->spacing;
        else
            advance = font_half(font_width(state->objects->banks[state->bank].slots[1]));
    }
    return advance;
}

uint32_t lifted_font_center(spx_font_render_context_v5 *context, font_state *state,
                            uint32_t x, uint32_t y, uint32_t length, font_bytes *text) {
    uint32_t width = context->services->measure(context->services->context, state, length, text);
    return lifted_font_line(context, state, x - font_half(width), y, length, text);
}
