#include "portable-component-implementation.h"
#include "title-state.h"

/* The binary uses integer sine samples multiplied by exactly 1/1024, then
 * an integer scale, and truncates toward zero. These admitted products fit
 * exactly in both the original x87 significand and this integer calculation. */
static uint32_t scaled_sine(const title_state *state, uint32_t angle, int64_t scale) {
    int64_t degrees = font_signed(angle);
    uint32_t index = degrees < 0 ? 360 - (uint32_t)(-degrees % 360) : (uint32_t)(degrees % 360);
    return (uint32_t)((int64_t)state->sine[index] * scale / 1024);
}

void lifted_title_scroll(spx_title_animation_context_v5 *context, title_state *state) {
    const spx_title_animation_services_v5 *services = context->services;
    void *user = services->context;
    services->select_font(user, state->font, 1);
    state->advance += 4;
    if (font_signed(state->advance) > font_signed(state->glyph_width)) {
        ++state->index;
        if (font_signed(state->index) > font_signed(state->length - 1)) state->index = 0;
        services->destination(user, state->font, state->back);
        state->glyph_width = services->glyph(user, state->font, state->message[state->index], 600, 470) + 1;
        if (state->glyph_width == 1) state->glyph_width = 15;
        state->advance = 0;
    }
    font_rect rectangle = {40, 440, 639, 475};
    services->blit_fast(user, state, state->back, 36, 440, state->back, &rectangle, 0x10);
}

void lifted_title_wave(spx_title_animation_context_v5 *context, title_state *state) {
    for (uint32_t x = 40; x <= 595; x += 5) {
        font_rect rectangle = {x, 440, x + 5, 475};
        font_surface *destination = state->fast ? state->primary : state->software;
        uint32_t y = 420 - scaled_sine(state, x, -20);
        context->services->blit_fast(context->services->context, state, destination,
            x, y, state->back, &rectangle, 0x10);
    }
}

void lifted_title_wobble(spx_title_animation_context_v5 *context, title_state *state) {
    state->wobble_phase += 20;
    if (font_signed(state->wobble_phase) > 359) state->wobble_phase %= 360;
    state->first_offset = scaled_sine(state, state->wobble_phase, 3);
    state->second_offset = scaled_sine(state, 0 - state->wobble_phase, 3);
    /* Retain the selected branch while reloading its object after the callback. */
    font_surface **destination = state->fast ? &state->primary : &state->software;
    font_rect first = {0, 335, 639, 353}, second = {0, 362, 639, 380};
    context->services->blit_fast(context->services->context, state, *destination,
        0, state->first_offset + 3, state->back, &first, 0x10);
    context->services->blit_fast(context->services->context, state, *destination,
        0, state->second_offset + 127, state->back, &second, 0x10);
}

void lifted_title_cycle(spx_title_animation_context_v5 *context, title_state *state) {
    if (state->flow->windowed) return;
    for (uint32_t i = 48; i <= state->palette_width + 48; ++i) {
        unsigned char *entry = state->palettes->current[i];
        if (entry[0]) entry[0] = (unsigned char)(entry[0] - 4);
        if (entry[2]) entry[2] = (unsigned char)(entry[2] - 2);
    }
    uint32_t center = state->palette_width / 2 + 48;
    state->palette_offset = scaled_sine(state, state->palette_phase, (int64_t)(state->palette_width / 2) - 1);
    ++state->palette_phase;
    if (font_signed(state->palette_phase) > 359) state->palette_phase %= 360;
    uint32_t red = center + state->palette_offset, blue = center - state->palette_offset;
    state->palettes->current[red][0] = state->palettes->current[red + 1][0] = 160;
    state->palettes->current[blue][2] = state->palettes->current[blue + 1][2] = 160;
    /* The count really is width + 48; retain the original extra palette range. */
    context->services->apply_palette(context->services->context, state, 48, state->palette_width + 48);
}
