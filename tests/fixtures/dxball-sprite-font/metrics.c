#include "portable-component-implementation.h"
#include "font-state.h"

void lifted_font_select(spx_font_metrics_context_v5 *context, font_state *state, uint32_t bank) {
    (void)context;
    state->bank = bank;
}

uint32_t lifted_font_find(spx_font_metrics_context_v5 *context, font_state *state, uint32_t character) {
    (void)context;
    struct cleanup_bank *bank = &state->objects->banks[state->bank];
    uint32_t slot = 1;
    while (font_signed(slot) < font_signed(bank->count)) {
        if (font_character(bank->slots[slot]) == (unsigned char)character)
            break;
        ++slot;
    }
    /* Preserve the native count<=0 quirk: it returns 1, without dereferencing. */
    return slot == bank->count ? 0 : slot;
}

uint32_t lifted_font_measure(spx_font_metrics_context_v5 *context, font_state *state,
                             uint32_t length, font_bytes *text) {
    uint32_t width = 0;
    for (uint32_t i = 0; font_signed(i) < font_signed(length); ++i) {
        uint32_t slot = lifted_font_find(context, state, text->data[i]);
        struct cleanup_bank *bank = &state->objects->banks[state->bank];
        width += slot ? font_width(bank->slots[slot]) + state->spacing
                      : font_half(font_width(bank->slots[1]));
    }
    return width;
}
