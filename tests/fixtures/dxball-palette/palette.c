#include "portable-component-implementation.h"
#include "palette-state.h"
#include <string.h>

void lifted_palette_fade(spx_palette_effects_context_v5 *context, palette_state *state,
                         uint32_t wait, uint32_t step, uint32_t first, uint32_t last, uint32_t direction) {
    if (state->flow->windowed == 1 || direction > 1) return;
    int changed;
    do {
        changed = 0;
        for (uint32_t i = first; font_signed(i) <= font_signed(last); ++i) {
            for (unsigned channel = 0; channel < 3; ++channel) {
                unsigned char *value = &state->colors->current[i][channel];
                unsigned target = direction ? state->colors->staged[i][channel] : 0;
                if (*value == target) continue;
                changed = 1;
                unsigned distance = *value < target ? target - *value : *value - target;
                if (font_signed(step) > distance) *value = (unsigned char)target;
                else if (*value < target) *value = (unsigned char)(*value + step);
                else *value = (unsigned char)(*value - step);
            }
        }
        context->services->apply(context->services->context, state, first, last - first + 1);
        context->services->wait(context->services->context, state, wait);
        /* The final unchanged iteration still publishes and waits. */
    } while (changed);
}

void lifted_palette_right(spx_palette_effects_context_v5 *context, palette_state *state,
                          uint32_t first, uint32_t last, uint32_t wrap) {
    if (state->flow->windowed == 1) return;
    unsigned char color[3] = {0};
    if (wrap == 1) memcpy(color, state->colors->current[last], 3);
    for (uint32_t i = last; i > first; --i)
        memcpy(state->colors->current[i], state->colors->current[i - 1], 4);
    /* Moved entries include their flag byte; the inserted RGB preserves it. */
    memcpy(state->colors->current[first], color, 3);
    context->services->apply(context->services->context, state, first, last - first + 1);
}

void lifted_palette_left(spx_palette_effects_context_v5 *context, palette_state *state,
                         uint32_t first, uint32_t last, uint32_t wrap) {
    if (state->flow->windowed == 1) return;
    unsigned char color[3] = {0};
    if (wrap == 1) memcpy(color, state->colors->current[first], 3);
    for (uint32_t i = first; i < last; ++i)
        memcpy(state->colors->current[i], state->colors->current[i + 1], 4);
    memcpy(state->colors->current[last], color, 3);
    context->services->apply(context->services->context, state, first, last - first + 1);
}

void lifted_palette_set(spx_palette_effects_context_v5 *context, palette_state *state,
                        uint32_t index, uint32_t red, uint32_t green, uint32_t blue) {
    if (state->flow->windowed == 1) return;
    state->colors->current[index][0] = (unsigned char)red;
    state->colors->current[index][1] = (unsigned char)green;
    state->colors->current[index][2] = (unsigned char)blue;
    context->services->apply(context->services->context, state, index, 1);
}

void lifted_palette_rotate(spx_palette_effects_context_v5 *context, palette_state *state,
                           uint32_t index, uint32_t count, palette_sequence *sequence) {
    if (state->flow->windowed == 1) return;
    uint32_t first[3];
    memcpy(first, sequence->values, sizeof(first));
    memmove(sequence->values, sequence->values + 3, (count - 3) * sizeof(uint32_t));
    memcpy(sequence->values + count - 3, first, sizeof(first));
    lifted_palette_set(context, state, index, sequence->values[0], sequence->values[1], sequence->values[2]);
}
