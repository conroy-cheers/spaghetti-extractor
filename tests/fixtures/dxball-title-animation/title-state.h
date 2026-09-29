#ifndef DXBALL_TITLE_STATE_H
#define DXBALL_TITLE_STATE_H
#include "flow-state.h"
#include "pcx-state.h"
typedef struct spx_opaque_title_state_v5 {
    font_state *font;
    pcx_state *palettes;
    flow_state *flow;
    font_surface *primary, *software, *back;
    const unsigned char *message;
    const int32_t *sine;
    uint32_t length, index, advance, glyph_width;
    uint32_t wobble_phase, first_offset, second_offset;
    uint32_t palette_width, palette_phase, palette_offset, fast;
} title_state;
#endif
