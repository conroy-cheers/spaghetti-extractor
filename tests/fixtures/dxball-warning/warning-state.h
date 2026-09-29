#ifndef DXBALL_WARNING_STATE_H
#define DXBALL_WARNING_STATE_H
#include "progression-state.h"
typedef struct { uint32_t y,row,column; } warning_input;
typedef struct spx_opaque_warning_state_v5 {
    progression_state *progression;
    uint32_t x;
    font_rect rectangle;
    warning_input fallback;
} warning_state;
#endif
