#ifndef DXBALL_MENU_STATE_H
#define DXBALL_MENU_STATE_H
#include "scene-state.h"
typedef struct { uint32_t x, y, phase, kind; } menu_dot;
typedef struct spx_opaque_menu_state_v5 {
    scene_state *scene;
    const int32_t *cosine;
    uint32_t score, input_ready, last_tick;
    menu_dot dots[287];
    uint32_t offsets[360][2];
} menu_state;
#endif
