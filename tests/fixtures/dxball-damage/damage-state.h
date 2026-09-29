#ifndef DXBALL_DAMAGE_STATE_H
#define DXBALL_DAMAGE_STATE_H
#include "scene-state.h"

typedef struct spx_opaque_damage_state_v5 {
    scene_state *scene;
    font_surface *background;
    uint32_t keys[2000];
    font_rect pending[2000];
    uint32_t count[2];
    font_rect history[1000][2];
    uint32_t pending_count, page, last_tick, clipped, capability;
} damage_state;
#endif
