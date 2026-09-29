#ifndef DXBALL_SCENE_STATE_H
#define DXBALL_SCENE_STATE_H
#include "title-state.h"
typedef struct spx_opaque_scene_state_v5 {
    title_state *animation;
    font_surface *flip;
    uint32_t presentation_mode, no_hardware, low_memory, refresh_ok;
    uint32_t mouse_x, mouse_y, cursor_x, cursor_y, mouse_buttons, scroll_auxiliary;
    uint32_t palette_cycle[66];
} scene_state;
#endif
