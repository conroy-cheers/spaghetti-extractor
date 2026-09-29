#ifndef DXBALL_MOTION_STATE_H
#define DXBALL_MOTION_STATE_H
#include "play-state.h"
#include "board-state.h"

typedef struct spx_opaque_ball_motion_state_v5 {
    play_state *play;
    board *board;
    uint32_t ball_count,gravity,paddle_width,paddle_power,sticky,pierce;
    uint32_t impact_dx,impact_dy;
} motion_state;

static inline font_sprite *motion_sprite(motion_state *state,uint32_t slot) {
    struct spx_opaque_cleanup_state_v5 *objects=state->play->menu->scene->animation->font->objects;
    return objects->banks[objects->current_bank].slots[slot];
}
#endif
