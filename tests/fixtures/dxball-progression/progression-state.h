#ifndef DXBALL_PROGRESSION_STATE_H
#define DXBALL_PROGRESSION_STATE_H
#include "paddle-state.h"
#include "brick-state.h"
typedef struct spx_opaque_progression_state_v5 {
    paddle_state *paddle;
    brick_state *bricks;
    uint32_t pending,board_changed,warning_y,warning_frames;
} progression_state;
#endif
