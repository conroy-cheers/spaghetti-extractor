#ifndef DXBALL_POWER_STATE_H
#define DXBALL_POWER_STATE_H
#include "motion-state.h"
typedef struct spx_opaque_powerup_state_v5 {
    motion_state *motion;
    play_balls staged_balls;
    play_events queued_cells;
} powerup_state;
#endif
