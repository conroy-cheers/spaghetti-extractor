#ifndef DXBALL_PADDLE_STATE_H
#define DXBALL_PADDLE_STATE_H
#include "pickup-state.h"
typedef struct spx_opaque_paddle_state_v5 {
    pickup_state *pickups;
    uint32_t phase,last_tick,spark_deadline,spark_width,spark_sprite;
} paddle_state;
#endif
