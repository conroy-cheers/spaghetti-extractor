#ifndef DXBALL_PICKUP_STATE_H
#define DXBALL_PICKUP_STATE_H
#include "motion-state.h"
typedef struct spx_opaque_pickup_v5 pickup;
struct spx_opaque_pickup_v5 {
    uint32_t kind,sprite,x,y,dx,dy,tick;
    pickup *next,*previous;
};
typedef struct spx_opaque_pickup_state_v5 {
    motion_state *motion;
    pickup *current,*first,*last;
    uint32_t count,lives,next_life,paddle_sprite;
} pickup_state;
#endif
