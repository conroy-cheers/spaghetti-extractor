#ifndef DXBALL_BRICK_STATE_H
#define DXBALL_BRICK_STATE_H
#include "motion-state.h"

typedef struct spx_opaque_brick_effect_v5 brick_effect;
struct spx_opaque_brick_effect_v5 {
    uint32_t kind,sprite,x,y;
    unsigned char tile,retained[3];
    uint32_t frames,delay,tick;
    brick_effect *next,*previous;
};
typedef struct spx_opaque_brick_state_v5 {
    motion_state *motion;
    brick_effect *current,*first,*last;
    uint32_t board_index;
} brick_state;
static inline title_state *brick_title(brick_state *state) {
    return state->motion->play->menu->scene->animation;
}
#endif
