#ifndef DXBALL_EXPLOSION_STATE_H
#define DXBALL_EXPLOSION_STATE_H
#include "play-state.h"
typedef struct spx_opaque_explosion_v5 explosion;
struct spx_opaque_explosion_v5 {
    uint32_t x,y,frame;
    explosion *next,*previous;
};
typedef struct spx_opaque_explosion_state_v5 {
    play_effects *roots;
    explosion *last;
    uint32_t retained;
} explosion_state;
/* The frame copies/tests these opaque identities; the owner accesses payloads. */
static inline explosion *explosion_current(explosion_state *state) { return (void *)state->roots->current; }
static inline explosion *explosion_first(explosion_state *state) { return (void *)state->roots->first; }
#endif
