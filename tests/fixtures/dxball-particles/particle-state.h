#ifndef DXBALL_PARTICLE_STATE_H
#define DXBALL_PARTICLE_STATE_H
#include "pcx-state.h"
typedef struct spx_opaque_particle_v5 particle;
struct spx_opaque_particle_v5 {
    uint32_t x,y,dx,dy,gravity,gravity_tick,color,age,color_tick;
    particle *next,*previous;
};
typedef struct spx_opaque_particle_state_v5 {
    font_surface **destination;
    particle *current,*first,*last;
} particle_state;
#endif
