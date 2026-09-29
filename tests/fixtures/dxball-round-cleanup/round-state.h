#ifndef DXBALL_ROUND_STATE_H
#define DXBALL_ROUND_STATE_H
#include "progression-state.h"
#include "power-state.h"
#include "particle-state.h"
#include "explosion-state.h"
typedef struct spx_opaque_round_storage_v5 round_storage;
typedef struct spx_opaque_round_state_v5 {
    progression_state *progression;
    powerup_state *powers;
    particle_state *particles;
    explosion_state *explosions;
} round_state;
#endif
