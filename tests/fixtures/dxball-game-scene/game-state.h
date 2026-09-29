#ifndef DXBALL_GAME_SCENE_STATE_H
#define DXBALL_GAME_SCENE_STATE_H
#include "progression-state.h"
#include "damage-state.h"
typedef struct spx_opaque_game_scene_state_v5 {
    progression_state *progression;
    damage_state *damage;
    double stereo_direction;
} game_scene_state;
#endif
