#ifndef DXBALL_SCORE_SCREEN_STATE_H
#define DXBALL_SCORE_SCREEN_STATE_H
#include "menu-state.h"
#include "scores-state.h"
typedef struct spx_opaque_score_screen_v5 {
    menu_state *menu;
    scores_state *scores;
    char name[40];
    uint32_t length, blink, entering, last_tick, show_table, highlight, shift;
} score_screen;
#endif
