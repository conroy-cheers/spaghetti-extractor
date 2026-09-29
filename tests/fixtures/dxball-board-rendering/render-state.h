#ifndef DXBALL_RENDER_STATE_H
#define DXBALL_RENDER_STATE_H
#include "menu-state.h"
#include "board-state.h"
typedef struct spx_opaque_board_renderer_v5 {
    menu_state *menu;
    board_set *boards;
} board_renderer;
#endif
