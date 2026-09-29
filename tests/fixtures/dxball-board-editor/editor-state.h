#ifndef DXBALL_EDITOR_STATE_H
#define DXBALL_EDITOR_STATE_H
#include "menu-state.h"
#include "board-state.h"
typedef struct { uint32_t left,top,right,bottom,enabled; } editor_region;
typedef struct spx_opaque_board_editor_v5 {
    menu_state *menu;
    board_set *boards;
    uint32_t selected_tile,index,region_count;
    editor_region regions[25];
} board_editor;
#endif
