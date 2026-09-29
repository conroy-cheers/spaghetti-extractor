/* The original scene table, expressed as calls to the existing components.
 * Scene 3 intentionally shares the menu leave operation. */
#include "program-state.h"
#include "flow-runtime.h"
#include "shell-runtime.h"
#include "bootstrap-runtime.h"
#include "menu-runtime.h"
#include "scene-runtime.h"
#include "screen-runtime.h"
#include "editor-runtime.h"
#include "game-scene/game-runtime.h"
#include "play-runtime.h"
#include "round-runtime.h"

void flow_initialize(void *u, flow_state *s) {
    (void)u;
    dxball_program *p = DXBALL_OWNER(s, flow);
    fixture_bootstrap_initialize(&p->bootstrap);
    dxball_program_refresh_views(p);
}
void flow_scene_enter(void *u, flow_state *s, uint32_t scene) {
    (void)u;
    dxball_program *p = DXBALL_OWNER(s, flow);
    dxball_program_refresh_views(p);
    switch (scene) {
    case 0: fixture_menu_enter(&p->menu); break;
    case 1: fixture_game_enter(&p->game); break;
    case 2: fixture_editor_enter(&p->editor); break;
    case 3: fixture_screen_enter(&p->screen); break;
    case 4: fixture_scene_enter(&p->scene); break;
    }
    dxball_program_refresh_views(p);
}
void flow_scene_update(void *u, flow_state *s, uint32_t scene) {
    (void)u;
    dxball_program *p = DXBALL_OWNER(s, flow);
    dxball_program_refresh_views(p);
    switch (scene) {
    case 0: fixture_menu_update(&p->menu); break;
    case 1: fixture_play_update(&p->play); break;
    case 2: fixture_editor_update(&p->editor); break;
    case 3: fixture_screen_update(&p->screen); break;
    case 4: fixture_scene_update(&p->scene); break;
    }
    dxball_program_refresh_views(p);
}
void flow_scene_key(void *u, flow_state *s, uint32_t scene, uint32_t key) {
    (void)u;
    dxball_program *p = DXBALL_OWNER(s, flow);
    dxball_program_refresh_views(p);
    switch (scene) {
    case 0: dxball_program_menu_key(p, key); break;
    case 1: fixture_game_key(&p->game, key); break;
    case 2: fixture_editor_key(&p->editor, key); break;
    case 3: fixture_screen_key(&p->screen, key); break;
    case 4: dxball_program_title_key(p, key); break;
    }
    dxball_program_refresh_views(p);
}
void flow_scene_leave(void *u, flow_state *s, uint32_t scene, uint32_t reason) {
    (void)u;
    dxball_program *p = DXBALL_OWNER(s, flow);
    dxball_program_refresh_views(p);
    switch (scene) {
    case 0: case 3: fixture_menu_leave(&p->menu, reason); break;
    case 1: fixture_round_leave(&p->round, reason); break;
    case 2: fixture_editor_leave(&p->editor, reason); break;
    case 4: fixture_scene_leave(&p->scene, reason); break;
    }
    dxball_program_refresh_views(p);
}
void flow_scene_redraw(void *u, flow_state *s, uint32_t scene) {
    (void)u;
    dxball_program *p = DXBALL_OWNER(s, flow);
    dxball_program_refresh_views(p);
    switch (scene) {
    case 0: fixture_menu_redraw(&p->menu); break;
    case 1: fixture_game_redraw(&p->game); break;
    case 2: fixture_editor_redraw(&p->editor); break;
    case 3: fixture_screen_redraw(&p->screen); break;
    case 4: fixture_scene_redraw(&p->scene); break;
    }
    dxball_program_refresh_views(p);
}
void flow_restore_banks(void *u, asset_state *s) {
    (void)u;
    fixture_sprite_restore(s);
}
void shell_frame(void *u, shell_state *s) {
    (void)u;
    dxball_program *p = DXBALL_OWNER(s, application);
    dxball_program_refresh_views(p);
    (void)fixture_flow_frame(&p->flow);
    dxball_program_refresh_views(p);
}
void shell_key(void *u, shell_state *s, uint32_t key) {
    (void)u;
    dxball_program *p = DXBALL_OWNER(s, application);
    dxball_program_refresh_views(p);
    fixture_flow_key(&p->flow, key);
    dxball_program_refresh_views(p);
}
void shell_leave_scene(void *u, shell_state *s, uint32_t reason) {
    (void)u;
    fixture_flow_leave(&DXBALL_OWNER(s, application)->flow, reason);
}
void shell_shutdown(void *u, shell_state *s, uint32_t reason) {
    (void)u;
    fixture_flow_shutdown(&DXBALL_OWNER(s, application)->flow, reason);
}

/* All platform window callbacks enter here, including nested dispatch while a
 * component is running. Preserve shell's order: key dispatch precedes writing
 * the modifier flag; readers are refreshed again when that event returns. */
uint32_t dxball_program_event(dxball_program *p, shell_handle *window,
                             uint32_t message, uint32_t wparam, uint32_t lparam) {
    dxball_program_refresh_views(p);
    uint32_t result = fixture_shell_event(&p->application, window, message, wparam, lparam);
    dxball_program_refresh_views(p);
    return result;
}
