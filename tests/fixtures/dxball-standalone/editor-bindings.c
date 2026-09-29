#include "program-state.h"
#include "editor-runtime.h"
#include "render-runtime.h"
#include "regions-runtime.h"
#include "drawing-runtime.h"
#include "damage-runtime.h"

#define EDITOR_PUSH() ((void)0)
#define EDITOR_PULL() ((void)0)
#include "editor-common.h"

uint32_t editor_sprite_id(void *u, uint32_t kind) { (void)u; return fixture_board_sprite(kind); }
void editor_select_board(void *u, board_set *s, uint32_t index) { (void)u; fixture_board_select(s, index); }
void editor_store_board(void *u, board_set *s, uint32_t index) { (void)u; fixture_board_store(s, index); }
void editor_load_boards(void *u, board_set *s, board_name *name) { (void)u; fixture_board_load(s, name); }
void editor_save_boards(void *u, board_set *s, board_name *name) { (void)u; fixture_board_save(s, name); }
void editor_sprite(void *u, menu_state *s, uint32_t slot, uint32_t x, uint32_t y) {
    (void)u; (void)fixture_sprite_opaque(s->scene->animation->font, slot, x, y);
}
void editor_reset_regions(void *u, board_editor *s, uint32_t count) {
    (void)u; fixture_regions_reset(&DXBALL_OWNER(s, editor)->regions, count);
}
void editor_define_region(void *u, board_editor *s, uint32_t index, font_rect *rectangle) {
    (void)u; fixture_regions_define(&DXBALL_OWNER(s, editor)->regions, index,
        rectangle->left, rectangle->top, rectangle->right, rectangle->bottom);
}
uint32_t editor_hit_region(void *u, board_editor *s, uint32_t x, uint32_t y) {
    (void)u; return fixture_regions_hit(&DXBALL_OWNER(s, editor)->regions, x, y);
}
void editor_cursor(void *u, board_editor *s, uint32_t slot, uint32_t x, uint32_t y) {
    (void)u; fixture_damage_transparent(&DXBALL_OWNER(s, editor)->damage, slot, x, y);
}
void editor_draw_board(void *u, board_editor *s, uint32_t mode) {
    (void)u; fixture_render_draw(&DXBALL_OWNER(s, editor)->renderer, mode);
}
void editor_draw_cell(void *u, board_editor *s, uint32_t column, uint32_t row, uint32_t mode) {
    (void)u; fixture_render_cell(&DXBALL_OWNER(s, editor)->renderer, column, row, mode);
}
void render_sprite_destination(void *u, scene_state *s, font_surface *surface) {
    scene_sprite_destination(u, s, surface);
}
void render_sprite(void *u, menu_state *s, uint32_t slot, uint32_t x, uint32_t y) {
    editor_sprite(u, s, slot, x, y);
}
void render_blit_fast(void *u, menu_state *s, font_surface *destination, uint32_t x, uint32_t y,
                      font_surface *source, font_rect *rectangle, uint32_t flags) {
    menu_blit_fast(u, s, destination, x, y, source, rectangle, flags);
}
void render_damage(void *u, menu_state *s, font_rect *rectangle) { menu_damage(u, s, rectangle); }
