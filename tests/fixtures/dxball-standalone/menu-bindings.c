#include "program-state.h"
#include "menu-runtime.h"
#include "title-runtime.h"
#include "drawing-runtime.h"
#include "damage-runtime.h"
#include "music-runtime.h"
#include "runtime-support.h"
#include "palette-runtime.h"
#include "pcx-runtime.h"

/* These forwarders previously published native-image snapshots. All their
 * objects now have the same C owner. Nested events must use program_event. */
#define MENU_COMMON_PUSH() ((void)0)
#define MENU_COMMON_PULL() ((void)0)
#include "menu-common.h"

void menu_text(void *u, scene_state *s, uint32_t x, uint32_t y, uint32_t length, font_bytes *bytes) {
    scene_text(u, s, x, y, length, bytes);
}
void menu_center(void *u, scene_state *s, uint32_t x, uint32_t y, uint32_t length, font_bytes *bytes) {
    scene_center(u, s, x, y, length, bytes);
}
void menu_load_track(void *u, menu_state *s, asset_name *name, uint32_t mode) {
    (void)u; music_name track = {name->text};
    (void)fixture_music_play(&DXBALL_OWNER(s, menu)->music, &track, mode);
}
uint32_t menu_elapsed(void *u, menu_state *s, uint32_t previous, uint32_t delay) {
    (void)u; return fixture_runtime_elapsed(&DXBALL_OWNER(s, menu)->runtime, previous, delay);
}
uint32_t menu_now(void *u, menu_state *s) {
    (void)u; dxball_program *p = DXBALL_OWNER(s, menu);
    return fixture_runtime_now(&p->runtime, &p->clock_history);
}
void menu_blit_fast(void *u, menu_state *s, font_surface *destination, uint32_t x, uint32_t y,
                    font_surface *source, font_rect *rectangle, uint32_t flags) {
    title_blit_fast(u, s->scene->animation, destination, x, y, source, rectangle, flags);
}
void menu_describe(void *u, font_surface *surface, pcx_view *view) { pcx_describe(u, surface, view); }
uint32_t menu_lock(void *u, font_surface *surface, pcx_view *view) { return pcx_lock(u, surface, view); }
void menu_unlock(void *u, font_surface *surface) { pcx_unlock(u, surface); }
void menu_sprite(void *u, menu_state *s, uint32_t slot, uint32_t x, uint32_t y) {
    (void)u; (void)fixture_sprite_transparent(s->scene->animation->font, slot, x, y);
}
void menu_cycle_palette(void *u, menu_state *s, uint32_t first, uint32_t last, uint32_t step) {
    (void)u; fixture_palette_right(&DXBALL_OWNER(s, menu)->palette, first, last, step);
}
void menu_cycle_dots_palette(void *u, menu_state *s, uint32_t first, uint32_t last, uint32_t step) {
    (void)u; fixture_palette_left(&DXBALL_OWNER(s, menu)->palette, first, last, step);
}
