/* Neighbor calls use the one program owner, with no native-image transport. */
#include "program-state.h"
#include "scene-runtime.h"
#include "title-runtime.h"
#include "flow-runtime.h"
#include "asset-runtime.h"
#include "drawing-runtime.h"
#include "damage-runtime.h"
#include "bootstrap-runtime.h"
#include "pcx-runtime.h"
#include "palette-runtime.h"
#include "raster-runtime.h"
#include "runtime-support.h"
#include "music-runtime.h"

void scene_reset_damage(void *u, scene_state *s) {
    (void)u; fixture_damage_reset(&DXBALL_OWNER(s, scene)->damage);
}
void scene_restore_damage(void *u, scene_state *s) {
    (void)u; fixture_damage_restore(&DXBALL_OWNER(s, scene)->damage);
}
void scene_present(void *u, scene_state *s) {
    (void)u; fixture_damage_present(&DXBALL_OWNER(s, scene)->damage);
}
void scene_clear(void *u, scene_state *s, font_surface *surface, uint32_t color) {
    (void)u; fixture_bootstrap_clear(&DXBALL_OWNER(s, scene)->bootstrap, surface, color);
}
void scene_image(void *u, scene_state *s, font_surface *surface, asset_name *name,
                 uint32_t palette, uint32_t x, uint32_t y) {
    (void)u; fixture_pcx_draw(s->animation->palettes, surface, name, palette, x, y);
}
void scene_load_bank(void *u, scene_state *s, uint32_t bank, uint32_t mode, asset_name *name) {
    (void)u; fixture_sprite_load(s->animation->flow->sprites, bank, mode, name);
}
void scene_select_bank(void *u, scene_state *s, uint32_t bank) {
    (void)u; fixture_select(s->animation->font->objects, bank);
}
void scene_select_font(void *u, scene_state *s, uint32_t bank) {
    (void)u; fixture_font_select(s->animation->font, bank);
}
void scene_damage_background(void *u, scene_state *s, font_surface *surface) {
    (void)u; fixture_damage_background(&DXBALL_OWNER(s, scene)->damage, surface);
}
void scene_damage_destination(void *u, scene_state *s, font_surface *surface) {
    (void)u; fixture_damage_destination(&DXBALL_OWNER(s, scene)->damage, surface);
}
void scene_redraw_scene(void *u, scene_state *s) {
    (void)u; fixture_flow_redraw(s->animation->flow);
}
void scene_fade(void *u, scene_state *s, uint32_t wait, uint32_t step,
                uint32_t first, uint32_t last, uint32_t direction) {
    (void)u; fixture_palette_fade(&DXBALL_OWNER(s, scene)->palette, wait, step, first, last, direction);
}
void scene_fill(void *u, scene_state *s, font_surface *surface,
                uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2, uint32_t color) {
    (void)u; (void)s; fixture_raster_fill(surface, x1, y1, x2, y2, color);
}
void scene_line(void *u, scene_state *s, font_surface *surface,
                uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2, uint32_t color) {
    (void)u; (void)s; fixture_raster_line(surface, x1, y1, x2, y2, color);
}
void scene_wobble(void *u, scene_state *s) { (void)u; fixture_title_wobble(s->animation); }
void scene_scroll(void *u, scene_state *s) { (void)u; fixture_title_scroll(s->animation); }
void scene_wave(void *u, scene_state *s) { (void)u; fixture_title_wave(s->animation); }
void scene_cycle(void *u, scene_state *s) { (void)u; fixture_title_cycle(s->animation); }
void scene_sprite_destination(void *u, scene_state *s, font_surface *surface) {
    (void)u; fixture_sprite_destination(s->animation->font, surface);
}
void scene_text(void *u, scene_state *s, uint32_t x, uint32_t y, uint32_t length, font_bytes *bytes) {
    (void)u; (void)fixture_font_line(s->animation->font, x, y, length, bytes);
}
void scene_center(void *u, scene_state *s, uint32_t x, uint32_t y, uint32_t length, font_bytes *bytes) {
    (void)u; (void)fixture_font_center(s->animation->font, x, y, length, bytes);
}
void scene_wait(void *u, scene_state *s, uint32_t count) {
    (void)u; fixture_runtime_wait(&DXBALL_OWNER(s, scene)->runtime, count);
}
void scene_rotate_palette(void *u, scene_state *s, uint32_t first, uint32_t count) {
    (void)u; palette_sequence sequence = {s->palette_cycle};
    fixture_palette_rotate(&DXBALL_OWNER(s, scene)->palette, first, count, &sequence);
}
void scene_release_banks(void *u, scene_state *s) {
    (void)u; fixture_clear(s->animation->font->objects);
}
void scene_release_track(void *u, scene_state *s) {
    (void)u; fixture_music_stop(&DXBALL_OWNER(s, scene)->music);
}
void title_select_font(void *u, font_state *s, uint32_t bank) {
    (void)u; fixture_font_select(s, bank);
}
void title_destination(void *u, font_state *s, font_surface *surface) {
    (void)u; fixture_sprite_destination(s, surface);
}
uint32_t title_glyph(void *u, font_state *s, uint32_t x, uint32_t y, uint32_t glyph) {
    (void)u; return fixture_font_glyph(s, x, y, glyph);
}
