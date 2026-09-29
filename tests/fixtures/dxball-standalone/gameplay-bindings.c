/* Application composition: these are calls to previously lifted components,
 * preserving the native service targets and the common program owner. */
#include "program-state.h"
#include "play-runtime.h"
#include "motion-runtime.h"
#include "brick-runtime.h"
#include "pickup-runtime.h"
#include "paddle-runtime.h"
#include "shot-runtime.h"
#include "particle-runtime.h"
#include "explosion-runtime.h"
#include "power-runtime.h"
#include "progress-runtime.h"
#include "round-runtime.h"
#include "warning-runtime.h"
#include "game-scene/game-runtime.h"
#include "damage-runtime.h"
#include "drawing-runtime.h"
#include "menu-runtime.h"
#include "flow-runtime.h"
#include "render-runtime.h"
#include "board-runtime.h"
#include "palette-runtime.h"
#include "runtime-support.h"
#include "math-runtime.h"
#include "pcx-runtime.h"
#include "lifecycle-runtime.h"
#include "music-runtime.h"

/* Publish aliases both before a possibly reentrant neighbor and on return. */
#define OWNER(type, member) (void)u; dxball_program *p = DXBALL_OWNER(s, member); dxball_program_refresh_views(p)
#define DONE() dxball_program_refresh_views(p)
#define CALL0(name, type, member, call) \
void name(void *u, type *s) { OWNER(type, member); call; DONE(); }

CALL0(play_refresh_score, play_state, play, fixture_progress_refresh(&p->progression))
CALL0(play_move_paddle, play_state, play, fixture_paddle_move(&p->paddle))
CALL0(play_move_balls, play_state, play, fixture_motion_update(&p->motion))
CALL0(play_move_shots, play_state, play, fixture_shot_update(&p->motion))
CALL0(play_move_pickups, play_state, play, fixture_pickup_update(&p->pickups))
CALL0(play_move_trails, play_state, play, fixture_particle_update(&p->particles))
CALL0(play_restore_damage, play_state, play, fixture_damage_restore(&p->damage))
CALL0(play_advance_brick_effects, play_state, play, fixture_brick_advance(&p->bricks))
CALL0(play_draw_explosions, play_state, play, fixture_explosion_draw(&p->explosions))
CALL0(play_draw_paddle, play_state, play, fixture_paddle_draw(&p->paddle))
CALL0(play_draw_pickups, play_state, play, fixture_pickup_draw(&p->pickups))
CALL0(play_draw_trails, play_state, play, fixture_particle_draw(&p->particles))
CALL0(play_present, play_state, play, fixture_damage_present(&p->damage))
CALL0(play_split, play_state, play, fixture_power_split(&p->powers))
CALL0(play_power, play_state, play, fixture_power_super(&p->powers))
CALL0(play_next_board, play_state, play, fixture_progress_next(&p->progression))
CALL0(play_advance_stage, play_state, play, fixture_progress_advance(&p->progression))
CALL0(play_fire, play_state, play, fixture_shot_fire(&p->motion))
/* Last-brick preparation needs the reviewed stack-history input. It remains a
 * separate binding until that input is supplied by the complete frame path. */
CALL0(play_draw_last_brick, play_state, play, fixture_warning_draw(&p->warning))

CALL0(motion_paddle_power, motion_state, motion, fixture_power_drop(&p->powers))
CALL0(motion_unstick, motion_state, motion, fixture_power_soften(&p->powers))
CALL0(motion_lose_life, motion_state, motion, fixture_progress_lose(&p->progression))
CALL0(pickup_next_board, pickup_state, pickups, fixture_progress_next(&p->progression))
CALL0(pickup_unstick, pickup_state, pickups, fixture_power_soften(&p->powers))
CALL0(pickup_queue_explosive_bricks, pickup_state, pickups, fixture_power_expand(&p->powers))
CALL0(pickup_detonate_bricks, pickup_state, pickups, fixture_power_detonate(&p->powers))
CALL0(pickup_release_attached, pickup_state, pickups, fixture_power_release(&p->powers))
CALL0(pickup_move_paddle, pickup_state, pickups, fixture_paddle_move(&p->paddle))
CALL0(pickup_lose_life, pickup_state, pickups, fixture_progress_lose(&p->progression))
CALL0(power_rebound, powerup_state, powers, fixture_motion_rebound(&p->motion))
CALL0(progress_load_board, progression_state, progression, fixture_brick_reset(&p->bricks))
CALL0(progress_redraw, progression_state, progression, fixture_flow_redraw(&p->flow))
CALL0(progress_create_ball, progression_state, progression, fixture_motion_create(&p->motion))
CALL0(progress_clear_objects, progression_state, progression, dxball_program_clear_objects(p))
CALL0(progress_reset_damage, progression_state, progression, fixture_damage_reset(&p->damage))
CALL0(game_load_board, game_scene_state, game, fixture_brick_reset(&p->bricks))
CALL0(game_restart, game_scene_state, game, fixture_progress_restart(&p->progression))
CALL0(game_reset_damage, game_scene_state, game, fixture_damage_reset(&p->damage))
CALL0(game_draw_score, game_scene_state, game, fixture_progress_draw(&p->progression))
CALL0(game_redraw_scene, game_scene_state, game, fixture_flow_redraw(&p->flow))
CALL0(game_stop_music, game_scene_state, game, fixture_music_stop(&p->music))
CALL0(round_clear_sprites, round_state, round, fixture_clear(&p->objects))
CALL0(round_stop_music, round_state, round, fixture_music_stop(&p->music))
#undef CALL0

#define RANDOM(prefix, type, member) \
uint32_t prefix##_random(void *u, type *s, uint32_t limit) { \
    OWNER(type, member); uint32_t result = fixture_runtime_random(&p->runtime, limit); DONE(); return result; \
}
RANDOM(play, play_state, play)
RANDOM(motion, motion_state, motion)
RANDOM(brick, brick_state, bricks)
RANDOM(pickup, pickup_state, pickups)
RANDOM(paddle, paddle_state, paddle)
RANDOM(shot, motion_state, motion)
RANDOM(game, game_scene_state, game)
RANDOM(warning, warning_state, warning)
#undef RANDOM
#define PAN(prefix, type) \
uint32_t prefix##_pan(void *u, type *s, uint32_t x) { (void)u; (void)s; return fixture_math_pan(x); }
PAN(motion, motion_state)
PAN(brick, brick_state)
PAN(pickup, pickup_state)
PAN(shot, motion_state)
PAN(progress, progression_state)
#undef PAN
#define NOW(prefix, type, member) \
uint32_t prefix##_now(void *u, type *s) { OWNER(type, member); \
    uint32_t result = fixture_runtime_now(&p->runtime, &p->clock_history); DONE(); return result; }
NOW(play, play_state, play)
NOW(paddle, paddle_state, paddle)
#undef NOW
#define ELAPSED(prefix, type, member) \
uint32_t prefix##_elapsed(void *u, type *s, uint32_t previous, uint32_t delay) { OWNER(type, member); \
    uint32_t result = fixture_runtime_elapsed(&p->runtime, previous, delay); DONE(); return result; }
ELAPSED(play, play_state, play)
ELAPSED(paddle, paddle_state, paddle)
#undef ELAPSED

void play_wait(void *u, play_state *s, uint32_t count) {
    OWNER(play_state, play); fixture_runtime_wait(&p->runtime, count); DONE();
}
void progress_wait(void *u, progression_state *s, uint32_t count) {
    OWNER(progression_state, progression); fixture_runtime_wait(&p->runtime, count); DONE();
}
void play_cycle(void *u, play_state *s, uint32_t first, uint32_t last, uint32_t amount) {
    OWNER(play_state, play); fixture_palette_left(&p->palette, first, last, amount); DONE();
}
void play_hit_tile(void *u, play_state *s, uint32_t column, uint32_t row) {
    OWNER(play_state, play); fixture_brick_blast(&p->bricks, column, row); DONE();
}
#define HIT(prefix, type, member) \
uint32_t prefix##_hit(void *u, type *s, uint32_t column, uint32_t row) { OWNER(type, member); \
    uint32_t result = fixture_brick_hit(&p->bricks, column, row); DONE(); return result; }
HIT(motion, motion_state, motion)
HIT(shot, motion_state, motion)
HIT(power, powerup_state, powers)
#undef HIT
#define PARTICLE(prefix, type, member) \
void prefix##_particle(void *u, type *s, uint32_t x, uint32_t y, uint32_t dx, uint32_t dy, uint32_t color, uint32_t gravity) { \
    OWNER(type, member); fixture_particle_create(&p->particles, x, y, dx, dy, color, gravity); DONE(); }
PARTICLE(motion, motion_state, motion)
PARTICLE(brick, brick_state, bricks)
PARTICLE(pickup, pickup_state, pickups)
PARTICLE(warning, warning_state, warning)
#undef PARTICLE
void play_spawn_debris(void *u, play_state *s, uint32_t column, uint32_t row, uint32_t dx, uint32_t dy) {
    OWNER(play_state, play); fixture_pickup_create(&p->pickups, column, row, dx, dy); DONE();
}
void brick_debris(void *u, brick_state *s, uint32_t column, uint32_t row, uint32_t dx, uint32_t dy) {
    OWNER(brick_state, bricks); fixture_pickup_create(&p->pickups, column, row, dx, dy); DONE();
}
void motion_explosion(void *u, motion_state *s, uint32_t x, uint32_t y) {
    OWNER(motion_state, motion); fixture_explosion_create(&p->explosions, x, y); DONE();
}
void warning_explosion(void *u, warning_state *s, uint32_t x, uint32_t y) {
    OWNER(warning_state, warning); fixture_explosion_create(&p->explosions, x, y); DONE();
}
void warning_queue(void *u, warning_state *s, uint32_t column, uint32_t row) {
    OWNER(warning_state, warning); fixture_brick_queue(&p->bricks, column, row); DONE();
}

#define SPRITE(name, type, member, operation) \
void name(void *u, type *s, uint32_t slot, uint32_t x, uint32_t y) { \
    OWNER(type, member); (void)operation; DONE(); }
SPRITE(play_sprite, play_state, play, (warning_history_frame_sprite(&p->frame_history), fixture_damage_transparent(&p->damage, slot, x, y)))
SPRITE(paddle_sprite, paddle_state, paddle, (warning_history_paddle(&p->frame_history, slot, p->play.paddle_y-y), fixture_damage_transparent(&p->damage, slot, x, y)))
SPRITE(pickup_sprite, pickup_state, pickups, (warning_history_pickup_sprite(&p->frame_history), fixture_damage_opaque(&p->damage, slot, x, y)))
SPRITE(explosion_sprite, explosion_state, explosions, fixture_damage_transparent(&p->damage, slot, x, y))
SPRITE(brick_sprite_fast, brick_state, bricks, fixture_damage_opaque(&p->damage, slot, x, y))
SPRITE(brick_sprite_opaque, brick_state, bricks, fixture_sprite_opaque(&p->font, slot, x, y))
SPRITE(brick_sprite_transparent, brick_state, bricks, fixture_sprite_transparent(&p->font, slot, x, y))
SPRITE(progress_sprite, progression_state, progression, fixture_sprite_transparent(&p->font, slot, x, y))
#undef SPRITE

void brick_select_board(void *u, brick_state *s, uint32_t index) {
    OWNER(brick_state, bricks); fixture_board_select(&p->boards, index); DONE();
}
void brick_cell(void *u, brick_state *s, uint32_t column, uint32_t row, uint32_t mode) {
    OWNER(brick_state, bricks); fixture_render_cell(&p->renderer, column, row, mode); DONE();
}
void power_cell(void *u, powerup_state *s, uint32_t column, uint32_t row, uint32_t mode) {
    OWNER(powerup_state, powers); fixture_render_cell(&p->renderer, column, row, mode); DONE();
}
#define DESTINATION(prefix, type, member) \
void prefix##_destination(void *u, type *s, font_surface *surface) { \
    OWNER(type, member); fixture_sprite_destination(&p->font, surface); DONE(); }
DESTINATION(brick, brick_state, bricks)
DESTINATION(power, powerup_state, powers)
DESTINATION(progress, progression_state, progression)
#undef DESTINATION
void brick_erase(void *u, brick_state *s, font_rect *rectangle) {
    OWNER(brick_state, bricks); fixture_damage_erase(&p->damage, rectangle); DONE();
}
void progress_text(void *u, progression_state *s, uint32_t x, uint32_t y, uint32_t length, font_bytes *bytes) {
    OWNER(progression_state, progression); (void)fixture_font_line(&p->font, x, y, length, bytes); DONE();
}
void progress_palette(void *u, progression_state *s, asset_name *name) {
    OWNER(progression_state, progression); fixture_pcx_palette_staged(&p->colors, name); DONE();
}

/* Reuse shared scene services instead of introducing another platform API. */
#define FADE(prefix, type, member) \
void prefix##_fade(void *u, type *s, uint32_t wait, uint32_t step, uint32_t first, uint32_t last, uint32_t direction) { \
    OWNER(type, member); scene_fade(NULL, &p->scene, wait, step, first, last, direction); DONE(); }
FADE(progress, progression_state, progression)
FADE(game, game_scene_state, game)
FADE(round, round_state, round)
#undef FADE
#define CLEAR(name, type, member) \
void name(void *u, type *s, font_surface *surface, uint32_t color) { \
    OWNER(type, member); scene_clear(NULL, &p->scene, surface, color); DONE(); }
CLEAR(progress_clear, progression_state, progression)
CLEAR(game_clear, game_scene_state, game)
CLEAR(round_clear_surface, round_state, round)
#undef CLEAR
#define BLIT(prefix, type, member) \
void prefix##_blit(void *u, type *s, font_surface *destination, font_rect *dr, font_surface *source, font_rect *sr, uint32_t flags) { \
    OWNER(type, member); scene_blit(NULL, &p->scene, destination, dr, source, sr, flags); DONE(); }
BLIT(game, game_scene_state, game)
BLIT(power, powerup_state, powers)
#undef BLIT
#define FAST(prefix, type, member) \
void prefix##_blit_fast(void *u, type *s, font_surface *destination, uint32_t x, uint32_t y, font_surface *source, font_rect *rectangle, uint32_t flags) { \
    OWNER(type, member); menu_blit_fast(NULL, &p->menu, destination, x, y, source, rectangle, flags); DONE(); }
FAST(brick, brick_state, bricks)
FAST(paddle, paddle_state, paddle)
FAST(progress, progression_state, progression)
FAST(warning, warning_state, warning)
#undef FAST

void game_image(void *u, game_scene_state *s, font_surface *surface, asset_name *name, uint32_t palette, uint32_t x, uint32_t y) {
    OWNER(game_scene_state, game); scene_image(NULL, &p->scene, surface, name, palette, x, y); DONE();
}
void game_load_bank(void *u, game_scene_state *s, uint32_t bank, uint32_t mode, asset_name *name) {
    OWNER(game_scene_state, game); scene_load_bank(NULL, &p->scene, bank, mode, name); DONE();
}
void game_load_sound(void *u, game_scene_state *s, uint32_t slot, asset_name *name) {
    OWNER(game_scene_state, game); scene_load_sound(NULL, &p->scene, slot, name); DONE();
}
void game_select_bank(void *u, game_scene_state *s, uint32_t bank) {
    OWNER(game_scene_state, game); fixture_select(&p->objects, bank); DONE();
}
void warning_select_bank(void *u, warning_state *s, uint32_t bank) {
    OWNER(warning_state, warning); fixture_select(&p->objects, bank); DONE();
}
void game_select_font(void *u, game_scene_state *s, uint32_t bank) {
    OWNER(game_scene_state, game); fixture_font_select(&p->font, bank); DONE();
}
void game_create_sprite(void *u, game_scene_state *s, uint32_t slot, uint32_t left, uint32_t top, uint32_t right, uint32_t bottom) {
    OWNER(game_scene_state, game); (void)fixture_sprite_capture(&p->assets, &p->font, slot, left, top, right, bottom); DONE();
}
void game_damage_background(void *u, game_scene_state *s, font_surface *surface) {
    OWNER(game_scene_state, game); fixture_damage_background(&p->damage, surface); DONE();
}
void game_damage_destination(void *u, game_scene_state *s, font_surface *surface) {
    OWNER(game_scene_state, game); fixture_damage_destination(&p->damage, surface); DONE();
}
void game_draw_board(void *u, game_scene_state *s, uint32_t mode) {
    OWNER(game_scene_state, game); fixture_render_draw(&p->renderer, mode); DONE();
}
void game_center(void *u, game_scene_state *s, uint32_t x, uint32_t y, uint32_t length, font_bytes *bytes) {
    OWNER(game_scene_state, game); (void)fixture_font_center(&p->font, x, y, length, bytes); DONE();
}
void game_play_music(void *u, game_scene_state *s, asset_name *name, uint32_t loop) {
    OWNER(game_scene_state, game); menu_load_track(NULL, &p->menu, name, loop); DONE();
}

/* Existing bridge post-call hooks publish borrowed views; they are not exits. */
void game_exit(game_scene_state *s) { dxball_program_refresh_views(DXBALL_OWNER(s, game)); }
void round_exit(round_state *s) { dxball_program_refresh_views(DXBALL_OWNER(s, round)); }
