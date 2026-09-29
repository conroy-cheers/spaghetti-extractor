/* Typed application allocations and calls to existing portable neighbors.
 * As with the original malloc wrapper, payload bytes are not zero-filled. */
#include <stdlib.h>
#include "program-state.h"
#include "motion-runtime.h"
#include "brick-runtime.h"
#include "pickup-runtime.h"
#include "particle-runtime.h"
#include "explosion-runtime.h"
#include "shot-runtime.h"
#include "power-runtime.h"
#include "round-runtime.h"
#include "progress-runtime.h"
#include "play-runtime.h"
#include "paddle-runtime.h"
#include "warning-runtime.h"
#include "damage-runtime.h"
#include "font-runtime.h"
#include "title-runtime.h"
#include "palette-runtime.h"
#include "flow-runtime.h"
#include "runtime-support.h"

#define ALLOCATE(name, state_type, result_type, allocated_type) \
result_type *name(void *u, state_type *s) { (void)u; (void)s; return malloc(sizeof(allocated_type)); }
ALLOCATE(motion_allocate, motion_state, play_ball, play_ball)
ALLOCATE(brick_allocate_effect, brick_state, brick_effect, brick_effect)
ALLOCATE(brick_allocate_event, brick_state, play_event, play_event)
ALLOCATE(pickup_allocate, pickup_state, pickup, pickup)
ALLOCATE(particle_allocate, particle_state, particle, particle)
ALLOCATE(explosion_allocate, explosion_state, explosion, explosion)
ALLOCATE(shot_allocate, motion_state, struct spx_opaque_allocation_v5, play_shot)
ALLOCATE(power_allocate_ball, powerup_state, play_ball, play_ball)
ALLOCATE(power_allocate_cell, powerup_state, play_event, play_event)
#undef ALLOCATE
#define FREE(name, state_type, record_type, member) \
void name(void *u, state_type *s, record_type *record) { \
    (void)u; dxball_program_refresh_views(DXBALL_OWNER(s, member)); free(record); }
FREE(motion_free, motion_state, play_ball, motion)
FREE(brick_free_effect, brick_state, brick_effect, bricks)
FREE(pickup_free, pickup_state, pickup, pickups)
FREE(particle_free, particle_state, particle, particles)
FREE(explosion_free, explosion_state, explosion, explosions)
FREE(shot_free, motion_state, struct spx_opaque_allocation_v5, motion)
FREE(power_free_ball, powerup_state, play_ball, powers)
FREE(power_free_cell, powerup_state, play_event, powers)
FREE(play_free_event, play_state, play_event, play)
FREE(round_free, round_state, round_storage, round)
#undef FREE
#define TERMINATE(name, state_type) \
void name(void *u, state_type *s, uint32_t status) { (void)u; (void)s; exit((int)status); }
TERMINATE(shot_terminate, motion_state)
TERMINATE(power_terminate, powerup_state)
TERMINATE(particle_terminate, particle_state)
TERMINATE(explosion_terminate, explosion_state)
#undef TERMINATE

uint32_t font_service_find(void *u, font_state *s, uint32_t code) {
    (void)u; return fixture_font_find(s, code);
}
uint32_t font_service_measure(void *u, font_state *s, uint32_t length, font_bytes *bytes) {
    (void)u; return fixture_font_measure(s, length, bytes);
}
uint32_t motion_overlap(void *u, motion_state *s, font_rect *a, font_rect *b) {
    (void)u; return fixture_damage_overlap(&DXBALL_OWNER(s, motion)->damage, a, b);
}
uint32_t pickup_overlap(void *u, pickup_state *s, font_rect *a, font_rect *b) {
    (void)u; return fixture_damage_overlap(&DXBALL_OWNER(s, pickups)->damage, a, b);
}
uint32_t damage_now(void *u, damage_state *s) {
    (void)u; dxball_program *p = DXBALL_OWNER(s, damage);
    return fixture_runtime_now(&p->runtime, &p->clock_history);
}
uint32_t damage_elapsed(void *u, damage_state *s, uint32_t previous, uint32_t delay) {
    (void)u; return fixture_runtime_elapsed(&DXBALL_OWNER(s, damage)->runtime, previous, delay);
}
void damage_wait(void *u, damage_state *s, uint32_t count) {
    (void)u; fixture_runtime_wait(&DXBALL_OWNER(s, damage)->runtime, count);
}
void damage_recover(void *u, damage_state *s) {
    (void)u; fixture_flow_restore(&DXBALL_OWNER(s, damage)->flow);
}
uint32_t paddle_clock(void *u, paddle_state *s) {
    (void)u; return runtime_ticks(NULL, &DXBALL_OWNER(s, paddle)->runtime);
}
uint32_t warning_now(void *u, warning_state *s) {
    (void)u; return runtime_ticks(NULL, &DXBALL_OWNER(s, warning)->runtime);
}
void title_apply_palette(void *u, title_state *s, uint32_t first, uint32_t count) {
    (void)u; palette_apply(NULL, &DXBALL_OWNER(s, title)->palette, first, count);
}
