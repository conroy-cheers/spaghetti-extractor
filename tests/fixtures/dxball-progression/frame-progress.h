/* Actual frame consumer; state and retained observations are shared with local cases. */
#include "play-runtime.h"
void play_enter(void) { ++frame_entries; }
static void frame_call(unsigned op,const uint32_t *args,unsigned count) { begin(&progress,100+op,args,count); (void)end(0); }
#define FRAME0(name,op) void play_##name(void *u,play_state *s) { (void)u; REQUIRE(s==&play); frame_call(op,NULL,0); }
FRAME0(move_paddle,PLAY_MOVE_PADDLE) FRAME0(move_shots,PLAY_MOVE_SHOTS) FRAME0(move_trails,PLAY_MOVE_TRAILS)
FRAME0(move_pickups,PLAY_MOVE_PICKUPS) FRAME0(draw_pickups,PLAY_DRAW_PICKUPS) FRAME0(restore_damage,PLAY_RESTORE_DAMAGE)
FRAME0(advance_brick_effects,PLAY_ADVANCE_BRICK_EFFECTS) FRAME0(draw_explosions,PLAY_DRAW_EXPLOSIONS)
FRAME0(draw_paddle,PLAY_DRAW_PADDLE) FRAME0(draw_trails,PLAY_DRAW_TRAILS) FRAME0(prepare_last_brick,PLAY_PREPARE_LAST_BRICK)
FRAME0(draw_last_brick,PLAY_DRAW_LAST_BRICK) FRAME0(present,PLAY_PRESENT) FRAME0(fire,PLAY_FIRE)
FRAME0(split,PLAY_SPLIT) FRAME0(power,PLAY_POWER)
#undef FRAME0
void play_refresh_score(void *u,play_state *s) { (void)u; REQUIRE(s==&play); fixture_progress_refresh(&progress); }
void play_next_board(void *u,play_state *s) { (void)u; REQUIRE(s==&play); fixture_progress_next(&progress); }
void play_advance_stage(void *u,play_state *s) { (void)u; REQUIRE(s==&play); fixture_progress_advance(&progress); }
static int frame_loses_life(void) { return frame_number==0 && (scenario==33 || scenario==35); }
void play_move_balls(void *u,play_state *s) {
    (void)u; REQUIRE(s==&play); frame_call(PLAY_MOVE_BALLS,NULL,0);
    if (frame_loses_life()) fixture_progress_lose(&progress);
}
void play_stop_sound(void *u,play_state *s,uint32_t sound) { REQUIRE(s==&play); progress_stop_sound(u,&progress,sound); }
void play_play_sound(void *u,play_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d) { REQUIRE(s==&play); progress_play_sound(u,&progress,a,b,c,d); }
void play_wait(void *u,play_state *s,uint32_t n) { REQUIRE(s==&play); progress_wait(u,&progress,n); }
void play_sprite(void *u,play_state *s,uint32_t a,uint32_t b,uint32_t c) { REQUIRE(s==&play); progress_sprite(u,&progress,a,b,c); }
void play_free_event(void *u,play_state *s,play_event *p) { (void)u; REQUIRE(s==&play && !p); REQUIRE(0); }
#define FRAME(name,op,params,...) void play_##name params { (void)u; REQUIRE(s==&play); const uint32_t args[]={__VA_ARGS__}; frame_call(op,args,sizeof(args)/sizeof(*args)); }
FRAME(cycle,PLAY_CYCLE,(void *u,play_state *s,uint32_t a,uint32_t b,uint32_t c),a,b,c)
FRAME(hit_tile,PLAY_HIT_TILE,(void *u,play_state *s,uint32_t a,uint32_t b),a,b)
FRAME(spawn_debris,PLAY_SPAWN_DEBRIS,(void *u,play_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d),a,b,c,d)
#undef FRAME
uint32_t play_elapsed(void *u,play_state *s,uint32_t a,uint32_t b) { (void)u; REQUIRE(s==&play); const uint32_t args[]={a,b}; frame_call(PLAY_ELAPSED,args,2); return 0; }
uint32_t play_now(void *u,play_state *s) { (void)u; REQUIRE(s==&play); frame_call(PLAY_NOW,NULL,0); return 9000; }
uint32_t play_random(void *u,play_state *s,uint32_t n) { (void)u; REQUIRE(s==&play && n); frame_call(PLAY_RANDOM,&n,1); return 0; }
#ifndef DX_STANDALONE
#define FRAME0(name) static void native_frame_##name(void) { progress_from_native(); play_##name(NULL,&play); progress_to_native(); }
FRAME0(move_paddle) FRAME0(move_shots) FRAME0(move_trails) FRAME0(move_pickups) FRAME0(draw_pickups) FRAME0(restore_damage)
FRAME0(advance_brick_effects) FRAME0(draw_explosions) FRAME0(draw_paddle) FRAME0(draw_trails) FRAME0(prepare_last_brick)
FRAME0(draw_last_brick) FRAME0(present) FRAME0(fire) FRAME0(split) FRAME0(power)
#undef FRAME0
static void native_frame_move_balls(void) {
    progress_from_native(); frame_call(PLAY_MOVE_BALLS,NULL,0); progress_to_native();
    if (frame_loses_life()) ((void (*)(void))0x408990)();
    progress_from_native();
}
#define FRAME(name,params,...) static void native_frame_##name params { progress_from_native(); play_##name(NULL,&play,__VA_ARGS__); progress_to_native(); }
FRAME(sprite,(uint32_t a,uint32_t b,uint32_t c),a,b,c) FRAME(cycle,(uint32_t a,uint32_t b,uint32_t c),a,b,c)
FRAME(hit_tile,(uint32_t a,uint32_t b),a,b) FRAME(spawn_debris,(uint32_t a,uint32_t b,uint32_t c,uint32_t d),a,b,c,d)
#undef FRAME
static void native_frame_free_event(uint32_t address) { REQUIRE(!address); REQUIRE(0); }
static uint32_t native_frame_elapsed(uint32_t a,uint32_t b) { progress_from_native(); uint32_t r=play_elapsed(NULL,&play,a,b); progress_to_native(); return r; }
static uint32_t native_frame_now(void) { progress_from_native(); uint32_t r=play_now(NULL,&play); progress_to_native(); return r; }
static uint32_t native_frame_random(uint32_t n) { progress_from_native(); uint32_t r=play_random(NULL,&play,n); progress_to_native(); return r; }
static void native_frame_update(void) { progress_from_native(); fixture_play_update(&play); progress_to_native(); }
static void frame_install(int source) {
#define FRAME(name) REQUIRE(install_frame_service_##name((void (*)(void))native_frame_##name));
    FRAME(move_paddle) FRAME(move_balls) FRAME(move_shots) FRAME(move_trails) FRAME(move_pickups) FRAME(draw_pickups) FRAME(restore_damage)
    FRAME(advance_brick_effects) FRAME(draw_explosions) FRAME(draw_paddle) FRAME(draw_trails) FRAME(prepare_last_brick)
    FRAME(draw_last_brick) FRAME(present) FRAME(fire) FRAME(split) FRAME(power) FRAME(sprite)
    FRAME(cycle) FRAME(hit_tile) FRAME(spawn_debris) FRAME(free_event) FRAME(elapsed) FRAME(now) FRAME(random)
#undef FRAME
    if (source) REQUIRE(install_frame_update(native_frame_update));
}
#endif
static void frame_setup(void) {
    play.gun=play.slow_balls=play.speedup_balls=play.fire_balls=play.split_balls=play.power_balls=play.warning_sound=0;
    pickups.next_life=0; play.remaining_bricks=2;
    if (scenario==34 || scenario==36) { memset(&current_board,0,400); play.remaining_bricks=0; }
    if (scenario==35) pickups.lives=1;
    if (scenario==36) bricks.board_index=49;
    if (scenario==37) { play.paused=1; progress.pending=1; }
}
static void frame_run(void) {
    for (frame_number=0;frame_number<4;++frame_number) {
#ifndef DX_STANDALONE
        ((void (*)(void))0x4044d0)(); progress_from_native();
#else
        fixture_play_update(&play);
#endif
        snapshot(NULL); if (flow.next_scene==3) break;
    }
}

/* This consumer retains its documented in-grid event domain. */
uint32_t play_read_pending(void *u,play_state *s,uint32_t column,uint32_t row) {
    (void)u;REQUIRE(s==&play && column<20 && row<20);
    return s->pending_cells[row*20+column];
}
