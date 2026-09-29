/* The existing frame and shot component share exactly the same C objects. */
#include "play-runtime.h"
static uint32_t frame_entered;
void play_enter(void) { ++frame_entered; }
static void frame_call(play_state *s,unsigned operation,const uint32_t *args,unsigned count) {
    REQUIRE(s==&play); begin(&motion,100+operation,args,count); (void)end(0);
}
#define FRAME0(name,operation) void play_##name(void *unused,play_state *s) { (void)unused; frame_call(s,operation,NULL,0); }
FRAME0(refresh_score,PLAY_REFRESH_SCORE) FRAME0(move_paddle,PLAY_MOVE_PADDLE) FRAME0(move_balls,PLAY_MOVE_BALLS)
FRAME0(move_pickups,PLAY_MOVE_PICKUPS) FRAME0(move_trails,PLAY_MOVE_TRAILS)
FRAME0(restore_damage,PLAY_RESTORE_DAMAGE) FRAME0(advance_brick_effects,PLAY_ADVANCE_BRICK_EFFECTS)
FRAME0(draw_explosions,PLAY_DRAW_EXPLOSIONS) FRAME0(draw_paddle,PLAY_DRAW_PADDLE) FRAME0(draw_pickups,PLAY_DRAW_PICKUPS)
FRAME0(draw_trails,PLAY_DRAW_TRAILS) FRAME0(prepare_last_brick,PLAY_PREPARE_LAST_BRICK) FRAME0(draw_last_brick,PLAY_DRAW_LAST_BRICK)
FRAME0(present,PLAY_PRESENT) FRAME0(split,PLAY_SPLIT) FRAME0(power,PLAY_POWER) FRAME0(next_board,PLAY_NEXT_BOARD)
FRAME0(advance_stage,PLAY_ADVANCE_STAGE)
#undef FRAME0
void play_move_shots(void *unused,play_state *s) { (void)unused; REQUIRE(s==&play); fixture_shot_update(&motion); }
void play_fire(void *unused,play_state *s) { (void)unused; REQUIRE(s==&play); fixture_shot_fire(&motion); }
void play_stop_sound(void *u,play_state *s,uint32_t sound) { REQUIRE(s==&play); shot_stop_sound(u,&motion,sound); }
uint32_t play_random(void *u,play_state *s,uint32_t limit) { REQUIRE(s==&play); return shot_random(u,&motion,limit); }
void play_play_sound(void *u,play_state *s,uint32_t sound,uint32_t repeat,uint32_t volume,uint32_t pan) {
    REQUIRE(s==&play); shot_play_sound(u,&motion,sound,repeat,volume,pan);
}
void play_free_event(void *u,play_state *s,play_event *event) { (void)u; (void)s; (void)event; REQUIRE(0); }
#define FRAME(name,operation,params,...) void play_##name params { (void)unused; const uint32_t args[]={__VA_ARGS__}; frame_call(s,operation,args,sizeof(args)/sizeof(*args)); }
FRAME(wait,PLAY_WAIT,(void *unused,play_state *s,uint32_t count),count)
FRAME(sprite,PLAY_SPRITE,(void *unused,play_state *s,uint32_t slot,uint32_t x,uint32_t y),slot,x,y)
FRAME(cycle,PLAY_CYCLE,(void *unused,play_state *s,uint32_t first,uint32_t last,uint32_t amount),first,last,amount)
FRAME(hit_tile,PLAY_HIT_TILE,(void *unused,play_state *s,uint32_t column,uint32_t row),column,row)
FRAME(spawn_debris,PLAY_SPAWN_DEBRIS,(void *unused,play_state *s,uint32_t column,uint32_t row,uint32_t dx,uint32_t dy),column,row,dx,dy)
#undef FRAME
uint32_t play_now(void *u,play_state *s) { (void)u; frame_call(s,PLAY_NOW,NULL,0); return 1234; }
uint32_t play_elapsed(void *u,play_state *s,uint32_t previous,uint32_t delay) {
    (void)u; const uint32_t args[]={previous,delay}; frame_call(s,PLAY_ELAPSED,args,2); return 0;
}
#ifndef DX_STANDALONE
#define FRAME0(name) static void native_frame_##name(void) { motion_from_native(); play_##name(NULL,&play); motion_to_native(); }
FRAME0(refresh_score) FRAME0(move_paddle) FRAME0(move_balls) FRAME0(move_pickups) FRAME0(move_trails)
FRAME0(restore_damage) FRAME0(advance_brick_effects) FRAME0(draw_explosions) FRAME0(draw_paddle) FRAME0(draw_pickups)
FRAME0(draw_trails) FRAME0(prepare_last_brick) FRAME0(draw_last_brick) FRAME0(present) FRAME0(split) FRAME0(power)
FRAME0(next_board) FRAME0(advance_stage)
#undef FRAME0
#define FRAME(name,params,...) static void native_frame_##name params { motion_from_native(); play_##name(NULL,&play,__VA_ARGS__); motion_to_native(); }
FRAME(wait,(uint32_t count),count) FRAME(sprite,(uint32_t slot,uint32_t x,uint32_t y),slot,x,y)
FRAME(cycle,(uint32_t first,uint32_t last,uint32_t amount),first,last,amount)
FRAME(hit_tile,(uint32_t column,uint32_t row),column,row)
FRAME(spawn_debris,(uint32_t column,uint32_t row,uint32_t dx,uint32_t dy),column,row,dx,dy)
#undef FRAME
static uint32_t native_frame_elapsed(uint32_t previous,uint32_t delay) {
    motion_from_native(); uint32_t result=play_elapsed(NULL,&play,previous,delay); motion_to_native(); return result;
}
static uint32_t native_frame_now(void) { motion_from_native(); uint32_t result=play_now(NULL,&play); motion_to_native(); return result; }
static void native_frame_update(void) { motion_from_native(); fixture_play_update(&play); motion_to_native(); }
static void frame_install(int source) {
#define FRAME(name) REQUIRE(install_frame_service_##name((void (*)(void))native_frame_##name));
    FRAME(refresh_score) FRAME(move_paddle) FRAME(move_balls) FRAME(move_pickups) FRAME(move_trails)
    FRAME(restore_damage) FRAME(advance_brick_effects) FRAME(draw_explosions) FRAME(draw_paddle) FRAME(draw_pickups)
    FRAME(draw_trails) FRAME(prepare_last_brick) FRAME(draw_last_brick) FRAME(present) FRAME(split) FRAME(power)
    FRAME(next_board) FRAME(advance_stage) FRAME(wait) FRAME(sprite) FRAME(cycle) FRAME(hit_tile)
    FRAME(spawn_debris) FRAME(elapsed) FRAME(now)
#undef FRAME
    if (source) REQUIRE(install_frame_update(native_frame_update));
}
#endif
static void frame_setup(void) {
    play.paddle_x=100; play.paddle_y=110; play.gun=scenario<32;
    motion.pierce=scenario==31; memset(&current_board,1,400);
    if (scenario==32) { play.paused=1; chain(2); }
    if (scenario==33) { chain(3); for (unsigned i=0;i<3;++i) items[i].y=7; }
}
static void frame_run(void) {
    for (unsigned i=0;i<8;++i) {
        scene.mouse_buttons=scenario<32 ? 1 : 0;
#ifndef DX_STANDALONE
        motion_to_native(); ((void (*)(void))0x4044d0)(); motion_from_native();
#else
        fixture_play_update(&play);
#endif
        snapshot(NULL);
    }
}

/* This consumer retains its documented in-grid event domain. */
uint32_t play_read_pending(void *u,play_state *s,uint32_t column,uint32_t row) {
    (void)u;REQUIRE(s==&play && column<20 && row<20);
    return s->pending_cells[row*20+column];
}
