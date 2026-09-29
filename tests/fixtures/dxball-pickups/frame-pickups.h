/* The existing frame and pickup lifecycle share the same C objects. */
#include "play-runtime.h"
static uint32_t frame_entered;
void play_enter(void) { ++frame_entered; }
static void frame_call(play_state *s,unsigned operation,const uint32_t *args,unsigned count) {
    REQUIRE(s==&play); begin(&pickups,100+operation,args,count); (void)end(0);
}
#define FRAME0(name,operation) void play_##name(void *unused,play_state *s) { (void)unused; frame_call(s,operation,NULL,0); }
FRAME0(refresh_score,PLAY_REFRESH_SCORE)
FRAME0(move_balls,PLAY_MOVE_BALLS) FRAME0(move_shots,PLAY_MOVE_SHOTS)  FRAME0(move_trails,PLAY_MOVE_TRAILS)
FRAME0(restore_damage,PLAY_RESTORE_DAMAGE) FRAME0(advance_brick_effects,PLAY_ADVANCE_BRICK_EFFECTS)
FRAME0(draw_explosions,PLAY_DRAW_EXPLOSIONS) FRAME0(draw_paddle,PLAY_DRAW_PADDLE)
FRAME0(draw_trails,PLAY_DRAW_TRAILS) FRAME0(prepare_last_brick,PLAY_PREPARE_LAST_BRICK) FRAME0(draw_last_brick,PLAY_DRAW_LAST_BRICK)
FRAME0(present,PLAY_PRESENT) FRAME0(split,PLAY_SPLIT) FRAME0(power,PLAY_POWER)
FRAME0(advance_stage,PLAY_ADVANCE_STAGE) FRAME0(fire,PLAY_FIRE)
#undef FRAME0
void play_move_pickups(void *unused,play_state *s) { (void)unused; REQUIRE(s==&play); fixture_pickup_update(&pickups); }
void play_draw_pickups(void *unused,play_state *s) { (void)unused; REQUIRE(s==&play); fixture_pickup_draw(&pickups); }
void play_move_paddle(void *u,play_state *s) { REQUIRE(s==&play); pickup_move_paddle(u,&pickups); }
void play_next_board(void *u,play_state *s) { REQUIRE(s==&play); pickup_next_board(u,&pickups); }
void play_spawn_debris(void *u,play_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d) { (void)u; REQUIRE(s==&play); fixture_pickup_create(&pickups,a,b,c,d); }
static void frame_free_event(play_event *event) {
    REQUIRE(event==&frame_event && frame_event_live); frame_call(&play,PLAY_FREE_EVENT,NULL,0); frame_event_live=0;
}
void play_stop_sound(void *u,play_state *s,uint32_t sound) { REQUIRE(s==&play); pickup_stop_sound(u,&pickups,sound); }
uint32_t play_random(void *u,play_state *s,uint32_t limit) { REQUIRE(s==&play); return pickup_random(u,&pickups,limit); }
void play_play_sound(void *u,play_state *s,uint32_t sound,uint32_t repeat,uint32_t volume,uint32_t pan) {
    REQUIRE(s==&play); pickup_play_sound(u,&pickups,sound,repeat,volume,pan);
}
void play_free_event(void *u,play_state *s,play_event *event) { (void)u; REQUIRE(s==&play); frame_free_event(event); }
#define FRAME(name,operation,params,...) void play_##name params { (void)unused; const uint32_t args[]={__VA_ARGS__}; frame_call(s,operation,args,sizeof(args)/sizeof(*args)); }
FRAME(wait,PLAY_WAIT,(void *unused,play_state *s,uint32_t count),count)
FRAME(sprite,PLAY_SPRITE,(void *unused,play_state *s,uint32_t slot,uint32_t x,uint32_t y),slot,x,y)
FRAME(cycle,PLAY_CYCLE,(void *unused,play_state *s,uint32_t first,uint32_t last,uint32_t amount),first,last,amount)
FRAME(hit_tile,PLAY_HIT_TILE,(void *unused,play_state *s,uint32_t column,uint32_t row),column,row)
#undef FRAME
uint32_t play_now(void *u,play_state *s) { (void)u; frame_call(s,PLAY_NOW,NULL,0); return 1234; }
uint32_t play_elapsed(void *u,play_state *s,uint32_t previous,uint32_t delay) {
    (void)u; const uint32_t args[]={previous,delay}; frame_call(s,PLAY_ELAPSED,args,2); return 0;
}
#ifndef DX_STANDALONE
#define FRAME0(name) static void native_frame_##name(void) { pickup_from_native(); play_##name(NULL,&play); pickup_to_native(); }
FRAME0(refresh_score) FRAME0(move_balls) FRAME0(move_shots)  FRAME0(move_trails)
FRAME0(restore_damage) FRAME0(advance_brick_effects) FRAME0(draw_explosions) FRAME0(draw_paddle)
FRAME0(draw_trails) FRAME0(prepare_last_brick) FRAME0(draw_last_brick) FRAME0(present) FRAME0(split) FRAME0(power)
 FRAME0(advance_stage) FRAME0(fire)
#undef FRAME0
#define FRAME(name,params,...) static void native_frame_##name params { pickup_from_native(); play_##name(NULL,&play,__VA_ARGS__); pickup_to_native(); }
FRAME(wait,(uint32_t count),count) FRAME(sprite,(uint32_t slot,uint32_t x,uint32_t y),slot,x,y)
FRAME(cycle,(uint32_t first,uint32_t last,uint32_t amount),first,last,amount)
FRAME(hit_tile,(uint32_t column,uint32_t row),column,row)
#undef FRAME
static uint32_t native_frame_elapsed(uint32_t previous,uint32_t delay) {
    pickup_from_native(); uint32_t result=play_elapsed(NULL,&play,previous,delay); pickup_to_native(); return result;
}
static uint32_t native_frame_now(void) { pickup_from_native(); uint32_t result=play_now(NULL,&play); pickup_to_native(); return result; }
static void native_frame_update(void) { pickup_from_native(); fixture_play_update(&play); pickup_to_native(); }
static void frame_install(int source) {
#define FRAME(name) REQUIRE(install_frame_service_##name((void (*)(void))native_frame_##name));
    FRAME(refresh_score) FRAME(move_balls) FRAME(move_shots)  FRAME(move_trails)
    FRAME(restore_damage) FRAME(advance_brick_effects) FRAME(draw_explosions) FRAME(draw_paddle)
    FRAME(draw_trails) FRAME(prepare_last_brick) FRAME(draw_last_brick) FRAME(present) FRAME(split) FRAME(power)
     FRAME(advance_stage) FRAME(fire) FRAME(wait) FRAME(sprite) FRAME(cycle) FRAME(hit_tile)
    FRAME(elapsed) FRAME(now)
#undef FRAME
    if (source) REQUIRE(install_frame_update(native_frame_update));
}
#endif
static void frame_setup(void) {
    play.remaining_bricks=10; play.old_paddle_x=play.paddle_x=300; play.old_paddle_y=play.paddle_y=450;
    if (scenario==25) {
        frame_event=(play_event){.kind=1,.column=18,.row=12}; frame_event_live=1;
        play.events=(play_events){&frame_event,&frame_event,&frame_event,0}; choice_kind=3;
    } else {
        list(scenario==24 ? 3 : 1); collide=scenario==22 || scenario==23;
        items[0].kind=scenario==22 ? 12 : 10;
        if (scenario==24) for (unsigned i=0;i<3;++i) items[i].y=500;
        if (scenario==26) { items[0].dx=UINT32_MAX; items[0].x=21; items[0].tick=20; }
    }
}
static void frame_run(void) {
    for (unsigned i=0;i<4;++i) {
#ifndef DX_STANDALONE
        ((void (*)(void))0x4044d0)(); pickup_from_native();
#else
        fixture_play_update(&play);
#endif
        snapshot(NULL);
        uint32_t fields[]={play.slow_balls,play.split_balls,play.power_balls,play.voice_pending,menu.score,frame_event_live};
        spx_observe_u32s(observer,NULL,fields,6);
    }
}

/* This consumer retains its documented in-grid event domain. */
uint32_t play_read_pending(void *u,play_state *s,uint32_t column,uint32_t row) {
    (void)u;REQUIRE(s==&play && column<20 && row<20);
    return s->pending_cells[row*20+column];
}
