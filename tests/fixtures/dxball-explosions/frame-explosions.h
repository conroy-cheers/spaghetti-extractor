/* Actual frame -> ball contact -> creation, followed by drawing and expiry. */
#include "motion-runtime.h"
#include "play-runtime.h"
static uint32_t frame_entered,motion_entered[5];
void play_enter(void) { ++frame_entered; }
void motion_enter(unsigned operation) { REQUIRE(operation<5); ++motion_entered[operation]; }
static void connected_call(unsigned operation,const uint32_t *args,unsigned count) {
    begin(&explosions,100+operation,args,count); (void)end(0);
}
play_ball *motion_allocate(void *u,motion_state *s) { (void)u; (void)s; REQUIRE(0); return NULL; }
void motion_free(void *u,motion_state *s,play_ball *item) { (void)u; REQUIRE(s==&motion && ball_id(item)); ball_live=0; }
uint32_t motion_hit(void *u,motion_state *s,uint32_t column,uint32_t row) {
    (void)u; REQUIRE(s==&motion && column<20 && row<20); const uint32_t args[]={column,row};
    begin(&explosions,200,args,2); current_board.cells[row][column]=0; play.remaining_bricks=0; return end(1);
}
uint32_t motion_random(void *u,motion_state *s,uint32_t limit) {
    (void)u; REQUIRE(s==&motion && limit); begin(&explosions,201,&limit,1); return end(1%limit);
}
uint32_t motion_pan(void *u,motion_state *s,uint32_t x) { (void)u; REQUIRE(s==&motion); begin(&explosions,202,&x,1); return end(x^0x6157); }
uint32_t motion_overlap(void *u,motion_state *s,font_rect *a,font_rect *b) {
    (void)u; REQUIRE(s==&motion); const uint32_t args[]={a->left,a->top,a->right,a->bottom,b->left,b->top,b->right,b->bottom};
    begin(&explosions,203,args,8); return end(0);
}
#define MOTION0(name,id) void motion_##name(void *u,motion_state *s) { (void)u; REQUIRE(s==&motion); connected_call(id,NULL,0); }
MOTION0(paddle_power,104) MOTION0(unstick,105) MOTION0(lose_life,106)
#undef MOTION0
#define MOTION(name,id,params,...) void motion_##name params { (void)u; REQUIRE(s==&motion); const uint32_t args[]={__VA_ARGS__}; connected_call(id,args,sizeof(args)/sizeof(*args)); }
MOTION(stop_sound,107,(void *u,motion_state *s,uint32_t id),id)
MOTION(play_sound,108,(void *u,motion_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d),a,b,c,d)
MOTION(particle,109,(void *u,motion_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f),a,b,c,d,e,f)
#undef MOTION
void motion_explosion(void *u,motion_state *s,uint32_t x,uint32_t y) { (void)u; REQUIRE(s==&motion); fixture_explosion_create(&explosions,x,y); }
static void frame_call(play_state *s,unsigned operation,const uint32_t *args,unsigned count) { REQUIRE(s==&play); connected_call(operation,args,count); }
#define FRAME0(name,operation) void play_##name(void *u,play_state *s) { (void)u; frame_call(s,operation,NULL,0); }
FRAME0(refresh_score,PLAY_REFRESH_SCORE) FRAME0(move_paddle,PLAY_MOVE_PADDLE)
FRAME0(move_shots,PLAY_MOVE_SHOTS) FRAME0(move_pickups,PLAY_MOVE_PICKUPS) FRAME0(move_trails,PLAY_MOVE_TRAILS)
FRAME0(restore_damage,PLAY_RESTORE_DAMAGE) FRAME0(advance_brick_effects,PLAY_ADVANCE_BRICK_EFFECTS)
FRAME0(draw_paddle,PLAY_DRAW_PADDLE) FRAME0(draw_pickups,PLAY_DRAW_PICKUPS) FRAME0(draw_trails,PLAY_DRAW_TRAILS)
FRAME0(prepare_last_brick,PLAY_PREPARE_LAST_BRICK) FRAME0(draw_last_brick,PLAY_DRAW_LAST_BRICK)
FRAME0(present,PLAY_PRESENT) FRAME0(split,PLAY_SPLIT) FRAME0(power,PLAY_POWER) FRAME0(advance_stage,PLAY_ADVANCE_STAGE) FRAME0(fire,PLAY_FIRE)
#undef FRAME0
void play_move_balls(void *u,play_state *s) { (void)u; REQUIRE(s==&play); fixture_motion_update(&motion); }
void play_draw_explosions(void *u,play_state *s) { (void)u; REQUIRE(s==&play); fixture_explosion_draw(&explosions); }
void play_next_board(void *u,play_state *s) { (void)u; REQUIRE(s==&play); begin(&explosions,100+PLAY_NEXT_BOARD,NULL,0); play.remaining_bricks=10; (void)end(0); }
void play_stop_sound(void *u,play_state *s,uint32_t sound) { REQUIRE(s==&play); motion_stop_sound(u,&motion,sound); }
uint32_t play_random(void *u,play_state *s,uint32_t limit) { REQUIRE(s==&play); return motion_random(u,&motion,limit); }
void play_play_sound(void *u,play_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d) { REQUIRE(s==&play); motion_play_sound(u,&motion,a,b,c,d); }
void play_free_event(void *u,play_state *s,play_event *event) { (void)u; (void)s; (void)event; REQUIRE(0); }
void play_sprite(void *u,play_state *s,uint32_t slot,uint32_t x,uint32_t y) { REQUIRE(s==&play); explosion_sprite(u,&explosions,slot,x,y); }
#define FRAME(name,operation,params,...) void play_##name params { (void)u; const uint32_t args[]={__VA_ARGS__}; frame_call(s,operation,args,sizeof(args)/sizeof(*args)); }
FRAME(wait,PLAY_WAIT,(void *u,play_state *s,uint32_t count),count)
FRAME(cycle,PLAY_CYCLE,(void *u,play_state *s,uint32_t a,uint32_t b,uint32_t c),a,b,c)
FRAME(hit_tile,PLAY_HIT_TILE,(void *u,play_state *s,uint32_t a,uint32_t b),a,b)
FRAME(spawn_debris,PLAY_SPAWN_DEBRIS,(void *u,play_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d),a,b,c,d)
#undef FRAME
uint32_t play_now(void *u,play_state *s) { (void)u; frame_call(s,PLAY_NOW,NULL,0); return 1234; }
uint32_t play_elapsed(void *u,play_state *s,uint32_t a,uint32_t b) { (void)u; const uint32_t args[]={a,b}; frame_call(s,PLAY_ELAPSED,args,2); return 0; }
#ifndef DX_STANDALONE
#define FRAME0(name) static void native_frame_##name(void) { explosion_from_native(); play_##name(NULL,&play); explosion_to_native(); }
FRAME0(refresh_score) FRAME0(move_paddle) FRAME0(move_shots) FRAME0(move_pickups) FRAME0(move_trails)
FRAME0(restore_damage) FRAME0(advance_brick_effects) FRAME0(draw_paddle) FRAME0(draw_pickups) FRAME0(draw_trails)
FRAME0(prepare_last_brick) FRAME0(draw_last_brick) FRAME0(present) FRAME0(split) FRAME0(power) FRAME0(next_board) FRAME0(advance_stage) FRAME0(fire)
#undef FRAME0
#define FRAME(name,params,...) static void native_frame_##name params { explosion_from_native(); play_##name(NULL,&play,__VA_ARGS__); explosion_to_native(); }
FRAME(wait,(uint32_t a),a) FRAME(cycle,(uint32_t a,uint32_t b,uint32_t c),a,b,c) FRAME(hit_tile,(uint32_t a,uint32_t b),a,b)
FRAME(spawn_debris,(uint32_t a,uint32_t b,uint32_t c,uint32_t d),a,b,c,d)
#undef FRAME
static uint32_t native_frame_elapsed(uint32_t a,uint32_t b) { explosion_from_native(); uint32_t r=play_elapsed(NULL,&play,a,b); explosion_to_native(); return r; }
static uint32_t native_frame_now(void) { explosion_from_native(); uint32_t r=play_now(NULL,&play); explosion_to_native(); return r; }
static void native_frame_update(void) { explosion_from_native(); fixture_play_update(&play); explosion_to_native(); }
#define MOTION0(name) static void native_motion_##name(void) { explosion_from_native(); motion_##name(NULL,&motion); explosion_to_native(); }
MOTION0(paddle_power) MOTION0(unstick) MOTION0(lose_life)
#undef MOTION0
#define MOTION(name,params,...) static void native_motion_##name params { explosion_from_native(); motion_##name(NULL,&motion,__VA_ARGS__); explosion_to_native(); }
MOTION(stop_sound,(uint32_t a),a) MOTION(play_sound,(uint32_t a,uint32_t b,uint32_t c,uint32_t d),a,b,c,d)
MOTION(particle,(uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f),a,b,c,d,e,f)
#undef MOTION
static uint32_t native_motion_random(uint32_t a) { explosion_from_native(); uint32_t r=motion_random(NULL,&motion,a); explosion_to_native(); return r; }
static uint32_t native_motion_pan(uint32_t a) { explosion_from_native(); uint32_t r=motion_pan(NULL,&motion,a); explosion_to_native(); return r; }
static uint32_t native_motion_hit(uint32_t a,uint32_t b) { explosion_from_native(); uint32_t r=motion_hit(NULL,&motion,a,b); explosion_to_native(); return r; }
static uint32_t native_motion_overlap(font_rect a,font_rect b) { explosion_from_native(); uint32_t r=motion_overlap(NULL,&motion,&a,&b); explosion_to_native(); return r; }
#define ROOT(name) static void native_motion_root_##name(void) { explosion_from_native(); fixture_motion_##name(&motion); explosion_to_native(); }
ROOT(create) ROOT(update) ROOT(rebound) ROOT(remove)
#undef ROOT
static uint32_t native_motion_root_contact(uint32_t x,uint32_t y) { explosion_from_native(); uint32_t r=fixture_motion_contact(&motion,x,y); explosion_to_native(); return r; }
static void frame_install(int source) {
#define FRAME(name) REQUIRE(install_frame_service_##name((void (*)(void))native_frame_##name));
    FRAME(refresh_score) FRAME(move_paddle) FRAME(move_shots) FRAME(move_pickups) FRAME(move_trails)
    FRAME(restore_damage) FRAME(advance_brick_effects) FRAME(draw_paddle) FRAME(draw_pickups) FRAME(draw_trails)
    FRAME(prepare_last_brick) FRAME(draw_last_brick) FRAME(present) FRAME(split) FRAME(power) FRAME(next_board)
    FRAME(advance_stage) FRAME(fire) FRAME(wait) FRAME(cycle) FRAME(hit_tile) FRAME(spawn_debris) FRAME(elapsed) FRAME(now)
#undef FRAME
#define MOTION(name) REQUIRE(install_motion_service_##name((void (*)(void))native_motion_##name));
    MOTION(random) MOTION(pan) MOTION(hit) MOTION(overlap) MOTION(paddle_power) MOTION(unstick) MOTION(lose_life)
    MOTION(stop_sound) MOTION(play_sound) MOTION(particle)
#undef MOTION
    if (!source) return;
    REQUIRE(install_frame_update(native_frame_update));
#define MOTION(name) REQUIRE(install_motion_##name((void (*)(void))native_motion_root_##name));
    MOTION(create) MOTION(update) MOTION(rebound) MOTION(contact) MOTION(remove)
#undef MOTION
}
#endif
static void frame_setup(void) {
    ball_live=1; motion.ball_count=1; ball=(play_ball){.x=200,.y=100,.dx=0,.dy=4,.sprite=61,.angle=75,.speed=5};
    play.balls=(play_balls){&ball,&ball,&ball,0}; play.old_paddle_x=300; play.old_paddle_y=450;
    for (unsigned i=0;i<361;++i) { sine[i]=1024; cosine[i]=512; }
    if (scenario<=22) { current_board.cells[4][6]=1; motion.pierce=scenario==22; }
    if (scenario==23) { play.remaining_bricks=0; chain(3); for (unsigned i=0;i<3;++i) items[i].frame=21; }
    if (scenario==24) { play.paused=1; chain(2); }
}
static void frame_run(void) {
    for (unsigned i=0;i<26;++i) {
#ifndef DX_STANDALONE
        explosion_to_native(); ((void (*)(void))0x4044d0)(); explosion_from_native();
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
