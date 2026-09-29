/* Three existing component interfaces share the same paddle and pickup state. */
#include "play-runtime.h"
#include "pickup-runtime.h"
static uint32_t frame_entered,pickup_entered[4];
void play_enter(void) { ++frame_entered; }
void pickup_enter(unsigned operation) { REQUIRE(operation<4); ++pickup_entered[operation]; }
static void call_record(unsigned operation,const uint32_t *args,unsigned count) { begin(&paddle,operation,args,count); (void)end(0); }
#define PICKUP0(name,operation) void pickup_##name(void *u,pickup_state *s) { (void)u; REQUIRE(s==&pickups); call_record(100+operation,NULL,0); }
PICKUP0(next_board,PICKUP_NEXT_BOARD) PICKUP0(unstick,PICKUP_UNSTICK) PICKUP0(queue_explosive_bricks,PICKUP_QUEUE_EXPLOSIVE_BRICKS)
PICKUP0(detonate_bricks,PICKUP_DETONATE_BRICKS) PICKUP0(release_attached,PICKUP_RELEASE_ATTACHED) PICKUP0(lose_life,PICKUP_LOSE_LIFE)
#undef PICKUP0
void pickup_move_paddle(void *u,pickup_state *s) { (void)u; REQUIRE(s==&pickups); fixture_paddle_move(&paddle); }
pickup *pickup_allocate(void *u,pickup_state *s) { (void)u; (void)s; REQUIRE(0); return NULL; }
void pickup_free(void *u,pickup_state *s,pickup *p) {
    (void)u; REQUIRE(s==&pickups && p==&frame_pickup && frame_pickup_live); call_record(100+PICKUP_FREE,NULL,0); frame_pickup_live=0;
}
uint32_t pickup_random(void *u,pickup_state *s,uint32_t n) { REQUIRE(s==&pickups); return paddle_random(u,&paddle,n); }
uint32_t pickup_pan(void *u,pickup_state *s,uint32_t x) { (void)u; REQUIRE(s==&pickups); call_record(100+PICKUP_PAN,&x,1); return x^17; }
uint32_t pickup_overlap(void *u,pickup_state *s,font_rect *a,font_rect *b) {
    (void)u; REQUIRE(s==&pickups); const uint32_t args[]={a->left,a->top,a->right,a->bottom,b->left,b->top,b->right,b->bottom};
    call_record(100+PICKUP_OVERLAP,args,8); return 1;
}
#define PICKUP(name,operation,params,...) void pickup_##name params { (void)u; REQUIRE(s==&pickups); const uint32_t args[]={__VA_ARGS__}; call_record(100+operation,args,sizeof(args)/sizeof(*args)); }
PICKUP(stop_sound,PICKUP_STOP_SOUND,(void *u,pickup_state *s,uint32_t a),a)
PICKUP(play_sound,PICKUP_PLAY_SOUND,(void *u,pickup_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d),a,b,c,d)
PICKUP(particle,PICKUP_PARTICLE,(void *u,pickup_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f),a,b,c,d,e,f)
PICKUP(sprite,PICKUP_SPRITE,(void *u,pickup_state *s,uint32_t a,uint32_t b,uint32_t c),a,b,c)
#undef PICKUP
static void frame_call(play_state *s,unsigned operation,const uint32_t *args,unsigned count) { REQUIRE(s==&play); call_record(200+operation,args,count); }
#define FRAME0(name,operation) void play_##name(void *u,play_state *s) { (void)u; frame_call(s,operation,NULL,0); }
FRAME0(refresh_score,PLAY_REFRESH_SCORE) FRAME0(move_shots,PLAY_MOVE_SHOTS) FRAME0(move_trails,PLAY_MOVE_TRAILS)
FRAME0(restore_damage,PLAY_RESTORE_DAMAGE) FRAME0(advance_brick_effects,PLAY_ADVANCE_BRICK_EFFECTS)
FRAME0(draw_explosions,PLAY_DRAW_EXPLOSIONS) FRAME0(draw_trails,PLAY_DRAW_TRAILS)
FRAME0(prepare_last_brick,PLAY_PREPARE_LAST_BRICK) FRAME0(draw_last_brick,PLAY_DRAW_LAST_BRICK)
FRAME0(present,PLAY_PRESENT) FRAME0(split,PLAY_SPLIT) FRAME0(power,PLAY_POWER) FRAME0(advance_stage,PLAY_ADVANCE_STAGE) FRAME0(fire,PLAY_FIRE)
#undef FRAME0
void play_move_balls(void *u,play_state *s) { (void)u; frame_call(s,PLAY_MOVE_BALLS,NULL,0); play.changed=1; }
void play_move_paddle(void *u,play_state *s) { (void)u; REQUIRE(s==&play); fixture_paddle_move(&paddle); }
void play_draw_paddle(void *u,play_state *s) { (void)u; REQUIRE(s==&play); fixture_paddle_draw(&paddle); }
void play_move_pickups(void *u,play_state *s) { (void)u; REQUIRE(s==&play); fixture_pickup_update(&pickups); }
void play_draw_pickups(void *u,play_state *s) { (void)u; REQUIRE(s==&play); fixture_pickup_draw(&pickups); }
void play_spawn_debris(void *u,play_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d) { (void)u; REQUIRE(s==&play); fixture_pickup_create(&pickups,a,b,c,d); }
void play_next_board(void *u,play_state *s) { REQUIRE(s==&play); pickup_next_board(u,&pickups); }
void play_stop_sound(void *u,play_state *s,uint32_t a) { REQUIRE(s==&play); pickup_stop_sound(u,&pickups,a); }
void play_play_sound(void *u,play_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d) { REQUIRE(s==&play); pickup_play_sound(u,&pickups,a,b,c,d); }
void play_free_event(void *u,play_state *s,play_event *event) { (void)u; (void)s; (void)event; REQUIRE(0); }
uint32_t play_elapsed(void *u,play_state *s,uint32_t a,uint32_t b) { REQUIRE(s==&play); return paddle_elapsed(u,&paddle,a,b); }
uint32_t play_now(void *u,play_state *s) { REQUIRE(s==&play); return paddle_now(u,&paddle); }
uint32_t play_random(void *u,play_state *s,uint32_t limit) { REQUIRE(s==&play); return paddle_random(u,&paddle,limit); }
void play_sprite(void *u,play_state *s,uint32_t a,uint32_t b,uint32_t c) { REQUIRE(s==&play); paddle_sprite(u,&paddle,a,b,c); }
#define FRAME(name,operation,params,...) void play_##name params { (void)u; const uint32_t args[]={__VA_ARGS__}; frame_call(s,operation,args,sizeof(args)/sizeof(*args)); }
FRAME(wait,PLAY_WAIT,(void *u,play_state *s,uint32_t count),count)
FRAME(cycle,PLAY_CYCLE,(void *u,play_state *s,uint32_t a,uint32_t b,uint32_t c),a,b,c)
FRAME(hit_tile,PLAY_HIT_TILE,(void *u,play_state *s,uint32_t a,uint32_t b),a,b)
#undef FRAME
#ifndef DX_STANDALONE
#define PICKUP0(name) static void native_pickup_##name(void) { paddle_from_native(); pickup_##name(NULL,&pickups); paddle_to_native(); }
PICKUP0(next_board) PICKUP0(unstick) PICKUP0(queue_explosive_bricks) PICKUP0(detonate_bricks) PICKUP0(release_attached) PICKUP0(lose_life)
#undef PICKUP0
static uint32_t native_pickup_allocate(uint32_t size) { REQUIRE(size==36); paddle_from_native(); uint32_t r=pickup_address(pickup_allocate(NULL,&pickups)); paddle_to_native(); return r; }
static void native_pickup_free(uint32_t address) { paddle_from_native(); pickup_free(NULL,&pickups,pickup_view(address)); paddle_to_native(); }
static uint32_t native_pickup_pan(uint32_t x) { paddle_from_native(); uint32_t r=pickup_pan(NULL,&pickups,x); paddle_to_native(); return r; }
static uint32_t native_pickup_overlap(font_rect a,font_rect b) { paddle_from_native(); uint32_t r=pickup_overlap(NULL,&pickups,&a,&b); paddle_to_native(); return r; }
#define PICKUP(name,params,...) static void native_pickup_##name params { paddle_from_native(); pickup_##name(NULL,&pickups,__VA_ARGS__); paddle_to_native(); }
PICKUP(stop_sound,(uint32_t a),a) PICKUP(play_sound,(uint32_t a,uint32_t b,uint32_t c,uint32_t d),a,b,c,d)
PICKUP(particle,(uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f),a,b,c,d,e,f)
PICKUP(sprite,(uint32_t a,uint32_t b,uint32_t c),a,b,c)
#undef PICKUP
#define PICKUP_ROOT(name) static void native_pickup_root_##name(void) { paddle_from_native(); fixture_pickup_##name(&pickups); paddle_to_native(); }
PICKUP_ROOT(update) PICKUP_ROOT(draw) PICKUP_ROOT(remove)
#undef PICKUP_ROOT
static void native_pickup_root_create(uint32_t a,uint32_t b,uint32_t c,uint32_t d) { paddle_from_native(); fixture_pickup_create(&pickups,a,b,c,d); paddle_to_native(); }
#define FRAME0(name) static void native_frame_##name(void) { paddle_from_native(); play_##name(NULL,&play); paddle_to_native(); }
FRAME0(refresh_score) FRAME0(move_balls) FRAME0(move_shots) FRAME0(move_trails)
FRAME0(restore_damage) FRAME0(advance_brick_effects) FRAME0(draw_explosions) FRAME0(draw_trails)
FRAME0(prepare_last_brick) FRAME0(draw_last_brick) FRAME0(present) FRAME0(split) FRAME0(power) FRAME0(advance_stage) FRAME0(fire)
#undef FRAME0
#define FRAME(name,params,...) static void native_frame_##name params { paddle_from_native(); play_##name(NULL,&play,__VA_ARGS__); paddle_to_native(); }
FRAME(wait,(uint32_t count),count) FRAME(cycle,(uint32_t a,uint32_t b,uint32_t c),a,b,c) FRAME(hit_tile,(uint32_t a,uint32_t b),a,b)
#undef FRAME
static void native_frame_update(void) { paddle_from_native(); fixture_play_update(&play); paddle_to_native(); }
static void frame_install(int source) {
#define PICKUP(name) REQUIRE(install_connected_pickup_service_##name((void (*)(void))native_pickup_##name));
    PICKUP(allocate) PICKUP(free) PICKUP(pan) PICKUP(overlap) PICKUP(stop_sound) PICKUP(play_sound) PICKUP(particle)
    PICKUP(sprite) PICKUP(next_board) PICKUP(unstick) PICKUP(queue_explosive_bricks) PICKUP(detonate_bricks) PICKUP(release_attached) PICKUP(lose_life)
#undef PICKUP
#define FRAME(name) REQUIRE(install_frame_service_##name((void (*)(void))native_frame_##name));
    FRAME(refresh_score) FRAME(move_balls) FRAME(move_shots) FRAME(move_trails) FRAME(restore_damage) FRAME(advance_brick_effects)
    FRAME(draw_explosions) FRAME(draw_trails) FRAME(prepare_last_brick) FRAME(draw_last_brick) FRAME(present) FRAME(split) FRAME(power)
    FRAME(advance_stage) FRAME(fire) FRAME(wait) FRAME(cycle) FRAME(hit_tile)
#undef FRAME
    if (!source) return;
    REQUIRE(install_frame_update(native_frame_update));
#define ROOT(name) REQUIRE(install_connected_pickup_##name((void (*)(void))native_pickup_root_##name));
    ROOT(create) ROOT(update) ROOT(draw) ROOT(remove)
#undef ROOT
}
#endif
static void frame_setup(void) {
    play.remaining_bricks=10; play.old_paddle_x=300; play.old_paddle_y=450; elapsed_value=1;
    scene.mouse_x=scenario==24 ? 0 : 609; flow.windowed=scenario==24;
    if (scenario!=24) {
        frame_pickup_live=1; frame_pickup=(pickup){.kind=scenario==21 ? 10 : scenario==22 ? 11 : 16,.sprite=45,.x=300,.y=440};
        pickups.current=pickups.first=pickups.last=&frame_pickup; pickups.count=1;
    }
}
static void frame_run(void) {
    for (unsigned i=0;i<8;++i) {
        clock_value+=64;
#ifndef DX_STANDALONE
        paddle_to_native(); ((void (*)(void))0x4044d0)(); paddle_from_native();
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
