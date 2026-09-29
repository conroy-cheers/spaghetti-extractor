/* Actual frame -> motion -> brick rules, sharing the same live object views. */
#include "motion-runtime.h"
#include "play-runtime.h"
static uint32_t motion_entered[5],frame_entered;
void motion_enter(unsigned op) { REQUIRE(op<5); ++motion_entered[op]; }
void play_enter(void) { ++frame_entered; }
static void connected_call(unsigned op,const uint32_t *args,unsigned count) {
    import_effects(); begin(&bricks,100+op,args,count); (void)end(0);
}
play_ball *motion_allocate(void *u,motion_state *s) {
    (void)u; REQUIRE(s==&motion); begin(&bricks,200,NULL,0);
    for (unsigned i=0;i<BALLS;++i) if (!ball_live[i]) { ball_live[i]=1; memset(&balls[i],0,sizeof(balls[i])); (void)end(i+1); return &balls[i]; }
    REQUIRE(0); return NULL;
}
void motion_free(void *u,motion_state *s,play_ball *ball) {
    (void)u; REQUIRE(s==&motion); uint32_t id=ball_id(ball); begin(&bricks,201,&id,1);
    REQUIRE(id && ball_live[id-1]); ball_live[id-1]=0; (void)end(0);
}
uint32_t motion_hit(void *u,motion_state *s,uint32_t column,uint32_t row) {
    (void)u; REQUIRE(s==&motion); import_effects(); uint32_t result=fixture_brick_hit(&bricks,column,row); publish_effects(); return result;
}
uint32_t motion_random(void *u,motion_state *s,uint32_t limit) { REQUIRE(s==&motion); return brick_random(u,&bricks,limit); }
uint32_t motion_pan(void *u,motion_state *s,uint32_t x) { REQUIRE(s==&motion); return brick_pan(u,&bricks,x); }
void motion_stop_sound(void *u,motion_state *s,uint32_t id) { REQUIRE(s==&motion); brick_stop_sound(u,&bricks,id); }
void motion_play_sound(void *u,motion_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d) { REQUIRE(s==&motion); brick_play_sound(u,&bricks,a,b,c,d); }
void motion_particle(void *u,motion_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f) { REQUIRE(s==&motion); brick_particle(u,&bricks,a,b,c,d,e,f); }
uint32_t motion_overlap(void *u,motion_state *s,font_rect *a,font_rect *b) {
    (void)u; REQUIRE(s==&motion); const uint32_t args[]={a->left,a->top,a->right,a->bottom,b->left,b->top,b->right,b->bottom};
    connected_call(102,args,8); return 0;
}
void motion_paddle_power(void *u,motion_state *s) { (void)u; REQUIRE(s==&motion); connected_call(103,NULL,0); }
void motion_unstick(void *u,motion_state *s) { (void)u; REQUIRE(s==&motion); connected_call(104,NULL,0); }
void motion_lose_life(void *u,motion_state *s) { (void)u; REQUIRE(s==&motion); connected_call(105,NULL,0); }
void motion_explosion(void *u,motion_state *s,uint32_t x,uint32_t y) { (void)u; REQUIRE(s==&motion); const uint32_t args[]={x,y}; connected_call(106,args,2); }

static void frame_call(play_state *s,unsigned op,const uint32_t *args,unsigned count) { REQUIRE(s==&play); connected_call(op,args,count); }
#define FRAME0(name,operation) void play_##name(void *u,play_state *s) { (void)u; frame_call(s,operation,NULL,0); }
FRAME0(refresh_score,PLAY_REFRESH_SCORE) FRAME0(move_paddle,PLAY_MOVE_PADDLE)
FRAME0(move_shots,PLAY_MOVE_SHOTS) FRAME0(move_pickups,PLAY_MOVE_PICKUPS) FRAME0(move_trails,PLAY_MOVE_TRAILS)
FRAME0(restore_damage,PLAY_RESTORE_DAMAGE) FRAME0(draw_explosions,PLAY_DRAW_EXPLOSIONS)
FRAME0(draw_paddle,PLAY_DRAW_PADDLE) FRAME0(draw_pickups,PLAY_DRAW_PICKUPS) FRAME0(draw_trails,PLAY_DRAW_TRAILS)
FRAME0(prepare_last_brick,PLAY_PREPARE_LAST_BRICK) FRAME0(draw_last_brick,PLAY_DRAW_LAST_BRICK)
FRAME0(present,PLAY_PRESENT) FRAME0(split,PLAY_SPLIT) FRAME0(power,PLAY_POWER)
FRAME0(next_board,PLAY_NEXT_BOARD) FRAME0(advance_stage,PLAY_ADVANCE_STAGE) FRAME0(fire,PLAY_FIRE)
#undef FRAME0
void play_move_balls(void *u,play_state *s) { (void)u; REQUIRE(s==&play); fixture_motion_update(&motion); }
void play_advance_brick_effects(void *u,play_state *s) { (void)u; REQUIRE(s==&play); import_effects(); fixture_brick_advance(&bricks); publish_effects(); }
void play_hit_tile(void *u,play_state *s,uint32_t column,uint32_t row) {
    (void)u; REQUIRE(s==&play); import_effects(); fixture_brick_blast(&bricks,column,row); publish_effects();
}
uint32_t play_read_pending(void *u,play_state *s,uint32_t column,uint32_t row) {
    (void)u;REQUIRE(s==&play);return *brick_byte(0x42cc10,column,row);
}
void play_free_event(void *u,play_state *s,play_event *event) {
    (void)u; REQUIRE(s==&play); uint32_t id=event_id(event); begin(&bricks,207,&id,1);
    REQUIRE(id && event_live[id-1]); event_live[id-1]=0; (void)end(0);
}
void play_stop_sound(void *u,play_state *s,uint32_t id) { REQUIRE(s==&play); brick_stop_sound(u,&bricks,id); }
uint32_t play_random(void *u,play_state *s,uint32_t limit) { REQUIRE(s==&play); return brick_random(u,&bricks,limit); }
void play_play_sound(void *u,play_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d) { REQUIRE(s==&play); brick_play_sound(u,&bricks,a,b,c,d); }
void play_spawn_debris(void *u,play_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d) { REQUIRE(s==&play); brick_debris(u,&bricks,a,b,c,d); }
#define FRAME(name,operation,params,...) void play_##name params { (void)u; const uint32_t args[]={__VA_ARGS__}; frame_call(s,operation,args,sizeof(args)/sizeof(*args)); }
FRAME(wait,PLAY_WAIT,(void *u,play_state *s,uint32_t count),count)
FRAME(sprite,PLAY_SPRITE,(void *u,play_state *s,uint32_t slot,uint32_t x,uint32_t y),slot,x,y)
FRAME(cycle,PLAY_CYCLE,(void *u,play_state *s,uint32_t first,uint32_t last,uint32_t amount),first,last,amount)
#undef FRAME
uint32_t play_now(void *u,play_state *s) { (void)u; frame_call(s,PLAY_NOW,NULL,0); return 1234; }
uint32_t play_elapsed(void *u,play_state *s,uint32_t previous,uint32_t delay) { (void)u; const uint32_t args[]={previous,delay}; frame_call(s,PLAY_ELAPSED,args,2); return 0; }

#ifndef DX_STANDALONE
static uint32_t connected_allocate(uint32_t bytes) { REQUIRE(bytes==60); return ball_address(motion_allocate(NULL,&motion)); }
static void connected_free(uint32_t address) {
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)&native_events[i]) { play_free_event(NULL,&play,&events[i]); return; }
    for (unsigned i=0;i<BALLS;++i) if (address==(uint32_t)(uintptr_t)&native_balls[i]) { motion_free(NULL,&motion,&balls[i]); return; }
    brick_free_effect(NULL,&bricks,brick_view(address));
}
#define FRAME0(name) static void native_frame_##name(void) { brick_from_native(); play_##name(NULL,&play); brick_to_native(); }
FRAME0(refresh_score) FRAME0(move_paddle) FRAME0(move_shots) FRAME0(move_pickups) FRAME0(move_trails)
FRAME0(restore_damage) FRAME0(draw_explosions) FRAME0(draw_paddle) FRAME0(draw_pickups) FRAME0(draw_trails)
FRAME0(prepare_last_brick) FRAME0(draw_last_brick) FRAME0(present) FRAME0(split) FRAME0(power) FRAME0(next_board) FRAME0(advance_stage) FRAME0(fire)
#undef FRAME0
#define FRAME(name,params,...) static void native_frame_##name params { brick_from_native(); play_##name(NULL,&play,__VA_ARGS__); brick_to_native(); }
FRAME(wait,(uint32_t count),count) FRAME(sprite,(uint32_t slot,uint32_t x,uint32_t y),slot,x,y)
FRAME(cycle,(uint32_t first,uint32_t last,uint32_t amount),first,last,amount)
#undef FRAME
static uint32_t native_frame_elapsed(uint32_t a,uint32_t b) { brick_from_native(); uint32_t result=play_elapsed(NULL,&play,a,b); brick_to_native(); return result; }
static uint32_t native_frame_now(void) { brick_from_native(); uint32_t result=play_now(NULL,&play); brick_to_native(); return result; }
static void native_frame_update(void) { brick_from_native(); fixture_play_update(&play); brick_to_native(); }
#define MOTION0(name) static void native_motion_##name(void) { brick_from_native(); motion_##name(NULL,&motion); brick_to_native(); }
MOTION0(paddle_power) MOTION0(unstick) MOTION0(lose_life)
#undef MOTION0
static void native_motion_explosion(uint32_t x,uint32_t y) { brick_from_native(); motion_explosion(NULL,&motion,x,y); brick_to_native(); }
static uint32_t native_motion_overlap(font_rect a,font_rect b) { brick_from_native(); uint32_t result=motion_overlap(NULL,&motion,&a,&b); brick_to_native(); return result; }
#define MOTION0(name) static void native_motion_root_##name(void) { brick_from_native(); fixture_motion_##name(&motion); brick_to_native(); }
MOTION0(create) MOTION0(update) MOTION0(rebound) MOTION0(remove)
#undef MOTION0
static uint32_t native_motion_root_contact(uint32_t x,uint32_t y) { brick_from_native(); uint32_t result=fixture_motion_contact(&motion,x,y); brick_to_native(); return result; }
static void connected_install(int source) {
#define FRAME(name) REQUIRE(install_frame_service_##name((void (*)(void))native_frame_##name));
    FRAME(refresh_score) FRAME(move_paddle) FRAME(move_shots) FRAME(move_pickups) FRAME(move_trails)
    FRAME(restore_damage) FRAME(draw_explosions) FRAME(draw_paddle) FRAME(draw_pickups) FRAME(draw_trails)
    FRAME(prepare_last_brick) FRAME(draw_last_brick) FRAME(present) FRAME(split) FRAME(power) FRAME(next_board)
    FRAME(advance_stage) FRAME(fire) FRAME(wait) FRAME(sprite) FRAME(cycle) FRAME(elapsed) FRAME(now)
#undef FRAME
#define MOTION(name) REQUIRE(install_motion_service_##name((void (*)(void))native_motion_##name));
    MOTION(paddle_power) MOTION(unstick) MOTION(lose_life) MOTION(explosion) MOTION(overlap)
#undef MOTION
    if (!source) return;
    REQUIRE(install_frame_update(native_frame_update));
#define MOTION(name) REQUIRE(install_motion_##name((void (*)(void))native_motion_root_##name));
    MOTION(create) MOTION(update) MOTION(rebound) MOTION(remove) MOTION(contact)
#undef MOTION
}
#endif
static void connected_setup(void) {
    if (scenario>=33) {
        uint32_t column=scenario==35 ? UINT32_MAX : scenario==36 ? WRAP_COLUMN : 0;
        uint32_t row=scenario==35 ? 85 : 84;
        *brick_byte(0x42ca60,column,row)=(scenario==35 || scenario==37) ? 8 : 7;
        if (scenario==34) *brick_byte(0x42cc10,column,row)=3;
        if (scenario==35) {
            *brick_byte(0x42ca60,UINT32_MAX,84)=1;
            *brick_byte(0x42ca60,0,84)=1;*brick_byte(0x42ca60,0,85)=1;
            *brick_byte(0x42ca60,UINT32_MAX-1,84)=2;
        }
        if (scenario==36) { *brick_byte(0x42ca60,0,84)=3;*brick_byte(0x42cc10,0,84)=9; }
        if (scenario==37) {
            *brick_byte(0x42ca60,0,83)=1;*brick_byte(0x42ca60,1,83)=1;*brick_byte(0x42ca60,1,84)=1;
        }
        if (scenario==38) *brick_byte(0x42cc10,1,84)=5;
        publish_effects();return;
    }
    const uint32_t slots[]={1,55,61};
    for (unsigned i=0;i<3;++i) {
        objects.banks[0].slots[slots[i]]=&connected_sprites[i];
        for (unsigned j=4;j<=8;j+=4) { uint32_t dimension=9; memcpy(connected_sprites[i].retained+j,&dimension,4); }
    }
    for (unsigned i=0;i<361;++i) { sine[i]=1024; cosine[i]=512; }
    motion.paddle_width=73; motion.ball_count=1; play.paddle_x=play.old_paddle_x=320; play.paddle_y=play.old_paddle_y=450;
    ball_live[0]=1; balls[0]=(play_ball){.x=200,.y=100,.dx=0,.dy=4,.sprite=1,.angle=75,.speed=5};
    play.balls=(play_balls){&balls[0],&balls[0],&balls[0],0};
    current_board.cells[4][6]=(unsigned char)(scenario==21 ? 3 : scenario==22 ? 8 : scenario==23 ? 2 : 7);
    if (scenario==22) for (unsigned r=3;r<=5;++r) for (unsigned c=5;c<=7;++c) if (r!=4 || c!=6) current_board.cells[r][c]=1;
    title.fast=scenario==24; publish_effects();
}
static void connected_run(void) {
    if (scenario>=33) {
        uint32_t column=scenario==35 ? UINT32_MAX : scenario==36 ? WRAP_COLUMN : 0;
        uint32_t row=scenario==35 ? 85 : 84;
        CALL2(queue,0x406410,column,row);
    }
    for (unsigned i=0;i<(scenario>=33 ? 16u : 12u);++i) {
#ifndef DX_STANDALONE
        ((void (*)(void))0x4044d0)(); brick_from_native();
#else
        fixture_play_update(&play); import_effects();
#endif
        snapshot(NULL);
    }
}
