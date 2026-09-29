/* Actual pickup and frame consumers over the same objects as powerup actions. */
#include "play-runtime.h"
void play_enter(void) { ++frame_entries; }
void pickup_enter(unsigned operation) { REQUIRE(operation<4); }
static void frame_call(unsigned op,const uint32_t *args,unsigned count) { begin(&powers,100+op,args,count); (void)end(0); }
#define FRAME0(name,op) void play_##name(void *u,play_state *s) { (void)u; REQUIRE(s==&play); frame_call(op,NULL,0); }
FRAME0(refresh_score,PLAY_REFRESH_SCORE) FRAME0(move_paddle,PLAY_MOVE_PADDLE) FRAME0(move_balls,PLAY_MOVE_BALLS)
FRAME0(move_shots,PLAY_MOVE_SHOTS) FRAME0(move_trails,PLAY_MOVE_TRAILS) FRAME0(restore_damage,PLAY_RESTORE_DAMAGE)
FRAME0(advance_brick_effects,PLAY_ADVANCE_BRICK_EFFECTS) FRAME0(draw_explosions,PLAY_DRAW_EXPLOSIONS)
FRAME0(draw_paddle,PLAY_DRAW_PADDLE) FRAME0(draw_trails,PLAY_DRAW_TRAILS) FRAME0(prepare_last_brick,PLAY_PREPARE_LAST_BRICK)
FRAME0(draw_last_brick,PLAY_DRAW_LAST_BRICK) FRAME0(present,PLAY_PRESENT) FRAME0(next_board,PLAY_NEXT_BOARD)
FRAME0(advance_stage,PLAY_ADVANCE_STAGE) FRAME0(fire,PLAY_FIRE)
#undef FRAME0
void play_move_pickups(void *u,play_state *s) { (void)u; REQUIRE(s==&play); fixture_pickup_update(&pickups); }
void play_draw_pickups(void *u,play_state *s) { (void)u; REQUIRE(s==&play); fixture_pickup_draw(&pickups); }
void play_split(void *u,play_state *s) { (void)u; REQUIRE(s==&play); fixture_power_split(&powers); }
void play_power(void *u,play_state *s) { (void)u; REQUIRE(s==&play); fixture_power_super(&powers); }
void play_stop_sound(void *u,play_state *s,uint32_t sound) { REQUIRE(s==&play); power_stop_sound(u,&powers,sound); }
void play_play_sound(void *u,play_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d) { REQUIRE(s==&play); power_play_sound(u,&powers,a,b,c,d); }
void play_free_event(void *u,play_state *s,play_event *p) { REQUIRE(s==&play); power_free_cell(u,&powers,p); }
#define FRAME(name,op,params,...) void play_##name params { (void)u; REQUIRE(s==&play); const uint32_t args[]={__VA_ARGS__}; frame_call(op,args,sizeof(args)/sizeof(*args)); }
FRAME(wait,PLAY_WAIT,(void *u,play_state *s,uint32_t n),n)
FRAME(sprite,PLAY_SPRITE,(void *u,play_state *s,uint32_t a,uint32_t b,uint32_t c),a,b,c)
FRAME(cycle,PLAY_CYCLE,(void *u,play_state *s,uint32_t a,uint32_t b,uint32_t c),a,b,c)
FRAME(hit_tile,PLAY_HIT_TILE,(void *u,play_state *s,uint32_t a,uint32_t b),a,b)
FRAME(spawn_debris,PLAY_SPAWN_DEBRIS,(void *u,play_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d),a,b,c,d)
#undef FRAME
uint32_t play_elapsed(void *u,play_state *s,uint32_t a,uint32_t b) { (void)u; REQUIRE(s==&play); const uint32_t args[]={a,b}; frame_call(PLAY_ELAPSED,args,2); return 0; }
uint32_t play_now(void *u,play_state *s) { (void)u; REQUIRE(s==&play); frame_call(PLAY_NOW,NULL,0); return 9000; }
uint32_t play_random(void *u,play_state *s,uint32_t n) { (void)u; REQUIRE(s==&play && n); frame_call(PLAY_RANDOM,&n,1); return 0; }
pickup *pickup_allocate(void *u,pickup_state *s) { (void)u; REQUIRE(s==&pickups); REQUIRE(0); return NULL; }
void pickup_free(void *u,pickup_state *s,pickup *p) {
    (void)u; REQUIRE(s==&pickups && p==&frame_pickup && frame_pickup_live);
    begin(&powers,200+PICKUP_FREE,NULL,0); frame_pickup_live=0; (void)end(0);
}
void pickup_stop_sound(void *u,pickup_state *s,uint32_t n) { REQUIRE(s==&pickups); power_stop_sound(u,&powers,n); }
void pickup_play_sound(void *u,pickup_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d) { REQUIRE(s==&pickups); power_play_sound(u,&powers,a,b,c,d); }
uint32_t pickup_random(void *u,pickup_state *s,uint32_t n) { REQUIRE(s==&pickups); return play_random(u,&play,n); }
uint32_t pickup_pan(void *u,pickup_state *s,uint32_t x) { (void)u; REQUIRE(s==&pickups); begin(&powers,200+PICKUP_PAN,&x,1); return end(x+11); }
uint32_t pickup_overlap(void *u,pickup_state *s,font_rect *a,font_rect *b) {
    (void)u; REQUIRE(s==&pickups); uint32_t args[]={a->left,a->top,a->right,a->bottom,b->left,b->top,b->right,b->bottom};
    begin(&powers,200+PICKUP_OVERLAP,args,8); return end(1);
}
void pickup_particle(void *u,pickup_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f) {
    (void)u; REQUIRE(s==&pickups); const uint32_t args[]={a,b,c,d,e,f}; begin(&powers,200+PICKUP_PARTICLE,args,6); (void)end(0);
}
void pickup_sprite(void *u,pickup_state *s,uint32_t a,uint32_t b,uint32_t c) { REQUIRE(s==&pickups); play_sprite(u,&play,a,b,c); }
#define PICKUP_ACTION(name,action) void pickup_##name(void *u,pickup_state *s) { (void)u; REQUIRE(s==&pickups); fixture_power_##action(&powers); }
PICKUP_ACTION(unstick,soften) PICKUP_ACTION(queue_explosive_bricks,expand) PICKUP_ACTION(detonate_bricks,detonate) PICKUP_ACTION(release_attached,release)
#undef PICKUP_ACTION
void pickup_move_paddle(void *u,pickup_state *s) { REQUIRE(s==&pickups); play_move_paddle(u,&play); }
void pickup_next_board(void *u,pickup_state *s) { REQUIRE(s==&pickups); play_next_board(u,&play); }
void pickup_lose_life(void *u,pickup_state *s) { (void)u; REQUIRE(s==&pickups); begin(&powers,200+PICKUP_LOSE_LIFE,NULL,0); (void)end(0); }
#ifndef DX_STANDALONE
static uint32_t native_pickup[9],native_sprite[12];
static uint32_t pickup_address(pickup *p) { if (!p) return 0; REQUIRE(p==&frame_pickup && frame_pickup_live); return (uint32_t)(uintptr_t)native_pickup; }
static pickup *pickup_view(uint32_t address) { if (!address) return NULL; REQUIRE(address==(uint32_t)(uintptr_t)native_pickup && frame_pickup_live); return &frame_pickup; }
static void connected_to_native(void) {
    *word(0x431c50)=pickup_address(pickups.current); *word(0x431c54)=pickup_address(pickups.first); *word(0x431c58)=pickup_address(pickups.last);
    *word(0x431cb8)=pickups.count; *word(0x431c84)=pickups.paddle_sprite; *word(0x431ca8)=pickups.lives; *word(0x431c7c)=pickups.next_life;
    if (frame_pickup_live) { memcpy(native_pickup,&frame_pickup,28); native_pickup[7]=pickup_address(frame_pickup.next); native_pickup[8]=pickup_address(frame_pickup.previous); }
    *word(0x434968)=0; *word(0x433d1c)=(uint32_t)(uintptr_t)native_sprite;
    memcpy((unsigned char *)native_sprite+4,frame_sprite.retained,41);
}
static void connected_from_native(void) {
    pickups.current=pickup_view(*word(0x431c50)); pickups.first=pickup_view(*word(0x431c54)); pickups.last=pickup_view(*word(0x431c58));
    pickups.count=*word(0x431cb8); pickups.paddle_sprite=*word(0x431c84); pickups.lives=*word(0x431ca8); pickups.next_life=*word(0x431c7c);
    if (frame_pickup_live) { memcpy(&frame_pickup,native_pickup,28); frame_pickup.next=pickup_view(native_pickup[7]); frame_pickup.previous=pickup_view(native_pickup[8]); }
    memcpy(frame_sprite.retained,(unsigned char *)native_sprite+4,41);
}
static int connected_free(uint32_t address) {
    if (address!=(uint32_t)(uintptr_t)native_pickup) return 0;
    pickup_free(NULL,&pickups,&frame_pickup); return 1;
}
#define FRAME0(name) static void native_frame_##name(void) { power_from_native(); play_##name(NULL,&play); power_to_native(); }
FRAME0(refresh_score) FRAME0(move_paddle) FRAME0(move_balls) FRAME0(move_shots) FRAME0(move_trails) FRAME0(restore_damage)
FRAME0(advance_brick_effects) FRAME0(draw_explosions) FRAME0(draw_paddle) FRAME0(draw_trails) FRAME0(prepare_last_brick)
FRAME0(draw_last_brick) FRAME0(present) FRAME0(next_board) FRAME0(advance_stage) FRAME0(fire)
#undef FRAME0
#define FRAME(name,params,...) static void native_frame_##name params { power_from_native(); play_##name(NULL,&play,__VA_ARGS__); power_to_native(); }
FRAME(wait,(uint32_t n),n) FRAME(sprite,(uint32_t a,uint32_t b,uint32_t c),a,b,c)
FRAME(cycle,(uint32_t a,uint32_t b,uint32_t c),a,b,c) FRAME(hit_tile,(uint32_t a,uint32_t b),a,b)
#undef FRAME
static uint32_t native_frame_elapsed(uint32_t a,uint32_t b) { power_from_native(); uint32_t r=play_elapsed(NULL,&play,a,b); power_to_native(); return r; }
static uint32_t native_frame_now(void) { power_from_native(); uint32_t r=play_now(NULL,&play); power_to_native(); return r; }
static uint32_t native_frame_random(uint32_t n) { power_from_native(); uint32_t r=play_random(NULL,&play,n); power_to_native(); return r; }
static uint32_t native_pickup_pan(uint32_t x) { power_from_native(); uint32_t r=pickup_pan(NULL,&pickups,x); power_to_native(); return r; }
static uint32_t native_pickup_overlap(font_rect a,font_rect b) { power_from_native(); uint32_t r=pickup_overlap(NULL,&pickups,&a,&b); power_to_native(); return r; }
static void native_pickup_particle(uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f) { power_from_native(); pickup_particle(NULL,&pickups,a,b,c,d,e,f); power_to_native(); }
static void native_pickup_sprite(uint32_t a,uint32_t b,uint32_t c) { power_from_native(); pickup_sprite(NULL,&pickups,a,b,c); power_to_native(); }
static void native_pickup_lose_life(void) { power_from_native(); pickup_lose_life(NULL,&pickups); power_to_native(); }
static void native_frame_update(void) { power_from_native(); fixture_play_update(&play); power_to_native(); }
#define PICKUP0(name) static void native_connected_pickup_##name(void) { power_from_native(); fixture_pickup_##name(&pickups); power_to_native(); }
PICKUP0(update) PICKUP0(draw) PICKUP0(remove)
#undef PICKUP0
static void native_connected_pickup_create(uint32_t a,uint32_t b,uint32_t c,uint32_t d) { power_from_native(); fixture_pickup_create(&pickups,a,b,c,d); power_to_native(); }
static void frame_install(int source) {
#define FRAME(name) REQUIRE(install_frame_service_##name((void (*)(void))native_frame_##name));
    FRAME(refresh_score) FRAME(move_paddle) FRAME(move_balls) FRAME(move_shots) FRAME(move_trails) FRAME(restore_damage)
    FRAME(advance_brick_effects) FRAME(draw_explosions) FRAME(draw_paddle) FRAME(draw_trails) FRAME(prepare_last_brick)
    FRAME(draw_last_brick) FRAME(present) FRAME(next_board) FRAME(advance_stage) FRAME(fire) FRAME(wait) FRAME(sprite)
    FRAME(cycle) FRAME(hit_tile) FRAME(elapsed) FRAME(now) FRAME(random)
#undef FRAME
#define PICKUP(name) REQUIRE(install_connected_pickup_service_##name((void (*)(void))native_pickup_##name));
    PICKUP(pan) PICKUP(overlap) PICKUP(particle) PICKUP(sprite) PICKUP(lose_life)
#undef PICKUP
    if (source) {
        REQUIRE(install_frame_update(native_frame_update));
#define PICKUP(name) REQUIRE(install_connected_pickup_##name((void (*)(void))native_connected_pickup_##name));
        PICKUP(create) PICKUP(update) PICKUP(draw) PICKUP(remove)
#undef PICKUP
    }
}
#endif
static void frame_setup(void) {
    REQUIRE(scenario>=30 && scenario<37); const uint32_t kinds[]={12,7,4,2,6,10,12};
    list_balls(3); balls[0].attached=1; balls[1].attached=2;
    play.remaining_bricks=20; play.old_paddle_x=play.paddle_x=300; play.old_paddle_y=play.paddle_y=450;
    motion.paddle_width=37; pickups.paddle_sprite=1; pickups.count=1;
    frame_pickup=(pickup){.kind=kinds[scenario-30],.sprite=1,.x=300,.y=445}; frame_pickup_live=1;
    pickups.current=pickups.first=pickups.last=&frame_pickup;
    uint32_t width=37,height=10; memcpy(frame_sprite.retained+4,&width,4); memcpy(frame_sprite.retained+8,&height,4);
    objects.banks[0].slots[1]=&frame_sprite;
    current_board.cells[5][5]=8; current_board.cells[5][4]=2; current_board.cells[3][3]=21; current_board.cells[8][8]=7;
    if (scenario==36) play.paused=1;
}
static void frame_run(void) {
    for (unsigned i=0;i<4;++i) {
#ifndef DX_STANDALONE
        ((void (*)(void))0x4044d0)(); power_from_native();
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
