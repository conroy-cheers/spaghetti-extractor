/* The existing frame calls actual particle operations over the same objects. */
#include "play-runtime.h"
static font_state font;
static flow_state flow;
static title_state title={.font=&font,.flow=&flow};
static scene_state scene={.animation=&title};
static menu_state menu={.scene=&scene};
static int32_t sine[361],cosine[361];
static play_state play={.menu=&menu,.sine=sine,.cosine=cosine};
static uint32_t frame_entered,frame_index;
void play_enter(void) { ++frame_entered; }
static void frame_call(play_state *s,unsigned operation,const uint32_t *args,unsigned count) {
    REQUIRE(s==&play); begin(&particles,100+operation,args,count); (void)end(0);
}
#define FRAME0(name,operation) void play_##name(void *unused,play_state *s) { (void)unused; frame_call(s,operation,NULL,0); }
FRAME0(refresh_score,PLAY_REFRESH_SCORE) FRAME0(move_paddle,PLAY_MOVE_PADDLE)
FRAME0(move_shots,PLAY_MOVE_SHOTS) FRAME0(move_pickups,PLAY_MOVE_PICKUPS)
FRAME0(restore_damage,PLAY_RESTORE_DAMAGE) FRAME0(advance_brick_effects,PLAY_ADVANCE_BRICK_EFFECTS)
FRAME0(draw_explosions,PLAY_DRAW_EXPLOSIONS) FRAME0(draw_paddle,PLAY_DRAW_PADDLE)
FRAME0(draw_pickups,PLAY_DRAW_PICKUPS) FRAME0(prepare_last_brick,PLAY_PREPARE_LAST_BRICK) FRAME0(draw_last_brick,PLAY_DRAW_LAST_BRICK)
FRAME0(present,PLAY_PRESENT) FRAME0(split,PLAY_SPLIT) FRAME0(power,PLAY_POWER)
FRAME0(advance_stage,PLAY_ADVANCE_STAGE) FRAME0(fire,PLAY_FIRE) FRAME0(next_board,PLAY_NEXT_BOARD)
#undef FRAME0
void play_move_trails(void *u,play_state *s) { (void)u; REQUIRE(s==&play); fixture_particle_update(&particles); }
void play_draw_trails(void *u,play_state *s) { (void)u; REQUIRE(s==&play); fixture_particle_draw(&particles); }
void play_move_balls(void *u,play_state *s) {
    (void)u; frame_call(s,PLAY_MOVE_BALLS,NULL,0);
    if (scenario==23 && frame_index<3) { SYNC(); CREATE(200+frame_index*20,100,1,0,16,1); }
}
void play_free_event(void *u,play_state *s,play_event *event) { (void)u; (void)s; (void)event; REQUIRE(0); }
#define FRAME(name,operation,params,...) void play_##name params { (void)unused; const uint32_t args[]={__VA_ARGS__}; frame_call(s,operation,args,sizeof(args)/sizeof(*args)); }
FRAME(wait,PLAY_WAIT,(void *unused,play_state *s,uint32_t count),count)
FRAME(sprite,PLAY_SPRITE,(void *unused,play_state *s,uint32_t slot,uint32_t x,uint32_t y),slot,x,y)
FRAME(cycle,PLAY_CYCLE,(void *unused,play_state *s,uint32_t first,uint32_t last,uint32_t amount),first,last,amount)
FRAME(hit_tile,PLAY_HIT_TILE,(void *unused,play_state *s,uint32_t column,uint32_t row),column,row)
FRAME(stop_sound,PLAY_STOP_SOUND,(void *unused,play_state *s,uint32_t sound),sound)
FRAME(play_sound,PLAY_PLAY_SOUND,(void *unused,play_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d),a,b,c,d)
FRAME(spawn_debris,PLAY_SPAWN_DEBRIS,(void *unused,play_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d),a,b,c,d)
#undef FRAME
uint32_t play_now(void *u,play_state *s) { (void)u; frame_call(s,PLAY_NOW,NULL,0); return 1234; }
uint32_t play_elapsed(void *u,play_state *s,uint32_t previous,uint32_t delay) {
    (void)u; const uint32_t args[]={previous,delay}; frame_call(s,PLAY_ELAPSED,args,2); return 0;
}
uint32_t play_random(void *u,play_state *s,uint32_t limit) { (void)u; frame_call(s,PLAY_RANDOM,&limit,1); return 0; }
#ifndef DX_STANDALONE
#define EMPTY(name,type) static uint32_t name##_address(type *p) { REQUIRE(!p); return 0; } \
    static type *name##_view(uint32_t p) { REQUIRE(!p); return NULL; }
EMPTY(ball,play_ball) EMPTY(shot,play_shot) EMPTY(event,play_event) EMPTY(effect,play_effect)
#undef EMPTY
static void play_objects_to_native(void) {}
static void play_objects_from_native(void) {}
static void play_parent_to_native(void) { *word(0x434960)=surface_address(font.destination); *word(0x431cbc)=menu.score; *word(0x417a04)=scene.presentation_mode; *word(0x434990)=scene.mouse_buttons; }
static void play_parent_from_native(void) { font.destination=surface_view(*word(0x434960)); menu.score=*word(0x431cbc); scene.presentation_mode=*word(0x417a04); scene.mouse_buttons=*word(0x434990); }
#include "play-native.h"
static void frame_to_native(void) { play_to_native(); particle_to_native(); }
static void frame_from_native(void) { play_from_native(); particle_from_native(); }
#define FRAME0(name) static void native_frame_##name(void) { frame_from_native(); play_##name(NULL,&play); frame_to_native(); }
FRAME0(refresh_score) FRAME0(move_paddle) FRAME0(move_balls) FRAME0(move_shots) FRAME0(move_pickups)
FRAME0(restore_damage) FRAME0(advance_brick_effects) FRAME0(draw_explosions) FRAME0(draw_paddle)
FRAME0(draw_pickups) FRAME0(prepare_last_brick) FRAME0(draw_last_brick) FRAME0(present) FRAME0(split) FRAME0(power)
FRAME0(advance_stage) FRAME0(fire) FRAME0(next_board)
#undef FRAME0
#define FRAME(name,params,...) static void native_frame_##name params { frame_from_native(); play_##name(NULL,&play,__VA_ARGS__); frame_to_native(); }
FRAME(wait,(uint32_t count),count) FRAME(sprite,(uint32_t slot,uint32_t x,uint32_t y),slot,x,y)
FRAME(cycle,(uint32_t first,uint32_t last,uint32_t amount),first,last,amount)
FRAME(hit_tile,(uint32_t column,uint32_t row),column,row) FRAME(stop_sound,(uint32_t sound),sound)
FRAME(play_sound,(uint32_t a,uint32_t b,uint32_t c,uint32_t d),a,b,c,d)
FRAME(spawn_debris,(uint32_t a,uint32_t b,uint32_t c,uint32_t d),a,b,c,d)
#undef FRAME
static uint32_t native_frame_elapsed(uint32_t previous,uint32_t delay) { frame_from_native(); uint32_t r=play_elapsed(NULL,&play,previous,delay); frame_to_native(); return r; }
static uint32_t native_frame_now(void) { frame_from_native(); uint32_t r=play_now(NULL,&play); frame_to_native(); return r; }
static uint32_t native_frame_random(uint32_t limit) { frame_from_native(); uint32_t r=play_random(NULL,&play,limit); frame_to_native(); return r; }
static void native_frame_update(void) { frame_from_native(); fixture_play_update(&play); frame_to_native(); }
static void frame_install(int source) {
#define FRAME(name) REQUIRE(install_frame_service_##name((void (*)(void))native_frame_##name));
    FRAME(refresh_score) FRAME(move_paddle) FRAME(move_balls) FRAME(move_shots) FRAME(move_pickups)
    FRAME(restore_damage) FRAME(advance_brick_effects) FRAME(draw_explosions) FRAME(draw_paddle)
    FRAME(draw_pickups) FRAME(prepare_last_brick) FRAME(draw_last_brick) FRAME(present) FRAME(split) FRAME(power)
    FRAME(advance_stage) FRAME(fire) FRAME(wait) FRAME(sprite) FRAME(cycle) FRAME(hit_tile) FRAME(next_board)
    FRAME(elapsed) FRAME(now) FRAME(random) FRAME(stop_sound) FRAME(play_sound) FRAME(spawn_debris)
#undef FRAME
    if (source) REQUIRE(install_frame_update(native_frame_update));
}
#endif
static void frame_setup(void) {
    font.destination=&surfaces[1]; /* Independent from the particle software surface. */
    play.remaining_bricks=10; play.paddle_x=300; play.paddle_y=450;
    if (scenario!=23) list(3);
    if (scenario==20) for (unsigned i=0;i<3;++i) { items[i].age=6; items[i].color_tick=3; }
    if (scenario==21) { items[0].x=619; items[1].x=620; }
    if (scenario==22) play.paused=1;
}
static void frame_run(void) {
    for (frame_index=0;frame_index<8;++frame_index) {
#ifndef DX_STANDALONE
        frame_to_native(); ((void (*)(void))0x4044d0)(); frame_from_native();
#else
        fixture_play_update(&play);
#endif
        snapshot(NULL);
        uint32_t fields[]={play.paused,play.last_tick,play.changed,play.old_paddle_x,play.old_paddle_y,menu.score};
        spx_observe_u32s(observer,NULL,fields,6);
    }
}

/* This consumer retains its documented in-grid event domain. */
uint32_t play_read_pending(void *u,play_state *s,uint32_t column,uint32_t row) {
    (void)u;REQUIRE(s==&play && column<20 && row<20);
    return s->pending_cells[row*20+column];
}
