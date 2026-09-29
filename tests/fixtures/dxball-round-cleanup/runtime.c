/* Original cleanup and portable C over complete controlled object graphs. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "round-runtime.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
enum { NODES=12 };
static uint32_t scenario,entered[2],calls,free_count;
static font_surface surfaces[4]={{1},{2},{3},{4}};
static font_sprite sprites[2];
static struct spx_opaque_cleanup_state_v5 objects;
static font_state font={.objects=&objects};
static pcx_state palettes;
static flow_state flow;
static title_state title={.font=&font,.flow=&flow,.palettes=&palettes};
static scene_state scene={.animation=&title};
static menu_state menu={.scene=&scene};
static int32_t sine[361],cosine[361];
static play_state play={.menu=&menu,.sine=sine,.cosine=cosine};
static board current_board;
static motion_state motion={.play=&play,.board=&current_board};
static pickup_state pickups={.motion=&motion};
static paddle_state paddle={.pickups=&pickups};
static brick_state bricks={.motion=&motion};
static progression_state progress={.paddle=&paddle,.bricks=&bricks};
static powerup_state powers={.motion=&motion};
static particle_state particles={.destination=&title.software};
static explosion_state explosions={.roots=&play.explosions};
static round_state rounds={.progression=&progress,.powers=&powers,.particles=&particles,.explosions=&explosions};
static play_ball balls[NODES];
static uint32_t ball_live[NODES];
static play_shot shots[NODES];
static uint32_t shot_live[NODES];
static brick_effect brick_items[NODES];
static uint32_t brick_live[NODES];
static play_event events[NODES];
static uint32_t event_live[NODES];
static pickup pickup_items[NODES];
static uint32_t pickup_live[NODES];
static particle particle_items[NODES];
static uint32_t particle_live[NODES];
static explosion explosion_items[NODES];
static uint32_t explosion_live[NODES];
static spx_observer *observer;
static void require(int test,const char *expression,unsigned line) {
    if (!test) { fprintf(stderr,"round-runtime.c:%u: adapter premise failed: %s\n",line,expression); exit(3); }
}
#define REQUIRE(test) require(!!(test),#test,__LINE__)
void round_enter(unsigned operation) { REQUIRE(operation<2); ++entered[operation]; }
static uint32_t ball_id(const play_ball *p) {
    if (!p) return 0;
    for (unsigned i=0;i<NODES;++i) if (p==&balls[i]) { REQUIRE(ball_live[i]); return 1*100+i+1; }
    REQUIRE(0); return 0;
}
static uint32_t shot_id(const play_shot *p) {
    if (!p) return 0;
    for (unsigned i=0;i<NODES;++i) if (p==&shots[i]) { REQUIRE(shot_live[i]); return 2*100+i+1; }
    REQUIRE(0); return 0;
}
static uint32_t brick_id(const brick_effect *p) {
    if (!p) return 0;
    for (unsigned i=0;i<NODES;++i) if (p==&brick_items[i]) { REQUIRE(brick_live[i]); return 3*100+i+1; }
    REQUIRE(0); return 0;
}
static uint32_t event_id(const play_event *p) {
    if (!p) return 0;
    for (unsigned i=0;i<NODES;++i) if (p==&events[i]) { REQUIRE(event_live[i]); return 4*100+i+1; }
    REQUIRE(0); return 0;
}
static uint32_t pickup_id(const pickup *p) {
    if (!p) return 0;
    for (unsigned i=0;i<NODES;++i) if (p==&pickup_items[i]) { REQUIRE(pickup_live[i]); return 5*100+i+1; }
    REQUIRE(0); return 0;
}
static uint32_t particle_id(const particle *p) {
    if (!p) return 0;
    for (unsigned i=0;i<NODES;++i) if (p==&particle_items[i]) { REQUIRE(particle_live[i]); return 6*100+i+1; }
    REQUIRE(0); return 0;
}
static uint32_t explosion_id(const explosion *p) {
    if (!p) return 0;
    for (unsigned i=0;i<NODES;++i) if (p==&explosion_items[i]) { REQUIRE(explosion_live[i]); return 7*100+i+1; }
    REQUIRE(0); return 0;
}
static uint32_t surface_id(const font_surface *p) {
    if (!p) return 0;
    for (unsigned i=0;i<4;++i) if (p==&surfaces[i]) return i+1;
    REQUIRE(0); return 0;
}
static void sync_views(void) {
    play.brick_effects.current=(void *)bricks.current; play.brick_effects.first=(void *)bricks.first;
}
void round_exit(round_state *s) { REQUIRE(s==&rounds); sync_views(); }
static void snapshot(const char *name) {
    spx_observe_object(observer,name);
    uint32_t fields[]={progress.pending,progress.board_changed,progress.warning_y,progress.warning_frames,
        menu.score,pickups.next_life,pickups.lives,pickups.count,pickups.paddle_sprite,bricks.board_index,
        flow.transition_pending,flow.next_scene,scene.mouse_x,scene.mouse_y,scene.mouse_buttons,scene.presentation_mode,
        play.paused,play.last_tick,play.changed,play.paddle_x,play.paddle_y,play.old_paddle_x,play.old_paddle_y,
        play.remaining_bricks,play.warning_sound,play.voice_pending,play.slow_balls,play.speedup_balls,play.fire_balls,
        play.split_balls,play.power_balls,play.launch_pressed,play.gun,play.shot_count,
        motion.ball_count,motion.gravity,motion.paddle_width,motion.paddle_power,motion.sticky,motion.pierce,motion.impact_dx,motion.impact_dy,
        paddle.phase,paddle.last_tick,paddle.spark_deadline,paddle.spark_width,paddle.spark_sprite,objects.current_bank,
        surface_id(title.back),surface_id(flow.primary),surface_id(flow.overlay),surface_id(font.destination)};
    spx_observe_u32s(observer,"fields",fields,sizeof(fields)/sizeof(*fields));
    spx_observe_array(observer,"lists");
    { uint32_t roots[]={ball_id(play.balls.current),ball_id(play.balls.first),ball_id(play.balls.last),play.balls.retained}; spx_observe_u32s(observer,NULL,roots,4); }
    { uint32_t roots[]={shot_id(play.shots.current),shot_id(play.shots.first),shot_id(play.shots.last),play.shots.retained}; spx_observe_u32s(observer,NULL,roots,4); }
    { uint32_t roots[]={brick_id(bricks.current),brick_id(bricks.first),brick_id(bricks.last),0}; spx_observe_u32s(observer,NULL,roots,4); }
    { uint32_t roots[]={event_id(play.events.current),event_id(play.events.first),event_id(play.events.last),play.events.retained}; spx_observe_u32s(observer,NULL,roots,4); }
    { uint32_t roots[]={pickup_id(pickups.current),pickup_id(pickups.first),pickup_id(pickups.last),0}; spx_observe_u32s(observer,NULL,roots,4); }
    { uint32_t roots[]={particle_id(particles.current),particle_id(particles.first),particle_id(particles.last),0}; spx_observe_u32s(observer,NULL,roots,4); }
    { uint32_t roots[]={ball_id(powers.staged_balls.current),ball_id(powers.staged_balls.first),ball_id(powers.staged_balls.last),powers.staged_balls.retained}; spx_observe_u32s(observer,NULL,roots,4); }
    { uint32_t roots[]={event_id(powers.queued_cells.current),event_id(powers.queued_cells.first),event_id(powers.queued_cells.last),powers.queued_cells.retained}; spx_observe_u32s(observer,NULL,roots,4); }
    { uint32_t roots[]={explosion_id(explosion_current(&explosions)),explosion_id(explosion_first(&explosions)),explosion_id(explosions.last),explosions.retained}; spx_observe_u32s(observer,NULL,roots,4); }
    spx_observe_end(observer);
    spx_observe_array(observer,"balls");
    for (unsigned i=0;i<NODES;++i) if (ball_live[i]) {
        uint32_t row[16]={1*100+i+1}; memcpy(row+1,&balls[i],52);
        row[14]=ball_id(balls[i].next); row[15]=ball_id(balls[i].previous); spx_observe_u32s(observer,NULL,row,16);
    }
    spx_observe_end(observer);
    spx_observe_array(observer,"shots");
    for (unsigned i=0;i<NODES;++i) if (shot_live[i]) {
        uint32_t row[7]={2*100+i+1}; memcpy(row+1,&shots[i],16);
        row[5]=shot_id(shots[i].next); row[6]=shot_id(shots[i].previous); spx_observe_u32s(observer,NULL,row,7);
    }
    spx_observe_end(observer);
    spx_observe_array(observer,"brick_items");
    for (unsigned i=0;i<NODES;++i) if (brick_live[i]) {
        uint32_t row[11]={3*100+i+1}; memcpy(row+1,&brick_items[i],32);
        row[9]=brick_id(brick_items[i].next); row[10]=brick_id(brick_items[i].previous); spx_observe_u32s(observer,NULL,row,11);
    }
    spx_observe_end(observer);
    spx_observe_array(observer,"events");
    for (unsigned i=0;i<NODES;++i) if (event_live[i]) {
        uint32_t row[6]={4*100+i+1}; memcpy(row+1,&events[i],12);
        row[4]=event_id(events[i].next); row[5]=event_id(events[i].previous); spx_observe_u32s(observer,NULL,row,6);
    }
    spx_observe_end(observer);
    spx_observe_array(observer,"pickup_items");
    for (unsigned i=0;i<NODES;++i) if (pickup_live[i]) {
        uint32_t row[10]={5*100+i+1}; memcpy(row+1,&pickup_items[i],28);
        row[8]=pickup_id(pickup_items[i].next); row[9]=pickup_id(pickup_items[i].previous); spx_observe_u32s(observer,NULL,row,10);
    }
    spx_observe_end(observer);
    spx_observe_array(observer,"particle_items");
    for (unsigned i=0;i<NODES;++i) if (particle_live[i]) {
        uint32_t row[12]={6*100+i+1}; memcpy(row+1,&particle_items[i],36);
        row[10]=particle_id(particle_items[i].next); row[11]=particle_id(particle_items[i].previous); spx_observe_u32s(observer,NULL,row,12);
    }
    spx_observe_end(observer);
    spx_observe_array(observer,"explosion_items");
    for (unsigned i=0;i<NODES;++i) if (explosion_live[i]) {
        uint32_t row[6]={7*100+i+1}; memcpy(row+1,&explosion_items[i],12);
        row[4]=explosion_id(explosion_items[i].next); row[5]=explosion_id(explosion_items[i].previous); spx_observe_u32s(observer,NULL,row,6);
    }
    spx_observe_end(observer);
    spx_observe_bytes(observer,"board",(const unsigned char *)&current_board,400);
    spx_observe_bytes(observer,"pending_cells",play.pending_cells,400);
    spx_observe_bytes(observer,"current_palette",(const unsigned char *)palettes.current,1024);
    spx_observe_bytes(observer,"staged_palette",(const unsigned char *)palettes.staged,1024);
    spx_observe_bytes(observer,"sprite_zero",sprites[0].retained,41);
    spx_observe_bytes(observer,"sprite_one",sprites[1].retained,41);
    spx_observe_end(observer);
}
static void begin(void *s,unsigned op,const uint32_t *args,unsigned count) {
    REQUIRE((s==&rounds || s==&progress) && calls++<2000); sync_views(); spx_observe_object(observer,NULL);
    spx_observe_u64(observer,"operation",op); spx_observe_u32s(observer,"arguments",args,count); snapshot("before");
}
static uint32_t end(uint32_t result) { sync_views(); snapshot("after"); spx_observe_u64(observer,"result",result); spx_observe_end(observer); return result; }
#define BEGIN0(op) (void)unused; begin(s,op,NULL,0)
#define BEGIN(op,...) (void)unused; const uint32_t args[]={__VA_ARGS__}; begin(s,op,args,sizeof(args)/sizeof(*args))
static void dimensions(font_sprite *sprite,uint32_t width,uint32_t height) {
    for (unsigned i=0;i<4;++i) { sprite->retained[4+i]=(unsigned char)(width>>(8*i)); sprite->retained[8+i]=(unsigned char)(height>>(8*i)); }
}
static play_ball *new_ball(void) {
    unsigned i=0; while (i<NODES && ball_live[i]) ++i; REQUIRE(i<NODES); ball_live[i]=1;
    for (unsigned j=0;j<13;++j) { uint32_t value=1*10000+i*100+j; memcpy((unsigned char *)&balls[i]+4*j,&value,4); }
    balls[i].next=balls[i].previous=NULL; return &balls[i];
}
static play_shot *new_shot(void) {
    unsigned i=0; while (i<NODES && shot_live[i]) ++i; REQUIRE(i<NODES); shot_live[i]=1;
    for (unsigned j=0;j<4;++j) { uint32_t value=2*10000+i*100+j; memcpy((unsigned char *)&shots[i]+4*j,&value,4); }
    shots[i].next=shots[i].previous=NULL; return &shots[i];
}
static brick_effect *new_brick(void) {
    unsigned i=0; while (i<NODES && brick_live[i]) ++i; REQUIRE(i<NODES); brick_live[i]=1;
    for (unsigned j=0;j<8;++j) { uint32_t value=3*10000+i*100+j; memcpy((unsigned char *)&brick_items[i]+4*j,&value,4); }
    brick_items[i].next=brick_items[i].previous=NULL; return &brick_items[i];
}
static play_event *new_event(void) {
    unsigned i=0; while (i<NODES && event_live[i]) ++i; REQUIRE(i<NODES); event_live[i]=1;
    for (unsigned j=0;j<3;++j) { uint32_t value=4*10000+i*100+j; memcpy((unsigned char *)&events[i]+4*j,&value,4); }
    events[i].next=events[i].previous=NULL; return &events[i];
}
static pickup *new_pickup(void) {
    unsigned i=0; while (i<NODES && pickup_live[i]) ++i; REQUIRE(i<NODES); pickup_live[i]=1;
    for (unsigned j=0;j<7;++j) { uint32_t value=5*10000+i*100+j; memcpy((unsigned char *)&pickup_items[i]+4*j,&value,4); }
    pickup_items[i].next=pickup_items[i].previous=NULL; return &pickup_items[i];
}
static particle *new_particle(void) {
    unsigned i=0; while (i<NODES && particle_live[i]) ++i; REQUIRE(i<NODES); particle_live[i]=1;
    for (unsigned j=0;j<9;++j) { uint32_t value=6*10000+i*100+j; memcpy((unsigned char *)&particle_items[i]+4*j,&value,4); }
    particle_items[i].next=particle_items[i].previous=NULL; return &particle_items[i];
}
static explosion *new_explosion(void) {
    unsigned i=0; while (i<NODES && explosion_live[i]) ++i; REQUIRE(i<NODES); explosion_live[i]=1;
    for (unsigned j=0;j<3;++j) { uint32_t value=7*10000+i*100+j; memcpy((unsigned char *)&explosion_items[i]+4*j,&value,4); }
    explosion_items[i].next=explosion_items[i].previous=NULL; return &explosion_items[i];
}
static void append_shot(void) {
    play_shot *p=new_shot(); p->previous=play.shots.last;
    if (play.shots.last) play.shots.last->next=p; else play.shots.first=p;
    play.shots.last=p; play.shots.current=p;
}
static void append_pickup(void) {
    pickup *p=new_pickup(); p->previous=pickups.last;
    if (pickups.last) pickups.last->next=p; else pickups.first=p;
    pickups.last=p; pickups.current=p;
}
void round_free(void *unused,round_state *s,round_storage *storage) {
    (void)unused; REQUIRE(s==&rounds); uint32_t id=0; uint32_t *live=NULL;
    for (unsigned i=0;i<NODES;++i) if ((void *)storage==&balls[i]) { REQUIRE(ball_live[i]); id=1*100+i+1; live=&ball_live[i]; }
    for (unsigned i=0;i<NODES;++i) if ((void *)storage==&shots[i]) { REQUIRE(shot_live[i]); id=2*100+i+1; live=&shot_live[i]; }
    for (unsigned i=0;i<NODES;++i) if ((void *)storage==&brick_items[i]) { REQUIRE(brick_live[i]); id=3*100+i+1; live=&brick_live[i]; }
    for (unsigned i=0;i<NODES;++i) if ((void *)storage==&events[i]) { REQUIRE(event_live[i]); id=4*100+i+1; live=&event_live[i]; }
    for (unsigned i=0;i<NODES;++i) if ((void *)storage==&pickup_items[i]) { REQUIRE(pickup_live[i]); id=5*100+i+1; live=&pickup_live[i]; }
    for (unsigned i=0;i<NODES;++i) if ((void *)storage==&particle_items[i]) { REQUIRE(particle_live[i]); id=6*100+i+1; live=&particle_live[i]; }
    for (unsigned i=0;i<NODES;++i) if ((void *)storage==&explosion_items[i]) { REQUIRE(explosion_live[i]); id=7*100+i+1; live=&explosion_live[i]; }
    REQUIRE(id && live); begin(s,ROUND_FREE,&id,1); *live=0; ++free_count;
    if (scenario==14 && free_count==1) play.balls.current=NULL;
    if (scenario==15 && free_count==1) play.shots.current=NULL;
    if (scenario==16 && free_count==1) play.shots.current=play.shots.last;
    if (scenario==17 && free_count==1) append_pickup();
    if (scenario==18 && id/100==6 && free_count<30) { append_shot(); play.shots.retained+=7; }
    if (scenario==19) { motion.ball_count+=3; pickups.count+=5; menu.score+=11; }
    if (scenario==20 && free_count==1) { REQUIRE(play.balls.first); play.balls.first->x=999; }
    if (scenario==31 && free_count==1) pickups.lives=0;
    (void)end(0);
}
void round_fade(void *unused,round_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e) {
    BEGIN(ROUND_FADE,a,b,c,d,e);
    if (scenario==26) { title.back=&surfaces[3]; progress.pending=99; }
    (void)end(0);
}
void round_clear_surface(void *unused,round_state *s,font_surface *surface,uint32_t color) {
    BEGIN(ROUND_CLEAR_SURFACE,surface_id(surface),color);
    if (scenario==26) flow.primary=&surfaces[2];
    (void)end(0);
}
void round_release_sounds(void *unused,round_state *s) { BEGIN0(ROUND_RELEASE_SOUNDS); (void)end(0); }
void round_clear_sprites(void *unused,round_state *s) { BEGIN0(ROUND_CLEAR_SPRITES); (void)end(0); }
void round_stop_music(void *unused,round_state *s) {
    BEGIN0(ROUND_STOP_MUSIC); if (scenario==26) append_shot(); (void)end(0);
}
#ifdef ROUND_CONNECTED
#include "progress-consumer.h"
#endif
#ifndef DX_STANDALONE
static uint32_t native_surfaces[4],native_sprites[2][12],vtable[8];
static uint32_t *word(uint32_t address) { return (uint32_t *)(uintptr_t)address; }
static uint32_t native_ball[NODES][15];
static uint32_t ball_address(play_ball *p) { uint32_t id=ball_id(p); return id ? (uint32_t)(uintptr_t)native_ball[id%100-1] : 0; }
static play_ball *ball_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)native_ball[i]) { REQUIRE(ball_live[i]); return &balls[i]; }
    REQUIRE(0); return NULL;
}
static uint32_t native_shot[NODES][6];
static uint32_t shot_address(play_shot *p) { uint32_t id=shot_id(p); return id ? (uint32_t)(uintptr_t)native_shot[id%100-1] : 0; }
static play_shot *shot_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)native_shot[i]) { REQUIRE(shot_live[i]); return &shots[i]; }
    REQUIRE(0); return NULL;
}
static uint32_t native_brick[NODES][10];
static uint32_t brick_address(brick_effect *p) { uint32_t id=brick_id(p); return id ? (uint32_t)(uintptr_t)native_brick[id%100-1] : 0; }
static brick_effect *brick_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)native_brick[i]) { REQUIRE(brick_live[i]); return &brick_items[i]; }
    REQUIRE(0); return NULL;
}
static uint32_t native_event[NODES][5];
static uint32_t event_address(play_event *p) { uint32_t id=event_id(p); return id ? (uint32_t)(uintptr_t)native_event[id%100-1] : 0; }
static play_event *event_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)native_event[i]) { REQUIRE(event_live[i]); return &events[i]; }
    REQUIRE(0); return NULL;
}
static uint32_t native_pickup[NODES][9];
static uint32_t pickup_address(pickup *p) { uint32_t id=pickup_id(p); return id ? (uint32_t)(uintptr_t)native_pickup[id%100-1] : 0; }
static pickup *pickup_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)native_pickup[i]) { REQUIRE(pickup_live[i]); return &pickup_items[i]; }
    REQUIRE(0); return NULL;
}
static uint32_t native_particle[NODES][11];
static uint32_t particle_address(particle *p) { uint32_t id=particle_id(p); return id ? (uint32_t)(uintptr_t)native_particle[id%100-1] : 0; }
static particle *particle_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)native_particle[i]) { REQUIRE(particle_live[i]); return &particle_items[i]; }
    REQUIRE(0); return NULL;
}
static uint32_t native_explosion[NODES][5];
static uint32_t explosion_address(explosion *p) { uint32_t id=explosion_id(p); return id ? (uint32_t)(uintptr_t)native_explosion[id%100-1] : 0; }
static explosion *explosion_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)native_explosion[i]) { REQUIRE(explosion_live[i]); return &explosion_items[i]; }
    REQUIRE(0); return NULL;
}
static uint32_t surface_address(font_surface *p) { uint32_t id=surface_id(p); return id ? (uint32_t)(uintptr_t)&native_surfaces[id-1] : 0; }
static font_surface *surface_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<4;++i) if (address==(uint32_t)(uintptr_t)&native_surfaces[i]) return &surfaces[i];
    REQUIRE(0); return NULL;
}
static uint32_t effect_address(play_effect *p) {
    if (!p) return 0;
    for (unsigned i=0;i<NODES;++i) {
        if ((void *)p==&brick_items[i]) return brick_address(&brick_items[i]);
        if ((void *)p==&explosion_items[i]) return explosion_address(&explosion_items[i]);
    }
    REQUIRE(0); return 0;
}
static play_effect *effect_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<NODES;++i) {
        if (address==(uint32_t)(uintptr_t)native_brick[i]) return (void *)brick_view(address);
        if (address==(uint32_t)(uintptr_t)native_explosion[i]) return (void *)explosion_view(address);
    }
    REQUIRE(0); return NULL;
}
static void play_objects_to_native(void) {
    for (unsigned i=0;i<NODES;++i) if (ball_live[i]) { memcpy(native_ball[i],&balls[i],52); native_ball[i][13]=ball_address(balls[i].next); native_ball[i][14]=ball_address(balls[i].previous); }
    for (unsigned i=0;i<NODES;++i) if (shot_live[i]) { memcpy(native_shot[i],&shots[i],16); native_shot[i][4]=shot_address(shots[i].next); native_shot[i][5]=shot_address(shots[i].previous); }
    for (unsigned i=0;i<NODES;++i) if (brick_live[i]) { memcpy(native_brick[i],&brick_items[i],32); native_brick[i][8]=brick_address(brick_items[i].next); native_brick[i][9]=brick_address(brick_items[i].previous); }
    for (unsigned i=0;i<NODES;++i) if (event_live[i]) { memcpy(native_event[i],&events[i],12); native_event[i][3]=event_address(events[i].next); native_event[i][4]=event_address(events[i].previous); }
    for (unsigned i=0;i<NODES;++i) if (pickup_live[i]) { memcpy(native_pickup[i],&pickup_items[i],28); native_pickup[i][7]=pickup_address(pickup_items[i].next); native_pickup[i][8]=pickup_address(pickup_items[i].previous); }
    for (unsigned i=0;i<NODES;++i) if (particle_live[i]) { memcpy(native_particle[i],&particle_items[i],36); native_particle[i][9]=particle_address(particle_items[i].next); native_particle[i][10]=particle_address(particle_items[i].previous); }
    for (unsigned i=0;i<NODES;++i) if (explosion_live[i]) { memcpy(native_explosion[i],&explosion_items[i],12); native_explosion[i][3]=explosion_address(explosion_items[i].next); native_explosion[i][4]=explosion_address(explosion_items[i].previous); }
}
static void play_objects_from_native(void) {
    for (unsigned i=0;i<NODES;++i) if (ball_live[i]) { memcpy(&balls[i],native_ball[i],52); balls[i].next=ball_view(native_ball[i][13]); balls[i].previous=ball_view(native_ball[i][14]); }
    for (unsigned i=0;i<NODES;++i) if (shot_live[i]) { memcpy(&shots[i],native_shot[i],16); shots[i].next=shot_view(native_shot[i][4]); shots[i].previous=shot_view(native_shot[i][5]); }
    for (unsigned i=0;i<NODES;++i) if (brick_live[i]) { memcpy(&brick_items[i],native_brick[i],32); brick_items[i].next=brick_view(native_brick[i][8]); brick_items[i].previous=brick_view(native_brick[i][9]); }
    for (unsigned i=0;i<NODES;++i) if (event_live[i]) { memcpy(&events[i],native_event[i],12); events[i].next=event_view(native_event[i][3]); events[i].previous=event_view(native_event[i][4]); }
    for (unsigned i=0;i<NODES;++i) if (pickup_live[i]) { memcpy(&pickup_items[i],native_pickup[i],28); pickup_items[i].next=pickup_view(native_pickup[i][7]); pickup_items[i].previous=pickup_view(native_pickup[i][8]); }
    for (unsigned i=0;i<NODES;++i) if (particle_live[i]) { memcpy(&particle_items[i],native_particle[i],36); particle_items[i].next=particle_view(native_particle[i][9]); particle_items[i].previous=particle_view(native_particle[i][10]); }
    for (unsigned i=0;i<NODES;++i) if (explosion_live[i]) { memcpy(&explosion_items[i],native_explosion[i],12); explosion_items[i].next=explosion_view(native_explosion[i][3]); explosion_items[i].previous=explosion_view(native_explosion[i][4]); }
}
#define PARENT_WORDS(X) X(menu.score,0x431cbc) X(scene.mouse_x,0x434970) X(scene.mouse_y,0x434978) \
    X(scene.mouse_buttons,0x434990) X(scene.presentation_mode,0x417a04) X(flow.next_scene,0x431fc4) X(flow.transition_pending,0x431fc8) \
    X(objects.current_bank,0x434968) X(pickups.count,0x431cb8) X(pickups.lives,0x431ca8) X(pickups.next_life,0x431c7c) X(pickups.paddle_sprite,0x431c84) \
    X(paddle.phase,0x431c64) X(paddle.last_tick,0x42ca50) X(paddle.spark_deadline,0x431c70) X(paddle.spark_sprite,0x42cc08) X(paddle.spark_width,0x431c18) \
    X(bricks.board_index,0x42ca54) X(progress.pending,0x42ca5c) X(progress.board_changed,0x431cc0) X(progress.warning_y,0x42cdc8) X(progress.warning_frames,0x431cb0)
static void play_parent_to_native(void) {
#define PUT(name,address) *word(address)=name;
    PARENT_WORDS(PUT)
#undef PUT
    *word(0x4349b4)=surface_address(title.back); *word(0x4349ac)=surface_address(flow.primary);
    *word(0x431fcc)=surface_address(flow.overlay); *word(0x434960)=surface_address(font.destination);
    memcpy((void *)0x42c148,palettes.current,1024); memcpy((void *)0x42c548,palettes.staged,1024);
    for (unsigned i=0;i<2;++i) {
        native_sprites[i][0]=surface_address(sprites[i].surface); memcpy((unsigned char *)native_sprites[i]+4,sprites[i].retained,41);
        *word(0x433e28+i*1048)=(uint32_t)(uintptr_t)native_sprites[i];
    }
}
static void play_parent_from_native(void) {
#define GET(name,address) name=*word(address);
    PARENT_WORDS(GET)
#undef GET
    title.back=surface_view(*word(0x4349b4)); flow.primary=surface_view(*word(0x4349ac));
    flow.overlay=surface_view(*word(0x431fcc)); font.destination=surface_view(*word(0x434960));
    memcpy(palettes.current,(void *)0x42c148,1024); memcpy(palettes.staged,(void *)0x42c548,1024);
    for (unsigned i=0;i<2;++i) {
        REQUIRE(*word(0x433e28+i*1048)==(uint32_t)(uintptr_t)native_sprites[i]);
        sprites[i].surface=surface_view(native_sprites[i][0]); memcpy(sprites[i].retained,(unsigned char *)native_sprites[i]+4,41);
    }
}
#include "play-native.h"
#include "motion-native.h"
static void round_to_native(void) {
    sync_views(); motion_to_native();
#define PUT_LIST(list,address,name) do { uint32_t *p=word(address); p[0]=name##_address(list.current); p[1]=name##_address(list.first); p[2]=name##_address(list.last); } while (0)
    PUT_LIST(bricks,0x42cbf8,brick); PUT_LIST(pickups,0x431c50,pickup); PUT_LIST(particles,0x42ca28,particle);
    PUT_LIST(powers.staged_balls,0x431c98,ball); PUT_LIST(powers.queued_cells,0x42ca40,event);
#undef PUT_LIST
    *word(0x431ca4)=powers.staged_balls.retained; *word(0x42ca4c)=powers.queued_cells.retained;
    *word(0x42cdc0)=explosion_address(explosions.last); *word(0x42cdc4)=explosions.retained;
}
static void round_from_native(void) {
    motion_from_native();
#define GET_LIST(list,address,name) do { const uint32_t *p=word(address); list.current=name##_view(p[0]); list.first=name##_view(p[1]); list.last=name##_view(p[2]); } while (0)
    GET_LIST(bricks,0x42cbf8,brick); GET_LIST(pickups,0x431c50,pickup); GET_LIST(particles,0x42ca28,particle);
    GET_LIST(powers.staged_balls,0x431c98,ball); GET_LIST(powers.queued_cells,0x42ca40,event);
#undef GET_LIST
    powers.staged_balls.retained=*word(0x431ca4); powers.queued_cells.retained=*word(0x42ca4c);
    explosions.last=explosion_view(*word(0x42cdc0)); explosions.retained=*word(0x42cdc4); sync_views();
}
static void native_round_free(uint32_t address) {
    round_from_native(); round_storage *storage=NULL;
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)native_ball[i]) storage=(void *)ball_view(address);
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)native_shot[i]) storage=(void *)shot_view(address);
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)native_brick[i]) storage=(void *)brick_view(address);
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)native_event[i]) storage=(void *)event_view(address);
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)native_pickup[i]) storage=(void *)pickup_view(address);
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)native_particle[i]) storage=(void *)particle_view(address);
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)native_explosion[i]) storage=(void *)explosion_view(address);
    REQUIRE(storage); round_free(NULL,&rounds,storage); round_to_native();
}
static void native_round_fade(uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e) { round_from_native(); round_fade(NULL,&rounds,a,b,c,d,e); round_to_native(); }
static void native_round_clear_surface(uint32_t surface,uint32_t color) { round_from_native(); round_clear_surface(NULL,&rounds,surface_view(surface),color); round_to_native(); }
#define ROUND_SERVICE(name) static void native_round_##name(void) { round_from_native(); round_##name(NULL,&rounds); round_to_native(); }
ROUND_SERVICE(release_sounds) ROUND_SERVICE(clear_sprites) ROUND_SERVICE(stop_music)
#undef ROUND_SERVICE
static void native_round_clear(void) { round_from_native(); fixture_round_clear(&rounds); round_to_native(); }
static void native_round_leave(uint32_t full) { round_from_native(); fixture_round_leave(&rounds,full); round_to_native(); }
static void install(int source) {
    for (unsigned i=0;i<4;++i) native_surfaces[i]=(uint32_t)(uintptr_t)vtable;
#define HOOK(name) REQUIRE(install_round_service_##name((void (*)(void))native_round_##name));
    HOOK(free) HOOK(fade) HOOK(clear_surface) HOOK(release_sounds) HOOK(clear_sprites) HOOK(stop_music)
#undef HOOK
    if (source) { REQUIRE(install_round_clear(native_round_clear)); REQUIRE(install_round_leave((void (*)(void))native_round_leave)); }
}
#endif
static unsigned list_size(unsigned kind) {
    if (scenario==0 || scenario==27) return 0;
    if (scenario==1) return 1;
    if (scenario>=6 && scenario<=13) {
        const unsigned selected[]={1,0,3,5,8,2,4,6};
        unsigned wanted=selected[scenario-6]; return kind==wanted || (scenario==8 && kind==7) ? 3 : 0;
    }
    return scenario==22 ? 1+kind%3 : 3;
}
static unsigned cursor_position(unsigned kind,unsigned count) {
    if (!count || scenario==4) return 99;
    if (scenario==2) return count/2;
    if (scenario==3) return count-1;
    if (scenario==5) return kind%4==3 ? 99 : (kind%3)%count;
    return 0;
}
static void setup(void) {
    title.back=&surfaces[0]; flow.primary=&surfaces[1]; flow.overlay=&surfaces[2]; font.destination=&surfaces[3];
    objects.banks[0].slots[68]=&sprites[0]; objects.banks[1].slots[68]=&sprites[1]; dimensions(&sprites[0],37,10); dimensions(&sprites[1],65,12);
    scene.mouse_x=320; flow.next_scene=2; menu.score=12345; pickups.next_life=999; pickups.lives=3; pickups.count=4;
    motion.ball_count=5; motion.paddle_width=75; play.shot_count=6; play.remaining_bricks=2;
    play.paddle_x=301; play.paddle_y=450; play.balls.retained=47; play.shots.retained=49; play.events.retained=51;
    powers.staged_balls.retained=53; powers.queued_cells.retained=55; explosions.retained=57;
    current_board.cells[1][2]=3; current_board.cells[2][3]=7; memset(play.pending_cells,7,400);
    for (unsigned i=0;i<256;++i) for (unsigned j=0;j<4;++j) { palettes.current[i][j]=(unsigned char)(i+j*23); palettes.staged[i][j]=(unsigned char)(3*i+j*71); }
    { unsigned count=list_size(0),position=cursor_position(0,count);
        for (unsigned i=0;i<count;++i) { play_shot *p=new_shot(); p->previous=play.shots.last;
            if (play.shots.last) play.shots.last->next=p; else play.shots.first=p;
            play.shots.last=p; if (i==position) play.shots.current=p;
        }
    }
    { unsigned count=list_size(1),position=cursor_position(1,count);
        for (unsigned i=0;i<count;++i) { play_ball *p=new_ball(); p->previous=play.balls.last;
            if (play.balls.last) play.balls.last->next=p; else play.balls.first=p;
            play.balls.last=p; if (i==position) play.balls.current=p;
        }
    }
    { unsigned count=list_size(2),position=cursor_position(2,count);
        for (unsigned i=0;i<count;++i) { brick_effect *p=new_brick(); p->previous=bricks.last;
            if (bricks.last) bricks.last->next=p; else bricks.first=p;
            bricks.last=p; if (i==position) bricks.current=p;
        }
    }
    { unsigned count=list_size(3),position=cursor_position(3,count);
        for (unsigned i=0;i<count;++i) { play_event *p=new_event(); p->previous=play.events.last;
            if (play.events.last) play.events.last->next=p; else play.events.first=p;
            play.events.last=p; if (i==position) play.events.current=p;
        }
    }
    { unsigned count=list_size(4),position=cursor_position(4,count);
        for (unsigned i=0;i<count;++i) { pickup *p=new_pickup(); p->previous=pickups.last;
            if (pickups.last) pickups.last->next=p; else pickups.first=p;
            pickups.last=p; if (i==position) pickups.current=p;
        }
    }
    { unsigned count=list_size(5),position=cursor_position(5,count);
        for (unsigned i=0;i<count;++i) { particle *p=new_particle(); p->previous=particles.last;
            if (particles.last) particles.last->next=p; else particles.first=p;
            particles.last=p; if (i==position) particles.current=p;
        }
    }
    { unsigned count=list_size(6),position=cursor_position(6,count);
        for (unsigned i=0;i<count;++i) { play_ball *p=new_ball(); p->previous=powers.staged_balls.last;
            if (powers.staged_balls.last) powers.staged_balls.last->next=p; else powers.staged_balls.first=p;
            powers.staged_balls.last=p; if (i==position) powers.staged_balls.current=p;
        }
    }
    { unsigned count=list_size(7),position=cursor_position(7,count);
        for (unsigned i=0;i<count;++i) { play_event *p=new_event(); p->previous=powers.queued_cells.last;
            if (powers.queued_cells.last) powers.queued_cells.last->next=p; else powers.queued_cells.first=p;
            powers.queued_cells.last=p; if (i==position) powers.queued_cells.current=p;
        }
    }
    { unsigned count=list_size(8),position=cursor_position(8,count);
        for (unsigned i=0;i<count;++i) { explosion *p=new_explosion(); p->previous=explosions.last;
            if (explosions.last) explosions.last->next=p; else explosions.roots->first=(void *)p;
            explosions.last=p; if (i==position) explosions.roots->current=(void *)p;
        }
    }
    if (scenario==25) progress.pending=1;
    sync_views();
}
#ifdef ROUND_CONNECTED
#include "connected-run.h"
#endif
static int run(int argc,char **argv) {
    REQUIRE(argc==3); scenario=(uint32_t)strtoul(argv[2],NULL,10); setup();
#ifdef ROUND_CONNECTED
    REQUIRE(scenario>=28 && scenario<32); connected_setup();
#else
    REQUIRE(scenario<28);
#endif
#ifndef DX_STANDALONE
    install(!strcmp(argv[1],"source")); round_to_native();
#ifdef ROUND_CONNECTED
    connected_install(!strcmp(argv[1],"source"));
#endif
#endif
    spx_observer output=spx_observe_begin(stdout); observer=&output; spx_observe_array(observer,"round_cleanup"); snapshot(NULL);
#ifdef ROUND_CONNECTED
    connected_run();
#else
    unsigned rounds_count=scenario==21 ? 2 : 1;
    for (unsigned i=0;i<rounds_count;++i) {
#ifndef DX_STANDALONE
        if (scenario>=23) ((void (*)(uint32_t))0x408f70)(scenario==23 ? 0 : scenario==25 ? 2 : 1);
        else ((void (*)(void))0x408fd0)();
        round_from_native();
#else
        if (scenario>=23) fixture_round_leave(&rounds,scenario==23 ? 0 : scenario==25 ? 2 : 1);
        else fixture_round_clear(&rounds);
#endif
        snapshot(NULL);
    }
#endif
    spx_observe_end(observer); REQUIRE(spx_observe_finish(observer)); fputc('\n',stdout); return 0;
}
#ifdef DX_STANDALONE
int main(int argc,char **argv) { return run(argc,argv); }
#else
__declspec(dllexport) void dx_round_anchor(void) {}
static void native_start(void) { int argc=0; char **argv=NULL; extern int __cdecl __getmainargs(int *,char ***,char ***,int,int *); char **env=NULL; int startup=0;
    __getmainargs(&argc,&argv,&env,0,&startup); ExitProcess((UINT)run(argc,argv)); }
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { (void)instance; (void)reserved;
    if (reason==DLL_PROCESS_ATTACH) REQUIRE(install_startup(native_start));
    return TRUE; }
#endif
