/* Local native frame comparisons: no scene startup, graphics or audio backend. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "play-runtime.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif

enum { NODES=4 };
struct play_effect { uint32_t id; };
static menu_state menu;
static scene_state scene;
static play_ball balls[NODES];
static play_shot shots[NODES];
static play_event events[NODES];
static play_effect effects[2]={{1},{2}};
static uint32_t event_live[NODES],mode,entered,call_count,seed=0x162d5839,callback_done;
static int32_t sine[361],cosine[361];
static play_state play={.menu=&menu,.sine=sine,.cosine=cosine};
static spx_observer *observer;
static void require(int condition,const char *expression,unsigned line) {
    if (!condition) { fprintf(stderr,"play-runtime.c:%u: adapter premise failed: %s\n",line,expression); exit(3); }
}
#define REQUIRE(test) require(!!(test),#test,__LINE__)
void play_enter(void) { ++entered; }
#define ID(name,type,array) static uint32_t name##_id(const type *p) { \
    if (!p) return 0; \
    for (uint32_t i=0;i<NODES;++i) if (p==&array[i]) return i+1; \
    REQUIRE(0); return 0; }
ID(ball,play_ball,balls) ID(shot,play_shot,shots) ID(event,play_event,events)
static uint32_t effect_id(const play_effect *p) { if (!p) return 0; REQUIRE(p==&effects[0] || p==&effects[1]); return p->id; }

static void snapshot(spx_observer *o,const char *name) {
    spx_observe_object(o,name);
    uint32_t fields[]={play.paused,play.last_tick,play.changed,play.paddle_x,play.paddle_y,play.old_paddle_x,play.old_paddle_y,
        play.remaining_bricks,play.warning_sound,play.voice_pending,play.slow_balls,play.speedup_balls,play.fire_balls,
        play.split_balls,play.power_balls,play.launch_pressed,play.gun,play.shot_count,menu.score,scene.presentation_mode,scene.mouse_buttons};
    spx_observe_u32s(o,"fields",fields,sizeof(fields)/sizeof(fields[0]));
    uint32_t lists[]={ball_id(play.balls.current),ball_id(play.balls.first),ball_id(play.balls.last),play.balls.retained,
        shot_id(play.shots.current),shot_id(play.shots.first),shot_id(play.shots.last),play.shots.retained,
        event_id(play.events.current),event_id(play.events.first),event_id(play.events.last),play.events.retained,
        effect_id(play.brick_effects.current),effect_id(play.brick_effects.first),effect_id(play.explosions.current),effect_id(play.explosions.first)};
    spx_observe_u32s(o,"lists",lists,16); spx_observe_array(o,"balls");
    for (unsigned i=0;i<NODES;++i) { uint32_t words[15]; memcpy(words,&balls[i],13*4);
        words[13]=ball_id(balls[i].next); words[14]=ball_id(balls[i].previous); spx_observe_u32s(o,NULL,words,15); }
    spx_observe_end(o); spx_observe_array(o,"shots");
    for (unsigned i=0;i<NODES;++i) { uint32_t words[6]; memcpy(words,&shots[i],4*4);
        words[4]=shot_id(shots[i].next); words[5]=shot_id(shots[i].previous); spx_observe_u32s(o,NULL,words,6); }
    spx_observe_end(o); spx_observe_array(o,"events");
    for (unsigned i=0;i<NODES;++i) {
        play_event *e=&events[i]; uint32_t words[]={event_live[i],e->kind,e->column,e->row,event_id(e->next),event_id(e->previous)};
        spx_observe_u32s(o,NULL,words,6);
    }
    spx_observe_end(o); spx_observe_bytes(o,"pending_cells",play.pending_cells,400); spx_observe_end(o);
}
static void begin_call(play_state *s,unsigned operation,const uint32_t *args,unsigned count) {
    REQUIRE(s==&play && call_count++<120); spx_observe_object(observer,NULL); spx_observe_u64(observer,"operation",operation);
    spx_observe_u32s(observer,"arguments",args,count); snapshot(observer,"before");
}
static uint32_t end_call(uint32_t result) {
    snapshot(observer,"after"); spx_observe_u64(observer,"result",result); spx_observe_end(observer); return result;
}
#define BEGIN0(operation) (void)unused; begin_call(s,operation,NULL,0)
#define BEGIN(operation,...) (void)unused; const uint32_t args[]={__VA_ARGS__}; begin_call(s,operation,args,sizeof(args)/sizeof(args[0]))
#define SIMPLE(name,operation) void play_##name(void *unused,play_state *s) { BEGIN0(operation); (void)end_call(0); }
SIMPLE(refresh_score,PLAY_REFRESH_SCORE) SIMPLE(move_balls,PLAY_MOVE_BALLS)
SIMPLE(move_shots,PLAY_MOVE_SHOTS) SIMPLE(move_pickups,PLAY_MOVE_PICKUPS) SIMPLE(move_trails,PLAY_MOVE_TRAILS)
SIMPLE(restore_damage,PLAY_RESTORE_DAMAGE) SIMPLE(advance_brick_effects,PLAY_ADVANCE_BRICK_EFFECTS)
SIMPLE(draw_explosions,PLAY_DRAW_EXPLOSIONS)
#ifndef PLAY_CONNECTED_PADDLE
SIMPLE(draw_paddle,PLAY_DRAW_PADDLE)
#endif
SIMPLE(draw_pickups,PLAY_DRAW_PICKUPS) SIMPLE(draw_trails,PLAY_DRAW_TRAILS)
SIMPLE(prepare_last_brick,PLAY_PREPARE_LAST_BRICK) SIMPLE(draw_last_brick,PLAY_DRAW_LAST_BRICK) SIMPLE(present,PLAY_PRESENT)
void play_move_paddle(void *unused,play_state *s) {
    BEGIN0(PLAY_MOVE_PADDLE); s->paddle_x+=3; s->paddle_y=450;
    if (mode>=16) s->changed=1;
    (void)end_call(0);
}
void play_wait(void *unused,play_state *s,uint32_t count) { BEGIN(PLAY_WAIT,count); (void)end_call(0); }
void play_sprite(void *unused,play_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    BEGIN(PLAY_SPRITE,slot,x,y);
    if (mode==4 && !callback_done++) { s->shots.current=&shots[1]; shots[2].x=99; }
    (void)end_call(0);
}
void play_stop_sound(void *unused,play_state *s,uint32_t sound) { BEGIN(PLAY_STOP_SOUND,sound); (void)end_call(0); }
uint32_t play_elapsed(void *unused,play_state *s,uint32_t previous,uint32_t delay) {
    BEGIN(PLAY_ELAPSED,previous,delay); return end_call(mode==1 || mode==3 || mode==7);
}
void play_cycle(void *unused,play_state *s,uint32_t first,uint32_t last,uint32_t amount) { BEGIN(PLAY_CYCLE,first,last,amount); (void)end_call(0); }
uint32_t play_now(void *unused,play_state *s) { BEGIN0(PLAY_NOW); return end_call(0x12345678); }
void play_hit_tile(void *unused,play_state *s,uint32_t column,uint32_t row) {
    BEGIN(PLAY_HIT_TILE,column,row); REQUIRE(column<20 && row<20);
    if (mode==5) { s->events.current=&events[2]; events[2].column=19; events[2].row=19; menu.score+=11; }
    (void)end_call(0);
}
uint32_t play_random(void *unused,play_state *s,uint32_t limit) {
    BEGIN(PLAY_RANDOM,limit); REQUIRE(limit);
    if (mode>=16) { REQUIRE(limit==4); return end_call((mode-16)%4); }
    seed=seed*1664525+1013904223; return end_call(seed%limit);
}
void play_spawn_debris(void *unused,play_state *s,uint32_t column,uint32_t row,uint32_t dx,uint32_t dy) {
    BEGIN(PLAY_SPAWN_DEBRIS,column,row,dx,dy); (void)end_call(0);
}
void play_free_event(void *unused,play_state *s,play_event *event) {
    uint32_t id=event_id(event); BEGIN(PLAY_FREE_EVENT,id); REQUIRE(id && event_live[id-1]); event_live[id-1]=0;
    if (mode==6) s->events.current=NULL;
    (void)end_call(0);
}
void play_play_sound(void *unused,play_state *s,uint32_t sound,uint32_t repeat,uint32_t volume,uint32_t pan) {
    BEGIN(PLAY_PLAY_SOUND,sound,repeat,volume,pan); (void)end_call(0);
}
void play_split(void *unused,play_state *s) {
    BEGIN0(PLAY_SPLIT); play_ball *last=s->balls.last;
    if (last) { last->next=&balls[3]; balls[3].previous=last; balls[3].next=NULL; s->balls.last=&balls[3]; }
    (void)end_call(0);
}
void play_power(void *unused,play_state *s) {
    BEGIN0(PLAY_POWER); for (play_ball *ball=s->balls.first;ball;ball=ball->next) ball->sprite=61; (void)end_call(0);
}
void play_next_board(void *unused,play_state *s) { BEGIN0(PLAY_NEXT_BOARD); s->remaining_bricks=77; (void)end_call(0); }
void play_advance_stage(void *unused,play_state *s) { BEGIN0(PLAY_ADVANCE_STAGE); (void)end_call(0); }
void play_fire(void *unused,play_state *s) { BEGIN0(PLAY_FIRE); ++s->shot_count; scene.mouse_buttons=7; (void)end_call(0); }

#ifndef DX_STANDALONE
static uint32_t native_balls[NODES][15],native_shots[NODES][6],native_events[NODES][5],native_effects[2][4];
#define ADDRESS(name,type,array) \
static uint32_t name##_address(type *p) { uint32_t id=name##_id(p); return id ? (uint32_t)(uintptr_t)&array[id-1] : 0; } \
static type *name##_view(uint32_t address) { if (!address) return NULL; \
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)&array[i]) return &name##s[i]; \
    REQUIRE(0); return NULL; }
ADDRESS(ball,play_ball,native_balls) ADDRESS(shot,play_shot,native_shots) ADDRESS(event,play_event,native_events)
static uint32_t effect_address(play_effect *p) { uint32_t id=effect_id(p); return id ? (uint32_t)(uintptr_t)&native_effects[id-1] : 0; }
static play_effect *effect_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<2;++i) if (address==(uint32_t)(uintptr_t)&native_effects[i]) return &effects[i];
    REQUIRE(0); return NULL;
}
static void play_parent_to_native(void) {
    *(uint32_t *)0x431cbc=menu.score; *(uint32_t *)0x417a04=scene.presentation_mode; *(uint32_t *)0x434990=scene.mouse_buttons;
}
static void play_parent_from_native(void) {
    menu.score=*(uint32_t *)0x431cbc; scene.presentation_mode=*(uint32_t *)0x417a04; scene.mouse_buttons=*(uint32_t *)0x434990;
}
static void play_objects_to_native(void) {
    for (unsigned i=0;i<NODES;++i) {
        memcpy(native_balls[i],&balls[i],52); native_balls[i][13]=ball_address(balls[i].next); native_balls[i][14]=ball_address(balls[i].previous);
        memcpy(native_shots[i],&shots[i],16); native_shots[i][4]=shot_address(shots[i].next); native_shots[i][5]=shot_address(shots[i].previous);
        if (event_live[i]) { memcpy(native_events[i],&events[i],12); native_events[i][3]=event_address(events[i].next); native_events[i][4]=event_address(events[i].previous); }
    }
}
static void play_objects_from_native(void) {
    for (unsigned i=0;i<NODES;++i) {
        memcpy(&balls[i],native_balls[i],52); balls[i].next=ball_view(native_balls[i][13]); balls[i].previous=ball_view(native_balls[i][14]);
        memcpy(&shots[i],native_shots[i],16); shots[i].next=shot_view(native_shots[i][4]); shots[i].previous=shot_view(native_shots[i][5]);
        if (event_live[i]) { memcpy(&events[i],native_events[i],12); events[i].next=event_view(native_events[i][3]); events[i].previous=event_view(native_events[i][4]); }
    }
}
#include "play-native.h"
#define NATIVE0(name) static void native_##name(void) { play_from_native(); play_##name(NULL,&play); play_to_native(); }
NATIVE0(refresh_score) NATIVE0(move_paddle) NATIVE0(move_balls) NATIVE0(move_shots) NATIVE0(move_pickups) NATIVE0(move_trails)
NATIVE0(restore_damage) NATIVE0(advance_brick_effects) NATIVE0(draw_explosions) NATIVE0(draw_paddle) NATIVE0(draw_pickups)
NATIVE0(draw_trails) NATIVE0(prepare_last_brick) NATIVE0(draw_last_brick) NATIVE0(present) NATIVE0(split) NATIVE0(power)
NATIVE0(next_board) NATIVE0(advance_stage) NATIVE0(fire)
static uint32_t native_now(void) { play_from_native(); uint32_t result=play_now(NULL,&play); play_to_native(); return result; }
#define NATIVE(name,parameters,...) static void native_##name parameters { play_from_native(); play_##name(NULL,&play,__VA_ARGS__); play_to_native(); }
NATIVE(wait,(uint32_t count),count) NATIVE(sprite,(uint32_t slot,uint32_t x,uint32_t y),slot,x,y)
NATIVE(stop_sound,(uint32_t sound),sound) NATIVE(cycle,(uint32_t first,uint32_t last,uint32_t amount),first,last,amount)
NATIVE(hit_tile,(uint32_t column,uint32_t row),column,row)
NATIVE(spawn_debris,(uint32_t column,uint32_t row,uint32_t dx,uint32_t dy),column,row,dx,dy)
NATIVE(play_sound,(uint32_t sound,uint32_t repeat,uint32_t volume,uint32_t pan),sound,repeat,volume,pan)
static uint32_t native_elapsed(uint32_t previous,uint32_t delay) {
    play_from_native(); uint32_t result=play_elapsed(NULL,&play,previous,delay); play_to_native(); return result;
}
static uint32_t native_random(uint32_t limit) { play_from_native(); uint32_t result=play_random(NULL,&play,limit); play_to_native(); return result; }
static void native_free_event(uint32_t address) { play_from_native(); play_free_event(NULL,&play,event_view(address)); play_to_native(); }
static void native_update(void) { play_from_native(); fixture_play_update(&play); play_to_native(); }
static void install(int source) {
#define HOOK(name) REQUIRE(install_play_service_##name((void (*)(void))native_##name));
    HOOK(refresh_score) HOOK(move_paddle) HOOK(move_balls) HOOK(move_shots) HOOK(move_pickups) HOOK(move_trails)
    HOOK(wait) HOOK(restore_damage) HOOK(advance_brick_effects) HOOK(sprite) HOOK(draw_explosions) HOOK(draw_paddle)
    HOOK(draw_pickups) HOOK(draw_trails) HOOK(prepare_last_brick) HOOK(stop_sound) HOOK(draw_last_brick) HOOK(present)
    HOOK(elapsed) HOOK(cycle) HOOK(now) HOOK(hit_tile) HOOK(random) HOOK(spawn_debris) HOOK(free_event)
    HOOK(play_sound) HOOK(split) HOOK(power) HOOK(next_board) HOOK(advance_stage) HOOK(fire)
#undef HOOK
    if (source) REQUIRE(install_play_update(native_update));
}
#endif

#ifdef PLAY_CONNECTED_PADDLE
#include "paddle-runtime.h"
#endif

static void setup(unsigned scenario) {
    mode=scenario; menu.scene=&scene; menu.score=0xfffffff9; scene.presentation_mode=mode%2; scene.mouse_buttons=0;
    for (unsigned i=0;i<361;++i) { sine[i]=(int32_t)((i%17)*128)-1024; cosine[i]=1024-(int32_t)(i%9)*128; }
    for (unsigned i=0;i<NODES;++i) {
        balls[i]=(play_ball){.x=30+i,.y=70+i,.old_x=20+i,.old_y=60+i,.dx=i%2 ? UINT32_MAX : 1,
            .dy=i==2 ? 0 : UINT32_MAX,.sprite=i==2 ? 61 : 2,.angle=i*45,.speed=3+i,.retained=0x87650000+i,
            .attached=0,.auxiliary=0x12340000+i,.tick=89+i};
        shots[i]=(play_shot){.x=100+i,.y=200+i,.old_x=90+i,.old_y=190+i};
        events[i]=(play_event){.kind=i==1 ? 2 : 1,.column=i,.row=i+1}; event_live[i]=1;
        if (i<2) { balls[i].next=&balls[i+1]; shots[i].next=&shots[i+1]; events[i].next=&events[i+1]; }
        if (i && i<3) { balls[i].previous=&balls[i-1]; shots[i].previous=&shots[i-1]; events[i].previous=&events[i-1]; }
    }
    play.balls=(play_balls){NULL,&balls[0],&balls[2],0x11111111};
    play.shots=(play_shots){NULL,&shots[0],&shots[2],0x22222222};
    play.events=(play_events){NULL,&events[0],&events[2],0x33333333};
    play.brick_effects=(play_effects){&effects[1],&effects[0]}; play.explosions=(play_effects){&effects[0],&effects[1]};
    play.paused=mode<2 ? 1 : 0; play.last_tick=0xfffffff0; play.changed=55; play.paddle_x=300; play.paddle_y=400;
    play.old_paddle_x=123; play.old_paddle_y=456; play.remaining_bricks=10; play.warning_sound=1;
    play.gun=1; play.shot_count=5;
    if (mode==2) { play.balls=(play_balls){0}; play.shots=(play_shots){0}; play.events=(play_events){0}; }
    if (mode==7) play.slow_balls=play.speedup_balls=play.fire_balls=play.split_balls=play.power_balls=play.voice_pending=1;
    if (mode==8) { play.remaining_bricks=1; play.pending_cells[20]=1; }
    if (mode==9) { play.remaining_bricks=0; play.brick_effects.first=NULL; play.explosions.first=NULL; }
    if (mode==10) { play.remaining_bricks=UINT32_MAX; play.brick_effects.first=NULL; }
    if (mode==11 || mode==12) { scene.mouse_buttons=1; play.shot_count=mode==11 ? 5 : 6; }
    if (mode==13) { scene.presentation_mode=2; scene.mouse_buttons=2; play.paused=2;
        play.slow_balls=play.speedup_balls=play.fire_balls=play.split_balls=play.power_balls=play.voice_pending=2; play.remaining_bricks=0x80000000; }
    if (mode==14) { play.speedup_balls=1; balls[0].angle=0; balls[0].speed=3;
        balls[1].angle=0xffffffd3; balls[1].speed=UINT32_MAX; balls[2].angle=0xfffffe98; balls[2].speed=0x80000000; }
    if (mode==15) { play.slow_balls=1; play.voice_pending=1; play.warning_sound=0;
        for (unsigned i=0;i<NODES;++i) { seed=seed*1664525+1013904223; balls[i].angle=seed%360; balls[i].dx=seed; balls[i].dy=0-seed; }
    }
}
int main(int argc,char **argv) {
    REQUIRE(argc==3); unsigned scenario=(unsigned)strtoul(argv[2],NULL,10);
#ifdef PLAY_CONNECTED_PADDLE
    REQUIRE(scenario>=16 && scenario<20);
#else
    REQUIRE(scenario<16);
#endif
    setup(scenario);
    int source=!strcmp(argv[1],"source"); REQUIRE(source || !strcmp(argv[1],"original"));
#ifndef DX_STANDALONE
    install(source); play_to_native(); unsigned short control; __asm__ volatile("fnstcw %0":"=m"(control));
    fprintf(stderr,"native floating control=%04x\n",control);
#ifdef PLAY_CONNECTED_PADDLE
    paddle_setup();
#endif
#else
    REQUIRE(source);
#endif
    spx_observer o=spx_observe_begin(stdout); observer=&o; spx_observe_object(&o,"frame"); snapshot(&o,"initial");
    spx_observe_array(&o,"calls");
    for (unsigned i=0;i<(mode==3 ? 2u : 1u);++i) {
#ifndef DX_STANDALONE
        ((void (*)(void))0x4044d0)(); play_from_native();
#else
        fixture_play_update(&play);
#endif
    }
    spx_observe_end(&o); snapshot(&o,"final"); spx_observe_end(&o); REQUIRE(spx_observe_finish(&o)); fputc('\n',stdout);
#ifndef DX_STANDALONE
    if (source) REQUIRE(entered && install_play_update_intact());
#else
    REQUIRE(entered);
#endif
    return 0;
}
#ifndef DX_STANDALONE
struct native_startupinfo { int newmode; };
int __cdecl __getmainargs(int *,char ***,char ***,int,struct native_startupinfo *);
static LONG WINAPI fault(EXCEPTION_POINTERS *p) {
    fprintf(stderr,"native fault %08lx at %08lx\n",p->ExceptionRecord->ExceptionCode,p->ContextRecord->Eip);
    fflush(NULL); ExitProcess(86); return EXCEPTION_EXECUTE_HANDLER;
}
static void run_case(void) {
    SetUnhandledExceptionFilter(fault); int argc; char **argv,**environment; struct native_startupinfo startup={0};
    REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&startup)); int result=main(argc,argv); fflush(NULL); ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_play_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance; (void)reserved;
    return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif

/* This consumer retains its documented in-grid event domain. */
uint32_t play_read_pending(void *u,play_state *s,uint32_t column,uint32_t row) {
    (void)u;REQUIRE(s==&play && column<20 && row<20);
    return s->pending_cells[row*20+column];
}
