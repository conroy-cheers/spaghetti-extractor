/* Complete live records and borrowed roots around actual native entries. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "explosion-runtime.h"
#include "motion-state.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
enum { NODES=8 };
static explosion items[NODES];
static uint32_t live[NODES],scenario,entered[3],calls,callback_done;
static struct spx_opaque_cleanup_state_v5 objects;
static font_state font={.objects=&objects};
static flow_state flow;
static title_state title={.font=&font,.flow=&flow};
static scene_state scene={.animation=&title};
static menu_state menu={.scene=&scene};
static int32_t sine[361],cosine[361];
static play_state play={.menu=&menu,.sine=sine,.cosine=cosine};
static board current_board;
static motion_state motion={.play=&play,.board=&current_board};
static explosion_state explosions={.roots=&play.explosions};
static play_ball ball;
static uint32_t ball_live;
static font_sprite ball_sprite;
static spx_observer *observer;
static void require(int condition,const char *expression,unsigned line) {
    if (!condition) { fprintf(stderr,"explosion-runtime.c:%u: adapter premise failed: %s\n",line,expression); exit(3); }
}
#define REQUIRE(test) require(!!(test),#test,__LINE__)
void explosion_enter(unsigned operation) { REQUIRE(operation<3); ++entered[operation]; }
static uint32_t explosion_id(const explosion *p) {
    if (!p) return 0;
    for (unsigned i=0;i<NODES;++i) if (p==&items[i]) return i+1;
    REQUIRE(0); return 0;
}
static uint32_t ball_id(const play_ball *p) { if (!p) return 0; REQUIRE(p==&ball && ball_live); return 1; }
static void snapshot(const char *name) {
    REQUIRE(explosions.roots==&play.explosions); spx_observe_object(observer,name);
    uint32_t roots[]={explosion_id(explosion_current(&explosions)),explosion_id(explosion_first(&explosions)),explosion_id(explosions.last),explosions.retained};
    spx_observe_u32s(observer,"roots",roots,4); spx_observe_array(observer,"objects");
    for (unsigned i=0;i<NODES;++i) {
        uint32_t words[6]={live[i]};
        if (live[i]) { memcpy(words+1,&items[i],12); words[4]=explosion_id(items[i].next); words[5]=explosion_id(items[i].previous); }
        spx_observe_u32s(observer,NULL,words,6);
    }
    spx_observe_end(observer);
    uint32_t fields[]={play.paused,play.last_tick,play.changed,play.paddle_x,play.paddle_y,play.old_paddle_x,play.old_paddle_y,
        play.remaining_bricks,play.warning_sound,play.voice_pending,play.launch_pressed,play.gun,play.shot_count,
        scene.mouse_buttons,scene.presentation_mode,menu.score,motion.ball_count,motion.gravity,motion.paddle_width,
        motion.paddle_power,motion.sticky,motion.pierce,motion.impact_dx,motion.impact_dy};
    spx_observe_u32s(observer,"fields",fields,sizeof(fields)/sizeof(*fields));
    uint32_t balls[]={ball_live,ball_id(play.balls.current),ball_id(play.balls.first),ball_id(play.balls.last)};
    spx_observe_u32s(observer,"ball_roots",balls,4);
    if (ball_live) spx_observe_u32s(observer,"ball",(uint32_t *)&ball,13);
    spx_observe_bytes(observer,"board",(unsigned char *)&current_board,400); spx_observe_end(observer);
}
static void begin(explosion_state *s,unsigned operation,const uint32_t *args,unsigned count) {
    REQUIRE(s==&explosions && calls++<10000); spx_observe_object(observer,NULL);
    spx_observe_u64(observer,"operation",operation); spx_observe_u32s(observer,"arguments",args,count); snapshot("before");
}
static uint32_t end(uint32_t result) { snapshot("after"); spx_observe_u64(observer,"result",result); spx_observe_end(observer); return result; }
#define BEGIN0(op) (void)unused; begin(s,op,NULL,0)
#define BEGIN(op,...) (void)unused; const uint32_t args[]={__VA_ARGS__}; begin(s,op,args,sizeof(args)/sizeof(*args))
explosion *explosion_allocate(void *unused,explosion_state *s) {
    BEGIN0(EXPLOSION_ALLOCATE);
    if (scenario==7) { (void)end(0); return NULL; }
    for (unsigned i=0;i<NODES;++i) if (!live[i]) {
        live[i]=1; items[i]=(explosion){0}; memset(&items[i],0xa5+i,12);
        if (scenario==6) { play.explosions.current=play.explosions.first=(void *)&items[0]; explosions.last=&items[0]; items[0].next=NULL; explosions.retained=123; }
        (void)end(i+1); return &items[i];
    }
    REQUIRE(0); return NULL;
}
void explosion_terminate(void *unused,explosion_state *s,uint32_t status) {
    BEGIN(EXPLOSION_TERMINATE,status); REQUIRE(scenario==7 && explosion_current(s)); explosions.retained=123; (void)end(0);
}
void explosion_free(void *unused,explosion_state *s,explosion *item) {
    uint32_t id=explosion_id(item); BEGIN(EXPLOSION_FREE,id); REQUIRE(id && live[id-1]); live[id-1]=0;
    if (scenario==17) { play.explosions.current=(void *)&items[3]; explosions.retained=999; }
    (void)end(0);
}
void explosion_sprite(void *unused,explosion_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    BEGIN(EXPLOSION_SPRITE,slot,x,y);
    if (!callback_done++) {
        if (scenario==14) play.explosions.current=(void *)&items[1];
        if (scenario==15) { explosion_current(s)->frame=UINT32_MAX; explosion_current(s)->x=99; }
        if (scenario==16) { items[0].next=&items[2]; items[2].previous=&items[0]; explosions.last=&items[2]; }
    }
    (void)end(0);
}
#ifndef DX_STANDALONE
static uint32_t native_items[NODES][5],native_ball[15],native_ball_sprite[12];
static uint32_t *word(uint32_t address) { return (uint32_t *)(uintptr_t)address; }
static uint32_t explosion_address(explosion *p) { uint32_t id=explosion_id(p); return id ? (uint32_t)(uintptr_t)&native_items[id-1] : 0; }
static explosion *explosion_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)&native_items[i]) { REQUIRE(live[i]); return &items[i]; }
    REQUIRE(0); return NULL;
}
static uint32_t effect_address(play_effect *p) { return explosion_address((void *)p); }
static play_effect *effect_view(uint32_t p) { return (void *)explosion_view(p); }
static uint32_t ball_address(play_ball *p) { return ball_id(p) ? (uint32_t)(uintptr_t)native_ball : 0; }
static play_ball *ball_view(uint32_t p) { if (!p) return NULL; REQUIRE(p==(uint32_t)(uintptr_t)native_ball && ball_live); return &ball; }
#define EMPTY(name,type) static uint32_t name##_address(type *p) { REQUIRE(!p); return 0; } \
    static type *name##_view(uint32_t p) { REQUIRE(!p); return NULL; }
EMPTY(shot,play_shot) EMPTY(event,play_event)
#undef EMPTY
static void play_objects_to_native(void) {
    for (unsigned i=0;i<NODES;++i) if (live[i]) {
        memcpy(native_items[i],&items[i],12); native_items[i][3]=explosion_address(items[i].next); native_items[i][4]=explosion_address(items[i].previous);
    }
    if (ball_live) { memcpy(native_ball,&ball,52); native_ball[13]=ball_address(ball.next); native_ball[14]=ball_address(ball.previous); }
}
static void play_objects_from_native(void) {
    for (unsigned i=0;i<NODES;++i) if (live[i]) {
        memcpy(&items[i],native_items[i],12); items[i].next=explosion_view(native_items[i][3]); items[i].previous=explosion_view(native_items[i][4]);
    }
    if (ball_live) { memcpy(&ball,native_ball,52); ball.next=ball_view(native_ball[13]); ball.previous=ball_view(native_ball[14]); }
}
static void play_parent_to_native(void) {
    *word(0x431cbc)=menu.score; *word(0x417a04)=scene.presentation_mode; *word(0x434990)=scene.mouse_buttons;
    *word(0x4349c8)=title.fast; *word(0x434968)=0;
    memcpy((unsigned char *)native_ball_sprite+4,ball_sprite.retained,41); *word(0x433d18+61*4)=(uint32_t)(uintptr_t)native_ball_sprite;
}
static void play_parent_from_native(void) {
    menu.score=*word(0x431cbc); scene.presentation_mode=*word(0x417a04); scene.mouse_buttons=*word(0x434990); title.fast=*word(0x4349c8);
    REQUIRE(*word(0x434968)==0 && *word(0x433d18+61*4)==(uint32_t)(uintptr_t)native_ball_sprite);
    memcpy(ball_sprite.retained,(unsigned char *)native_ball_sprite+4,41);
}
#include "play-native.h"
#include "motion-native.h"
static void explosion_to_native(void) {
    motion_to_native(); *word(0x42cdc0)=explosion_address(explosions.last); *word(0x42cdc4)=explosions.retained;
}
static void explosion_from_native(void) {
    motion_from_native(); explosions.last=explosion_view(*word(0x42cdc0)); explosions.retained=*word(0x42cdc4);
}
static uint32_t native_allocate(uint32_t size) { REQUIRE(size==20); explosion_from_native(); uint32_t p=explosion_address(explosion_allocate(NULL,&explosions)); explosion_to_native(); return p; }
static void native_free(uint32_t address) { explosion_from_native(); explosion_free(NULL,&explosions,explosion_view(address)); explosion_to_native(); }
static void native_terminate(uint32_t status) { explosion_from_native(); explosion_terminate(NULL,&explosions,status); explosion_to_native(); }
static void native_sprite(uint32_t slot,uint32_t x,uint32_t y) { explosion_from_native(); explosion_sprite(NULL,&explosions,slot,x,y); explosion_to_native(); }
static void native_root_reset(void) { explosion_from_native(); fixture_explosion_reset(&explosions); explosion_to_native(); }
static void native_root_create(uint32_t x,uint32_t y) { explosion_from_native(); fixture_explosion_create(&explosions,x,y); explosion_to_native(); }
static void native_root_draw(void) { explosion_from_native(); fixture_explosion_draw(&explosions); explosion_to_native(); }
static void install(int source) {
#define HOOK(name) REQUIRE(install_explosion_service_##name((void (*)(void))native_##name));
    HOOK(allocate) HOOK(free) HOOK(terminate) HOOK(sprite)
#undef HOOK
    if (source) { REQUIRE(install_explosion_reset(native_root_reset)); REQUIRE(install_explosion_create((void (*)(void))native_root_create)); REQUIRE(install_explosion_draw(native_root_draw)); }
}
#define SYNC() explosion_to_native()
#define RESET() do { SYNC(); ((void (*)(void))0x404100)(); explosion_from_native(); } while (0)
#define CREATE(x,y) do { SYNC(); ((void (*)(uint32_t,uint32_t))0x406d30)(x,y); explosion_from_native(); } while (0)
#define DRAW() do { SYNC(); ((void (*)(void))0x406e10)(); explosion_from_native(); } while (0)
#else
#define SYNC() ((void)0)
#define RESET() fixture_explosion_reset(&explosions)
#define CREATE(x,y) fixture_explosion_create(&explosions,x,y)
#define DRAW() fixture_explosion_draw(&explosions)
#endif
static void setup(void) {
    memset(items,0,sizeof(items)); memset(live,0,sizeof(live)); memset(&play,0,sizeof(play)); memset(&current_board,0,sizeof(current_board));
    play.menu=&menu; play.sine=sine; play.cosine=cosine; play.paddle_x=300; play.paddle_y=450; play.remaining_bricks=10;
    menu.score=7; scene.mouse_buttons=scene.presentation_mode=0; title.fast=1;
    motion=(motion_state){.play=&play,.board=&current_board,.paddle_width=74};
    explosions=(explosion_state){.roots=&play.explosions,.retained=55}; ball_live=0; ball=(play_ball){0}; callback_done=0;
    uint32_t size=8; memcpy(ball_sprite.retained+4,&size,4); memcpy(ball_sprite.retained+8,&size,4); objects.banks[0].slots[61]=&ball_sprite;
}
static void chain(unsigned count) {
    REQUIRE(count<=NODES);
    for (unsigned i=0;i<count;++i) { live[i]=1; items[i]=(explosion){.x=20+i*30,.y=50+i*15,.frame=i,
        .next=i+1<count ? &items[i+1] : NULL,.previous=i ? &items[i-1] : NULL}; }
    play.explosions.current=play.explosions.first=count ? (void *)&items[0] : NULL; explosions.last=count ? &items[count-1] : NULL;
}
static void run_scenario(void) {
    switch (scenario) {
    case 0: DRAW(); break;
    case 1: RESET(); break;
    case 2: chain(3); RESET(); break;
    case 3: case 4: case 6: case 7:
        if (scenario!=3) chain(scenario==7 ? 1 : 2);
        CREATE(400,300); break;
    case 5: {
        const uint32_t pairs[][2]={{0,0},{23,22},{24,23},{25,24},{619,459},{620,460},{639,479},
            {UINT32_MAX,UINT32_MAX},{0x80000000,0x80000000},{0x7fffffff,0x7fffffff}};
        for (unsigned i=0;i<sizeof(pairs)/sizeof(*pairs);++i) { setup(); CREATE(pairs[i][0],pairs[i][1]); snapshot(NULL); }
        break;
    }
    case 8: chain(2); DRAW(); break;
    case 9: chain(1); items[0].frame=21; DRAW(); break;
    case 10: case 11: case 12:
        chain(3); items[scenario-10].frame=21; DRAW(); break;
    case 13: chain(4); for (unsigned i=0;i<4;++i) items[i].frame=21; DRAW(); break;
    case 14: case 15: case 16: chain(3); DRAW(); break;
    case 17: chain(4); items[0].frame=21; DRAW(); break;
    case 18: {
        const uint32_t frames[]={0,20,21,22,UINT32_MAX,0x80000000,0x7fffffff};
        for (unsigned i=0;i<sizeof(frames)/sizeof(*frames);++i) { setup(); chain(1); items[0].frame=frames[i]; DRAW(); snapshot(NULL); }
        break;
    }
    case 19:
        CREATE(20,60); CREATE(300,200); snapshot(NULL);
        for (unsigned i=0;i<24;++i) { DRAW(); snapshot(NULL); } break;
    case 20: chain(3); play.explosions.current=(void *)&items[2]; DRAW(); break;
    default: REQUIRE(0);
    }
}
#ifdef EXPLOSION_CONNECTED
#include "frame-explosions.h"
#endif
int main(int argc,char **argv) {
    REQUIRE(argc==3); scenario=(uint32_t)strtoul(argv[2],NULL,10); setup();
#ifdef EXPLOSION_CONNECTED
    REQUIRE(scenario>=21 && scenario<25); frame_setup();
#else
    REQUIRE(scenario<21);
#endif
    int source=!strcmp(argv[1],"source"); REQUIRE(source || !strcmp(argv[1],"original"));
#ifndef DX_STANDALONE
    install(source);
#ifdef EXPLOSION_CONNECTED
    frame_install(source);
#endif
    SYNC();
#else
    REQUIRE(source);
#endif
    spx_observer out=spx_observe_begin(stdout); observer=&out; spx_observe_object(observer,"explosions"); snapshot("initial"); spx_observe_array(observer,"calls");
#ifdef EXPLOSION_CONNECTED
    if (scenario>=21) frame_run(); else run_scenario();
#else
    run_scenario();
#endif
    spx_observe_end(observer); snapshot("final"); spx_observe_end(observer); REQUIRE(spx_observe_finish(observer)); fputc('\n',stdout); return 0;
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
__declspec(dllexport) void dx_explosions_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance; (void)reserved;
    return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
