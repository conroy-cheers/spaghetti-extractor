/* Native shot bodies over existing shared records and controlled services. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shot-runtime.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
enum { NODES=16,SPRITES=2 };
static play_shot items[NODES];
static uint32_t live[NODES],scenario,entered[3],calls,allocation_calls,callback_done,random_value,hit_value;
static font_sprite sprites[SPRITES];
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
static spx_observer *observer;
static void require(int condition,const char *expression,unsigned line) {
    if (!condition) { fprintf(stderr,"shot-runtime.c:%u: adapter premise failed: %s\n",line,expression); exit(3); }
}
#define REQUIRE(test) require(!!(test),#test,__LINE__)
void shot_enter(unsigned operation) { REQUIRE(operation<3); ++entered[operation]; }
static uint32_t shot_id(const play_shot *p) {
    if (!p) return 0;
    for (unsigned i=0;i<NODES;++i) if (p==&items[i]) return i+1;
    REQUIRE(0); return 0;
}
static uint32_t sprite_id(const font_sprite *p) {
    if (!p) return 0;
    for (unsigned i=0;i<SPRITES;++i) if (p==&sprites[i]) return i+1;
    REQUIRE(0); return 0;
}
static void dimensions(font_sprite *p,uint32_t width,uint32_t height) {
    memcpy(p->retained+4,&width,4); memcpy(p->retained+8,&height,4);
}
static void snapshot(const char *name) {
    spx_observe_object(observer,name);
    uint32_t fields[]={play.shot_count,motion.paddle_width,play.paddle_x,play.paddle_y,motion.pierce,
        motion.impact_dx,motion.impact_dy,menu.score,objects.current_bank,play.paused,play.last_tick,play.changed,
        play.old_paddle_x,play.old_paddle_y,play.remaining_bricks,play.warning_sound,play.voice_pending,
        play.slow_balls,play.speedup_balls,play.fire_balls,play.split_balls,play.power_balls,play.launch_pressed,
        play.gun,scene.presentation_mode,scene.mouse_buttons};
    spx_observe_u32s(observer,"fields",fields,sizeof(fields)/sizeof(*fields));
    uint32_t roots[]={shot_id(play.shots.current),shot_id(play.shots.first),shot_id(play.shots.last),play.shots.retained};
    spx_observe_u32s(observer,"roots",roots,4); spx_observe_array(observer,"objects");
    for (unsigned i=0;i<NODES;++i) {
        uint32_t words[7]={live[i]};
        if (live[i]) { memcpy(words+1,&items[i],16); words[5]=shot_id(items[i].next); words[6]=shot_id(items[i].previous); }
        spx_observe_u32s(observer,NULL,words,7);
    }
    spx_observe_end(observer); spx_observe_array(observer,"sprites");
    for (unsigned i=0;i<SPRITES;++i) spx_observe_bytes(observer,NULL,sprites[i].retained,41);
    spx_observe_end(observer);
    uint32_t banks[]={sprite_id(objects.banks[0].slots[32]),sprite_id(objects.banks[1].slots[32])};
    spx_observe_u32s(observer,"banks",banks,2); spx_observe_bytes(observer,"board",(unsigned char *)&current_board,400);
    spx_observe_end(observer);
}
static void begin(motion_state *s,unsigned operation,const uint32_t *args,unsigned count) {
    REQUIRE(s==&motion && calls++<10000); spx_observe_object(observer,NULL);
    spx_observe_u64(observer,"operation",operation); spx_observe_u32s(observer,"arguments",args,count); snapshot("before");
}
static uint32_t end(uint32_t result) {
    snapshot("after"); spx_observe_u64(observer,"result",result); spx_observe_end(observer); return result;
}
#define BEGIN0(op) (void)unused; begin(s,op,NULL,0)
#define BEGIN(op,...) (void)unused; const uint32_t args[]={__VA_ARGS__}; begin(s,op,args,sizeof(args)/sizeof(*args))
struct spx_opaque_allocation_v5 *shot_allocate(void *unused,motion_state *s) {
    BEGIN0(SHOT_ALLOCATE); ++allocation_calls;
    if (scenario==9 && allocation_calls==1) { (void)end(0); return NULL; }
    for (unsigned i=0;i<NODES;++i) if (!live[i]) {
        live[i]=1; items[i]=(play_shot){0}; memset(&items[i],0xa5+i,16);
        if (scenario==4 && allocation_calls==1) { motion.paddle_width=100; play.paddle_x=417; objects.current_bank=1; }
        if (scenario==5 && allocation_calls==2) { motion.paddle_width=37; play.paddle_x=201; play.paddle_y=317; objects.current_bank=1; dimensions(&sprites[1],11,17); }
        (void)end(i+1); return (void *)&items[i];
    }
    REQUIRE(0); return NULL;
}
void shot_terminate(void *unused,motion_state *s,uint32_t status) {
    BEGIN(SHOT_TERMINATE,status); REQUIRE(scenario==9 && play.shots.current); play.shot_count=7; (void)end(0);
}
void shot_free(void *unused,motion_state *s,struct spx_opaque_allocation_v5 *storage) {
    uint32_t id=shot_id((void *)storage); BEGIN(SHOT_FREE,id); REQUIRE(id && live[id-1]); live[id-1]=0;
    if (scenario==15) { play.shots.current=&items[2]; play.shot_count=0; }
    (void)end(0);
}
uint32_t shot_random(void *unused,motion_state *s,uint32_t limit) {
    BEGIN(SHOT_RANDOM,limit); REQUIRE(limit==3);
    if (scenario==24 && !callback_done++) { play.shots.current=&items[1]; objects.current_bank=1; items[1].x=68; items[1].y=84; motion.impact_dx=999; }
    return end(random_value);
}
uint32_t shot_hit(void *unused,motion_state *s,uint32_t column,uint32_t row) {
    BEGIN(SHOT_HIT,column,row); uint32_t index=row*20+column; REQUIRE(row<20 && index<400);
    ((unsigned char *)&current_board)[index]=0;
    if (scenario==25 && !callback_done++) { play.shots.current=&items[2]; menu.score=UINT32_MAX-1; motion.pierce=1; }
    return end(hit_value);
}
void shot_stop_sound(void *unused,motion_state *s,uint32_t sound) {
    BEGIN(SHOT_STOP_SOUND,sound);
    if (scenario==6) { play.shots.current=play.shots.first; play.shots.current->x=501; }
    (void)end(0);
}
uint32_t shot_pan(void *unused,motion_state *s,uint32_t x) {
    BEGIN(SHOT_PAN,x);
    if (scenario==7) { play.shots.current=play.shots.first; play.shots.current->y=99; play.shot_count=UINT32_MAX; }
    return end(x^0x6157);
}
void shot_play_sound(void *unused,motion_state *s,uint32_t sound,uint32_t repeat,uint32_t pan,uint32_t flags) {
    BEGIN(SHOT_PLAY_SOUND,sound,repeat,pan,flags);
    if (scenario==8) { play.shot_count=41; current_board.cells[0][0]=2; }
    (void)end(0);
}
#ifndef DX_STANDALONE
static uint32_t native_items[NODES][6],native_sprites[SPRITES][12];
static uint32_t *word(uint32_t address) { return (uint32_t *)(uintptr_t)address; }
static uint32_t shot_address(play_shot *p) { uint32_t id=shot_id(p); return id ? (uint32_t)(uintptr_t)&native_items[id-1] : 0; }
static play_shot *shot_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)&native_items[i]) { REQUIRE(live[i]); return &items[i]; }
    REQUIRE(0); return NULL;
}
static uint32_t sprite_address(font_sprite *p) { uint32_t id=sprite_id(p); return id ? (uint32_t)(uintptr_t)&native_sprites[id-1] : 0; }
static font_sprite *sprite_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<SPRITES;++i) if (address==(uint32_t)(uintptr_t)&native_sprites[i]) return &sprites[i];
    REQUIRE(0); return NULL;
}
#define EMPTY(name,type) static uint32_t name##_address(type *p) { REQUIRE(!p); return 0; } \
    static type *name##_view(uint32_t p) { REQUIRE(!p); return NULL; }
EMPTY(ball,play_ball) EMPTY(event,play_event) EMPTY(effect,play_effect)
#undef EMPTY
static void play_objects_to_native(void) {
    for (unsigned i=0;i<NODES;++i) if (live[i]) {
        memcpy(native_items[i],&items[i],16); native_items[i][4]=shot_address(items[i].next); native_items[i][5]=shot_address(items[i].previous);
    }
}
static void play_objects_from_native(void) {
    for (unsigned i=0;i<NODES;++i) if (live[i]) {
        memcpy(&items[i],native_items[i],16); items[i].next=shot_view(native_items[i][4]); items[i].previous=shot_view(native_items[i][5]);
    }
}
static void play_parent_to_native(void) {
    *word(0x431cbc)=menu.score; *word(0x417a04)=scene.presentation_mode; *word(0x434990)=scene.mouse_buttons; *word(0x434968)=objects.current_bank;
    for (unsigned i=0;i<SPRITES;++i) memcpy((unsigned char *)native_sprites[i]+4,sprites[i].retained,41);
    for (unsigned b=0;b<2;++b) *word(0x433d18+b*1048+32*4)=sprite_address(objects.banks[b].slots[32]);
}
static void play_parent_from_native(void) {
    menu.score=*word(0x431cbc); scene.presentation_mode=*word(0x417a04); scene.mouse_buttons=*word(0x434990); objects.current_bank=*word(0x434968);
    for (unsigned i=0;i<SPRITES;++i) memcpy(sprites[i].retained,(unsigned char *)native_sprites[i]+4,41);
    for (unsigned b=0;b<2;++b) objects.banks[b].slots[32]=sprite_view(*word(0x433d18+b*1048+32*4));
}
#include "play-native.h"
#include "motion-native.h"
static uint32_t native_allocate(uint32_t bytes) { REQUIRE(bytes==24); motion_from_native(); uint32_t r=shot_address((void *)shot_allocate(NULL,&motion)); motion_to_native(); return r; }
static void native_free(uint32_t address) { motion_from_native(); shot_free(NULL,&motion,(void *)shot_view(address)); motion_to_native(); }
static uint32_t native_random(uint32_t limit) { motion_from_native(); uint32_t r=shot_random(NULL,&motion,limit); motion_to_native(); return r; }
static uint32_t native_pan(uint32_t x) { motion_from_native(); uint32_t r=shot_pan(NULL,&motion,x); motion_to_native(); return r; }
static uint32_t native_hit(uint32_t a,uint32_t b) { motion_from_native(); uint32_t r=shot_hit(NULL,&motion,a,b); motion_to_native(); return r; }
#define SERVICE(name,params,...) static void native_##name params { motion_from_native(); shot_##name(NULL,&motion,__VA_ARGS__); motion_to_native(); }
SERVICE(terminate,(uint32_t status),status) SERVICE(stop_sound,(uint32_t id),id)
SERVICE(play_sound,(uint32_t a,uint32_t b,uint32_t c,uint32_t d),a,b,c,d)
#undef SERVICE
#define ROOT(name) static void native_root_##name(void) { motion_from_native(); fixture_shot_##name(&motion); motion_to_native(); }
ROOT(update) ROOT(fire) ROOT(remove)
#undef ROOT
static void install(int source) {
#define HOOK(name) REQUIRE(install_shot_service_##name((void (*)(void))native_##name));
    HOOK(allocate) HOOK(free) HOOK(terminate) HOOK(random) HOOK(hit) HOOK(stop_sound) HOOK(pan) HOOK(play_sound)
#undef HOOK
    if (source) { REQUIRE(install_shot_update(native_root_update)); REQUIRE(install_shot_fire(native_root_fire)); REQUIRE(install_shot_remove(native_root_remove)); }
}
#define SYNC() motion_to_native()
#define CALL(name,address) do { ((void (*)(void))address)(); motion_from_native(); } while (0)
#else
#define SYNC() ((void)0)
#define CALL(name,address) fixture_shot_##name(&motion)
#endif
static void setup(void) {
    memset(live,0,sizeof(live)); memset(items,0,sizeof(items)); memset(&objects,0,sizeof(objects)); memset(sprites,0,sizeof(sprites));
    memset(&play,0,sizeof(play)); memset(&current_board,0,sizeof(current_board));
    play.menu=&menu; play.sine=sine; play.cosine=cosine; play.paddle_x=300; play.paddle_y=450; play.shots.retained=0xdeadbeef;
    play.remaining_bricks=10; menu.score=7; scene.mouse_buttons=scene.presentation_mode=0;
    motion=(motion_state){.play=&play,.board=&current_board,.paddle_width=74,.impact_dx=99,.impact_dy=100};
    dimensions(&sprites[0],8,12); dimensions(&sprites[1],11,17);
    objects.banks[0].slots[32]=&sprites[0]; objects.banks[1].slots[32]=&sprites[1];
    allocation_calls=callback_done=0; random_value=2; hit_value=1;
}
static void chain(unsigned count) {
    REQUIRE(count<=NODES); play.shot_count=count;
    for (unsigned i=0;i<count;++i) {
        live[i]=1; items[i]=(play_shot){.x=26+i*30,.y=62,.old_x=100+i,.old_y=200+i,
            .next=i+1<count ? &items[i+1] : NULL,.previous=i ? &items[i-1] : NULL};
    }
    play.shots.current=play.shots.first=count ? &items[0] : NULL; play.shots.last=count ? &items[count-1] : NULL;
}
static void run_scenario(void) {
    switch (scenario) {
    case 0: SYNC(); CALL(update,0x4069c0); break;
    case 1: case 2: case 4: case 5: case 6: case 7: case 8: case 9:
        if (scenario==2 || scenario==4 || scenario==9) chain(2);
        SYNC(); CALL(fire,0x406af0); break;
    case 3: {
        const uint32_t widths[]={0,1,2,18,37,40,73,74,148,UINT32_MAX,0x80000000,0x7fffffff};
        for (unsigned i=0;i<sizeof(widths)/sizeof(*widths);++i) { setup(); motion.paddle_width=widths[i]; play.paddle_x=i%2 ? UINT32_MAX : 300; SYNC(); CALL(fire,0x406af0); snapshot(NULL); }
        break;
    }
    case 10: play.shot_count=0; SYNC(); CALL(remove,0x406cc0); break;
    case 11: case 12: case 13: case 14: case 15:
        chain(scenario==11 ? 1 : 3); play.shots.current=&items[scenario==13 ? 1 : scenario==14 ? 2 : 0];
        SYNC(); CALL(remove,0x406cc0); break;
    case 16: case 17: case 18: case 19:
        chain(1); items[0].y=scenario==17 ? 30 : scenario==18 ? 400 : scenario==19 ? 7 : 200;
        SYNC(); CALL(update,0x4069c0); break;
    case 20: case 21: case 22: case 23: case 24: case 25:
        chain(scenario>=23 ? 3 : 1); memset(&current_board,1,400); hit_value=scenario!=21; motion.pierce=scenario==22;
        if (scenario==23) items[0].y=7;
        SYNC(); CALL(update,0x4069c0); break;
    case 26:
        for (unsigned i=0;i<3;++i) { setup(); chain(1); random_value=i; SYNC(); CALL(update,0x4069c0); snapshot(NULL); } break;
    case 27:
        chain(1); items[0].x=UINT32_C(0xffffffe2); items[0].y=73; current_board.cells[0][19]=1;
        SYNC(); CALL(update,0x4069c0); break;
    case 28: objects.current_bank=1; SYNC(); CALL(fire,0x406af0); CALL(update,0x4069c0); break;
    case 29:
        SYNC(); CALL(fire,0x406af0); snapshot(NULL);
        for (unsigned i=0;i<64;++i) { SYNC(); CALL(update,0x4069c0); snapshot(NULL); }
        break;
    default: REQUIRE(0);
    }
}
#ifdef SHOT_CONNECTED
#include "frame-shots.h"
#endif
int main(int argc,char **argv) {
    REQUIRE(argc==3); scenario=(uint32_t)strtoul(argv[2],NULL,10); setup();
#ifdef SHOT_CONNECTED
    REQUIRE(scenario>=30 && scenario<34); frame_setup();
#else
    REQUIRE(scenario<30);
#endif
    int source=!strcmp(argv[1],"source"); REQUIRE(source || !strcmp(argv[1],"original"));
#ifndef DX_STANDALONE
    install(source); unsigned short control; __asm__ volatile("fnstcw %0":"=m"(control)); REQUIRE(control==0x027f);
#ifdef SHOT_CONNECTED
    frame_install(source);
#endif
    SYNC();
#else
    REQUIRE(source);
#endif
    spx_observer out=spx_observe_begin(stdout); observer=&out; spx_observe_object(observer,"shots"); snapshot("initial"); spx_observe_array(observer,"calls");
#ifdef SHOT_CONNECTED
    if (scenario>=30) frame_run(); else run_scenario();
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
__declspec(dllexport) void dx_shots_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance; (void)reserved;
    return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
