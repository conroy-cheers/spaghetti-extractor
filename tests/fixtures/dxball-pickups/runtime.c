/* Real entry bodies over local objects and controlled synchronous services. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pickup-runtime.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
enum { NODES=8,SPRITES=21 };
static pickup items[NODES];
static uint32_t live[NODES],scenario,entered[4],calls,seed,callback_done,choice_kind,choice_rare,choice_chance,collide;
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
static pickup_state pickups={.motion=&motion};
static spx_observer *observer;
#ifdef PICKUP_CONNECTED
static play_event frame_event;
static uint32_t frame_event_live;
static void frame_free_event(play_event *event);
#endif
static void require(int condition,const char *expression,unsigned line) {
    if (!condition) { fprintf(stderr,"pickup-runtime.c:%u: adapter premise failed: %s\n",line,expression); exit(3); }
}
#define REQUIRE(test) require(!!(test),#test,__LINE__)
void pickup_enter(unsigned operation) { REQUIRE(operation<4); ++entered[operation]; }
static uint32_t pickup_id(const pickup *p) {
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
    uint32_t fields[]={pickups.count,pickups.lives,pickups.next_life,pickups.paddle_sprite,menu.score,title.fast,
        motion.paddle_width,motion.gravity,motion.paddle_power,motion.sticky,motion.pierce,play.gun,
        play.slow_balls,play.speedup_balls,play.fire_balls,play.split_balls,play.power_balls,
        play.old_paddle_x,play.old_paddle_y,objects.current_bank,play.changed};
    spx_observe_u32s(observer,"fields",fields,sizeof(fields)/sizeof(*fields));
    uint32_t roots[]={pickup_id(pickups.current),pickup_id(pickups.first),pickup_id(pickups.last)};
    spx_observe_u32s(observer,"roots",roots,3); spx_observe_array(observer,"objects");
    for (unsigned i=0;i<NODES;++i) {
        uint32_t words[10]={live[i]};
        if (live[i]) { memcpy(words+1,&items[i],28); words[8]=pickup_id(items[i].next); words[9]=pickup_id(items[i].previous); }
        spx_observe_u32s(observer,NULL,words,10);
    }
    spx_observe_end(observer); spx_observe_array(observer,"sprites");
    for (unsigned i=0;i<SPRITES;++i) spx_observe_bytes(observer,NULL,sprites[i].retained,sizeof(sprites[i].retained));
    spx_observe_end(observer); spx_observe_array(observer,"banks");
    for (unsigned bank=0;bank<2;++bank) {
        uint32_t ids[20]={sprite_id(objects.banks[bank].slots[9])};
        for (unsigned i=0;i<19;++i) ids[i+1]=sprite_id(objects.banks[bank].slots[35+i]);
        spx_observe_u32s(observer,NULL,ids,20);
    }
    spx_observe_end(observer); spx_observe_bytes(observer,"board",(unsigned char *)&current_board,400); spx_observe_end(observer);
}
static void begin(pickup_state *s,unsigned operation,const uint32_t *args,unsigned count) {
    REQUIRE(s==&pickups && calls++<10000); spx_observe_object(observer,NULL);
    spx_observe_u64(observer,"operation",operation); spx_observe_u32s(observer,"arguments",args,count); snapshot("before");
}
static uint32_t end(uint32_t result) {
    snapshot("after"); spx_observe_u64(observer,"result",result); spx_observe_end(observer); return result;
}
#define BEGIN0(operation) (void)unused; begin(s,operation,NULL,0)
#define BEGIN(operation,...) (void)unused; const uint32_t args[]={__VA_ARGS__}; begin(s,operation,args,sizeof(args)/sizeof(*args))
pickup *pickup_allocate(void *unused,pickup_state *s) {
    BEGIN0(PICKUP_ALLOCATE);
    for (unsigned i=0;i<NODES;++i) if (!live[i]) {
        live[i]=1; memset(&items[i],0,sizeof(items[i])); memset(&items[i],0xa5,28);
        if (scenario==4) { pickups.last=&items[0]; items[0].next=NULL; pickups.count=5; }
        (void)end(i+1); return &items[i];
    }
    REQUIRE(0); return NULL;
}
void pickup_free(void *unused,pickup_state *s,pickup *item) {
    uint32_t id=pickup_id(item); BEGIN(PICKUP_FREE,id); REQUIRE(id && live[id-1]); live[id-1]=0;
    if (scenario==19) { pickups.current=&items[2]; pickups.count=55; }
    (void)end(0);
}
uint32_t pickup_random(void *unused,pickup_state *s,uint32_t limit) {
    BEGIN(PICKUP_RANDOM,limit); REQUIRE(limit); seed=seed*1664525+1013904223;
    uint32_t value=limit==10 ? choice_chance : limit==19 ? choice_kind : limit==5 ? choice_rare : seed%limit;
    if (scenario==5 && limit==19) pickups.current=&items[0];
    return end(value);
}
uint32_t pickup_pan(void *unused,pickup_state *s,uint32_t x) { BEGIN(PICKUP_PAN,x); return end(x^0x6157); }
void pickup_stop_sound(void *unused,pickup_state *s,uint32_t sound) {
    BEGIN(PICKUP_STOP_SOUND,sound);
    if (scenario==6) title.fast=0;
    if (scenario==11 && !callback_done++) { pickups.current=&items[1]; dimensions(&sprites[1],19,11); }
    (void)end(0);
}
void pickup_play_sound(void *unused,pickup_state *s,uint32_t sound,uint32_t repeat,uint32_t volume,uint32_t pan) {
    BEGIN(PICKUP_PLAY_SOUND,sound,repeat,volume,pan);
    if (scenario==13) { motion.paddle_width=23; dimensions(&sprites[0],41,8); pickups.current->kind=13; }
    (void)end(0);
}
void pickup_particle(void *unused,pickup_state *s,uint32_t x,uint32_t y,uint32_t dx,uint32_t dy,uint32_t color,uint32_t gravity) {
    BEGIN(PICKUP_PARTICLE,x,y,dx,dy,color,gravity); (void)end(0);
}
uint32_t pickup_overlap(void *unused,pickup_state *s,font_rect *a,font_rect *b) {
    BEGIN(PICKUP_OVERLAP,a->left,a->top,a->right,a->bottom,b->left,b->top,b->right,b->bottom);
    if (scenario==12) { pickups.current=&items[1]; items[1].kind=3; menu.score=UINT32_MAX; }
    return end(collide);
}
void pickup_sprite(void *unused,pickup_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    BEGIN(PICKUP_SPRITE,slot,x,y);
    if (scenario==17 && !callback_done++) { pickups.current=&items[1]; items[2].x=197; }
    (void)end(0);
}
#define SIMPLE(name,operation) void pickup_##name(void *unused,pickup_state *s) { BEGIN0(operation); (void)end(0); }
SIMPLE(unstick,PICKUP_UNSTICK) SIMPLE(queue_explosive_bricks,PICKUP_QUEUE_EXPLOSIVE_BRICKS)
SIMPLE(detonate_bricks,PICKUP_DETONATE_BRICKS) SIMPLE(move_paddle,PICKUP_MOVE_PADDLE) SIMPLE(lose_life,PICKUP_LOSE_LIFE)
#undef SIMPLE
void pickup_release_attached(void *unused,pickup_state *s) {
    BEGIN0(PICKUP_RELEASE_ATTACHED);
    if (scenario==14) { objects.current_bank=1; objects.banks[1].slots[9]=&sprites[20]; motion.paddle_width=33; }
    (void)end(0);
}
void pickup_next_board(void *unused,pickup_state *s) {
    BEGIN0(PICKUP_NEXT_BOARD);
    if (scenario==15) { pickups.current=&items[1]; menu.score+=7; }
    (void)end(0);
}

#ifndef DX_STANDALONE
static uint32_t native_items[NODES][9],native_sprites[SPRITES][12];
static uint32_t *word(uint32_t address) { return (uint32_t *)(uintptr_t)address; }
static uint32_t pickup_address(pickup *p) { uint32_t id=pickup_id(p); return id ? (uint32_t)(uintptr_t)&native_items[id-1] : 0; }
static pickup *pickup_view(uint32_t p) {
    if (!p) return NULL;
    for (unsigned i=0;i<NODES;++i) if (p==(uint32_t)(uintptr_t)&native_items[i]) { REQUIRE(live[i]); return &items[i]; }
    REQUIRE(0); return NULL;
}
static uint32_t sprite_address(font_sprite *p) { uint32_t id=sprite_id(p); return id ? (uint32_t)(uintptr_t)&native_sprites[id-1] : 0; }
static font_sprite *sprite_view(uint32_t p) {
    if (!p) return NULL;
    for (unsigned i=0;i<SPRITES;++i) if (p==(uint32_t)(uintptr_t)&native_sprites[i]) return &sprites[i];
    REQUIRE(0); return NULL;
}
#define EMPTY(name,type) static uint32_t name##_address(type *p) { REQUIRE(!p); return 0; } \
    static type *name##_view(uint32_t p) { REQUIRE(!p); return NULL; }
EMPTY(ball,play_ball) EMPTY(shot,play_shot) EMPTY(effect,play_effect)
#ifndef PICKUP_CONNECTED
EMPTY(event,play_event)
#else
static uint32_t native_frame_event[5];
static uint32_t event_address(play_event *p) { if (!p) return 0; REQUIRE(p==&frame_event && frame_event_live); return (uint32_t)(uintptr_t)native_frame_event; }
static play_event *event_view(uint32_t p) { if (!p) return NULL; REQUIRE(p==(uint32_t)(uintptr_t)native_frame_event && frame_event_live); return &frame_event; }
#endif
#undef EMPTY
static void play_objects_to_native(void) {
#ifdef PICKUP_CONNECTED
    if (frame_event_live) { memcpy(native_frame_event,&frame_event,12); native_frame_event[3]=native_frame_event[4]=0; }
#endif
}
static void play_objects_from_native(void) {
#ifdef PICKUP_CONNECTED
    if (frame_event_live) { memcpy(&frame_event,native_frame_event,12); REQUIRE(!native_frame_event[3] && !native_frame_event[4]); }
#endif
}
static void play_parent_to_native(void) {
    *word(0x431cbc)=menu.score; *word(0x417a04)=scene.presentation_mode; *word(0x434990)=scene.mouse_buttons;
    *word(0x4349c8)=title.fast; *word(0x434968)=objects.current_bank;
    for (unsigned i=0;i<SPRITES;++i) memcpy((unsigned char *)&native_sprites[i]+4,sprites[i].retained,sizeof(sprites[i].retained));
    for (unsigned bank=0;bank<2;++bank) {
        *word(0x433d18+bank*1048+9*4)=sprite_address(objects.banks[bank].slots[9]);
        for (unsigned i=0;i<19;++i) *word(0x433d18+bank*1048+(35+i)*4)=sprite_address(objects.banks[bank].slots[35+i]);
    }
}
static void play_parent_from_native(void) {
    menu.score=*word(0x431cbc); scene.presentation_mode=*word(0x417a04); scene.mouse_buttons=*word(0x434990);
    title.fast=*word(0x4349c8); objects.current_bank=*word(0x434968);
    for (unsigned i=0;i<SPRITES;++i) memcpy(sprites[i].retained,(unsigned char *)&native_sprites[i]+4,sizeof(sprites[i].retained));
    for (unsigned bank=0;bank<2;++bank) {
        objects.banks[bank].slots[9]=sprite_view(*word(0x433d18+bank*1048+9*4));
        for (unsigned i=0;i<19;++i) objects.banks[bank].slots[35+i]=sprite_view(*word(0x433d18+bank*1048+(35+i)*4));
    }
}
#include "play-native.h"
#include "motion-native.h"
#define PICKUP_WORDS(X) X(count,0x431cb8) X(lives,0x431ca8) X(next_life,0x431c7c) X(paddle_sprite,0x431c84)
static void pickup_to_native(void) {
    motion_to_native();
#define PUT(name,address) *word(address)=pickups.name;
    PICKUP_WORDS(PUT)
#undef PUT
    *word(0x431c50)=pickup_address(pickups.current); *word(0x431c54)=pickup_address(pickups.first); *word(0x431c58)=pickup_address(pickups.last);
    for (unsigned i=0;i<NODES;++i) if (live[i]) {
        memcpy(native_items[i],&items[i],28); native_items[i][7]=pickup_address(items[i].next); native_items[i][8]=pickup_address(items[i].previous);
    }
}
static void pickup_from_native(void) {
    motion_from_native();
#define GET(name,address) pickups.name=*word(address);
    PICKUP_WORDS(GET)
#undef GET
    pickups.current=pickup_view(*word(0x431c50)); pickups.first=pickup_view(*word(0x431c54)); pickups.last=pickup_view(*word(0x431c58));
    for (unsigned i=0;i<NODES;++i) if (live[i]) {
        memcpy(&items[i],native_items[i],28); items[i].next=pickup_view(native_items[i][7]); items[i].previous=pickup_view(native_items[i][8]);
    }
}
static uint32_t native_allocate(uint32_t bytes) { REQUIRE(bytes==36); pickup_from_native(); uint32_t result=pickup_address(pickup_allocate(NULL,&pickups)); pickup_to_native(); return result; }
static void native_free(uint32_t p) {
    pickup_from_native();
#ifdef PICKUP_CONNECTED
    if (p==(uint32_t)(uintptr_t)native_frame_event) frame_free_event(event_view(p)); else
#endif
    pickup_free(NULL,&pickups,pickup_view(p));
    pickup_to_native();
}
static uint32_t native_random(uint32_t limit) { pickup_from_native(); uint32_t result=pickup_random(NULL,&pickups,limit); pickup_to_native(); return result; }
static uint32_t native_pan(uint32_t x) { pickup_from_native(); uint32_t result=pickup_pan(NULL,&pickups,x); pickup_to_native(); return result; }
static uint32_t native_overlap(font_rect a,font_rect b) { pickup_from_native(); uint32_t result=pickup_overlap(NULL,&pickups,&a,&b); pickup_to_native(); return result; }
#define SERVICE0(name) static void native_##name(void) { pickup_from_native(); pickup_##name(NULL,&pickups); pickup_to_native(); }
SERVICE0(next_board) SERVICE0(unstick) SERVICE0(queue_explosive_bricks) SERVICE0(detonate_bricks)
SERVICE0(release_attached) SERVICE0(move_paddle) SERVICE0(lose_life)
#undef SERVICE0
#define SERVICE(name,params,...) static void native_##name params { pickup_from_native(); pickup_##name(NULL,&pickups,__VA_ARGS__); pickup_to_native(); }
SERVICE(stop_sound,(uint32_t id),id)
SERVICE(play_sound,(uint32_t a,uint32_t b,uint32_t c,uint32_t d),a,b,c,d)
SERVICE(particle,(uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f),a,b,c,d,e,f)
SERVICE(sprite,(uint32_t a,uint32_t b,uint32_t c),a,b,c)
#undef SERVICE
#define ROOT0(name) static void native_root_##name(void) { pickup_from_native(); fixture_pickup_##name(&pickups); pickup_to_native(); }
ROOT0(update) ROOT0(draw) ROOT0(remove)
#undef ROOT0
static void native_root_create(uint32_t a,uint32_t b,uint32_t c,uint32_t d) { pickup_from_native(); fixture_pickup_create(&pickups,a,b,c,d); pickup_to_native(); }
static void install(int source) {
#define HOOK(name) REQUIRE(install_pickup_service_##name((void (*)(void))native_##name));
    HOOK(allocate) HOOK(free) HOOK(random) HOOK(pan) HOOK(stop_sound) HOOK(play_sound) HOOK(particle) HOOK(overlap)
    HOOK(sprite) HOOK(next_board) HOOK(unstick) HOOK(queue_explosive_bricks) HOOK(detonate_bricks)
    HOOK(release_attached) HOOK(move_paddle) HOOK(lose_life)
#undef HOOK
    if (!source) return;
#define ROOT(name) REQUIRE(install_pickup_##name((void (*)(void))native_root_##name));
    ROOT(create) ROOT(update) ROOT(draw) ROOT(remove)
#undef ROOT
}
#define SYNC() pickup_to_native()
#define CREATE(a,b,c,d) do { ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))0x406ef0)(a,b,c,d); pickup_from_native(); } while (0)
#define CALL(name,address) do { ((void (*)(void))address)(); pickup_from_native(); } while (0)
#else
#define SYNC() ((void)0)
#define CREATE(a,b,c,d) fixture_pickup_create(&pickups,a,b,c,d)
#define CALL(name,address) fixture_pickup_##name(&pickups)
#endif
static void setup(void) {
    memset(items,0,sizeof(items)); memset(live,0,sizeof(live)); memset(&objects,0,sizeof(objects)); memset(sprites,0,sizeof(sprites));
    memset(&play,0,sizeof(play)); play.menu=&menu; play.sine=sine; play.cosine=cosine;
    memset(&motion,0,sizeof(motion)); motion.play=&play; motion.board=&current_board;
    pickups=(pickup_state){.motion=&motion,.lives=3,.next_life=5000,.paddle_sprite=9};
    menu.score=7; title.fast=1; motion.paddle_width=74; play.old_paddle_x=300; play.old_paddle_y=450;
    for (unsigned i=0;i<SPRITES;++i) dimensions(&sprites[i],i ? 32 : 37,i ? 15 : 8);
    for (unsigned bank=0;bank<2;++bank) {
        objects.banks[bank].slots[9]=&sprites[0];
        for (unsigned i=0;i<19;++i) objects.banks[bank].slots[35+i]=&sprites[i+1];
    }
    dimensions(&sprites[20],43,12); choice_chance=0; choice_kind=3; choice_rare=1; collide=0; callback_done=0; seed=0x981fd234;
}
static void list(unsigned count) {
    pickups.count=count; pickups.current=pickups.first=count ? &items[0] : NULL; pickups.last=count ? &items[count-1] : NULL;
    for (unsigned i=0;i<count;++i) {
        live[i]=1; items[i]=(pickup){.kind=3,.sprite=38,.x=100+i*40,.y=100,.dx=1,.dy=2,.tick=5,
            .next=i+1<count ? &items[i+1] : NULL,.previous=i ? &items[i-1] : NULL};
    }
}
static void run_scenario(void) {
    switch (scenario) {
    case 0:
        for (unsigned kind=0;kind<19;++kind) { setup(); choice_kind=kind; SYNC(); CREATE(18,12,1,UINT32_C(0xfffffffe)); snapshot(NULL); } break;
    case 1:
        for (unsigned kind=0;kind<2;++kind) { setup(); choice_kind=kind; choice_rare=4; SYNC(); CREATE(2,3,4,5); snapshot(NULL); } break;
    case 2: title.fast=0; SYNC(); CREATE(19,19,UINT32_MAX,2); break;
    case 3:
        for (unsigned i=0;i<4;++i) { setup(); pickups.count=i==0 ? 1 : i==1 ? UINT32_MAX : 0; choice_chance=i>=2 ? i : 0; SYNC(); CREATE(2,3,0,0); snapshot(NULL); } break;
    case 4: case 5: list(1); pickups.count=0; SYNC(); CREATE(2,3,4,5); break;
    case 6: SYNC(); CREATE(2,3,4,5); break;
    case 7:
        for (unsigned i=0;i<7;++i) {
            setup(); list(1); items[0].x=i==0 ? 19 : i==1 ? 620 : 100; items[0].y=i==2 ? 0 : i==3 ? 478 : 100;
            items[0].dx=i==0 ? UINT32_MAX : 1; items[0].dy=i==2 ? UINT32_MAX : 2; items[0].tick=i==4 ? 20 : i==5 ? 0x7fffffff : i==6 ? UINT32_MAX : 5;
            SYNC(); CALL(update,0x407420); snapshot(NULL);
        } break;
    case 8:
        for (unsigned kind=0;kind<20;++kind) { setup(); list(1); collide=1; items[0].kind=kind; items[0].sprite=35+(kind%19); SYNC(); CALL(update,0x407420); snapshot(NULL); } break;
    case 9:
        for (unsigned kind=10;kind<=16;kind+=(kind==10 ? 1 : 5)) for (unsigned i=0;i<5;++i) {
            const uint32_t widths[]={18,37,38,111,148}; setup(); list(1); collide=1; items[0].kind=kind; motion.paddle_width=widths[i];
            SYNC(); CALL(update,0x407420); snapshot(NULL);
        } break;
    case 10: list(1); SYNC(); CALL(update,0x407420); break;
    case 11: list(2); items[0].x=0; items[0].dx=UINT32_MAX; SYNC(); CALL(update,0x407420); break;
    case 12: case 15: list(2); collide=1; items[0].kind=1; SYNC(); CALL(update,0x407420); break;
    case 13: case 14: list(1); collide=1; items[0].kind=10; SYNC(); CALL(update,0x407420); break;
    case 16: case 17: list(3); SYNC(); CALL(draw,0x407a40); break;
    case 18:
        for (unsigned i=0;i<4;++i) { setup(); list(i ? 3 : 0); if (i) pickups.current=&items[i-1]; SYNC(); CALL(remove,0x407a90); snapshot(NULL); } break;
    case 19: list(3); SYNC(); CALL(remove,0x407a90); break;
    case 20: list(3); items[0].y=items[1].y=items[2].y=500; SYNC(); CALL(update,0x407420); break;
    case 21:
        for (unsigned i=0;i<12;++i) {
            if (!pickups.first) { choice_kind=(i*7)%19; pickups.count=0; SYNC(); CREATE(i%20,(i*3)%20,i%5-2,2); }
            collide=(i%4)==3; SYNC(); CALL(update,0x407420); CALL(draw,0x407a40); snapshot(NULL);
        } break;
    default: REQUIRE(0);
    }
}
#ifdef PICKUP_CONNECTED
#include "frame-pickups.h"
#endif
int main(int argc,char **argv) {
    REQUIRE(argc==3); scenario=(uint32_t)strtoul(argv[2],NULL,10); setup();
#ifdef PICKUP_CONNECTED
    REQUIRE(scenario>=22 && scenario<27); frame_setup();
#else
    REQUIRE(scenario<22);
#endif
    int source=!strcmp(argv[1],"source"); REQUIRE(source || !strcmp(argv[1],"original"));
#ifndef DX_STANDALONE
    install(source);
#ifdef PICKUP_CONNECTED
    frame_install(source);
#endif
    SYNC();
#else
    REQUIRE(source);
#endif
    spx_observer out=spx_observe_begin(stdout); observer=&out; spx_observe_object(observer,"pickups"); snapshot("initial");
    spx_observe_array(observer,"calls");
#ifdef PICKUP_CONNECTED
    if (scenario>=22) frame_run(); else run_scenario();
#else
    run_scenario();
#endif
    spx_observe_end(observer); snapshot("final");
    spx_observe_end(observer); REQUIRE(spx_observe_finish(observer)); fputc('\n',stdout); return 0;
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
__declspec(dllexport) void dx_pickups_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance; (void)reserved;
    return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
