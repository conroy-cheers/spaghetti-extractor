/* Actual native paddle entries over shared views and controlled services. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "paddle-runtime.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
enum { SPRITES=160 };
static uint32_t scenario,entered[2],calls,clock_calls,elapsed_value,clock_value,random_value;
static font_surface surfaces[4]={{1},{2},{3},{4}};
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
static paddle_state paddle={.pickups=&pickups};
static spx_observer *observer;
#ifdef PADDLE_CONNECTED
static pickup frame_pickup;
static uint32_t frame_pickup_live;
#endif
static void require(int test,const char *expression,unsigned line) {
    if (!test) { fprintf(stderr,"paddle-runtime.c:%u: adapter premise failed: %s\n",line,expression); exit(3); }
}
#define REQUIRE(test) require(!!(test),#test,__LINE__)
void paddle_enter(unsigned operation) { REQUIRE(operation<2); ++entered[operation]; }
static uint32_t surface_id(const font_surface *p) {
    if (!p) return 0;
    for (unsigned i=0;i<4;++i) if (p==&surfaces[i]) return i+1;
    REQUIRE(0); return 0;
}
static uint32_t sprite_id(const font_sprite *p) {
    if (!p) return 0;
    for (unsigned i=0;i<SPRITES;++i) if (p==&sprites[i]) return i+1;
    REQUIRE(0); return 0;
}
static void dimensions(font_sprite *s,uint32_t width,uint32_t height) { memcpy(s->retained+4,&width,4); memcpy(s->retained+8,&height,4); }
static void snapshot(const char *name) {
    spx_observe_object(observer,name);
    uint32_t fields[]={paddle.phase,paddle.last_tick,paddle.spark_deadline,paddle.spark_width,paddle.spark_sprite,
        motion.paddle_width,play.paddle_x,play.paddle_y,play.old_paddle_x,play.old_paddle_y,play.changed,play.gun,
        scene.mouse_x,scene.mouse_y,flow.windowed,pickups.paddle_sprite,objects.current_bank,
        surface_id(title.software),surface_id(font.destination),pickups.count,menu.score,pickups.lives,pickups.next_life,
        motion.gravity,motion.paddle_power,motion.sticky,motion.pierce};
    spx_observe_u32s(observer,"fields",fields,sizeof(fields)/sizeof(*fields));
    spx_observe_array(observer,"sprites");
    for (unsigned i=0;i<SPRITES;++i) { spx_observe_object(observer,NULL); spx_observe_u64(observer,"surface",surface_id(sprites[i].surface)); spx_observe_bytes(observer,"bytes",sprites[i].retained,41); spx_observe_end(observer); }
    spx_observe_end(observer); spx_observe_array(observer,"banks");
    for (unsigned b=0;b<2;++b) { uint32_t ids[SPRITES]; for (unsigned i=0;i<SPRITES;++i) ids[i]=sprite_id(objects.banks[b].slots[i]); spx_observe_u32s(observer,NULL,ids,SPRITES); }
    spx_observe_end(observer); spx_observe_bytes(observer,"board",(unsigned char *)&current_board,400);
#ifdef PADDLE_CONNECTED
    uint32_t roots[]={frame_pickup_live,pickups.current==&frame_pickup,pickups.first==&frame_pickup,pickups.last==&frame_pickup};
    spx_observe_u32s(observer,"pickup_roots",roots,4);
    if (frame_pickup_live) spx_observe_u32s(observer,"pickup",(const uint32_t *)&frame_pickup,7);
#endif
    spx_observe_end(observer);
}
static void begin(paddle_state *s,unsigned op,const uint32_t *args,unsigned count) {
    REQUIRE(s==&paddle && calls++<10000); spx_observe_object(observer,NULL); spx_observe_u64(observer,"operation",op);
    spx_observe_u32s(observer,"arguments",args,count); snapshot("before");
}
static uint32_t end(uint32_t result) { snapshot("after"); spx_observe_u64(observer,"result",result); spx_observe_end(observer); return result; }
#define BEGIN0(op) (void)unused; begin(s,op,NULL,0)
#define BEGIN(op,...) (void)unused; const uint32_t args[]={__VA_ARGS__}; begin(s,op,args,sizeof(args)/sizeof(*args))
void paddle_cursor(void *unused,paddle_state *s,uint32_t x,uint32_t y) {
    BEGIN(PADDLE_CURSOR,x,y);
    if (scenario==3) { play.paddle_x=317; scene.mouse_x=999; pickups.paddle_sprite=8; }
    (void)end(0);
}
uint32_t paddle_elapsed(void *unused,paddle_state *s,uint32_t previous,uint32_t delay) {
    BEGIN(PADDLE_ELAPSED,previous,delay);
    if (scenario==12) { paddle.phase=3; play.gun=1; play.changed=1; motion.paddle_width=74; }
    return end(elapsed_value);
}
uint32_t paddle_now(void *unused,paddle_state *s) {
    BEGIN0(PADDLE_NOW);
    if (scenario==13) { paddle.phase=2; play.changed=1; objects.current_bank=1; }
    return end(5000);
}
uint32_t paddle_clock(void *unused,paddle_state *s) {
    BEGIN0(PADDLE_CLOCK); ++clock_calls;
    if (scenario==14 && clock_calls==1) { motion.paddle_width=111; play.gun=1; paddle.spark_deadline=clock_value; }
    if (scenario==16 && clock_calls==2) { motion.paddle_width=40; paddle.spark_sprite=131; }
    return end(clock_value);
}
uint32_t paddle_random(void *unused,paddle_state *s,uint32_t limit) {
    BEGIN(PADDLE_RANDOM,limit); REQUIRE(limit==4);
    if (scenario==15) { motion.paddle_width=74; paddle.phase=99; objects.current_bank=1; paddle.spark_sprite=139; }
    return end(random_value);
}
void paddle_blit_fast(void *unused,paddle_state *s,font_surface *destination,uint32_t x,uint32_t y,font_surface *source,font_rect *bounds,uint32_t flags) {
    BEGIN(PADDLE_BLIT_FAST,surface_id(destination),x,y,surface_id(source),bounds->left,bounds->top,bounds->right,bounds->bottom,flags);
    if (scenario==17) { play.paddle_x=321; play.paddle_y=449; motion.paddle_width=37; bounds->bottom=999; }
    (void)end(0);
}
void paddle_damage(void *unused,paddle_state *s,font_rect *bounds) {
    BEGIN(PADDLE_DAMAGE,bounds->left,bounds->top,bounds->right,bounds->bottom);
    if (scenario==18) { play.paddle_x=401; motion.paddle_width=38; objects.current_bank=1; paddle.phase=3; }
    (void)end(0);
}
void paddle_sprite(void *unused,paddle_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    BEGIN(PADDLE_SPRITE,slot,x,y); (void)end(0);
}
#ifndef DX_STANDALONE
static uint32_t native_sprites[SPRITES][12],native_surfaces[4],vtable[8];
static uint32_t *word(uint32_t address) { return (uint32_t *)(uintptr_t)address; }
static uint32_t surface_address(font_surface *p) { uint32_t id=surface_id(p); return id ? (uint32_t)(uintptr_t)&native_surfaces[id-1] : 0; }
static font_surface *surface_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<4;++i) if (address==(uint32_t)(uintptr_t)&native_surfaces[i]) return &surfaces[i];
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
EMPTY(ball,play_ball) EMPTY(shot,play_shot) EMPTY(event,play_event) EMPTY(effect,play_effect)
#undef EMPTY
static void play_objects_to_native(void) {}
static void play_objects_from_native(void) {}
static void play_parent_to_native(void) {
    *word(0x431cbc)=menu.score; *word(0x417a04)=scene.presentation_mode; *word(0x434990)=scene.mouse_buttons;
    *word(0x434970)=scene.mouse_x; *word(0x434978)=scene.mouse_y; *word(0x434998)=flow.windowed;
    *word(0x434968)=objects.current_bank; *word(0x41c728)=surface_address(title.software); *word(0x434960)=surface_address(font.destination);
    for (unsigned i=0;i<SPRITES;++i) { native_sprites[i][0]=surface_address(sprites[i].surface); memcpy((unsigned char *)native_sprites[i]+4,sprites[i].retained,41); }
    for (unsigned b=0;b<2;++b) for (unsigned i=0;i<SPRITES;++i) *word(0x433d18+b*1048+i*4)=sprite_address(objects.banks[b].slots[i]);
}
static void play_parent_from_native(void) {
    menu.score=*word(0x431cbc); scene.presentation_mode=*word(0x417a04); scene.mouse_buttons=*word(0x434990);
    scene.mouse_x=*word(0x434970); scene.mouse_y=*word(0x434978); flow.windowed=*word(0x434998);
    objects.current_bank=*word(0x434968); title.software=surface_view(*word(0x41c728)); font.destination=surface_view(*word(0x434960));
    for (unsigned i=0;i<SPRITES;++i) { sprites[i].surface=surface_view(native_sprites[i][0]); memcpy(sprites[i].retained,(unsigned char *)native_sprites[i]+4,41); }
    for (unsigned b=0;b<2;++b) for (unsigned i=0;i<SPRITES;++i) objects.banks[b].slots[i]=sprite_view(*word(0x433d18+b*1048+i*4));
}
#include "play-native.h"
#include "motion-native.h"
#define PADDLE_WORDS(X) X(phase,0x431c64) X(last_tick,0x42ca50) X(spark_deadline,0x431c70) X(spark_width,0x431c18) X(spark_sprite,0x42cc08)
#ifdef PADDLE_CONNECTED
static uint32_t native_frame_pickup[9];
static uint32_t pickup_address(pickup *p) { if (!p) return 0; REQUIRE(p==&frame_pickup && frame_pickup_live); return (uint32_t)(uintptr_t)native_frame_pickup; }
static pickup *pickup_view(uint32_t p) { if (!p) return NULL; REQUIRE(p==(uint32_t)(uintptr_t)native_frame_pickup && frame_pickup_live); return &frame_pickup; }
#endif
static void paddle_to_native(void) {
    motion_to_native();
#define PUT(name,address) *word(address)=paddle.name;
    PADDLE_WORDS(PUT)
#undef PUT
    *word(0x431c84)=pickups.paddle_sprite; *word(0x431cb8)=pickups.count; *word(0x431ca8)=pickups.lives; *word(0x431c7c)=pickups.next_life;
#ifdef PADDLE_CONNECTED
    *word(0x431c50)=pickup_address(pickups.current); *word(0x431c54)=pickup_address(pickups.first); *word(0x431c58)=pickup_address(pickups.last);
    if (frame_pickup_live) { memcpy(native_frame_pickup,&frame_pickup,28); native_frame_pickup[7]=pickup_address(frame_pickup.next); native_frame_pickup[8]=pickup_address(frame_pickup.previous); }
#endif
}
static void paddle_from_native(void) {
    motion_from_native();
#define GET(name,address) paddle.name=*word(address);
    PADDLE_WORDS(GET)
#undef GET
    pickups.paddle_sprite=*word(0x431c84); pickups.count=*word(0x431cb8); pickups.lives=*word(0x431ca8); pickups.next_life=*word(0x431c7c);
#ifdef PADDLE_CONNECTED
    pickups.current=pickup_view(*word(0x431c50)); pickups.first=pickup_view(*word(0x431c54)); pickups.last=pickup_view(*word(0x431c58));
    if (frame_pickup_live) { memcpy(&frame_pickup,native_frame_pickup,28); frame_pickup.next=pickup_view(native_frame_pickup[7]); frame_pickup.previous=pickup_view(native_frame_pickup[8]); }
#endif
}
static int WINAPI native_cursor(uint32_t x,uint32_t y) { paddle_from_native(); paddle_cursor(NULL,&paddle,x,y); paddle_to_native(); return 1; }
static uint32_t WINAPI native_clock(void) { paddle_from_native(); uint32_t r=paddle_clock(NULL,&paddle); paddle_to_native(); return r; }
static uint32_t native_elapsed(uint32_t a,uint32_t b) { paddle_from_native(); uint32_t r=paddle_elapsed(NULL,&paddle,a,b); paddle_to_native(); return r; }
static uint32_t native_now(void) { paddle_from_native(); uint32_t r=paddle_now(NULL,&paddle); paddle_to_native(); return r; }
static uint32_t native_random(uint32_t limit) { paddle_from_native(); uint32_t r=paddle_random(NULL,&paddle,limit); paddle_to_native(); return r; }
static void native_damage(font_rect bounds) { paddle_from_native(); paddle_damage(NULL,&paddle,&bounds); paddle_to_native(); }
static void native_sprite(uint32_t slot,uint32_t x,uint32_t y) { paddle_from_native(); paddle_sprite(NULL,&paddle,slot,x,y); paddle_to_native(); }
static uint32_t WINAPI native_blit(uint32_t destination,uint32_t x,uint32_t y,uint32_t source,font_rect *bounds,uint32_t flags) {
    paddle_from_native(); paddle_blit_fast(NULL,&paddle,surface_view(destination),x,y,surface_view(source),bounds,flags); paddle_to_native(); return 0;
}
static void native_root_move(void) { paddle_from_native(); fixture_paddle_move(&paddle); paddle_to_native(); }
static void native_root_draw(void) { paddle_from_native(); fixture_paddle_draw(&paddle); paddle_to_native(); }
static void install(int source) {
    vtable[7]=(uint32_t)(uintptr_t)native_blit;
    for (unsigned i=0;i<4;++i) native_surfaces[i]=(uint32_t)(uintptr_t)vtable;
    const uint32_t imports[]={0x415114,0x415174},hooks[]={(uint32_t)(uintptr_t)native_cursor,(uint32_t)(uintptr_t)native_clock};
    for (unsigned i=0;i<2;++i) { DWORD old,ignored; REQUIRE(VirtualProtect(word(imports[i]),4,PAGE_READWRITE,&old)); *word(imports[i])=hooks[i]; REQUIRE(VirtualProtect(word(imports[i]),4,old,&ignored)); }
#define HOOK(name) REQUIRE(install_paddle_service_##name((void (*)(void))native_##name));
    HOOK(elapsed) HOOK(now) HOOK(random) HOOK(damage) HOOK(sprite)
#undef HOOK
    if (source) { REQUIRE(install_paddle_move(native_root_move)); REQUIRE(install_paddle_draw(native_root_draw)); }
}
#define SYNC() paddle_to_native()
#define CALL(name,address) do { ((void (*)(void))address)(); paddle_from_native(); } while (0)
#else
#define SYNC() ((void)0)
#define CALL(name,address) fixture_paddle_##name(&paddle)
#endif
static void setup(void) {
    memset(&objects,0,sizeof(objects)); memset(sprites,0,sizeof(sprites)); memset(&play,0,sizeof(play));
    play.menu=&menu; play.sine=sine; play.cosine=cosine; play.paddle_x=300; play.paddle_y=450;
    motion.paddle_width=73; motion.gravity=motion.paddle_power=motion.sticky=motion.pierce=0;
    scene.mouse_x=300; scene.mouse_y=451; flow.windowed=0; menu.score=7;
    pickups=(pickup_state){.motion=&motion,.paddle_sprite=68,.lives=3,.next_life=5000};
    paddle=(paddle_state){.pickups=&pickups,.last_tick=100,.spark_deadline=0,.spark_width=73,.spark_sprite=128};
    elapsed_value=0; clock_value=1000; random_value=2; clock_calls=0;
    font.destination=&surfaces[1]; title.software=&surfaces[0];
    for (unsigned i=0;i<SPRITES;++i) { sprites[i].surface=&surfaces[i%4]; dimensions(&sprites[i],37,20+i%3); }
    for (unsigned b=0;b<2;++b) for (unsigned i=0;i<SPRITES;++i) objects.banks[b].slots[i]=&sprites[i];
    objects.banks[1].slots[68]=&sprites[69]; dimensions(&sprites[69],40,23);
}
static void draw(void) { SYNC(); CALL(draw,0x4067b0); snapshot(NULL); }
static void run_scenario(void) {
    switch (scenario) {
    case 0: case 1: {
        const uint32_t positions[]={0,20,21,56,57,300,581,582,618,619,0x7fffffff,0x80000000,UINT32_MAX};
        for (unsigned i=0;i<sizeof(positions)/sizeof(*positions);++i) { setup(); scene.mouse_x=positions[i]; flow.windowed=scenario==1; SYNC(); CALL(move,0x406730); snapshot(NULL); } break;
    }
    case 2: {
        const uint32_t widths[]={0,1,2,37,73,74,1200,UINT32_MAX,0x80000000};
        for (unsigned i=0;i<sizeof(widths)/sizeof(*widths);++i) { setup(); motion.paddle_width=widths[i]; scene.mouse_x=UINT32_MAX; SYNC(); CALL(move,0x406730); snapshot(NULL); } break;
    }
    case 3: scene.mouse_x=0; SYNC(); CALL(move,0x406730); break;
    case 4: draw(); break;
    case 5:
        for (unsigned i=0;i<4;++i) { setup(); elapsed_value=1; paddle.phase=i; draw(); } break;
    case 6: play.gun=1; draw(); break;
    case 7: play.changed=1; draw(); break;
    case 8: play.changed=play.gun=1; draw(); break;
    case 9:
        for (unsigned i=0;i<4;++i) { setup(); play.changed=1; paddle.spark_deadline=i==0 ? clock_value-1 : i==1 ? clock_value : i==2 ? clock_value+1 : UINT32_MAX; paddle.spark_width=i==3 ? 37 : 73; draw(); } break;
    case 10:
        for (unsigned i=0;i<4;++i) { setup(); play.changed=1; random_value=i; draw(); } break;
    case 11: {
        const uint32_t widths[]={18,37,40,73,74,100,148};
        for (unsigned gun=0;gun<2;++gun) for (unsigned i=0;i<7;++i) { setup(); motion.paddle_width=widths[i]; play.changed=1; play.gun=gun; draw(); }
        break;
    }
    case 12: case 13: elapsed_value=1; draw(); break;
    case 14: case 15: case 16: case 17: case 18: play.changed=1; draw(); break;
    case 19: objects.current_bank=1; play.changed=1; draw(); break;
    case 20:
        for (unsigned i=0;i<12;++i) { scene.mouse_x=20+i*53; play.changed=i%2; play.gun=(i%3)==2; elapsed_value=i%2; clock_value+=33; SYNC(); CALL(move,0x406730); CALL(draw,0x4067b0); snapshot(NULL); } break;
    default: REQUIRE(0);
    }
}
#ifdef PADDLE_CONNECTED
#include "frame-paddle.h"
#endif
int main(int argc,char **argv) {
    REQUIRE(argc==3); scenario=(uint32_t)strtoul(argv[2],NULL,10); setup();
#ifdef PADDLE_CONNECTED
    REQUIRE(scenario>=21 && scenario<25); frame_setup();
#else
    REQUIRE(scenario<21);
#endif
    int source=!strcmp(argv[1],"source"); REQUIRE(source || !strcmp(argv[1],"original"));
#ifndef DX_STANDALONE
    install(source); unsigned short control; __asm__ volatile("fnstcw %0":"=m"(control)); REQUIRE(control==0x027f);
#ifdef PADDLE_CONNECTED
    frame_install(source);
#endif
    SYNC();
#else
    REQUIRE(source);
#endif
    spx_observer out=spx_observe_begin(stdout); observer=&out; spx_observe_object(observer,"paddles"); snapshot("initial"); spx_observe_array(observer,"calls");
#ifdef PADDLE_CONNECTED
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
__declspec(dllexport) void dx_paddles_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance; (void)reserved;
    return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
