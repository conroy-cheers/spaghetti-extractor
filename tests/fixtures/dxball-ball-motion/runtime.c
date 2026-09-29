/* Real original operations with local storage and observable service effects. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "motion-runtime.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
enum { NODES=6,SPRITES=6 };
struct play_effect { uint32_t unused; };
static play_ball balls[NODES];
static uint32_t live[NODES],mode,entered[5],calls,random_seed,callback_done;
static font_sprite sprites[SPRITES];
static struct spx_opaque_cleanup_state_v5 objects;
static font_state font={.objects=&objects};
static title_state title={.font=&font};
static scene_state scene={.animation=&title};
static menu_state menu={.scene=&scene};
static int32_t sine[361],cosine[361];
static play_state play={.menu=&menu,.sine=sine,.cosine=cosine};
static board current_board;
static motion_state motion={.play=&play,.board=&current_board};
static spx_observer *observer;
static void require(int condition,const char *expression,unsigned line) {
    if (!condition) { fprintf(stderr,"motion-runtime.c:%u: adapter premise failed: %s\n",line,expression); exit(3); }
}
#define REQUIRE(test) require(!!(test),#test,__LINE__)
void motion_enter(unsigned operation) { REQUIRE(operation<5); ++entered[operation]; }
static uint32_t ball_id(const play_ball *p) {
    if (!p) return 0;
    for (unsigned i=0;i<NODES;++i) if (p==&balls[i]) return i+1;
    REQUIRE(0); return 0;
}
static void sprite_word(font_sprite *p,unsigned offset,uint32_t value) {
    memcpy(p->retained+offset-4,&value,4);
}
static void snapshot(const char *name) {
    spx_observe_object(observer,name);
    uint32_t fields[]={motion.ball_count,motion.gravity,motion.paddle_width,motion.paddle_power,motion.sticky,motion.pierce,
        motion.impact_dx,motion.impact_dy,play.paddle_x,play.paddle_y,play.old_paddle_x,play.old_paddle_y,play.changed,
        play.launch_pressed,play.remaining_bricks,menu.score,title.fast,objects.current_bank};
    spx_observe_u32s(observer,"fields",fields,sizeof(fields)/sizeof(*fields));
    uint32_t list[]={ball_id(play.balls.current),ball_id(play.balls.first),ball_id(play.balls.last),play.balls.retained};
    spx_observe_u32s(observer,"list",list,4); spx_observe_array(observer,"balls");
    for (unsigned i=0;i<NODES;++i) {
        uint32_t words[16]={live[i]}; memcpy(words+1,&balls[i],52);
        words[14]=ball_id(balls[i].next); words[15]=ball_id(balls[i].previous);
        spx_observe_u32s(observer,NULL,words,16);
    }
    spx_observe_end(observer); spx_observe_bytes(observer,"board",(const unsigned char *)&current_board,400);
    spx_observe_array(observer,"sprites");
    for (unsigned i=0;i<SPRITES;++i) spx_observe_bytes(observer,NULL,sprites[i].retained,sizeof(sprites[i].retained));
    spx_observe_end(observer); spx_observe_end(observer);
}
static void begin_call(motion_state *s,unsigned operation,const uint32_t *args,unsigned count) {
    REQUIRE(s==&motion && calls++<1000); spx_observe_object(observer,NULL); spx_observe_u64(observer,"operation",operation);
    spx_observe_u32s(observer,"arguments",args,count); snapshot("before");
}
static uint32_t end_call(uint32_t result) {
    snapshot("after"); spx_observe_u64(observer,"result",result); spx_observe_end(observer); return result;
}
#define BEGIN0(operation) (void)unused; begin_call(s,operation,NULL,0)
#define BEGIN(operation,...) (void)unused; const uint32_t args[]={__VA_ARGS__}; begin_call(s,operation,args,sizeof(args)/sizeof(*args))
play_ball *motion_allocate(void *unused,motion_state *s) {
    BEGIN0(MOTION_ALLOCATE);
    for (unsigned i=0;i<NODES;++i) if (!live[i]) {
        live[i]=1; memset(&balls[i],0,sizeof(balls[i])); balls[i].x=0x76543210;
        (void)end_call(i+1); return &balls[i];
    }
    (void)end_call(0); return NULL;
}
void motion_free(void *unused,motion_state *s,play_ball *ball) {
    uint32_t id=ball_id(ball); BEGIN(MOTION_FREE,id); REQUIRE(id && live[id-1]); live[id-1]=0;
    if (mode==24) { s->ball_count+=2; s->play->balls.current=&balls[2]; }
    (void)end_call(0);
}
uint32_t motion_random(void *unused,motion_state *s,uint32_t limit) {
    BEGIN(MOTION_RANDOM,limit); REQUIRE(limit && limit<0x80000000);
    random_seed=random_seed*1664525+1013904223;
    return end_call(mode==11 ? 0 : random_seed%limit);
}
void motion_stop_sound(void *unused,motion_state *s,uint32_t sound) {
    BEGIN(MOTION_STOP_SOUND,sound);
    if (mode==19 && !callback_done++) {
        play.balls.current=&balls[1]; balls[1].x=617; balls[1].y=100;
        objects.current_bank=1; sprite_word(&sprites[3],8,17); motion.gravity=1;
    }
    (void)end_call(0);
}
uint32_t motion_pan(void *unused,motion_state *s,uint32_t x) { BEGIN(MOTION_PAN,x); return end_call(x^0x1357); }
void motion_play_sound(void *unused,motion_state *s,uint32_t sound,uint32_t repeat,uint32_t volume,uint32_t pan) {
    BEGIN(MOTION_PLAY_SOUND,sound,repeat,volume,pan); (void)end_call(0);
}
uint32_t motion_overlap(void *unused,motion_state *s,font_rect *a,font_rect *b) {
    BEGIN(MOTION_OVERLAP,a->left,a->top,a->right,a->bottom,b->left,b->top,b->right,b->bottom);
    return end_call(mode>=8 && mode<=10);
}
void motion_paddle_power(void *unused,motion_state *s) { BEGIN0(MOTION_PADDLE_POWER); ++play.menu->score; (void)end_call(0); }
void motion_particle(void *unused,motion_state *s,uint32_t x,uint32_t y,uint32_t dx,uint32_t dy,uint32_t color,uint32_t gravity) {
    BEGIN(MOTION_PARTICLE,x,y,dx,dy,color,gravity); (void)end_call(0);
}
void motion_explosion(void *unused,motion_state *s,uint32_t x,uint32_t y) { BEGIN(MOTION_EXPLOSION,x,y); (void)end_call(0); }
uint32_t motion_hit(void *unused,motion_state *s,uint32_t column,uint32_t row) {
    BEGIN(MOTION_HIT,column,row); REQUIRE(column<20 && row<20);
    uint32_t value=s->board->cells[row][column]; s->board->cells[row][column]=0;
    if (mode==16) s->pierce=1;
    if (mode==17) ++s->play->balls.current->speed;
    return end_call(value==2 ? 0 : 1);
}
void motion_unstick(void *unused,motion_state *s) { BEGIN0(MOTION_UNSTICK); ++s->play->balls.current->angle; (void)end_call(0); }
void motion_lose_life(void *unused,motion_state *s) { BEGIN0(MOTION_LOSE_LIFE); ++s->play->menu->score; (void)end_call(0); }

#ifndef DX_STANDALONE
static uint32_t native_balls[NODES][15],native_sprites[SPRITES][12];
static uint32_t ball_address(play_ball *p) { uint32_t id=ball_id(p); return id ? (uint32_t)(uintptr_t)&native_balls[id-1] : 0; }
static play_ball *ball_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)&native_balls[i]) { REQUIRE(live[i]); return &balls[i]; }
    REQUIRE(0); return NULL;
}
static uint32_t shot_address(play_shot *p) { REQUIRE(!p); return 0; }
static play_shot *shot_view(uint32_t p) { REQUIRE(!p); return NULL; }
static uint32_t event_address(play_event *p) { REQUIRE(!p); return 0; }
static play_event *event_view(uint32_t p) { REQUIRE(!p); return NULL; }
static uint32_t effect_address(play_effect *p) { REQUIRE(!p); return 0; }
static play_effect *effect_view(uint32_t p) { REQUIRE(!p); return NULL; }
static void play_parent_to_native(void) {
    *(uint32_t *)0x431cbc=menu.score; *(uint32_t *)0x417a04=scene.presentation_mode; *(uint32_t *)0x434990=scene.mouse_buttons;
    *(uint32_t *)0x4349c8=title.fast; *(uint32_t *)0x434968=objects.current_bank;
    for (unsigned bank=0;bank<2;++bank) for (unsigned i=0;i<3;++i) {
        const uint32_t slots[]={1,55,61}; unsigned id=bank*3+i;
        *(uint32_t *)(uintptr_t)(0x433d18+bank*0x418+4*slots[i])=(uint32_t)(uintptr_t)&native_sprites[id];
        memcpy((unsigned char *)native_sprites[id]+4,sprites[id].retained,sizeof(sprites[id].retained));
    }
}
static void play_parent_from_native(void) {
    menu.score=*(uint32_t *)0x431cbc; scene.presentation_mode=*(uint32_t *)0x417a04; scene.mouse_buttons=*(uint32_t *)0x434990;
    title.fast=*(uint32_t *)0x4349c8; objects.current_bank=*(uint32_t *)0x434968;
    for (unsigned i=0;i<SPRITES;++i) memcpy(sprites[i].retained,(unsigned char *)native_sprites[i]+4,sizeof(sprites[i].retained));
}
static void play_objects_to_native(void) {
    for (unsigned i=0;i<NODES;++i) if (live[i]) {
        memcpy(native_balls[i],&balls[i],52); native_balls[i][13]=ball_address(balls[i].next); native_balls[i][14]=ball_address(balls[i].previous);
    }
}
static void play_objects_from_native(void) {
    for (unsigned i=0;i<NODES;++i) if (live[i]) {
        memcpy(&balls[i],native_balls[i],52); balls[i].next=ball_view(native_balls[i][13]); balls[i].previous=ball_view(native_balls[i][14]);
    }
}
#include "play-native.h"
#include "motion-native.h"
static uint32_t native_allocate(uint32_t bytes) {
    REQUIRE(bytes==60); motion_from_native(); play_ball *ball=motion_allocate(NULL,&motion); motion_to_native(); return ball_address(ball);
}
static void native_free(uint32_t address) { motion_from_native(); motion_free(NULL,&motion,ball_view(address)); motion_to_native(); }
static uint32_t native_random(uint32_t limit) { motion_from_native(); uint32_t result=motion_random(NULL,&motion,limit); motion_to_native(); return result; }
static uint32_t native_pan(uint32_t x) { motion_from_native(); uint32_t result=motion_pan(NULL,&motion,x); motion_to_native(); return result; }
static uint32_t native_overlap(font_rect a,font_rect b) {
    motion_from_native(); uint32_t result=motion_overlap(NULL,&motion,&a,&b); motion_to_native(); return result;
}
static uint32_t native_hit(uint32_t column,uint32_t row) {
    motion_from_native(); uint32_t result=motion_hit(NULL,&motion,column,row); motion_to_native(); return result;
}
#define SERVICE0(name) static void native_##name(void) { motion_from_native(); motion_##name(NULL,&motion); motion_to_native(); }
SERVICE0(paddle_power) SERVICE0(unstick) SERVICE0(lose_life)
#define SERVICE(name,params,...) static void native_##name params { motion_from_native(); motion_##name(NULL,&motion,__VA_ARGS__); motion_to_native(); }
SERVICE(stop_sound,(uint32_t sound),sound)
SERVICE(play_sound,(uint32_t sound,uint32_t repeat,uint32_t volume,uint32_t pan),sound,repeat,volume,pan)
SERVICE(particle,(uint32_t x,uint32_t y,uint32_t dx,uint32_t dy,uint32_t color,uint32_t gravity),x,y,dx,dy,color,gravity)
SERVICE(explosion,(uint32_t x,uint32_t y),x,y)
#define ROOT(name) static void native_root_##name(void) { motion_from_native(); fixture_motion_##name(&motion); motion_to_native(); }
ROOT(create) ROOT(update) ROOT(rebound) ROOT(remove)
static uint32_t native_root_contact(uint32_t x,uint32_t y) {
    motion_from_native(); uint32_t result=fixture_motion_contact(&motion,x,y); motion_to_native(); return result;
}
static void install(int source) {
#define HOOK(name) REQUIRE(install_motion_service_##name((void (*)(void))native_##name));
    HOOK(allocate) HOOK(free) HOOK(random) HOOK(stop_sound) HOOK(pan) HOOK(play_sound)
    HOOK(overlap) HOOK(paddle_power) HOOK(particle) HOOK(explosion) HOOK(hit) HOOK(unstick) HOOK(lose_life)
#undef HOOK
    if (!source) return;
#define HOOK(name) REQUIRE(install_motion_##name((void (*)(void))native_root_##name));
    HOOK(create) HOOK(update) HOOK(rebound) HOOK(contact) HOOK(remove)
#undef HOOK
}
#endif
#ifdef MOTION_FRAME_CONSUMER
#include "frame-motion.h"
#endif

static void setup(unsigned scenario) {
    mode=scenario; random_seed=0x69185a73; callback_done=0;
    memset(balls,0,sizeof(balls)); memset(live,0,sizeof(live)); memset(&current_board,0,sizeof(current_board));
    memset(sprites,0,sizeof(sprites)); memset(&objects,0,sizeof(objects));
    play=(play_state){.menu=&menu,.sine=sine,.cosine=cosine,.paddle_x=320,.paddle_y=450,.old_paddle_x=320,.old_paddle_y=450,.remaining_bricks=20};
    motion=(motion_state){.play=&play,.board=&current_board,.paddle_width=73,.ball_count=1};
    menu.score=0xfffffff8; title.fast=0; scene.presentation_mode=0; scene.mouse_buttons=0;
    for (unsigned i=0;i<361;++i) { sine[i]=1024-(int32_t)(i%7)*64; cosine[i]=1024-(int32_t)(i%19)*128; }
    for (unsigned bank=0;bank<2;++bank) for (unsigned i=0;i<3;++i) {
        const uint32_t slots[]={1,55,61}; unsigned id=bank*3+i;
        objects.banks[bank].slots[slots[i]]=&sprites[id];
        sprite_word(&sprites[id],8,9+bank*2); sprite_word(&sprites[id],12,9+bank*2);
    }
    for (unsigned i=0;i<NODES;++i) balls[i]=(play_ball){.x=200+i*11,.y=400,.old_x=100+i,.old_y=200+i,.dx=3,.dy=4,.sprite=1,.angle=75,.speed=5};
    live[0]=1; play.balls=(play_balls){&balls[0],&balls[0],&balls[0],0x10203040};
    if (mode==0 || mode==20) { live[0]=0; motion.ball_count=0; play.balls=(play_balls){0}; }
    if (mode==1 || mode==2) { balls[0].attached=1; balls[0].auxiliary=7; play.launch_pressed=mode==2; }
    if (mode==4 || mode==19) { balls[0].x=19; balls[0].dx=0xfffffffb; }
    if (mode==5) { balls[0].x=617; balls[0].dx=5; }
    if (mode==6) { balls[0].y=1; balls[0].dy=0xfffffffb; }
    if (mode==7) balls[0].y=476;
    if (mode>=8 && mode<=10) { balls[0].x=290; balls[0].y=439; balls[0].dy=4; balls[0].retained=41; }
    if (mode==9) { motion.sticky=1; motion.paddle_power=1; balls[0].x=100; }
    if (mode==10) { title.fast=1; balls[0].speed=8; }
    if (mode==11) { balls[0].sprite=61; balls[0].dx=0xfffffffd; }
    if (mode>=12 && mode<=17) {
        balls[0].x=200; balls[0].y=100; balls[0].dx=mode==14 ? 0xfffffffd : 3; balls[0].dy=mode==12 ? 0xfffffffc : 4;
        memset(current_board.cells,3,400);
        if (mode==14 || mode==15) {
            uint32_t x=balls[0].x+balls[0].dx+4,y=balls[0].y+balls[0].dy+9;
            current_board.cells[(y-50)/15][(x-20)/30]=0;
        }
        if (mode==16) motion.pierce=1;
        if (mode==17) { balls[0].sprite=61; memset(current_board.cells,2,400); }
    }
    if (mode==18 || mode==19 || mode==21 || mode==23 || mode==24) {
        motion.ball_count=3; live[1]=live[2]=1;
        balls[0].next=&balls[1]; balls[1].previous=&balls[0]; balls[1].next=&balls[2]; balls[2].previous=&balls[1]; play.balls.last=&balls[2];
        if (mode==18) { balls[0].y=479; balls[2].attached=1; }
        if (mode==23) play.balls.current=&balls[2];
    }
    if (mode==22) play.balls.current=NULL;
    if (mode==27) balls[0].tick=301;
}

#ifndef DX_STANDALONE
#define CALL0(name,address) ((void (*)(void))address)(); motion_from_native()
#define CALL_CONTACT(x,y) ((uint32_t (*)(uint32_t,uint32_t))0x405910)(x,y)
#define SYNC() motion_to_native()
#else
#define CALL0(name,address) fixture_motion_##name(&motion)
#define CALL_CONTACT(x,y) fixture_motion_contact(&motion,x,y)
#define SYNC() ((void)0)
#endif
static void run(void) {
    if (mode==20 || mode==21) { CALL0(create,0x404d70); }
    else if (mode>=22 && mode<=24) { CALL0(remove,0x405a00); }
    else if (mode==25) {
        const uint32_t offsets[]={0xfffffff0,0,1,5,11,22,33,44,54,64,72,80};
        for (unsigned i=0;i<sizeof(offsets)/sizeof(*offsets);++i) {
            balls[0].x=play.paddle_x-font_half(motion.paddle_width)+offsets[i]-4; SYNC(); CALL0(rebound,0x405710);
        }
    } else if (mode==26) {
        const uint32_t points[][2]={{20,49},{20,50},{619,349},{619,350},{0xffffffff,50},{0x80000000,50},{0x7fffffff,349}};
        memset(current_board.cells,3,400); SYNC();
        for (unsigned i=0;i<sizeof(points)/sizeof(*points);++i) {
            uint32_t result=CALL_CONTACT(points[i][0],points[i][1]);
#ifndef DX_STANDALONE
            motion_from_native();
#endif
            spx_observe_object(observer,NULL); spx_observe_u32s(observer,"point",points[i],2); spx_observe_u64(observer,"result",result); snapshot("state"); spx_observe_end(observer);
        }
    } else if (mode==28) {
        uint32_t seed=0x893725;
        for (unsigned i=0;i<12;++i) {
            seed=seed*1664525+1013904223; setup(3);
            balls[0].x=20+seed%580; balls[0].y=(seed>>10)%480;
            balls[0].dx=(seed>>20)%13-6; balls[0].dy=(seed>>24)%13-6;
            motion.gravity=seed%3; memset(current_board.cells,seed%5 ? 0 : 3,400);
            SYNC(); CALL0(update,0x404e80);
        }
    } else { CALL0(update,0x404e80); }
}
int main(int argc,char **argv) {
    REQUIRE(argc==3); unsigned scenario=(unsigned)strtoul(argv[2],NULL,10); REQUIRE(scenario<29); setup(scenario);
    int source=!strcmp(argv[1],"source"); REQUIRE(source || !strcmp(argv[1],"original"));
#ifndef DX_STANDALONE
    install(source); motion_to_native(); unsigned short control; __asm__ volatile("fnstcw %0":"=m"(control)); REQUIRE(control==0x027f);
#ifdef MOTION_FRAME_CONSUMER
    frame_install(source);
#endif
#else
    REQUIRE(source);
#endif
    spx_observer o=spx_observe_begin(stdout); observer=&o; spx_observe_object(&o,"motion"); snapshot("initial"); spx_observe_array(&o,"calls");
    (void)run;
#ifdef MOTION_FRAME_CONSUMER
    frame_run();
#else
    run();
#endif
    spx_observe_end(&o); snapshot("final"); spx_observe_end(&o); REQUIRE(spx_observe_finish(&o)); fputc('\n',stdout);
    if (source) REQUIRE(entered[0]+entered[1]+entered[2]+entered[3]+entered[4]);
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
__declspec(dllexport) void dx_motion_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance; (void)reserved;
    return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
