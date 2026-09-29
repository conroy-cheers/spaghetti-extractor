/* Independent original/source consumers; no window, audio or game startup. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "progress-runtime.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
enum { NODES=4 };
static uint32_t scenario,entered[8],calls,blits,sprite_calls,fade_calls;
#ifdef PROGRESS_CONNECTED
static uint32_t frame_entries,frame_number;
#endif
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
static play_ball balls[NODES];
static uint32_t ball_live[NODES];
static spx_observer *observer;
static void require(int test,const char *expression,unsigned line) {
    if (!test) { fprintf(stderr,"progress-runtime.c:%u: adapter premise failed: %s\n",line,expression); exit(3); }
}
#define REQUIRE(test) require(!!(test),#test,__LINE__)
void progress_enter(unsigned operation) { REQUIRE(operation<8); ++entered[operation]; }
static uint32_t ball_id(const play_ball *p) {
    if (!p) return 0;
    for (unsigned i=0;i<NODES;++i) if (p==&balls[i]) { REQUIRE(ball_live[i]); return i+1; }
    REQUIRE(0); return 0;
}
static uint32_t surface_id(const font_surface *p) {
    if (!p) return 0;
    for (unsigned i=0;i<4;++i) if (p==&surfaces[i]) return i+1;
    REQUIRE(0); return 0;
}
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
    uint32_t roots[]={ball_id(play.balls.current),ball_id(play.balls.first),ball_id(play.balls.last),play.balls.retained};
    spx_observe_u32s(observer,"ball_roots",roots,4); spx_observe_array(observer,"balls");
    for (unsigned i=0;i<NODES;++i) if (ball_live[i]) {
        uint32_t row[16]={i+1}; memcpy(row+1,&balls[i],52); row[14]=ball_id(balls[i].next); row[15]=ball_id(balls[i].previous);
        spx_observe_u32s(observer,NULL,row,16);
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
static void begin(progression_state *s,unsigned op,const uint32_t *args,unsigned count) {
    REQUIRE(s==&progress && calls++<2000); spx_observe_object(observer,NULL); spx_observe_u64(observer,"operation",op);
    spx_observe_u32s(observer,"arguments",args,count); snapshot("before");
}
static uint32_t end(uint32_t result) { snapshot("after"); spx_observe_u64(observer,"result",result); spx_observe_end(observer); return result; }
#define BEGIN0(op) (void)unused; begin(s,op,NULL,0)
#define BEGIN(op,...) (void)unused; const uint32_t args[]={__VA_ARGS__}; begin(s,op,args,sizeof(args)/sizeof(*args))
static void dimensions(font_sprite *sprite,uint32_t width,uint32_t height) {
    for (unsigned i=0;i<4;++i) { sprite->retained[4+i]=(unsigned char)(width>>(8*i)); sprite->retained[8+i]=(unsigned char)(height>>(8*i)); }
}
void progress_blit_fast(void *unused,progression_state *s,font_surface *destination,uint32_t x,uint32_t y,font_surface *source,font_rect *bounds,uint32_t flags) {
    BEGIN(PROGRESS_BLIT_FAST,surface_id(destination),x,y,surface_id(source),bounds->left,bounds->top,bounds->right,bounds->bottom,flags);
    ++blits;
    if (scenario==7) { bounds->left+=3; bounds->bottom+=2; title.back=&surfaces[3]; pickups.lives=blits==1 ? 25 : 14; menu.score=777; }
    (void)end(0);
}
void progress_destination(void *unused,progression_state *s,font_surface *surface) {
    BEGIN(PROGRESS_DESTINATION,surface_id(surface)); font.destination=surface;
    if (scenario==7) menu.score=888;
    (void)end(0);
}
void progress_text(void *unused,progression_state *s,uint32_t x,uint32_t y,uint32_t length,font_bytes *bytes) {
    BEGIN(PROGRESS_TEXT,x,y,length); REQUIRE(length<=10); spx_observe_bytes(observer,"text",bytes->data,length);
    if (scenario==7) menu.score=999;
    (void)end(0);
}
void progress_damage(void *unused,progression_state *s,font_rect *bounds) {
    BEGIN(PROGRESS_DAMAGE,bounds->left,bounds->top,bounds->right,bounds->bottom); (void)end(0);
}
void progress_sprite(void *unused,progression_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    BEGIN(PROGRESS_SPRITE,slot,x,y); if (scenario==7 && ++sprite_calls==2) pickups.lives=5; (void)end(0);
}
void progress_load_board(void *unused,progression_state *s) {
    BEGIN0(PROGRESS_LOAD_BOARD); memset(&current_board,0,sizeof(current_board));
    if (scenario!=12) { current_board.cells[1][2]=7; current_board.cells[3][4]=8; current_board.cells[19][0]=2; }
    if (scenario==15) { progress.pending=7; progress.board_changed=9; }
    (void)end(0);
}
void progress_stop_sound(void *unused,progression_state *s,uint32_t sound) {
    BEGIN(PROGRESS_STOP_SOUND,sound);
    if (scenario==18) { play.paddle_x=UINT32_MAX; pickups.lives=9; progress.pending=77; }
    if (scenario==22) { scene.mouse_x=333; motion.paddle_width=55; objects.current_bank=1; }
    (void)end(0);
}
uint32_t progress_pan(void *unused,progression_state *s,uint32_t x) { BEGIN(PROGRESS_PAN,x); return end(x+17); }
void progress_play_sound(void *unused,progression_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d) {
    BEGIN(PROGRESS_PLAY_SOUND,a,b,c,d); if (scenario==18) progress.pending=99; (void)end(0);
}
void progress_wait(void *unused,progression_state *s,uint32_t count) {
    BEGIN(PROGRESS_WAIT,count); if (scenario==19) { flow.next_scene=8; flow.transition_pending=9; pickups.lives=3; } (void)end(0);
}
void progress_redraw(void *unused,progression_state *s) {
    BEGIN0(PROGRESS_REDRAW); if (scenario==22) { current_board.cells[1][2]=0; play.remaining_bricks=19; } (void)end(0);
}
void progress_palette(void *unused,progression_state *s,asset_name *name) {
    BEGIN0(PROGRESS_PALETTE); spx_observe_bytes(observer,"name",(const unsigned char *)name->text,strlen(name->text));
    REQUIRE(!strcmp(name->text,"mbbkgrnd.pcx"));
    for (unsigned i=0;i<256;++i) { palettes.staged[i][0]=(unsigned char)i; palettes.staged[i][1]=(unsigned char)(i*3); palettes.staged[i][2]=(unsigned char)(255-i); }
    if (scenario==22) scene.mouse_x=123;
    (void)end(0);
}
void progress_fade(void *unused,progression_state *s,uint32_t wait,uint32_t step,uint32_t first,uint32_t last,uint32_t direction) {
    BEGIN(PROGRESS_FADE,wait,step,first,last,direction); ++fade_calls;
    if (direction) memcpy(palettes.current,palettes.staged,1024); else memset(palettes.current,0,1024);
    if (scenario==30 && fade_calls==1) { progress.board_changed=1; pickups.lives=0; title.back=&surfaces[3]; }
    (void)end(0);
}
void progress_create_ball(void *unused,progression_state *s) {
    BEGIN0(PROGRESS_CREATE_BALL); unsigned i=0; while (i<NODES && ball_live[i]) ++i; REQUIRE(i<NODES); ball_live[i]=1;
    play_ball *ball=&balls[i]; *ball=(play_ball){.x=play.paddle_x,.y=430,.sprite=1,.speed=5,.angle=45,.tick=91,.retained=71,.auxiliary=81,.attached=99};
    ball->previous=play.balls.last;
    if (play.balls.last) play.balls.last->next=ball; else play.balls.first=ball;
    play.balls.current=play.balls.last=ball; ++motion.ball_count;
    if (scenario==22) { play.balls.current=play.balls.first; play.paddle_x+=11; progress.pending=13; progress.board_changed=14; }
    (void)end(0);
}
void progress_clear(void *unused,progression_state *s,font_surface *surface,uint32_t color) {
    BEGIN(PROGRESS_CLEAR,surface_id(surface),color); (void)end(0);
}
void progress_clear_objects(void *unused,progression_state *s) {
    BEGIN0(PROGRESS_CLEAR_OBJECTS); memset(ball_live,0,sizeof(ball_live)); play.balls.current=play.balls.first=play.balls.last=NULL;
    if (scenario==29) { flow.next_scene=3; pickups.lives=1; }
    (void)end(0);
}
void progress_reset_damage(void *unused,progression_state *s) {
    BEGIN0(PROGRESS_RESET_DAMAGE); if (scenario==31) { flow.next_scene=2; pickups.lives=2; } (void)end(0);
}
#ifndef DX_STANDALONE
static uint32_t native_balls[NODES][15],native_surfaces[4],native_sprites[2][12],vtable[8];
static uint32_t *word(uint32_t address) { return (uint32_t *)(uintptr_t)address; }
static uint32_t ball_address(play_ball *p) { uint32_t id=ball_id(p); return id ? (uint32_t)(uintptr_t)native_balls[id-1] : 0; }
static play_ball *ball_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)native_balls[i]) { REQUIRE(ball_live[i]); return &balls[i]; }
    REQUIRE(0); return NULL;
}
static uint32_t surface_address(font_surface *p) { uint32_t id=surface_id(p); return id ? (uint32_t)(uintptr_t)&native_surfaces[id-1] : 0; }
static font_surface *surface_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<4;++i) if (address==(uint32_t)(uintptr_t)&native_surfaces[i]) return &surfaces[i];
    REQUIRE(0); return NULL;
}
#define EMPTY(name,type) static uint32_t name##_address(type *p) { REQUIRE(!p); return 0; } \
    static type *name##_view(uint32_t p) { REQUIRE(!p); return NULL; }
EMPTY(shot,play_shot) EMPTY(event,play_event) EMPTY(effect,play_effect)
#undef EMPTY
static void play_objects_to_native(void) {
    for (unsigned i=0;i<NODES;++i) if (ball_live[i]) { memcpy(native_balls[i],&balls[i],52); native_balls[i][13]=ball_address(balls[i].next); native_balls[i][14]=ball_address(balls[i].previous); }
}
static void play_objects_from_native(void) {
    for (unsigned i=0;i<NODES;++i) if (ball_live[i]) { memcpy(&balls[i],native_balls[i],52); balls[i].next=ball_view(native_balls[i][13]); balls[i].previous=ball_view(native_balls[i][14]); }
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
static void progress_to_native(void) { motion_to_native(); }
static void progress_from_native(void) { motion_from_native(); }
#define NATIVE0(name) static void native_##name(void) { progress_from_native(); progress_##name(NULL,&progress); progress_to_native(); }
NATIVE0(load_board) NATIVE0(redraw) NATIVE0(create_ball) NATIVE0(clear_objects) NATIVE0(reset_damage)
#undef NATIVE0
#define NATIVE(name,params,...) static void native_##name params { progress_from_native(); progress_##name(NULL,&progress,__VA_ARGS__); progress_to_native(); }
NATIVE(stop_sound,(uint32_t n),n) NATIVE(play_sound,(uint32_t a,uint32_t b,uint32_t c,uint32_t d),a,b,c,d)
NATIVE(sprite,(uint32_t a,uint32_t b,uint32_t c),a,b,c) NATIVE(wait,(uint32_t n),n)
NATIVE(fade,(uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e),a,b,c,d,e)
NATIVE(damage,(font_rect bounds),&bounds)
#undef NATIVE
static uint32_t native_pan(uint32_t x) { progress_from_native(); uint32_t result=progress_pan(NULL,&progress,x); progress_to_native(); return result; }
static void native_destination(uint32_t surface) { progress_from_native(); progress_destination(NULL,&progress,surface_view(surface)); progress_to_native(); }
static void native_clear(uint32_t surface,uint32_t color) { progress_from_native(); progress_clear(NULL,&progress,surface_view(surface),color); progress_to_native(); }
static void native_text(uint32_t x,uint32_t y,uint32_t length,const unsigned char *bytes) { progress_from_native(); font_bytes view={bytes}; progress_text(NULL,&progress,x,y,length,&view); progress_to_native(); }
static void native_palette(const char *name) { progress_from_native(); asset_name view={name}; progress_palette(NULL,&progress,&view); progress_to_native(); }
static uint32_t WINAPI native_blit_fast(uint32_t destination,uint32_t x,uint32_t y,uint32_t source,font_rect *bounds,uint32_t flags) {
    progress_from_native(); progress_blit_fast(NULL,&progress,surface_view(destination),x,y,surface_view(source),bounds,flags); progress_to_native(); return 0x88760001;
}
#define ENTRY(name) static void native_progress_##name(void) { progress_from_native(); fixture_progress_##name(&progress); progress_to_native(); }
ENTRY(refresh) ENTRY(draw) ENTRY(next) ENTRY(lose) ENTRY(over) ENTRY(restart) ENTRY(advance)
#undef ENTRY
static uint32_t native_progress_count(void) { progress_from_native(); uint32_t result=fixture_progress_count(&progress); progress_to_native(); return result; }
static void install(int source) {
    vtable[7]=(uint32_t)(uintptr_t)native_blit_fast;
    for (unsigned i=0;i<4;++i) native_surfaces[i]=(uint32_t)(uintptr_t)vtable;
#define HOOK(name) REQUIRE(install_progress_service_##name((void (*)(void))native_##name));
    HOOK(destination) HOOK(text) HOOK(damage) HOOK(sprite) HOOK(load_board) HOOK(stop_sound) HOOK(pan) HOOK(play_sound)
    HOOK(wait) HOOK(redraw) HOOK(palette) HOOK(fade) HOOK(create_ball) HOOK(clear) HOOK(clear_objects) HOOK(reset_damage)
#undef HOOK
    if (source) {
#define ENTRY(name) REQUIRE(install_progress_##name((void (*)(void))native_progress_##name));
        ENTRY(refresh) ENTRY(draw) ENTRY(count) ENTRY(next) ENTRY(lose) ENTRY(over) ENTRY(restart) ENTRY(advance)
#undef ENTRY
    }
}
#endif
static void setup(void) {
    title.back=&surfaces[0]; flow.primary=&surfaces[1]; flow.overlay=&surfaces[2]; font.destination=&surfaces[3];
    objects.banks[0].slots[68]=&sprites[0]; objects.banks[1].slots[68]=&sprites[1];
    dimensions(&sprites[0],37,10); dimensions(&sprites[1],65,12);
    scene.mouse_x=320; scene.mouse_y=450; flow.next_scene=2; menu.score=12345;
    pickups.next_life=12345; pickups.lives=3; pickups.count=4; pickups.paddle_sprite=72;
    motion.paddle_width=75; motion.gravity=3; motion.paddle_power=2; motion.sticky=1; motion.pierce=4;
    play.gun=play.slow_balls=play.speedup_balls=play.fire_balls=play.split_balls=play.power_balls=play.warning_sound=1;
    play.paddle_x=301; play.paddle_y=440; play.old_paddle_x=299; play.old_paddle_y=439;
    play.last_tick=123; play.launch_pressed=1; play.shot_count=2; play.remaining_bricks=7;
    paddle.phase=2; paddle.last_tick=99; paddle.spark_deadline=88; paddle.spark_sprite=144; paddle.spark_width=55;
    progress.warning_y=123; progress.warning_frames=4; play.balls.retained=47;
    current_board.cells[1][2]=3; current_board.cells[2][3]=2; current_board.cells[19][19]=255;
    memset(play.pending_cells,7,400);
    for (unsigned i=0;i<256;++i) for (unsigned j=0;j<4;++j) {
        palettes.current[i][j]=(unsigned char)(i+j*23); palettes.staged[i][j]=(unsigned char)(3*i+j*71);
    }
    if (scenario==1 || scenario==7) pickups.next_life=0;
    if (scenario==2 || scenario==4) menu.score=UINT32_MAX;
    if (scenario==3) pickups.next_life=menu.score=UINT32_MAX;
    if (scenario==5) pickups.lives=UINT32_MAX;
    if (scenario==6) pickups.lives=35;
    if (scenario==8 || scenario==14) memset(&current_board,0,400);
    if (scenario==9) for (unsigned i=0;i<400;++i) ((unsigned char *)&current_board)[i]=(unsigned char)i;
    if (scenario==10) memset(&current_board,2,400);
    if (scenario==13 || scenario==14) bricks.board_index=49;
    if (scenario==15) bricks.board_index=UINT32_MAX;
    if (scenario==17) pickups.lives=0;
    if (scenario==21) motion.paddle_width=UINT32_C(0xffffffd3);
    if (scenario==22) { ball_live[0]=1; balls[0]=(play_ball){.attached=77,.retained=99}; play.balls.current=play.balls.first=play.balls.last=&balls[0]; }
    if (scenario==24) progress.pending=2;
    if (scenario>=25 && scenario<=31) progress.pending=1;
    if (scenario==26) progress.board_changed=1;
    if (scenario==27) pickups.lives=0;
    if (scenario==28 || scenario==31) flow.next_scene=3;
}
#ifndef PROGRESS_CONNECTED
static void invoke(unsigned operation) {
    uint32_t result=0;
#ifndef DX_STANDALONE
    const uint32_t address[]={0x408740,0x408770,0x408900,0x408930,0x408990,0x4089e0,0x408a00,0x408b40};
    REQUIRE(operation<8);
    if (operation==2) result=((uint32_t (*)(void))(uintptr_t)address[operation])();
    else ((void (*)(void))(uintptr_t)address[operation])();
    progress_from_native();
#else
    void (*operations[])(progression_state *)={fixture_progress_refresh,fixture_progress_draw,NULL,fixture_progress_next,fixture_progress_lose,fixture_progress_over,fixture_progress_restart,fixture_progress_advance};
    REQUIRE(operation<8); if (operation==2) result=fixture_progress_count(&progress); else operations[operation](&progress);
#endif
    spx_observe_object(observer,NULL); spx_observe_u64(observer,"entry",operation); spx_observe_u64(observer,"returned",result); snapshot("state"); spx_observe_end(observer);
}
#endif
#ifdef PROGRESS_CONNECTED
#include "frame-progress.h"
#endif
static int run(int argc,char **argv) {
    REQUIRE(argc==3); scenario=(uint32_t)strtoul(argv[2],NULL,10); setup();
#ifdef PROGRESS_CONNECTED
    REQUIRE(scenario>=33 && scenario<38); frame_setup();
#else
    REQUIRE(scenario<33);
#endif
#ifndef DX_STANDALONE
    install(!strcmp(argv[1],"source")); progress_to_native();
#ifdef PROGRESS_CONNECTED
    frame_install(!strcmp(argv[1],"source"));
#endif
#endif
    spx_observer output=spx_observe_begin(stdout); observer=&output; spx_observe_array(observer,"progression"); snapshot(NULL);
#ifdef PROGRESS_CONNECTED
    frame_run();
#else
    if (scenario==32) { invoke(4); invoke(7); invoke(3); invoke(7); invoke(0); invoke(2); }
    else invoke(scenario<=3 || scenario==7 ? 0 : scenario<=6 ? 1 : scenario<=10 ? 2 : scenario<=15 ? 3 : scenario<=18 ? 4 : scenario==19 ? 5 : scenario<=22 ? 6 : 7);
#endif
    spx_observe_end(observer); REQUIRE(spx_observe_finish(observer)); fputc('\n',stdout); return 0;
}
#ifdef DX_STANDALONE
int main(int argc,char **argv) { return run(argc,argv); }
#else
__declspec(dllexport) void dx_progress_anchor(void) {}
static void native_start(void) { int argc=0; char **argv=NULL; extern int __cdecl __getmainargs(int *,char ***,char ***,int,int *); char **env=NULL; int startup=0;
    __getmainargs(&argc,&argv,&env,0,&startup); ExitProcess((UINT)run(argc,argv)); }
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { (void)instance; (void)reserved;
    if (reason==DLL_PROCESS_ATTACH) REQUIRE(install_startup(native_start));
    return TRUE; }
#endif
