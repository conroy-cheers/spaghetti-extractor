/* Independent original/source consumers; no window, audio or game startup. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "game-runtime.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
enum { NODES=4 };
static uint32_t scenario,entered[3],calls,blits,fade_calls,random_choice;
#ifdef GAME_CONNECTED
static uint32_t game_depth,sprite_calls;
#endif
static font_surface surfaces[4]={{1},{2},{3},{4}};
static font_sprite sprites[4];
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
static damage_state damage={.scene=&scene};
static game_scene_state game={.progression=&progress,.damage=&damage,.stereo_direction=1.0};
static play_ball balls[NODES];
static uint32_t ball_live[NODES];
static spx_observer *observer;
static void require(int test,const char *expression,unsigned line) {
    if (!test) { fprintf(stderr,"progress-runtime.c:%u: adapter premise failed: %s\n",line,expression); exit(3); }
}
#define REQUIRE(test) require(!!(test),#test,__LINE__)
void game_enter(unsigned operation) { REQUIRE(operation<3); ++entered[operation]; }
void game_exit(game_scene_state *s) { REQUIRE(s==&game); title.primary=flow.primary; }
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
    uint32_t extra[]={menu.input_ready,damage.capability,surface_id(scene.flip),font.bank,
        objects.banks[2].count,objects.banks[2].retained[0],surface_id(damage.background)};
    spx_observe_u32s(observer,"scene_fields",extra,sizeof(extra)/sizeof(*extra));
    uint64_t direction; memcpy(&direction,&game.stereo_direction,8); spx_observe_u64(observer,"stereo_bits",direction);
    for (unsigned i=0;i<3;++i) { uint32_t words[7]={objects.banks[i].count}; memcpy(words+1,objects.banks[i].retained,24); spx_observe_u32s(observer,i==0 ? "bank0" : i==1 ? "bank1" : "bank2",words,7); }
    spx_observe_end(observer);
}
static void begin(void *s,unsigned op,const uint32_t *args,unsigned count) {
    REQUIRE((s==&progress || s==&game) && calls++<6000); spx_observe_object(observer,NULL); spx_observe_u64(observer,"operation",op);
    spx_observe_u32s(observer,"arguments",args,count); snapshot("before");
}
static uint32_t end(uint32_t result) { snapshot("after"); spx_observe_u64(observer,"result",result); spx_observe_end(observer); return result; }
#define BEGIN0(op) (void)unused; begin(s,op,NULL,0)
#define BEGIN(op,...) (void)unused; const uint32_t args[]={__VA_ARGS__}; begin(s,op,args,sizeof(args)/sizeof(*args))
static void dimensions(font_sprite *sprite,uint32_t width,uint32_t height) {
    for (unsigned i=0;i<4;++i) { sprite->retained[4+i]=(unsigned char)(width>>(8*i)); sprite->retained[8+i]=(unsigned char)(height>>(8*i)); }
}
#include "game-services.h"
#ifdef GAME_CONNECTED
#include "progress-consumer.h"
#endif
#include "game-native.h"
#ifdef GAME_CONNECTED
#include "connected-native.h"
#endif
static void setup(void) {
    title.back=&surfaces[0]; flow.primary=title.primary=&surfaces[1]; flow.overlay=&surfaces[2]; scene.flip=&surfaces[3]; font.destination=&surfaces[0];
    objects.banks[0].slots[68]=&sprites[0]; objects.banks[1].slots[68]=&sprites[1]; dimensions(&sprites[0],37,10); dimensions(&sprites[1],65,12);
    for (unsigned i=0;i<3;++i) { objects.banks[i].count=70+i; for (unsigned j=0;j<6;++j) objects.banks[i].retained[j]=400+i*7+j; }
    scene.mouse_x=320; flow.next_scene=2; menu.score=12345; pickups.next_life=999; pickups.lives=4; pickups.count=5;
    motion.ball_count=6; motion.paddle_width=75; play.shot_count=7; play.remaining_bricks=2; menu.input_ready=1;
    play.paddle_x=301; play.paddle_y=450; play.balls.retained=47; paddle.phase=9; paddle.last_tick=11; bricks.board_index=13;
    damage.capability=1; font.bank=2; scene.presentation_mode=scenario==1 || scenario==5;
    current_board.cells[1][2]=3; current_board.cells[2][3]=7; memset(play.pending_cells,7,400);
    for (unsigned i=0;i<256;++i) for (unsigned j=0;j<4;++j) { palettes.current[i][j]=(unsigned char)(i+j*23); palettes.staged[i][j]=(unsigned char)(3*i+j*71); }
    if (scenario==2 || scenario==11) title.back=flow.primary=title.primary=flow.overlay=scene.flip=&surfaces[0];
    if (scenario==6) damage.capability=0;
    if (scenario==7) damage.capability=UINT32_MAX;
    if (scenario==8) play.paused=1;
    if (scenario==9) play.paused=2;
    if (scenario==18) objects.current_bank=1;
    if (scenario==19) dimensions(&sprites[0],UINT32_C(0x80000001),10);
}
static void invoke(unsigned operation,uint32_t key) {
    snapshot(NULL);
#ifndef DX_STANDALONE
    game_to_native();
    if (operation==0) ((void (*)(void))0x404120)();
    else if (operation==1) ((void (*)(void))0x4043d0)();
    else ((void (*)(uint32_t))0x404ad0)(key);
    game_from_native();
#else
    if (operation==0) fixture_game_enter(&game);
    else if (operation==1) fixture_game_redraw(&game);
    else fixture_game_key(&game,key);
#endif
    snapshot(NULL);
}
#ifndef GAME_CONNECTED
static void exercise(void) {
    if (scenario<4) invoke(0,0);
    else if (scenario<12) invoke(1,0);
    else if (scenario==12 || scenario==13) {
        for (unsigned key=0;key<256;++key) { play.paused=0; progress.pending=0; menu.input_ready=scenario==13; invoke(2,key); }
    } else if (scenario==14) {
        const uint32_t keys[]={0,'P','p','q','t',0x80,UINT32_MAX,0x10050};
        for (unsigned i=0;i<sizeof(keys)/sizeof(*keys);++i) { play.paused=1; progress.pending=i%2; invoke(2,keys[i]); }
    } else if (scenario==15) { progress.pending=2; invoke(2,'P'); invoke(2,'t'); }
    else if (scenario==16) { invoke(2,'P'); play.paused=1; progress.pending=0; invoke(2,0); }
    else if (scenario==17) { play.paused=2; invoke(2,'P'); invoke(2,'q'); }
    else if (scenario==18 || scenario==19) { invoke(2,'s'); invoke(2,'p'); }
    else if (scenario==20 || scenario==21) {
        const uint32_t choices[]={0,1,2,3,4,5,6,UINT32_MAX};
        for (unsigned i=0;i<sizeof(choices)/sizeof(*choices);++i) { random_choice=choices[i]; invoke(2,'t'); }
    } else if (scenario==22) {
        const double values[]={1.0,-1.0,0.0,-0.0,1.5,-2.25,0x1p-1022,0x1.fffffffffffffp1023};
        for (unsigned i=0;i<sizeof(values)/sizeof(*values);++i) { game.stereo_direction=values[i]; invoke(2,'{'); invoke(2,'{'); }
    } else { invoke(0,0); invoke(1,0); invoke(2,'P'); invoke(2,'q'); invoke(2,'s'); }
}
#endif
static int run(int argc,char **argv) {
    REQUIRE(argc==3); scenario=(uint32_t)strtoul(argv[2],NULL,10); setup();
#ifdef GAME_CONNECTED
    REQUIRE(scenario>=24 && scenario<27);
#else
    REQUIRE(scenario<24);
#endif
#ifndef DX_STANDALONE
    install(!strcmp(argv[1],"source"));
#ifdef GAME_CONNECTED
    connected_install(!strcmp(argv[1],"source"));
#endif
#endif
    spx_observer output=spx_observe_begin(stdout); observer=&output; spx_observe_array(observer,"game_scene");
#ifdef GAME_CONNECTED
    invoke(0,0);
    if (scenario==25) { invoke(2,'P'); invoke(2,'t'); invoke(1,0); }
    if (scenario==26) {
        invoke(2,'s'); invoke(2,'q'); invoke(2,'r');
#ifndef DX_STANDALONE
        game_to_native(); ((void (*)(void))0x408a00)(); game_from_native();
#else
        fixture_progress_restart(&progress);
#endif
        snapshot(NULL);
    }
#else
    exercise();
#endif
    spx_observe_end(observer); REQUIRE(spx_observe_finish(observer)); fputc('\n',stdout); return 0;
}
#ifdef DX_STANDALONE
int main(int argc,char **argv) { return run(argc,argv); }
#else
__declspec(dllexport) void dx_game_anchor(void) {}
static void native_start(void) { int argc=0; char **argv=NULL; extern int __cdecl __getmainargs(int *,char ***,char ***,int,int *); char **env=NULL; int startup=0;
    __getmainargs(&argc,&argv,&env,0,&startup); ExitProcess((UINT)run(argc,argv)); }
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { (void)instance; (void)reserved;
    if (reason==DLL_PROCESS_ATTACH) REQUIRE(install_startup(native_start));
    return TRUE; }
#endif
