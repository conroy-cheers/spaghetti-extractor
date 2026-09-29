/* Local native powerup entries; no window, audio device or game startup. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "power-runtime.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
enum { NODES=64 };
static uint32_t scenario,entered[7],calls,allocations,cell_calls,free_calls,rebound_calls;
static font_surface surfaces[4]={{1},{2},{3},{4}};
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
static powerup_state powers={.motion=&motion};
static play_ball balls[NODES];
static play_event cells[NODES];
static uint32_t ball_live[NODES],cell_live[NODES];
static spx_observer *observer;
#ifdef POWER_CONNECTED
#include "pickup-runtime.h"
static pickup_state pickups={.motion=&motion};
static pickup frame_pickup;
static font_sprite frame_sprite;
static uint32_t frame_pickup_live,frame_entries;
#ifndef DX_STANDALONE
static void connected_to_native(void),connected_from_native(void);
static int connected_free(uint32_t address);
#endif
#endif
static void require(int test,const char *expression,unsigned line) {
    if (!test) { fprintf(stderr,"power-runtime.c:%u: adapter premise failed: %s\n",line,expression); exit(3); }
}
#define REQUIRE(test) require(!!(test),#test,__LINE__)
void power_enter(unsigned operation) { REQUIRE(operation<7); ++entered[operation]; }
#define ID(name,type,array,live) static uint32_t name##_id(const type *p) { \
    if (!p) return 0; \
    for (unsigned i=0;i<NODES;++i) if (p==&array[i]) { REQUIRE(live[i]); return i+1; } \
    REQUIRE(0); return 0; }
ID(ball,play_ball,balls,ball_live) ID(event,play_event,cells,cell_live)
#undef ID
static uint32_t surface_id(const font_surface *p) {
    if (!p) return 0;
    for (unsigned i=0;i<4;++i) if (p==&surfaces[i]) return i+1;
    REQUIRE(0); return 0;
}
static void snapshot(const char *name) {
    spx_observe_object(observer,name);
    uint32_t fields[]={motion.ball_count,motion.paddle_power,play.remaining_bricks,menu.score,
        surface_id(title.back),surface_id(flow.overlay),surface_id(font.destination),play.split_balls,play.power_balls};
    spx_observe_u32s(observer,"fields",fields,sizeof(fields)/sizeof(*fields));
    uint32_t roots[]={ball_id(play.balls.current),ball_id(play.balls.first),ball_id(play.balls.last),play.balls.retained,
        ball_id(powers.staged_balls.current),ball_id(powers.staged_balls.first),ball_id(powers.staged_balls.last),powers.staged_balls.retained,
        event_id(powers.queued_cells.current),event_id(powers.queued_cells.first),event_id(powers.queued_cells.last),powers.queued_cells.retained,
        event_id(play.events.current),event_id(play.events.first),event_id(play.events.last),play.events.retained};
    spx_observe_u32s(observer,"roots",roots,16); spx_observe_bytes(observer,"board",(unsigned char *)&current_board,400);
    spx_observe_array(observer,"balls");
    for (unsigned i=0;i<NODES;++i) if (ball_live[i]) {
        uint32_t row[16]={i+1}; memcpy(row+1,&balls[i],52); row[14]=ball_id(balls[i].next); row[15]=ball_id(balls[i].previous);
        spx_observe_u32s(observer,NULL,row,16);
    }
    spx_observe_end(observer); spx_observe_array(observer,"cells");
    for (unsigned i=0;i<NODES;++i) if (cell_live[i]) {
        uint32_t row[]={i+1,cells[i].kind,cells[i].column,cells[i].row,event_id(cells[i].next),event_id(cells[i].previous)};
        spx_observe_u32s(observer,NULL,row,6);
    }
    spx_observe_end(observer);
#ifdef POWER_CONNECTED
    uint32_t pickup_fields[]={frame_pickup_live,pickups.count,pickups.current==&frame_pickup,pickups.first==&frame_pickup,
        pickups.last==&frame_pickup,pickups.paddle_sprite,motion.paddle_width,play.paused};
    spx_observe_u32s(observer,"pickup_fields",pickup_fields,8);
    if (frame_pickup_live) spx_observe_u32s(observer,"pickup",(const uint32_t *)&frame_pickup,7);
#endif
    spx_observe_end(observer);
}
static void begin(powerup_state *s,unsigned op,const uint32_t *args,unsigned count) {
    REQUIRE(s==&powers && calls++<20000); spx_observe_object(observer,NULL); spx_observe_u64(observer,"operation",op);
    spx_observe_u32s(observer,"arguments",args,count); snapshot("before");
}
static uint32_t end(uint32_t result) { snapshot("after"); spx_observe_u64(observer,"result",result); spx_observe_end(observer); return result; }
#define BEGIN0(op) (void)unused; begin(s,op,NULL,0)
#define BEGIN(op,...) (void)unused; const uint32_t args[]={__VA_ARGS__}; begin(s,op,args,sizeof(args)/sizeof(*args))
static play_ball *new_ball(void) {
    for (unsigned i=0;i<NODES;++i) if (!ball_live[i]) {
        ball_live[i]=1; memset(&balls[i],0xa5,52); balls[i].next=balls[i].previous=NULL; return &balls[i];
    }
    REQUIRE(0); return NULL;
}
static play_event *new_cell(void) {
    for (unsigned i=0;i<NODES;++i) if (!cell_live[i]) {
        cell_live[i]=1; cells[i]=(play_event){.kind=0xa5a5a5a5,.column=0x77777777,.row=0x88888888}; return &cells[i];
    }
    REQUIRE(0); return NULL;
}
play_ball *power_allocate_ball(void *unused,powerup_state *s) {
    BEGIN0(POWER_ALLOCATE_BALL); ++allocations;
    if (scenario==4 && allocations==1) { play.balls.current=play.balls.last; play.balls.current->dx=0x80000000; }
    play_ball *ball=((scenario==6 && allocations==1)||(scenario==7 && allocations==2)) ? NULL : new_ball();
    (void)end(ball_id(ball)); return ball;
}
play_event *power_allocate_cell(void *unused,powerup_state *s) {
    BEGIN0(POWER_ALLOCATE_CELL); ++allocations;
    if (scenario==12 && allocations==1) current_board.cells[5][10]=8;
    play_event *cell=new_cell(); (void)end(event_id(cell)); return cell;
}
void power_free_ball(void *unused,powerup_state *s,play_ball *ball) {
    BEGIN(POWER_FREE_BALL,ball_id(ball)); ++free_calls; ball_live[ball_id(ball)-1]=0;
    if (scenario==5) motion.ball_count+=13;
    (void)end(0);
}
void power_free_cell(void *unused,powerup_state *s,play_event *cell) {
    BEGIN(POWER_FREE_CELL,event_id(cell)); ++free_calls; cell_live[event_id(cell)-1]=0;
    if (scenario==14) { powers.queued_cells.retained+=3; play.remaining_bricks+=7; }
    (void)end(0);
}
void power_terminate(void *unused,powerup_state *s,uint32_t status) { BEGIN(POWER_TERMINATE,status); REQUIRE(status==1); (void)end(0); }
void power_destination(void *unused,powerup_state *s,font_surface *surface) {
    BEGIN(POWER_DESTINATION,surface_id(surface)); font.destination=surface;
    if (scenario==17) { current_board.cells[1][2]=2; motion.paddle_power=13; }
    (void)end(0);
}
void power_cell(void *unused,powerup_state *s,uint32_t column,uint32_t row,uint32_t mode) {
    BEGIN(POWER_CELL,column,row,mode); ++cell_calls; REQUIRE(column<20 && row<20);
    if (scenario==13 && cell_calls==1) { powers.queued_cells.current=powers.queued_cells.last; powers.queued_cells.current->column=18; }
    if (scenario==16 && cell_calls<=2) current_board.cells[row][column]=cell_calls==1 ? 7 : 3;
    if (scenario==25 && cell_calls==1) current_board.cells[19][19]=12;
    (void)end(0);
}
uint32_t power_hit(void *unused,powerup_state *s,uint32_t column,uint32_t row) {
    BEGIN(POWER_HIT,column,row); REQUIRE(column<20 && row<20); current_board.cells[row][column]=0;
    if (scenario==19) { current_board.cells[2][4]=0; current_board.cells[1][19]=8; }
    return end((column+row)%2 ? 0 : 2);
}
void power_rebound(void *unused,powerup_state *s) {
    BEGIN0(POWER_REBOUND); ++rebound_calls; REQUIRE(play.balls.current);
    play.balls.current->dx=7; play.balls.current->dy=0xfffffffb;
    if (scenario==27 && rebound_calls==1) play.balls.current=play.balls.last;
    (void)end(0);
}
void power_stop_sound(void *unused,powerup_state *s,uint32_t sound) {
    BEGIN(POWER_STOP_SOUND,sound); if (scenario==29) current_board.cells[4][8]=7; (void)end(0);
}
void power_play_sound(void *unused,powerup_state *s,uint32_t sound,uint32_t repeat,uint32_t volume,uint32_t pan) {
    BEGIN(POWER_PLAY_SOUND,sound,repeat,volume,pan); (void)end(0);
}
void power_blit(void *unused,powerup_state *s,font_surface *destination,font_rect *a,font_surface *source,font_rect *b,uint32_t flags) {
    BEGIN(POWER_BLIT,surface_id(destination),a->left,a->top,a->right,a->bottom,surface_id(source),b->left,b->top,b->right,b->bottom,flags,a==b);
    if (scenario==24) { REQUIRE(a==b); a->left=23; a->bottom=351; title.back=&surfaces[3]; current_board.cells[10][3]=8; }
    (void)end(0);
}
void power_damage(void *unused,powerup_state *s,font_rect *bounds) {
    BEGIN(POWER_DAMAGE,bounds->left,bounds->top,bounds->right,bounds->bottom); (void)end(0);
}
#ifndef DX_STANDALONE
static uint32_t native_balls[NODES][15],native_cells[NODES][5],native_surfaces[4],vtable[8];
static uint32_t *word(uint32_t address) { return (uint32_t *)(uintptr_t)address; }
#define ADDRESS(name,type,array,live,native) \
    static uint32_t name##_address(type *p) { uint32_t id=name##_id(p); return id ? (uint32_t)(uintptr_t)native[id-1] : 0; } \
    static type *name##_view(uint32_t p) { if (!p) return NULL; \
        for (unsigned i=0;i<NODES;++i) if (p==(uint32_t)(uintptr_t)native[i]) { REQUIRE(live[i]); return &array[i]; } \
        REQUIRE(0); return NULL; }
ADDRESS(ball,play_ball,balls,ball_live,native_balls) ADDRESS(event,play_event,cells,cell_live,native_cells)
#undef ADDRESS
static uint32_t surface_address(font_surface *p) { uint32_t id=surface_id(p); return id ? (uint32_t)(uintptr_t)&native_surfaces[id-1] : 0; }
static font_surface *surface_view(uint32_t p) {
    if (!p) return NULL;
    for (unsigned i=0;i<4;++i) if (p==(uint32_t)(uintptr_t)&native_surfaces[i]) return &surfaces[i];
    REQUIRE(0); return NULL;
}
#define EMPTY(name,type) static uint32_t name##_address(type *p) { REQUIRE(!p); return 0; } \
    static type *name##_view(uint32_t p) { REQUIRE(!p); return NULL; }
EMPTY(shot,play_shot) EMPTY(effect,play_effect)
#undef EMPTY
static void play_objects_to_native(void) {
    for (unsigned i=0;i<NODES;++i) {
        if (ball_live[i]) { memcpy(native_balls[i],&balls[i],52); native_balls[i][13]=ball_address(balls[i].next); native_balls[i][14]=ball_address(balls[i].previous); }
        if (cell_live[i]) { memcpy(native_cells[i],&cells[i],12); native_cells[i][3]=event_address(cells[i].next); native_cells[i][4]=event_address(cells[i].previous); }
    }
}
static void play_objects_from_native(void) {
    for (unsigned i=0;i<NODES;++i) {
        if (ball_live[i]) { memcpy(&balls[i],native_balls[i],52); balls[i].next=ball_view(native_balls[i][13]); balls[i].previous=ball_view(native_balls[i][14]); }
        if (cell_live[i]) { memcpy(&cells[i],native_cells[i],12); cells[i].next=event_view(native_cells[i][3]); cells[i].previous=event_view(native_cells[i][4]); }
    }
}
static void play_parent_to_native(void) {
    *word(0x431cbc)=menu.score; *word(0x417a04)=scene.presentation_mode; *word(0x434990)=scene.mouse_buttons;
    *word(0x4349b4)=surface_address(title.back); *word(0x431fcc)=surface_address(flow.overlay); *word(0x434960)=surface_address(font.destination);
}
static void play_parent_from_native(void) {
    menu.score=*word(0x431cbc); scene.presentation_mode=*word(0x417a04); scene.mouse_buttons=*word(0x434990);
    title.back=surface_view(*word(0x4349b4)); flow.overlay=surface_view(*word(0x431fcc)); font.destination=surface_view(*word(0x434960));
}
#include "play-native.h"
#include "motion-native.h"
static void power_to_native(void) {
    motion_to_native();
#define LIST(name,address,singular) do { uint32_t *p=word(address); p[0]=singular##_address(powers.name.current); \
    p[1]=singular##_address(powers.name.first); p[2]=singular##_address(powers.name.last); p[3]=powers.name.retained; } while (0)
    LIST(staged_balls,0x431c98,ball); LIST(queued_cells,0x42ca40,event);
#undef LIST
#ifdef POWER_CONNECTED
    connected_to_native();
#endif
}
static void power_from_native(void) {
    motion_from_native();
#define LIST(name,address,singular) do { const uint32_t *p=word(address); powers.name.current=singular##_view(p[0]); \
    powers.name.first=singular##_view(p[1]); powers.name.last=singular##_view(p[2]); powers.name.retained=p[3]; } while (0)
    LIST(staged_balls,0x431c98,ball); LIST(queued_cells,0x42ca40,event);
#undef LIST
#ifdef POWER_CONNECTED
    connected_from_native();
#endif
}
static uint32_t native_allocate(uint32_t size) {
    power_from_native(); uint32_t address;
    if (size==60) address=ball_address(power_allocate_ball(NULL,&powers));
    else { REQUIRE(size==20); address=event_address(power_allocate_cell(NULL,&powers)); }
    power_to_native(); return address;
}
static void native_free(uint32_t address) {
    power_from_native(); unsigned i;
#ifdef POWER_CONNECTED
    if (connected_free(address)) { power_to_native(); return; }
#endif
    for (i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)native_balls[i]) break;
    if (i<NODES) power_free_ball(NULL,&powers,ball_view(address)); else power_free_cell(NULL,&powers,event_view(address));
    power_to_native();
}
static void native_terminate(uint32_t status) { power_from_native(); power_terminate(NULL,&powers,status); power_to_native(); }
static void native_destination(uint32_t surface) { power_from_native(); power_destination(NULL,&powers,surface_view(surface)); power_to_native(); }
static void native_cell(uint32_t column,uint32_t row,uint32_t mode) { power_from_native(); power_cell(NULL,&powers,column,row,mode); power_to_native(); }
static uint32_t native_hit(uint32_t column,uint32_t row) { power_from_native(); uint32_t result=power_hit(NULL,&powers,column,row); power_to_native(); return result; }
static void native_rebound(void) { power_from_native(); power_rebound(NULL,&powers); power_to_native(); }
static void native_stop_sound(uint32_t sound) { power_from_native(); power_stop_sound(NULL,&powers,sound); power_to_native(); }
static void native_play_sound(uint32_t a,uint32_t b,uint32_t c,uint32_t d) { power_from_native(); power_play_sound(NULL,&powers,a,b,c,d); power_to_native(); }
static uint32_t WINAPI native_blit(uint32_t destination,font_rect *a,uint32_t source,font_rect *b,uint32_t flags,void *effects) {
    REQUIRE(!effects); power_from_native(); power_blit(NULL,&powers,surface_view(destination),a,surface_view(source),b,flags); power_to_native(); return 0x88760001;
}
static void native_damage(font_rect bounds) { power_from_native(); power_damage(NULL,&powers,&bounds); power_to_native(); }
#define ENTRY(name) static void native_power_##name(void) { power_from_native(); fixture_power_##name(&powers); power_to_native(); }
ENTRY(split) ENTRY(expand) ENTRY(soften) ENTRY(detonate) ENTRY(super) ENTRY(drop) ENTRY(release)
#undef ENTRY
static void install(int source) {
    vtable[5]=(uint32_t)(uintptr_t)native_blit;
    for (unsigned i=0;i<4;++i) native_surfaces[i]=(uint32_t)(uintptr_t)vtable;
#define HOOK(name) REQUIRE(install_power_service_##name((void (*)(void))native_##name));
    HOOK(allocate) HOOK(free) HOOK(terminate) HOOK(destination) HOOK(cell) HOOK(hit) HOOK(rebound) HOOK(stop_sound) HOOK(play_sound) HOOK(damage)
#undef HOOK
    if (source) {
#define ENTRY(name) REQUIRE(install_power_##name(native_power_##name));
        ENTRY(split) ENTRY(expand) ENTRY(soften) ENTRY(detonate) ENTRY(super) ENTRY(drop) ENTRY(release)
#undef ENTRY
    }
}
#endif
static void list_balls(unsigned count) {
    for (unsigned i=0;i<count;++i) {
        play_ball *ball=new_ball(); *ball=(play_ball){.x=100+i*30,.y=200,.old_x=99+i*30,.old_y=199,
            .dx=3+i,.dy=0xfffffffc,.sprite=1+i,.angle=45,.speed=5,.retained=71+i,.auxiliary=90+i,.tick=333+i};
        ball->previous=play.balls.last;
        if (play.balls.last) play.balls.last->next=ball; else play.balls.first=ball;
        play.balls.last=ball;
    }
    play.balls.current=play.balls.first; motion.ball_count=count;
}
static void setup(void) {
    title.back=&surfaces[0]; flow.overlay=&surfaces[1]; font.destination=&surfaces[2];
    motion.paddle_power=1; play.remaining_bricks=20; play.balls.retained=17;
    powers.staged_balls.retained=29; powers.queued_cells.retained=31; play.events.retained=53;
    menu.score=0xfffffffe;
    for (unsigned i=0;i<361;++i) { sine[i]=(int32_t)(i%17)*10; cosine[i]=(int32_t)(i%13)*11; }
    if (scenario>=1 && scenario<=7) {
        list_balls(scenario==2 ? 6 : scenario==4 ? 2 : 1);
        if (scenario==2) {
            const uint32_t speeds[]={5,4,0,0x80000000,0xffffffff,9};
            for (unsigned i=0;i<6;++i) { balls[i].attached=i==5 ? 2 : 1; balls[i].speed=speeds[i]; }
        }
        if (scenario==3 || scenario==6) { play_ball *p=new_ball(); *p=balls[0]; p->next=p->previous=NULL; p->dx=99; powers.staged_balls=(play_balls){p,p,p,29}; }
    }
    if (scenario>=9 && scenario<=14) {
        current_board.cells[5][5]=8; current_board.cells[5][4]=2; current_board.cells[4][5]=7; current_board.cells[5][6]=21;
        if (scenario==10) { current_board.cells[0][0]=8; current_board.cells[19][19]=8; }
        if (scenario==13 || scenario==14) current_board.cells[10][10]=8;
        if (scenario==11) { play_event *p=new_cell(); p->column=1; p->row=1; powers.queued_cells=(play_events){p,p,p,31}; }
    }
    if (scenario==15) for (unsigned i=0;i<24;++i) current_board.cells[i%20][i/20]=(unsigned char)i;
    if (scenario==16) current_board.cells[0][0]=2;
    if (scenario==18 || scenario==19) { current_board.cells[1][1]=8; current_board.cells[2][4]=8; current_board.cells[8][5]=8; }
    if (scenario==20 || scenario==26 || scenario==27) { list_balls(3); balls[0].attached=balls[2].attached=1; balls[1].attached=2; }
    if (scenario==22 || scenario==24 || scenario==25) { current_board.cells[0][0]=3; current_board.cells[17][0]=4; current_board.cells[18][0]=5; current_board.cells[19][1]=6; }
    if (scenario==23) for (unsigned i=0;i<20;++i) current_board.cells[19][i]=(unsigned char)(1+i);
    if (scenario==28) { list_balls(3); balls[0].attached=1; current_board.cells[3][3]=8; current_board.cells[5][9]=2; current_board.cells[17][12]=7; }
}
static void invoke(unsigned operation) {
#ifndef DX_STANDALONE
    const uint32_t address[]={0x407eb0,0x408260,0x4084b0,0x408540,0x408580,0x4085d0,0x4086e0};
    REQUIRE(operation<7); ((void (*)(void))(uintptr_t)address[operation])(); power_from_native();
#else
    void (*operations[])(powerup_state *)={fixture_power_split,fixture_power_expand,fixture_power_soften,fixture_power_detonate,fixture_power_super,fixture_power_drop,fixture_power_release};
    REQUIRE(operation<7); operations[operation](&powers);
#endif
    snapshot(NULL);
}
#ifdef POWER_CONNECTED
#include "frame-power.h"
#endif
static int run(int argc,char **argv) {
    REQUIRE(argc==3); scenario=(uint32_t)strtoul(argv[2],NULL,10); REQUIRE(scenario<37); setup();
#ifdef POWER_CONNECTED
    if (scenario>=30) frame_setup();
#else
    REQUIRE(scenario<30);
#endif
#ifndef DX_STANDALONE
    install(!strcmp(argv[1],"source")); power_to_native();
#ifdef POWER_CONNECTED
    frame_install(!strcmp(argv[1],"source"));
#endif
#endif
    spx_observer output=spx_observe_begin(stdout); observer=&output; spx_observe_array(observer,"powerups"); snapshot(NULL);
#ifdef POWER_CONNECTED
    if (scenario>=30) frame_run(); else
#endif
    if (scenario==0 || scenario==28) for (unsigned i=0;i<7;++i) invoke(i);
    else invoke(scenario<=7 ? 0 : scenario<=14 ? 1 : scenario<=17 ? 2 : scenario<=19 ? 3 : scenario==20 ? 4 : scenario<=25 || scenario==29 ? 5 : 6);
    spx_observe_end(observer); REQUIRE(spx_observe_finish(observer)); fputc('\n',stdout); return 0;
}
#ifdef DX_STANDALONE
int main(int argc,char **argv) { return run(argc,argv); }
#else
__declspec(dllexport) void dx_power_anchor(void) {}
static void native_start(void) { int argc=0; char **argv=NULL; extern int __cdecl __getmainargs(int *,char ***,char ***,int,int *); char **env=NULL; int startup=0;
    __getmainargs(&argc,&argv,&env,0,&startup); ExitProcess((UINT)run(argc,argv)); }
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { (void)instance; (void)reserved;
    if (reason==DLL_PROCESS_ATTACH) REQUIRE(install_startup(native_start));
    return TRUE; }
#endif
