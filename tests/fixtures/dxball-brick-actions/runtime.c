/* Local native brick lifecycles, without application startup or DirectDraw. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include "brick-runtime.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#include "comparison-services.h"
#endif
enum { NODES=32,BALLS=2,EXTERNAL_ADDRESS=0x20000000,FAULT_ADDRESS=0x21000000,
    WRAP_COLUMN=143165577,WRAP_PAGE=0x08cb5000 };
struct play_effect { uint32_t id; };
static font_surface surfaces[4]={{1},{2},{3},{4}};
static play_effect identities[NODES];
static brick_effect effects[NODES];
static play_event events[NODES];
static play_ball balls[BALLS];
static uint32_t effect_live[NODES],event_live[NODES],ball_live[BALLS];
static uint32_t scenario,entered[8],calls,seed,callback_done;
static struct spx_opaque_cleanup_state_v5 objects;
static font_state font={.objects=&objects};
static flow_state flow;
static title_state title={.font=&font,.flow=&flow};
static scene_state scene={.animation=&title};
static menu_state menu={.scene=&scene};
static int32_t sine[361],cosine[361];
static play_state play={.menu=&menu,.sine=sine,.cosine=cosine};
static board current_board;
static board saved_boards[50];
static unsigned char external_byte;
static unsigned char wrapped_memory[4096];
static jmp_buf memory_landing;
static uint32_t memory_fault_address,memory_landing_active;
static int source_side;
static motion_state motion={.play=&play,.board=&current_board};
static brick_state bricks={.motion=&motion};
static spx_observer *observer;
#ifdef BRICK_CONNECTED
static font_sprite connected_sprites[3];
#endif
static void require(int condition,const char *expression,unsigned line) {
    if (!condition) { fprintf(stderr,"brick-runtime.c:%u: adapter premise failed: %s\n",line,expression); exit(3); }
}
#define REQUIRE(test) require(!!(test),#test,__LINE__)
void brick_enter(unsigned operation) { REQUIRE(operation<8); ++entered[operation]; }
#define ID(name,type,array,count) static uint32_t name##_id(const type *p) { \
    if (!p) return 0; \
    for (unsigned i=0;i<count;++i) if (p==&array[i]) return i+1; \
    REQUIRE(0); return 0; }
ID(brick,brick_effect,effects,NODES) ID(event,play_event,events,NODES)
ID(ball,play_ball,balls,BALLS) ID(surface,font_surface,surfaces,4)
#undef ID
static void publish_effects(void) {
    uint32_t current=brick_id(bricks.current),first=brick_id(bricks.first);
    play.brick_effects.current=current ? &identities[current-1] : NULL;
    play.brick_effects.first=first ? &identities[first-1] : NULL;
}
static void import_effects(void) {
    bricks.current=play.brick_effects.current ? &effects[play.brick_effects.current->id-1] : NULL;
    bricks.first=play.brick_effects.first ? &effects[play.brick_effects.first->id-1] : NULL;
}
/* Full byte contents, with omitted zeroes defined by the observed extent. */
static void sparse_bytes(const char *name,const unsigned char *bytes,size_t size) {
    spx_observe_object(observer,name);spx_observe_u64(observer,"extent",size);
    spx_observe_array(observer,"nonzero");
    for (size_t i=0;i<size;++i) if (bytes[i]) {
        uint32_t pair[]={(uint32_t)i,bytes[i]};spx_observe_u32s(observer,NULL,pair,2);
    }
    spx_observe_end(observer);spx_observe_end(observer);
}
static void snapshot(const char *name) {
    spx_observe_object(observer,name);
    uint32_t fields[]={play.remaining_bricks,play.voice_pending,menu.score,title.fast,motion.pierce,
        motion.impact_dx,motion.impact_dy,bricks.board_index,surface_id(font.destination),
        surface_id(title.primary),surface_id(title.back),surface_id(flow.overlay)};
    spx_observe_u32s(observer,"fields",fields,sizeof(fields)/sizeof(*fields));
    uint32_t roots[]={brick_id(bricks.current),brick_id(bricks.first),brick_id(bricks.last),
        event_id(play.events.current),event_id(play.events.first),event_id(play.events.last),play.events.retained};
    spx_observe_u32s(observer,"roots",roots,7); spx_observe_array(observer,"effects");
    for (unsigned i=0;i<NODES;++i) {
        uint32_t words[11]={effect_live[i]};
        if (effect_live[i]) { memcpy(words+1,&effects[i],32); words[9]=brick_id(effects[i].next); words[10]=brick_id(effects[i].previous); }
        spx_observe_u32s(observer,NULL,words,11);
    }
    spx_observe_end(observer); spx_observe_array(observer,"events");
    for (unsigned i=0;i<NODES;++i) {
        uint32_t words[6]={event_live[i]};
        if (event_live[i]) { memcpy(words+1,&events[i],12); words[4]=event_id(events[i].next); words[5]=event_id(events[i].previous); }
        spx_observe_u32s(observer,NULL,words,6);
    }
    spx_observe_end(observer); spx_observe_array(observer,"balls");
    for (unsigned i=0;i<BALLS;++i) {
        uint32_t words[16]={ball_live[i]};
        if (ball_live[i]) { memcpy(words+1,&balls[i],52); words[14]=ball_id(balls[i].next); words[15]=ball_id(balls[i].previous); }
        spx_observe_u32s(observer,NULL,words,16);
    }
    spx_observe_end(observer); spx_observe_bytes(observer,"board",(const unsigned char *)&current_board,400);
    spx_observe_bytes(observer,"pending",play.pending_cells,400);
    if (scenario>=25) {
        if (scenario<33) spx_observe_bytes(observer,"saved_boards",(const unsigned char *)saved_boards,sizeof(saved_boards));
        else sparse_bytes("saved_boards",(const unsigned char *)saved_boards,sizeof(saved_boards));
        if (scenario==36) sparse_bytes("wrapped_memory",wrapped_memory,sizeof(wrapped_memory));
        uint32_t memory[]={external_byte,memory_fault_address};spx_observe_u32s(observer,"memory",memory,2);
    }
    spx_observe_end(observer);
}
static void begin(brick_state *s,unsigned operation,const uint32_t *args,unsigned count) {
    publish_effects();
    REQUIRE(s==&bricks && calls++<10000); spx_observe_object(observer,NULL);
    spx_observe_u64(observer,"operation",operation); spx_observe_u32s(observer,"arguments",args,count); snapshot("before");
}
static uint32_t end(uint32_t result) {
    publish_effects(); snapshot("after"); spx_observe_u64(observer,"result",result); spx_observe_end(observer); return result;
}
#define BEGIN0(operation) (void)unused; begin(s,operation,NULL,0)
#define BEGIN(operation,...) (void)unused; const uint32_t args[]={__VA_ARGS__}; begin(s,operation,args,sizeof(args)/sizeof(*args))
/* This is an address-space adapter, with live aliases to the state
 * owners. A missing mapping is a fixture error, not evidence of a native fault.
 * Only the explicitly inaccessible region supplies the memory-fault outcome. */
static unsigned char *brick_byte(uint32_t base,uint32_t column,uint32_t row) {
    uint32_t address=base+row*20+column;
    if (address>=0x42ca60 && address-0x42ca60<sizeof(current_board))
        return (unsigned char *)&current_board+(address-0x42ca60);
    if (address>=0x42cc10 && address-0x42cc10<sizeof(play.pending_cells))
        return play.pending_cells+(address-0x42cc10);
    if (address>=0x42cdf8 && address-0x42cdf8<sizeof(saved_boards))
        return (unsigned char *)saved_boards+(address-0x42cdf8);
    if (scenario==36 && address>=WRAP_PAGE && address-WRAP_PAGE<sizeof(wrapped_memory))
        return wrapped_memory+(address-WRAP_PAGE);
    if (scenario==30 && address==EXTERNAL_ADDRESS) return &external_byte;
    if (scenario==31 && address==FAULT_ADDRESS) {
        REQUIRE(memory_landing_active);memory_fault_address=address;longjmp(memory_landing,1);
    }
    fprintf(stderr,"unmapped local byte address %08x\n",address);REQUIRE(0);return NULL;
}
uint32_t brick_read_cell(void *unused,brick_state *s,uint32_t column,uint32_t row) {
    (void)unused;REQUIRE(s==&bricks);return *brick_byte(0x42ca60,column,row);
}
void brick_write_cell(void *unused,brick_state *s,uint32_t column,uint32_t row,uint32_t value) {
    (void)unused;REQUIRE(s==&bricks);*brick_byte(0x42ca60,column,row)=(unsigned char)value;
}
void brick_write_pending(void *unused,brick_state *s,uint32_t column,uint32_t row,uint32_t value) {
    (void)unused;REQUIRE(s==&bricks);*brick_byte(0x42cc10,column,row)=(unsigned char)value;
}
brick_effect *brick_allocate_effect(void *unused,brick_state *s) {
    BEGIN0(BRICK_ALLOCATE_EFFECT);
    for (unsigned i=0;i<NODES;++i) if (!effect_live[i]) {
        effect_live[i]=1; memset(&effects[i],0,sizeof(effects[i])); memset(&effects[i],0xa5,32);
        if (scenario==5 && !callback_done++) { bricks.last=&effects[0]; effects[0].next=NULL; motion.pierce=1; }
        (void)end(i+1); return &effects[i];
    }
    REQUIRE(0); return NULL;
}
play_event *brick_allocate_event(void *unused,brick_state *s) {
    BEGIN0(BRICK_ALLOCATE_EVENT);
    if (scenario==37 && bricks.current && bricks.current->frames==5 && !callback_done++)
        *brick_byte(0x42ca60,0,84)=2;
    for (unsigned i=0;i<NODES;++i) if (!event_live[i]) {
        event_live[i]=1; memset(&events[i],0,sizeof(events[i])); events[i].kind=0x12345678;
        (void)end(i+1); return &events[i];
    }
    REQUIRE(0); return NULL;
}
void brick_free_effect(void *unused,brick_state *s,brick_effect *effect) {
    uint32_t id=brick_id(effect); BEGIN(BRICK_FREE_EFFECT,id); REQUIRE(id && effect_live[id-1]); effect_live[id-1]=0;
    if (scenario==18) { bricks.current=&effects[2]; play.remaining_bricks+=5; }
    (void)end(0);
}
void brick_select_board(void *unused,brick_state *s,uint32_t index) {
    BEGIN(BRICK_SELECT_BOARD,index); memset(&current_board,(unsigned char)(index+3),400); (void)end(0);
}
uint32_t brick_pan(void *unused,brick_state *s,uint32_t x) {
    BEGIN(BRICK_PAN,x);
    if (scenario==4 && !callback_done++) { current_board.cells[5][6]=7; title.fast=1; }
    return end(x^0x6157);
}
uint32_t brick_random(void *unused,brick_state *s,uint32_t limit) {
    BEGIN(BRICK_RANDOM,limit); REQUIRE(limit); seed=seed*1664525+1013904223; return end(seed%limit);
}
void brick_stop_sound(void *unused,brick_state *s,uint32_t sound) {
    BEGIN(BRICK_STOP_SOUND,sound);
    if (scenario==6 && !callback_done++) { motion.pierce=1; play.remaining_bricks=0; title.fast=1; }
    (void)end(0);
}
void brick_play_sound(void *unused,brick_state *s,uint32_t sound,uint32_t repeat,uint32_t volume,uint32_t pan) {
    BEGIN(BRICK_PLAY_SOUND,sound,repeat,volume,pan); (void)end(0);
}
void brick_particle(void *unused,brick_state *s,uint32_t x,uint32_t y,uint32_t dx,uint32_t dy,uint32_t color,uint32_t gravity) {
    BEGIN(BRICK_PARTICLE,x,y,dx,dy,color,gravity); (void)end(0);
}
void brick_debris(void *unused,brick_state *s,uint32_t column,uint32_t row,uint32_t dx,uint32_t dy) {
    BEGIN(BRICK_DEBRIS,column,row,dx,dy); (void)end(0);
}
void brick_destination(void *unused,brick_state *s,font_surface *surface) {
    BEGIN(BRICK_DESTINATION,surface_id(surface)); font.destination=surface;
    if (scenario==7 && !callback_done++) { current_board.cells[5][6]=21; title.back=&surfaces[3]; }
    (void)end(0);
}
void brick_cell(void *unused,brick_state *s,uint32_t column,uint32_t row,uint32_t mode) {
    BEGIN(BRICK_CELL,column,row,mode); REQUIRE(column<20 && row<20);
    if (scenario==16 && !callback_done++) { bricks.current=&effects[1]; effects[1].sprite=27; }
    (void)end(0);
}
#define SPRITE(name,operation) \
void brick_##name(void *unused,brick_state *s,uint32_t slot,uint32_t x,uint32_t y) { BEGIN(operation,slot,x,y); (void)end(0); }
SPRITE(sprite_fast,BRICK_SPRITE_FAST) SPRITE(sprite_opaque,BRICK_SPRITE_OPAQUE) SPRITE(sprite_transparent,BRICK_SPRITE_TRANSPARENT)
#undef SPRITE
void brick_erase(void *unused,brick_state *s,font_rect *rectangle) {
    BEGIN(BRICK_ERASE,rectangle->left,rectangle->top,rectangle->right,rectangle->bottom);
    if (scenario==38 && !callback_done++) bricks.current->x=50;
    (void)end(0);
}
void brick_blit_fast(void *unused,brick_state *s,font_surface *destination,uint32_t x,uint32_t y,font_surface *source,font_rect *rectangle,uint32_t flags) {
    BEGIN(BRICK_BLIT_FAST,surface_id(destination),x,y,surface_id(source),rectangle->left,rectangle->top,rectangle->right,rectangle->bottom,flags);
    if (scenario==12) { rectangle->right-=2; rectangle->bottom-=1; }
    (void)end(0);
}

#ifndef DX_STANDALONE
static uint32_t native_effects[NODES][10],native_events[NODES][5],native_balls[BALLS][15];
static uint32_t native_surfaces[4][2],surface_vtable[16];
#ifdef BRICK_CONNECTED
static uint32_t native_sprites[3][12];
static uint32_t connected_allocate(uint32_t bytes);
static void connected_free(uint32_t address);
#endif
#define ADDRESS(name,type,array) static uint32_t name##_address(type *p) { uint32_t id=name##_id(p); return id ? (uint32_t)(uintptr_t)&array[id-1] : 0; }
ADDRESS(brick,brick_effect,native_effects) ADDRESS(event,play_event,native_events) ADDRESS(ball,play_ball,native_balls) ADDRESS(surface,font_surface,native_surfaces)
#undef ADDRESS
#define VIEW(name,type,array,views,count,live) static type *name##_view(uint32_t address) { \
    if (!address) return NULL; \
    for (unsigned i=0;i<count;++i) if (address==(uint32_t)(uintptr_t)&array[i]) { REQUIRE(live); return &views[i]; } \
    REQUIRE(0); return NULL; }
VIEW(brick,brick_effect,native_effects,effects,NODES,effect_live[i]) VIEW(event,play_event,native_events,events,NODES,event_live[i])
VIEW(ball,play_ball,native_balls,balls,BALLS,ball_live[i]) VIEW(surface,font_surface,native_surfaces,surfaces,4,1)
#undef VIEW
static uint32_t shot_address(play_shot *p) { REQUIRE(!p); return 0; }
static play_shot *shot_view(uint32_t p) { REQUIRE(!p); return NULL; }
static uint32_t effect_address(play_effect *p) { return p ? brick_address(&effects[p->id-1]) : 0; }
static play_effect *effect_view(uint32_t p) { brick_effect *e=brick_view(p); return e ? &identities[brick_id(e)-1] : NULL; }
static void play_parent_to_native(void) {
    *(uint32_t *)0x431cbc=menu.score; *(uint32_t *)0x417a04=scene.presentation_mode; *(uint32_t *)0x434990=scene.mouse_buttons;
    *(uint32_t *)0x4349c8=title.fast; *(uint32_t *)0x434968=objects.current_bank;
    *(uint32_t *)0x4349b4=surface_address(title.back); *(uint32_t *)0x41c728=surface_address(title.primary);
    *(uint32_t *)0x431fcc=surface_address(flow.overlay); *(uint32_t *)0x434960=surface_address(font.destination);
#ifdef BRICK_CONNECTED
    const uint32_t slots[]={1,55,61};
    for (unsigned i=0;i<3;++i) {
        * (uint32_t *)(uintptr_t)(0x433d18+4*slots[i])=(uint32_t)(uintptr_t)&native_sprites[i];
        memcpy((unsigned char *)native_sprites[i]+4,connected_sprites[i].retained,41);
    }
#endif
}
static void play_parent_from_native(void) {
    menu.score=*(uint32_t *)0x431cbc; scene.presentation_mode=*(uint32_t *)0x417a04; scene.mouse_buttons=*(uint32_t *)0x434990;
    title.fast=*(uint32_t *)0x4349c8; objects.current_bank=*(uint32_t *)0x434968;
    title.back=surface_view(*(uint32_t *)0x4349b4); title.primary=surface_view(*(uint32_t *)0x41c728);
    flow.overlay=surface_view(*(uint32_t *)0x431fcc); font.destination=surface_view(*(uint32_t *)0x434960);
}
static void play_objects_to_native(void) {
    for (unsigned i=0;i<NODES;++i) if (event_live[i]) {
        memcpy(native_events[i],&events[i],12); native_events[i][3]=event_address(events[i].next); native_events[i][4]=event_address(events[i].previous);
    }
    for (unsigned i=0;i<BALLS;++i) if (ball_live[i]) {
        memcpy(native_balls[i],&balls[i],52); native_balls[i][13]=ball_address(balls[i].next); native_balls[i][14]=ball_address(balls[i].previous);
    }
}
static void play_objects_from_native(void) {
    for (unsigned i=0;i<NODES;++i) if (event_live[i]) {
        memcpy(&events[i],native_events[i],12); events[i].next=event_view(native_events[i][3]); events[i].previous=event_view(native_events[i][4]);
    }
    for (unsigned i=0;i<BALLS;++i) if (ball_live[i]) {
        memcpy(&balls[i],native_balls[i],52); balls[i].next=ball_view(native_balls[i][13]); balls[i].previous=ball_view(native_balls[i][14]);
    }
}
#include "play-native.h"
#include "motion-native.h"
static void brick_to_native(void) {
    publish_effects(); motion_to_native();
    *play_word(0x42cbf8)=brick_address(bricks.current); *play_word(0x42cbfc)=brick_address(bricks.first); *play_word(0x42cc00)=brick_address(bricks.last);
    *play_word(0x42ca54)=bricks.board_index;
    if (scenario>=25) memcpy((void *)0x42cdf8,saved_boards,sizeof(saved_boards));
    if (scenario==36) memcpy((void *)WRAP_PAGE,wrapped_memory,sizeof(wrapped_memory));
    for (unsigned i=0;i<NODES;++i) if (effect_live[i]) {
        memcpy(native_effects[i],&effects[i],32); native_effects[i][8]=brick_address(effects[i].next); native_effects[i][9]=brick_address(effects[i].previous);
    }
}
static void brick_from_native(void) {
    motion_from_native();
    bricks.current=brick_view(*play_word(0x42cbf8)); bricks.first=brick_view(*play_word(0x42cbfc)); bricks.last=brick_view(*play_word(0x42cc00));
    bricks.board_index=*play_word(0x42ca54);
    if (scenario>=25) memcpy(saved_boards,(void *)0x42cdf8,sizeof(saved_boards));
    if (scenario==36) memcpy(wrapped_memory,(void *)WRAP_PAGE,sizeof(wrapped_memory));
    for (unsigned i=0;i<NODES;++i) if (effect_live[i]) {
        memcpy(&effects[i],native_effects[i],32); effects[i].next=brick_view(native_effects[i][8]); effects[i].previous=brick_view(native_effects[i][9]);
    }
}
static uint32_t native_allocate(uint32_t bytes) {
    brick_from_native(); uint32_t result;
#ifdef BRICK_CONNECTED
    if (bytes==60) { result=connected_allocate(bytes); brick_to_native(); return result; }
#endif
    if (bytes==40) result=brick_address(brick_allocate_effect(NULL,&bricks));
    else { REQUIRE(bytes==20); result=event_address(brick_allocate_event(NULL,&bricks)); }
    brick_to_native(); return result;
}
static void native_free(uint32_t address) {
    brick_from_native();
#ifdef BRICK_CONNECTED
    connected_free(address);
#else
    brick_free_effect(NULL,&bricks,brick_view(address));
#endif
    brick_to_native();
}
static uint32_t native_pan(uint32_t x) { brick_from_native(); uint32_t result=brick_pan(NULL,&bricks,x); brick_to_native(); return result; }
static uint32_t native_random(uint32_t limit) { brick_from_native(); uint32_t result=brick_random(NULL,&bricks,limit); brick_to_native(); return result; }
static void native_destination(uint32_t surface) { brick_from_native(); brick_destination(NULL,&bricks,surface_view(surface)); brick_to_native(); }
static void native_erase(font_rect rectangle) { brick_from_native(); brick_erase(NULL,&bricks,&rectangle); brick_to_native(); }
static uint32_t WINAPI native_blit_fast(uint32_t destination,uint32_t x,uint32_t y,uint32_t source,font_rect *rectangle,uint32_t flags) {
    brick_from_native(); brick_blit_fast(NULL,&bricks,surface_view(destination),x,y,surface_view(source),rectangle,flags); brick_to_native(); return 0x88760001;
}
#define SERVICE(name,params,...) static void native_##name params { brick_from_native(); brick_##name(NULL,&bricks,__VA_ARGS__); brick_to_native(); }
SERVICE(select_board,(uint32_t index),index) SERVICE(stop_sound,(uint32_t sound),sound)
SERVICE(play_sound,(uint32_t a,uint32_t b,uint32_t c,uint32_t d),a,b,c,d)
SERVICE(particle,(uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f),a,b,c,d,e,f)
SERVICE(debris,(uint32_t a,uint32_t b,uint32_t c,uint32_t d),a,b,c,d)
SERVICE(cell,(uint32_t a,uint32_t b,uint32_t c),a,b,c)
SERVICE(sprite_fast,(uint32_t a,uint32_t b,uint32_t c),a,b,c)
SERVICE(sprite_opaque,(uint32_t a,uint32_t b,uint32_t c),a,b,c)
SERVICE(sprite_transparent,(uint32_t a,uint32_t b,uint32_t c),a,b,c)
#undef SERVICE
#define ROOT0(name) static void native_root_##name(void) { brick_from_native(); fixture_brick_##name(&bricks); brick_to_native(); }
ROOT0(reset) ROOT0(advance) ROOT0(step_blast) ROOT0(step_flash)
#undef ROOT0
#define ROOT2(name) static void native_root_##name(uint32_t column,uint32_t row) { brick_from_native(); fixture_brick_##name(&bricks,column,row); brick_to_native(); }
ROOT2(blast) ROOT2(queue)
#undef ROOT2
static uint32_t native_root_hit(uint32_t column,uint32_t row) { brick_from_native(); uint32_t result=fixture_brick_hit(&bricks,column,row); brick_to_native(); return result; }
static void native_root_flash(uint32_t column,uint32_t row,uint32_t tile,uint32_t transient) {
    brick_from_native(); fixture_brick_flash(&bricks,column,row,tile,transient); brick_to_native();
}
static void install(int source) {
    surface_vtable[7]=(uint32_t)(uintptr_t)native_blit_fast;
    for (unsigned i=0;i<4;++i) native_surfaces[i][0]=(uint32_t)(uintptr_t)surface_vtable;
#define HOOK(name) REQUIRE(install_brick_service_##name((void (*)(void))native_##name));
    HOOK(allocate) HOOK(free) HOOK(select_board) HOOK(pan) HOOK(stop_sound) HOOK(play_sound) HOOK(random)
    HOOK(particle) HOOK(debris) HOOK(destination) HOOK(cell) HOOK(sprite_fast) HOOK(sprite_opaque) HOOK(sprite_transparent) HOOK(erase)
#undef HOOK
    if (!source) return;
#define ROOT(name) REQUIRE(install_brick_##name((void (*)(void))native_root_##name));
    ROOT(reset) ROOT(hit) ROOT(advance) ROOT(blast) ROOT(step_blast) ROOT(queue) ROOT(flash) ROOT(step_flash)
#undef ROOT
}
#endif

static void setup(void) {
    memset(effects,0,sizeof(effects)); memset(events,0,sizeof(events)); memset(balls,0,sizeof(balls));
    memset(effect_live,0,sizeof(effect_live)); memset(event_live,0,sizeof(event_live)); memset(ball_live,0,sizeof(ball_live));
    for (unsigned i=0;i<NODES;++i) identities[i].id=i+1;
    memset(&current_board,0,sizeof(current_board));
    memset(saved_boards,0,sizeof(saved_boards));external_byte=0;memory_fault_address=memory_landing_active=0;
    memset(wrapped_memory,0,sizeof(wrapped_memory));
    play=(play_state){.menu=&menu,.sine=sine,.cosine=cosine,.remaining_bricks=19};
    motion=(motion_state){.play=&play,.board=&current_board,.impact_dx=0xfffffffc,.impact_dy=3};
    bricks=(brick_state){.motion=&motion,.board_index=3}; seed=0x752159ad; callback_done=0;
    title.primary=&surfaces[0]; title.back=&surfaces[1]; flow.overlay=&surfaces[2]; font.destination=&surfaces[3];
    title.fast=0; menu.score=17;
}
static void existing_effects(unsigned count,uint32_t kind) {
    for (unsigned i=0;i<count;++i) {
        effects[i]=(brick_effect){.kind=kind,.sprite=20,.x=6+i,.y=5,.tile=3,.retained={0x21,0x43,0x65},.frames=3,.delay=2,.tick=2};
        effects[i].previous=i ? &effects[i-1] : NULL; effects[i].next=i+1<count ? &effects[i+1] : NULL; effect_live[i]=1;
    }
    bricks.current=bricks.first=&effects[0]; bricks.last=&effects[count-1]; publish_effects();
}
#ifndef DX_STANDALONE
#define SYNC() brick_to_native()
#define CALL0(name,address) ((void (*)(void))address)(); brick_from_native()
#define CALL2(name,address,a,b) ((void (*)(uint32_t,uint32_t))address)(a,b); brick_from_native()
#define HIT(a,b) ((uint32_t (*)(uint32_t,uint32_t))0x405c80)(a,b)
#define FLASH(a,b,c,d) ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))0x4064b0)(a,b,c,d); brick_from_native()
#else
#define SYNC() publish_effects()
#define CALL0(name,address) fixture_brick_##name(&bricks)
#define CALL2(name,address,a,b) fixture_brick_##name(&bricks,a,b)
#define HIT(a,b) fixture_brick_hit(&bricks,a,b)
#define FLASH(a,b,c,d) fixture_brick_flash(&bricks,a,b,c,d)
#endif
static void hit_case(uint32_t tile,uint32_t pierce) {
    setup(); motion.pierce=pierce; current_board.cells[5][6]=(unsigned char)tile;
    if (scenario==3) title.fast=1;
    if (scenario==5) existing_effects(2,99);
    SYNC(); uint32_t result=HIT(6,5);
#ifndef DX_STANDALONE
    brick_from_native();
#endif
    spx_observe_object(observer,NULL); spx_observe_u64(observer,"hit_result",result); snapshot("state"); spx_observe_end(observer);
}
static void run(void) {
    if (scenario>=25) {
        uint32_t column=0,row=84;
        if (scenario==26 || scenario==27) saved_boards[1].cells[18][0]=7;
        if (scenario==28) { column=21;row=UINT32_C(0x80000000);current_board.cells[1][1]=5; }
        if (scenario==29) { column=12;row=21;play.pending_cells[0]=9; }
        if (scenario==30) { column=(uint32_t)EXTERNAL_ADDRESS-UINT32_C(0x42ca60);row=0;external_byte=11; }
        if (scenario==31) { column=(uint32_t)FAULT_ADDRESS-UINT32_C(0x42ca60);row=0; }
        if (scenario==32) { column=UINT32_C(0x42cdf8)+sizeof(saved_boards)-1-UINT32_C(0x42ca60);row=0;saved_boards[49].cells[19][19]=255; }
#ifndef DX_STANDALONE
        if (scenario==30 || scenario==31) {
            void *address=(void *)(uintptr_t)(scenario==30 ? EXTERNAL_ADDRESS : FAULT_ADDRESS);
            REQUIRE(VirtualAlloc(address,4096,MEM_RESERVE|MEM_COMMIT,scenario==30 ? PAGE_READWRITE : PAGE_NOACCESS)==address);
            if (scenario==30) *(unsigned char *)address=external_byte;
        }
#endif
        SYNC();memory_landing_active=1;
#ifndef DX_STANDALONE
        uint32_t handler=source_side ? spx_service_handler_begin() : 0;
#endif
        if (!setjmp(memory_landing)) {
            CALL2(queue,0x406410,column,row);REQUIRE(scenario!=31);
            if (scenario==27) {
                saved_boards[1].cells[18][0]=0;SYNC();CALL2(queue,0x406410,column,row);
                saved_boards[1].cells[18][0]=9;SYNC();CALL2(queue,0x406410,column,row);
            }
        } else {
            REQUIRE(scenario==31 && memory_fault_address==FAULT_ADDRESS);
#ifndef DX_STANDALONE
            if (source_side) spx_service_handler_catch(handler,"memory-fault");
#endif
        }
#ifndef DX_STANDALONE
        if (source_side) spx_service_handler_end(handler);
#endif
        memory_landing_active=0;
    } else if (scenario<=7) {
        if (scenario<=1) for (uint32_t tile=0;tile<=22;++tile) hit_case(tile,scenario);
        else if (scenario==2) { hit_case(23,0); hit_case(127,0); hit_case(128,0); hit_case(255,0); }
        else hit_case(scenario==3 ? 7 : scenario==4 ? 1 : scenario==6 ? 21 : 3,0);
    } else if (scenario==8) {
        memset(play.pending_cells,0xa7,400); SYNC(); CALL0(reset,0x405a70);
    } else if (scenario==9) {
        current_board.cells[5][6]=8; current_board.cells[0][0]=2; SYNC();
        CALL2(queue,0x406410,6,5); CALL2(queue,0x406410,19,19); CALL2(queue,0x406410,0,0); CALL2(queue,0x406410,6,5);
    } else if (scenario>=10 && scenario<=14) {
        uint32_t column=scenario==11 ? 0 : scenario==12 ? 19 : 6,row=scenario==11 ? 0 : 5;
        memset(&current_board,2,400); current_board.cells[row][column]=scenario==13 ? 2 : 8;
        title.fast=scenario==12; SYNC(); CALL2(blast,0x406070,column,row);
        if (scenario==14) { bricks.current->delay=4; bricks.current->tick=0xfffffffd; SYNC(); }
        for (unsigned i=0;i<(scenario==14 ? 9u : 8u);++i) { CALL0(advance,0x406020); }
    } else if (scenario==15) {
        SYNC(); FLASH(6,5,0x12345607,0); FLASH(0,0,0xff,1);
        for (unsigned i=0;i<8;++i) { CALL0(advance,0x406020); }
    } else if (scenario==16) {
        existing_effects(2,2); SYNC(); CALL0(step_flash,0x4065e0);
    } else if (scenario==17 || scenario==18) {
        existing_effects(3,2); effects[0].kind=99; effects[1].frames=1; SYNC(); CALL0(advance,0x406020);
    } else if (scenario==19) {
        existing_effects(3,99); effects[1].kind=0; effects[2].kind=UINT32_MAX; SYNC(); CALL0(advance,0x406020);
    } else {
        for (unsigned i=0;i<12;++i) {
            setup(); existing_effects(3,2); effects[i%3].frames=1; effects[(i+1)%3].tick=0x7fffffff;
            effects[(i+2)%3].delay=0xffffffff; SYNC();
            for (unsigned j=0;j<5;++j) { CALL0(advance,0x406020); }
            snapshot(NULL);
        }
    }
}
#ifdef BRICK_CONNECTED
#include "connected.h"
#endif
int main(int argc,char **argv) {
    (void)import_effects;
    REQUIRE(argc==3); scenario=(uint32_t)strtoul(argv[2],NULL,10); setup();
#ifdef BRICK_CONNECTED
    REQUIRE((scenario>=21 && scenario<25) || (scenario>=33 && scenario<39)); connected_setup();
#else
    REQUIRE(scenario<21 || (scenario>=25 && scenario<33));
#endif
    source_side=!strcmp(argv[1],"source");REQUIRE(source_side || !strcmp(argv[1],"original"));
#ifndef DX_STANDALONE
    install(source_side);
    if (scenario==36) {
        /* Windows reservations use 64 KiB allocation granularity. */
        void *reservation=(void *)(uintptr_t)(WRAP_PAGE&~UINT32_C(0xffff));
        REQUIRE(VirtualAlloc(reservation,65536,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE)==reservation);
    }
#ifdef BRICK_CONNECTED
    connected_install(!strcmp(argv[1],"source"));
#endif
#else
    REQUIRE(!strcmp(argv[1],"source"));
#endif
    SYNC(); spx_observer out=spx_observe_begin(stdout); observer=&out;
    spx_observe_object(observer,"bricks"); snapshot("initial"); spx_observe_array(observer,"calls");
#ifdef BRICK_CONNECTED
    (void)run; connected_run();
#else
    run();
#endif
    spx_observe_end(observer); snapshot("final"); spx_observe_end(observer);
    REQUIRE(spx_observe_finish(observer)); fputc('\n',stdout); return 0;
}
#ifndef DX_STANDALONE
struct native_startupinfo { int newmode; };
int __cdecl __getmainargs(int *,char ***,char ***,int,struct native_startupinfo *);
static LONG WINAPI fault(EXCEPTION_POINTERS *p) {
    if (memory_landing_active && scenario==31 && !source_side && p->ExceptionRecord->ExceptionCode==EXCEPTION_ACCESS_VIOLATION
            && p->ContextRecord->Eip==0x40641d && p->ExceptionRecord->NumberParameters>=2
            && p->ExceptionRecord->ExceptionInformation[0]==0 && p->ExceptionRecord->ExceptionInformation[1]==FAULT_ADDRESS) {
        memory_fault_address=FAULT_ADDRESS;longjmp(memory_landing,1);
    }
    fprintf(stderr,"native fault %08lx at %08lx\n",p->ExceptionRecord->ExceptionCode,p->ContextRecord->Eip);
    fflush(NULL); ExitProcess(86); return EXCEPTION_EXECUTE_HANDLER;
}
static void run_case(void) {
    SetUnhandledExceptionFilter(fault); int argc; char **argv,**environment; struct native_startupinfo startup={0};
    REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&startup)); int result=main(argc,argv); fflush(NULL); ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_bricks_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance; (void)reserved;
    return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
