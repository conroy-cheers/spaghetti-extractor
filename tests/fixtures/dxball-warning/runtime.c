/* Local original/source warning consumer, with explicit native entry history. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "warning-runtime.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
static uint32_t scenario,entered[2],calls,seed,clock_value,clock_calls,particle_calls;
static int source_side;
static font_surface surfaces[3]={{1},{2},{3}};
static font_sprite sprites[3];
static struct spx_opaque_cleanup_state_v5 objects;
static font_state font={.objects=&objects};
static pcx_state palettes;
static flow_state flow;
static title_state title={.font=&font,.flow=&flow,.palettes=&palettes};
static scene_state scene={.animation=&title};
static menu_state menu={.scene=&scene};
static play_state play={.menu=&menu};
static board current_board;
static motion_state motion={.play=&play,.board=&current_board};
static pickup_state pickups={.motion=&motion};
static paddle_state paddle={.pickups=&pickups};
static brick_state bricks={.motion=&motion};
static progression_state progress={.paddle=&paddle,.bricks=&bricks};
static warning_state warning={.progression=&progress};
static spx_observer *observer;
static void require(int test,const char *expression,unsigned line) {
    if (!test) { fprintf(stderr,"warning-runtime.c:%u: adapter premise failed: %s\n",line,expression);exit(3); }
}
#define REQUIRE(test) require(!!(test),#test,__LINE__)
void warning_enter(unsigned operation) { REQUIRE(operation<2);++entered[operation]; }
static uint32_t surface_id(font_surface *surface) {
    for (unsigned i=0;i<3;++i) if (surface==&surfaces[i]) return i+1;
    REQUIRE(0);return 0;
}
static void dimensions(font_sprite *sprite,uint32_t width,uint32_t height) {
    for (unsigned i=0;i<4;++i) { sprite->retained[4+i]=(unsigned char)(width>>(8*i));sprite->retained[8+i]=(unsigned char)(height>>(8*i)); }
}
static void snapshot(const char *name) {
    spx_observe_object(observer,name);
    uint32_t fields[]={play.warning_sound,warning.x,progress.warning_y,progress.warning_frames,
        warning.rectangle.left,warning.rectangle.top,warning.rectangle.right,warning.rectangle.bottom,
        title.fast,objects.current_bank,surface_id(title.software),play.remaining_bricks,
        warning.fallback.y,warning.fallback.row,warning.fallback.column};
    spx_observe_u32s(observer,"fields",fields,sizeof(fields)/sizeof(*fields));
    spx_observe_bytes(observer,"board",(const unsigned char *)&current_board,400);
    for (unsigned i=0;i<3;++i) {
        uint32_t values[]={font_width(&sprites[i]),font_height(&sprites[i]),surface_id(sprites[i].surface)};
        spx_observe_u32s(observer,i==0 ? "sprite0" : i==1 ? "sprite1" : "sprite2",values,3);
    }
    spx_observe_end(observer);
}
static void begin(warning_state *s,unsigned operation,const uint32_t *args,unsigned count) {
    REQUIRE(s==&warning && calls++<1000);spx_observe_object(observer,NULL);
    spx_observe_u64(observer,"operation",operation);spx_observe_u32s(observer,"arguments",args,count);snapshot("before");
}
static uint32_t end(uint32_t value) { snapshot("after");spx_observe_u64(observer,"result",value);spx_observe_end(observer);return value; }
#define BEGIN0(op) (void)unused;begin(s,op,NULL,0)
#define BEGIN(op,...) (void)unused;const uint32_t args[]={__VA_ARGS__};begin(s,op,args,sizeof(args)/sizeof(*args))
uint32_t warning_now(void *unused,warning_state *s) {
    BEGIN0(WARNING_NOW);return end(clock_value+clock_calls++);
}
uint32_t warning_random(void *unused,warning_state *s,uint32_t limit) {
    BEGIN(WARNING_RANDOM,limit);REQUIRE(limit);seed=seed*1664525+1013904223;return end(seed%limit);
}
void warning_stop_sound(void *unused,warning_state *s,uint32_t sound) { BEGIN(WARNING_STOP_SOUND,sound);(void)end(0); }
void warning_play_sound(void *unused,warning_state *s,uint32_t sound,uint32_t repeat,uint32_t volume,uint32_t pan) {
    BEGIN(WARNING_PLAY_SOUND,sound,repeat,volume,pan);
    if (scenario==15) { memset(&current_board,0,400);current_board.cells[19][19]=255; }
    (void)end(0);
}
void warning_loop_sound(void *unused,warning_state *s,uint32_t sound,uint32_t repeat,uint32_t volume,uint32_t pan) {
    BEGIN(WARNING_LOOP_SOUND,sound,repeat,volume,pan);(void)end(0);
}
void warning_queue(void *unused,warning_state *s,uint32_t column,uint32_t row) {
    BEGIN(WARNING_QUEUE,column,row);
    if (scenario==16) { memset(&current_board,2,400);progress.warning_y=777;warning.x=888; }
    (void)end(0);
}
void warning_explosion(void *unused,warning_state *s,uint32_t x,uint32_t y) {
    BEGIN(WARNING_EXPLOSION,x,y);if (scenario==17) title.fast=0;(void)end(0);
}
void warning_particle(void *unused,warning_state *s,uint32_t x,uint32_t y,uint32_t dx,uint32_t dy,uint32_t color,uint32_t gravity) {
    BEGIN(WARNING_PARTICLE,x,y,dx,dy,color,gravity);
    if (scenario==18 && !particle_calls) { title.fast=0;warning.x=444;progress.warning_y=333; }
    ++particle_calls;(void)end(0);
}
void warning_select_bank(void *unused,warning_state *s,uint32_t bank) {
    BEGIN(WARNING_SELECT_BANK,bank);REQUIRE(bank<3);objects.current_bank=bank;
    if (scenario==19 && bank==2) { objects.current_bank=1;dimensions(&sprites[1],241,97); }
    if (scenario==24 && bank==0) progress.warning_frames=13;
    (void)end(0);
}
void warning_blit_fast(void *unused,warning_state *s,font_surface *destination,uint32_t x,uint32_t y,
                       font_surface *source,font_rect *bounds,uint32_t flags) {
    BEGIN(WARNING_BLIT_FAST,surface_id(destination),x,y,surface_id(source),bounds->left,bounds->top,bounds->right,bounds->bottom,flags);
    REQUIRE(bounds==&warning.rectangle);
    if (scenario==22) { bounds->right+=19;bounds->bottom+=7;warning.x=111;progress.warning_y=222;progress.warning_frames=9;title.software=&surfaces[2]; }
    (void)end(0);
}
void warning_damage(void *unused,warning_state *s,font_rect *bounds) {
    BEGIN(WARNING_DAMAGE,bounds->left,bounds->top,bounds->right,bounds->bottom);
    if (scenario==23) { progress.warning_frames=17;bounds->left=12345; }
    (void)end(0);
}
#ifndef DX_STANDALONE
uint32_t warning_entry_words[3] __attribute__((used));
static uint32_t native_sprites[3][12],native_surfaces[3],native_vtable[33];
static uint32_t *word(uint32_t address) { return (uint32_t *)(uintptr_t)address; }
static uint32_t native_surface(font_surface *s) { return (uint32_t)(uintptr_t)&native_surfaces[surface_id(s)-1]; }
static font_surface *surface_view(uint32_t address) {
    for (unsigned i=0;i<3;++i) if (address==(uint32_t)(uintptr_t)&native_surfaces[i]) return &surfaces[i];
    REQUIRE(0);return NULL;
}
#define WARNING_WORDS(X) X(play.warning_sound,0x42cdd4) X(warning.x,0x42cdb0) X(progress.warning_y,0x42cdc8) \
    X(progress.warning_frames,0x431cb0) X(title.fast,0x4349c8) X(objects.current_bank,0x434968) X(play.remaining_bricks,0x431c48)
static void to_native(void) {
#define PUT(value,address) *word(address)=value;
    WARNING_WORDS(PUT)
#undef PUT
    memcpy((void *)0x42ca60,&current_board,400);memcpy((void *)0x42cda0,&warning.rectangle,16);
    *word(0x41c728)=native_surface(title.software);
    for (unsigned i=0;i<3;++i) {
        native_surfaces[i]=(uint32_t)(uintptr_t)native_vtable;
        native_sprites[i][0]=native_surface(sprites[i].surface);memcpy(native_sprites[i]+1,sprites[i].retained,41);
        *word(0x433d1c+i*1048)=(uint32_t)(uintptr_t)native_sprites[i];
    }
}
static void from_native(void) {
#define GET(value,address) value=*word(address);
    WARNING_WORDS(GET)
#undef GET
    memcpy(&current_board,(void *)0x42ca60,400);memcpy(&warning.rectangle,(void *)0x42cda0,16);
    title.software=surface_view(*word(0x41c728));
    for (unsigned i=0;i<3;++i) { sprites[i].surface=surface_view(native_sprites[i][0]);memcpy(sprites[i].retained,native_sprites[i]+1,41); }
}
#define WRAP1(name,result) static result native_##name(uint32_t a) { from_native();result value=warning_##name(NULL,&warning,a);to_native();return value; }
WRAP1(random,uint32_t)
#undef WRAP1
static DWORD WINAPI native_now(void) { from_native();uint32_t value=warning_now(NULL,&warning);to_native();return value; }
#define VOID1(name) static void native_##name(uint32_t a) { from_native();warning_##name(NULL,&warning,a);to_native(); }
VOID1(stop_sound) VOID1(select_bank)
#undef VOID1
#define VOID2(name) static void native_##name(uint32_t a,uint32_t b) { from_native();warning_##name(NULL,&warning,a,b);to_native(); }
VOID2(queue) VOID2(explosion)
#undef VOID2
#define VOID4(name) static void native_##name(uint32_t a,uint32_t b,uint32_t c,uint32_t d) { from_native();warning_##name(NULL,&warning,a,b,c,d);to_native(); }
VOID4(play_sound) VOID4(loop_sound)
#undef VOID4
static void native_particle(uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f) {
    from_native();warning_particle(NULL,&warning,a,b,c,d,e,f);to_native();
}
static uint32_t WINAPI native_blit(uint32_t destination,uint32_t x,uint32_t y,uint32_t source,void *bounds,uint32_t flags) {
    REQUIRE(bounds==(void *)0x42cda0);from_native();
    warning_blit_fast(NULL,&warning,surface_view(destination),x,y,surface_view(source),&warning.rectangle,flags);to_native();return 0;
}
static void native_damage(font_rect bounds) { from_native();warning_damage(NULL,&warning,&bounds);to_native(); }
static void __attribute__((naked)) enter_native_prepare(void) {
    __asm__ volatile("movl _warning_entry_words, %eax\n\tmovl %eax, -28(%esp)\n\t"
        "movl _warning_entry_words+4, %eax\n\tmovl %eax, -24(%esp)\n\t"
        "movl _warning_entry_words+8, %eax\n\tmovl %eax, -20(%esp)\n\t"
        "movl $0x408c20, %eax\n\tjmp *%eax\n\t");
}
static void invoke(unsigned operation) {
    to_native();memcpy(warning_entry_words,&warning.fallback,12);
    if (source_side) { if (operation) fixture_warning_draw(&warning);else fixture_warning_prepare(&warning); }
    else { if (operation) ((void (*)(void))0x408ed0)();else enter_native_prepare();from_native(); }
}
#else
static void invoke(unsigned operation) { if (operation) fixture_warning_draw(&warning);else fixture_warning_prepare(&warning); }
#endif
static void setup(void) {
    play.warning_sound=1;clock_value=2;seed=17;title.fast=1;title.software=&surfaces[0];
    play.remaining_bricks=1;warning.fallback=(warning_input){120,2,3};
    warning.x=30;progress.warning_y=50;progress.warning_frames=3;warning.rectangle=(font_rect){2,3,159,479};
    current_board.cells[2][3]=5;
    for (unsigned i=0;i<3;++i) { sprites[i].surface=&surfaces[1];dimensions(&sprites[i],159,479);objects.banks[i].slots[1]=&sprites[i]; }
    switch (scenario) {
    case 0: play.warning_sound=0;clock_value=1000;break;
    case 1: play.warning_sound=clock_value+1;break;
    case 2: play.warning_sound=clock_value+123456;break;
    case 3: play.warning_sound=clock_value;break;
    case 4: play.warning_sound=0x7fffffff;clock_value=0xffffffff;break;
    case 5: title.fast=0;break;
    case 6: current_board.cells[19][1]=5;current_board.cells[1][19]=7;break;
    case 7: current_board.cells[19][19]=255;break;
    case 8: memset(&current_board,0,400);break;
    case 9: memset(&current_board,2,400);warning.fallback=(warning_input){300,5,7};break;
    case 10: memset(&current_board,0,400);warning.fallback=(warning_input){1,84,0};break;
    case 11: memset(&current_board,0,400);warning.fallback=(warning_input){0x80000000,2,0xfffffff0};break;
    case 12: memset(&current_board,0,400);current_board.cells[0][0]=5;break;
    case 13: memset(&current_board,0,400);current_board.cells[19][19]=5;dimensions(&sprites[2],200,10);break;
    case 14: dimensions(&sprites[2],0xfffffffb,0xfffffff9);break;
    case 20: progress.warning_frames=0x80000000;break;
    default: break;
    }
}
static int run(int argc,char **argv) {
    REQUIRE(argc==3 && (!strcmp(argv[1],"source") || !strcmp(argv[1],"original")));
    source_side=!strcmp(argv[1],"source");scenario=(uint32_t)strtoul(argv[2],NULL,10);REQUIRE(scenario<26);
    setup();spx_observer out=spx_observe_begin(stdout);observer=&out;spx_observe_array(observer,"warning");snapshot(NULL);
    if (scenario>=20 && scenario<=24) { unsigned count=scenario==21 ? 5 : 1;for (unsigned i=0;i<count;++i) invoke(1); }
    else { invoke(0);if (scenario==25) for (unsigned i=0;i<5;++i) invoke(1); }
    snapshot(NULL);spx_observe_end(observer);REQUIRE(spx_observe_finish(observer));fputc('\n',stdout);return 0;
}
#ifndef DX_STANDALONE
static void startup(void) {
    int argc=0,startup_info=0;char **argv=NULL,**environment=NULL;
    extern int __cdecl __getmainargs(int *,char ***,char ***,int,int *);
    REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&startup_info));int result=run(argc,argv);fflush(NULL);ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_warning_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reserved;if (reason!=DLL_PROCESS_ATTACH) return TRUE;
#define HOOK(name) REQUIRE(install_warning_service_##name((void (*)(void))native_##name))
    HOOK(random);HOOK(stop_sound);HOOK(play_sound);HOOK(loop_sound);HOOK(queue);HOOK(explosion);HOOK(particle);HOOK(select_bank);HOOK(damage);
#undef HOOK
    native_vtable[7]=(uint32_t)(uintptr_t)native_blit;
    DWORD old,ignored;REQUIRE(VirtualProtect((void *)0x415174,4,PAGE_READWRITE,&old));*word(0x415174)=(uint32_t)(uintptr_t)native_now;
    REQUIRE(VirtualProtect((void *)0x415174,4,old,&ignored));REQUIRE(install_startup(startup));return TRUE;
}
#else
int main(int argc,char **argv) { return run(argc,argv); }
#endif
