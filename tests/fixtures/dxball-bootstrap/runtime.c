/* Per-target machine boundary adapters; these callbacks are component inputs. */
#include "bootstrap-runtime.h"
#include "spx-observation.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#include "comparison-services.h"
#endif
#define REQUIRE(x) do { if(!(x)) { fprintf(stderr,"bootstrap boundary %s:%d: %s\n",__func__,__LINE__,#x);abort(); } } while(0)
struct spx_opaque_shell_device_v5 { uint32_t identity; };
struct spx_opaque_shell_palette_v5 { uint32_t identity; };
static shell_device devices[2]={{1},{2}};
static shell_palette palette_objects[3]={{1},{2},{3}};
static font_surface surfaces[4]={{1},{2},{3},{4}};
static pcx_state colors;
static flow_state flow;
static title_state title={.flow=&flow,.palettes=&colors};
static scene_state scene={.animation=&title};
static shell_state application={.scene=&scene};
static bootstrap_state state={&application,0};
static uint32_t mode,selected[3],calls,clock_count,vblank_count,terminated;
static uint32_t surface_live[4]={1,1,0,1},palette_live[3]={1,0,1},clocks[3];
static int source_side;
static spx_observer *observer;
static jmp_buf termination;
#define ID(name,type,array,count) static uint32_t name##_id(const type *p) { \
    if(!p)return 0; \
    for(unsigned i=0;i<count;++i)if(p==&array[i])return i+1; \
    REQUIRE(0);return 0; }
ID(device,shell_device,devices,2) ID(surface,font_surface,surfaces,4) ID(palette,shell_palette,palette_objects,3)
#undef ID
void bootstrap_enter(unsigned op) { REQUIRE(op<3);++selected[op]; }
static void snapshot(const char *name) {
    REQUIRE(flow.primary==title.primary && flow.back==title.back);
    spx_observe_object(observer,name);
    uint32_t fields[]={flow.first_frame,flow.scene,flow.next_scene,flow.transition_pending,flow.windowed,flow.refresh_needed,
        title.fast,scene.no_hardware,scene.refresh_ok,state.last_refresh,application.active,application.control,scene.mouse_x};
    uint32_t roots[]={device_id(application.graphics),surface_id(title.primary),surface_id(title.back),surface_id(flow.overlay),palette_id(application.palette)};
    spx_observe_u32s(observer,"fields",fields,sizeof(fields)/4);spx_observe_u32s(observer,"roots",roots,5);
    spx_observe_u32s(observer,"surface_live",surface_live,4);spx_observe_u32s(observer,"palette_live",palette_live,3);
    spx_observe_bytes(observer,"colors",(const unsigned char *)&colors,sizeof(colors));spx_observe_end(observer);
}
static void begin(bootstrap_state *s,unsigned operation,const uint32_t *args,unsigned count) {
    REQUIRE(s==&state && ++calls<200);spx_observe_object(observer,NULL);spx_observe_u64(observer,"operation",operation);
    spx_observe_u32s(observer,"arguments",args,count);snapshot("before");
}
static uint32_t end(uint32_t result) { snapshot("after");spx_observe_u64(observer,"result",result);spx_observe_end(observer);return result; }
#define BEGIN0(n) (void)u;begin(s,BOOTSTRAP_SERVICE_##n,NULL,0)
#define BEGIN(n,...) (void)u;const uint32_t args[]={__VA_ARGS__};begin(s,BOOTSTRAP_SERVICE_##n,args,sizeof(args)/4)
uint32_t bootstrap_create_overlay(void *u,bootstrap_state *s,shell_device *device,display_surface *d) {
    REQUIRE(device && d);BEGIN(CREATE_OVERLAY,device_id(device),d->size,d->flags,d->height,d->width,d->caps);
    uint32_t result=mode==9 || mode==11 ? UINT32_MAX : mode==10 ? 1 : 0;
    if(mode!=9) { flow.overlay=&surfaces[2];surface_live[2]=1; }
    if(mode==15) { application.graphics=&devices[1];title.primary=flow.primary=&surfaces[3];title.fast=2;flow.scene=19; }
    return end(result);
}
void bootstrap_terminate(void *u,bootstrap_state *s,uint32_t code) {
    BEGIN(TERMINATE,code);terminated=code;(void)end(0);longjmp(termination,1);
}
void bootstrap_scores_initialize(void *u,bootstrap_state *s) {
    BEGIN0(SCORES_INITIALIZE);
    if(mode==16) { flow.scene=7;flow.transition_pending=3;colors.staged[4][3]=9; }
    (void)end(0);
}
void bootstrap_scores_load(void *u,bootstrap_state *s) {
    BEGIN0(SCORES_LOAD);if(mode==16) { flow.next_scene=9;scene.no_hardware=2; }(void)end(0);
}
void bootstrap_boards_load(void *u,bootstrap_state *s,asset_name *name) {
    BEGIN0(BOARDS_LOAD);REQUIRE(name && name->text);spx_observe_bytes(observer,"name",(const unsigned char *)name->text,strlen(name->text));
    if(mode==17) { flow.first_frame=0;application.graphics=&devices[1];title.primary=flow.primary=&surfaces[3]; }
    (void)end(0);
}
void bootstrap_seed_random(void *u,bootstrap_state *s) { BEGIN0(SEED_RANDOM);(void)end(0); }
uint32_t bootstrap_now(void *u,bootstrap_state *s) {
    BEGIN0(NOW);REQUIRE(clock_count<3);uint32_t result=clocks[clock_count++];
    if(mode==20 && clock_count==3) { scene.refresh_ok=7;title.fast=2;state.last_refresh=0xabadcafe; }
    return end(result);
}
void bootstrap_vertical_blank(void *u,bootstrap_state *s,shell_device *device,uint32_t flags) {
    REQUIRE(device);BEGIN(VERTICAL_BLANK,device_id(device),flags);++vblank_count;
    if(mode==19 && vblank_count==1) { application.graphics=&devices[1];title.fast=1;scene.no_hardware=2; }
    (void)end(0);
}
uint32_t bootstrap_create_palette(void *u,bootstrap_state *s,shell_device *device,uint32_t flags) {
    REQUIRE(device);BEGIN(CREATE_PALETTE,device_id(device),flags);
    uint32_t result=mode==12 || mode==14 || mode==22 ? UINT32_MAX : mode==13 || mode==23 ? 1 : 0;
    if(mode!=12 && mode!=22) { application.palette=&palette_objects[1];palette_live[1]=1; }
    if(mode==18 || mode==24) {
        application.palette=&palette_objects[2];title.primary=flow.primary=&surfaces[3];colors.current[3][1]=42;
    }
    return end(result);
}
void bootstrap_attach_palette(void *u,bootstrap_state *s,font_surface *surface,shell_palette *palette) {
    REQUIRE(surface && palette && surface_live[surface_id(surface)-1] && palette_live[palette_id(palette)-1]);
    BEGIN(ATTACH_PALETTE,surface_id(surface),palette_id(palette));(void)end(0);
}
void bootstrap_fill(void *u,bootstrap_state *s,font_surface *surface,font_rect *r,uint32_t size,uint32_t flags,uint32_t color) {
    REQUIRE(surface && surface_live[surface_id(surface)-1] && r);
    BEGIN(FILL,surface_id(surface),r->left,r->top,r->right,r->bottom,size,flags,color);
    if(mode==27) { scene.refresh_ok=9;colors.current[5][3]=111;title.primary=flow.primary=&surfaces[3]; }
    (void)end(0);
}
#undef BEGIN
#undef BEGIN0

#ifndef DX_STANDALONE
static uint32_t native_devices[2],native_surfaces[4],draw_vtable[23],surface_vtable[32];
static uint32_t *word(uint32_t address) { return (uint32_t *)(uintptr_t)address; }
#define NATIVE_VIEW(name,type,array,count,id) \
static uint32_t name##_address(type *p) { uint32_t n=id(p);return n ? (uint32_t)(uintptr_t)&native_##array[n-1] : 0; } \
static type *name##_view(uint32_t address) { \
    if(!address)return NULL; \
    for(unsigned i=0;i<count;++i)if(address==(uint32_t)(uintptr_t)&native_##array[i])return &array[i]; \
    REQUIRE(0);return NULL; }
NATIVE_VIEW(device,shell_device,devices,2,device_id) NATIVE_VIEW(surface,font_surface,surfaces,4,surface_id)
#undef NATIVE_VIEW
static uint32_t palette_address(shell_palette *p) { uint32_t n=palette_id(p);return n ? 0x31010000+n*16 : 0; }
static shell_palette *palette_view(uint32_t address) {
    if(!address)return NULL;
    for(unsigned i=0;i<3;++i)if(address==palette_address(&palette_objects[i]))return &palette_objects[i];
    REQUIRE(0);return NULL;
}
#define FIELDS(X) X(flow.first_frame,0x417a00) X(flow.scene,0x431fd0) X(flow.next_scene,0x431fc4) \
    X(flow.transition_pending,0x431fc8) X(flow.windowed,0x434998) X(flow.refresh_needed,0x4349a4) \
    X(title.fast,0x4349c8) X(scene.no_hardware,0x417a08) X(scene.refresh_ok,0x4349c0) X(state.last_refresh,0x4349c4) \
    X(application.active,0x43498c) X(application.control,0x434994) X(scene.mouse_x,0x434970)
static void push(void) {
#define PUT(field,address) *word(address)=field;
    FIELDS(PUT)
#undef PUT
    *word(0x4349a8)=device_address(application.graphics);*word(0x4349b8)=palette_address(application.palette);
    *word(0x4349ac)=surface_address(title.primary);*word(0x4349b4)=surface_address(title.back);*word(0x431fcc)=surface_address(flow.overlay);
    memcpy((void *)0x42c148,&colors,sizeof(colors));
}
static void pull(void) {
#define GET(field,address) field=*word(address);
    FIELDS(GET)
#undef GET
    application.graphics=device_view(*word(0x4349a8));application.palette=palette_view(*word(0x4349b8));
    title.primary=flow.primary=surface_view(*word(0x4349ac));title.back=flow.back=surface_view(*word(0x4349b4));flow.overlay=surface_view(*word(0x431fcc));
    memcpy(&colors,(void *)0x42c148,sizeof(colors));
}
#undef FIELDS
static uint32_t WINAPI native_overlay(uint32_t device,uint32_t *d,uint32_t *slot,void *outer) {
    REQUIRE(d && slot==word(0x431fcc) && !outer);pull();display_surface view={.size=d[0],.flags=d[1],.height=d[2],.width=d[3],.caps=d[26]};
    uint32_t result=bootstrap_create_overlay(NULL,&state,device_view(device),&view);push();return result;
}
static uint32_t WINAPI native_palette(uint32_t device,uint32_t flags,void *entries,uint32_t *slot,void *outer) {
    REQUIRE(entries==(void *)0x42c148 && slot==word(0x4349b8) && !outer);pull();
    uint32_t result=bootstrap_create_palette(NULL,&state,device_view(device),flags);push();return result;
}
static uint32_t WINAPI native_attach(uint32_t surface,uint32_t palette) {
    pull();bootstrap_attach_palette(NULL,&state,surface_view(surface),palette_view(palette));push();return UINT32_MAX;
}
static uint32_t WINAPI native_fill(uint32_t surface,uint32_t *r,uint32_t source,void *source_rect,uint32_t flags,uint32_t *effects) {
    REQUIRE(r && !source && !source_rect && effects);pull();font_rect view={r[0],r[1],r[2],r[3]};
    bootstrap_fill(NULL,&state,surface_view(surface),&view,effects[0],flags,effects[20]);push();return UINT32_MAX;
}
static uint32_t WINAPI native_blank(uint32_t device,uint32_t flags,void *event) {
    REQUIRE(!event);pull();bootstrap_vertical_blank(NULL,&state,device_view(device),flags);push();return UINT32_MAX;
}
#define NATIVE0(n) static void native_##n(void) { pull();bootstrap_##n(NULL,&state);push(); }
NATIVE0(scores_initialize) NATIVE0(scores_load) NATIVE0(seed_random)
#undef NATIVE0
static void native_boards_load(const char *text) { pull();asset_name name={text};bootstrap_boards_load(NULL,&state,&name);push(); }
static uint32_t native_now(void) { pull();uint32_t result=bootstrap_now(NULL,&state);push();return result; }
static void native_terminate(uint32_t code) { pull();bootstrap_terminate(NULL,&state,code); }
static void live_initialize(void) { pull();fixture_bootstrap_initialize(&state);push(); }
static void live_palette(void) { pull();fixture_bootstrap_palette(&state);push(); }
static void live_clear(uint32_t surface,uint32_t color) { pull();fixture_bootstrap_clear(&state,surface_view(surface),color);push(); }
#endif
static void invoke(unsigned op,uint32_t color) {
#ifndef DX_STANDALONE
    push();
    if(op==0)((void (*)(void))0x40ad10)();
    else if(op==1)((void (*)(void))0x4022b0)();
    else ((void (*)(uint32_t,uint32_t))0x402710)(surface_address(title.primary),color);
    pull();
#else
    if(op==0)fixture_bootstrap_initialize(&state);
    else if(op==1)fixture_bootstrap_palette(&state);
    else fixture_bootstrap_clear(&state,title.primary,color);
#endif
}
int main(int argc,char **argv) {
    REQUIRE(argc==3);source_side=!strcmp(argv[1],"source");mode=(uint32_t)strtoul(argv[2],NULL,10);REQUIRE(mode<29);
    application.graphics=&devices[0];application.palette=&palette_objects[0];title.primary=flow.primary=&surfaces[0];title.back=flow.back=&surfaces[1];
    flow.first_frame=1;flow.scene=11;flow.next_scene=12;flow.transition_pending=13;flow.windowed=1;flow.refresh_needed=17;
    scene.refresh_ok=19;scene.mouse_x=321;application.active=7;application.control=9;state.last_refresh=0x12345678;
    for(unsigned i=0;i<sizeof(colors);++i)((unsigned char *)&colors)[i]=(unsigned char)(i*13+i/4+3);
    clocks[0]=mode==4 ? 0xffffff80 : 100;clocks[1]=clocks[0]+(mode==1 ? 399 : mode==2 ? 400 : mode==3 || mode==4 ? 401 : mode==7 || mode==8 ? 320 : 512);clocks[2]=0xfedcba98;
    if(mode==5)title.fast=1;
    if(mode==6)title.fast=2;
    if(mode==7 || mode==8)scene.no_hardware=mode-6;
#ifndef DX_STANDALONE
    draw_vtable[5]=(uint32_t)(uintptr_t)native_palette;draw_vtable[6]=(uint32_t)(uintptr_t)native_overlay;draw_vtable[22]=(uint32_t)(uintptr_t)native_blank;
    surface_vtable[5]=(uint32_t)(uintptr_t)native_fill;surface_vtable[31]=(uint32_t)(uintptr_t)native_attach;
    for(unsigned i=0;i<2;++i)native_devices[i]=(uint32_t)(uintptr_t)draw_vtable;
    for(unsigned i=0;i<4;++i)native_surfaces[i]=(uint32_t)(uintptr_t)surface_vtable;
#define INSTALL(n) REQUIRE(install_bootstrap_##n((void (*)(void))native_##n));
    INSTALL(scores_initialize) INSTALL(scores_load) INSTALL(boards_load) INSTALL(seed_random) INSTALL(now) INSTALL(terminate)
#undef INSTALL
    if(source_side) { REQUIRE(install_bootstrap_initialize((void (*)(void))live_initialize));REQUIRE(install_bootstrap_palette((void (*)(void))live_palette));REQUIRE(install_bootstrap_clear((void (*)(void))live_clear)); }
#else
    REQUIRE(source_side);
#endif
    spx_observer out=spx_observe_begin(stdout);observer=&out;spx_observe_object(observer,"bootstrap");snapshot("initial");spx_observe_array(observer,"calls");
#ifndef DX_STANDALONE
    uint32_t handler=source_side ? spx_service_handler_begin() : 0;
#endif
    if(!setjmp(termination)) {
        unsigned op=mode>=21 && mode<=24 ? 1 : mode>=25 && mode<=27 ? 2 : 0;
        invoke(op,mode==26 ? 0xfedcba98 : 0);
        if(mode==28) { invoke(2,0x12345678);invoke(1,0); }
    } else {
        REQUIRE(terminated);
#ifndef DX_STANDALONE
        if(source_side)spx_service_handler_catch(handler,"process-exit");
#endif
    }
#ifndef DX_STANDALONE
    if(source_side)spx_service_handler_end(handler);
#endif
    spx_observe_end(observer);snapshot("final");uint32_t outcomes[]={terminated,clock_count,vblank_count};
    spx_observe_u32s(observer,"outcomes",outcomes,3);spx_observe_end(observer);REQUIRE(spx_observe_finish(observer));puts("");
    if(source_side)REQUIRE(selected[0]+selected[1]+selected[2]);
    return 0;
}
#ifndef DX_STANDALONE
struct native_startupinfo { int newmode; };
extern int __cdecl __getmainargs(int *,char ***,char ***,int,struct native_startupinfo *);
static void run_case(void) {
    int argc;char **argv,**environment;struct native_startupinfo s={0};REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&s));
    int result=main(argc,argv);fflush(NULL);ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_bootstrap_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reserved;return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
