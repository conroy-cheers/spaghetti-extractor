/* Main menu consumer reuses the scene's controlled platform and live storage. */
#define SCENE_LIBRARY_ONLY 1
#include "scene-runtime.c"
#include "menu-runtime.h"

static menu_state menu;
static int32_t cosine[361];
static uint32_t menu_entries[7], menu_mode, elapsed_calls, clock_value, lock_attempts, active_lease;
#ifndef MENU_TEXT_CAPACITY
#define MENU_TEXT_CAPACITY 32
#endif
static uint32_t menu_calls[1600][8], menu_count, text_count, text_calls[MENU_TEXT_CAPACITY][4], text_lengths[MENU_TEXT_CAPACITY];
static unsigned char text_bytes[MENU_TEXT_CAPACITY][128];
static const char *menu_track_name = "ethno_pa.mds";
#define MENU_COMMON_PUSH() ((void)0)
#define MENU_COMMON_PULL() ((void)0)
#include "menu-common.h"
void menu_enter(unsigned operation) { REQUIRE(operation < 7); ++menu_entries[operation]; }
#define MENU_RECORD(...) do { const uint32_t values[] = {__VA_ARGS__}; REQUIRE(menu_count < 1600); \
    memcpy(menu_calls[menu_count++],values,sizeof(values)); } while (0)
static void menu_text_record(uint32_t centered,uint32_t x,uint32_t y,uint32_t length,const unsigned char *data) {
    REQUIRE(text_count < MENU_TEXT_CAPACITY && length <= 128); uint32_t i = text_count++;
    text_calls[i][0] = centered; text_calls[i][1] = x; text_calls[i][2] = y; text_calls[i][3] = font.bank;
    text_lengths[i] = length; memcpy(text_bytes[i],data,length);
}
void menu_text(void *unused,scene_state *s,uint32_t x,uint32_t y,uint32_t length,font_bytes *bytes) {
    menu_text_record(0,x,y,length,bytes->data); scene_text(unused,s,x,y,length,bytes);
}
void menu_center(void *unused,scene_state *s,uint32_t x,uint32_t y,uint32_t length,font_bytes *bytes) {
    menu_text_record(1,x,y,length,bytes->data); scene_center(unused,s,x,y,length,bytes);
}
void menu_load_track(void *unused,menu_state *s,asset_name *name,uint32_t mode) {
    (void)unused; REQUIRE(s == &menu && !strcmp(name->text,menu_track_name)); MENU_RECORD(0,mode);
}
uint32_t menu_elapsed(void *unused,menu_state *s,uint32_t previous,uint32_t delay) {
    (void)unused; REQUIRE(s == &menu);
    uint32_t result = menu_mode != 0 && (menu_mode != 1 || (++elapsed_calls % 2));
    MENU_RECORD(1,previous,delay,result); return result;
}
uint32_t menu_now(void *unused,menu_state *s) {
    (void)unused; REQUIRE(s == &menu); clock_value += 57; MENU_RECORD(2,clock_value); return clock_value;
}
void menu_blit_fast(void *unused,menu_state *s,font_surface *destination,uint32_t x,uint32_t y,
                    font_surface *source,font_rect *rectangle,uint32_t flags) {
    REQUIRE(s == &menu); title_blit_fast(unused,&title,destination,x,y,source,rectangle,flags);
}
void menu_describe(void *unused,font_surface *surface,pcx_view *view) {
    (void)unused; MENU_RECORD(3,surface_id(surface)); view->width=640; view->height=480;
    view->image=(asset_view){scene_pixels(surface),640};
}
uint32_t menu_lock(void *unused,font_surface *surface,pcx_view *view) {
    (void)unused; REQUIRE(!active_lease); uint32_t result=menu_mode == 5 && !lock_attempts++;
    MENU_RECORD(4,surface_id(surface),result);
    if (!result) { active_lease=surface_id(surface); view->width=640; view->height=480; view->image=(asset_view){scene_pixels(surface),640}; }
    return result;
}
void menu_unlock(void *unused,font_surface *surface) {
    (void)unused; REQUIRE(active_lease == surface_id(surface)); MENU_RECORD(5,active_lease); active_lease=0;
}
void menu_sprite(void *unused,menu_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    (void)unused; REQUIRE(s == &menu); (void)fixture_sprite_transparent(&font,slot,x,y);
}
void menu_damage(void *unused,menu_state *s,font_rect *rectangle) {
    (void)unused; REQUIRE(s == &menu); MENU_RECORD(6,rectangle->left,rectangle->top,rectangle->right,rectangle->bottom);
}
void menu_cycle_palette(void *unused,menu_state *s,uint32_t first,uint32_t last,uint32_t step) {
    (void)unused; REQUIRE(s == &menu && first <= last && last < 256); MENU_RECORD(7,first,last,step);
    for (uint32_t i=first;i<=last;++i) palettes.current[i][0]=(unsigned char)(palettes.current[i][0]+step);
}
void menu_cycle_dots_palette(void *unused,menu_state *s,uint32_t first,uint32_t last,uint32_t step) {
    (void)unused; REQUIRE(s == &menu && first <= last && last < 256); MENU_RECORD(8,first,last,step);
    for (uint32_t i=first;i<=last;++i) palettes.current[i][2]=(unsigned char)(palettes.current[i][2]-step);
}
#ifndef MENU_LIBRARY_ONLY
static void menu_redraw_callback(scene_state *s) { REQUIRE(s == &scene); fixture_menu_redraw(&menu); }
#endif

#ifndef DX_STANDALONE
#include "menu-native.h"
static void native_menu_load_track(const char *name,uint32_t mode) {
    asset_name text={name}; menu_from_native(); menu_load_track(NULL,&menu,&text,mode); menu_to_native();
}
static uint32_t native_menu_elapsed(uint32_t previous,uint32_t delay) {
    menu_from_native(); uint32_t result=menu_elapsed(NULL,&menu,previous,delay); menu_to_native(); return result;
}
static uint32_t native_menu_now(void) { menu_from_native(); uint32_t value=menu_now(NULL,&menu); menu_to_native(); return value; }
static void native_menu_damage(font_rect rectangle) { menu_from_native(); menu_damage(NULL,&menu,&rectangle); menu_to_native(); }
#define PALETTE_CALLBACK(name) static void native_menu_##name(uint32_t first,uint32_t last,uint32_t step) { \
    menu_from_native(); menu_##name(NULL,&menu,first,last,step); menu_to_native(); }
PALETTE_CALLBACK(cycle_palette) PALETTE_CALLBACK(cycle_dots_palette)
static uint32_t WINAPI native_menu_describe(uint32_t surface,uint32_t *desc) {
    REQUIRE(desc[0] == 108); pcx_view view={0}; menu_from_native(); menu_describe(NULL,title_surface_view(surface),&view);
    desc[2]=view.height; desc[3]=view.width; desc[4]=view.image.pitch; desc[9]=(uint32_t)(uintptr_t)view.image.pixels;
    menu_to_native(); return 0;
}
static uint32_t WINAPI native_menu_lock(uint32_t surface,void *rectangle,uint32_t *desc,uint32_t flags,void *event) {
    REQUIRE(!rectangle && !flags && !event && desc[0] == 108); pcx_view view={0}; menu_from_native();
    uint32_t result=menu_lock(NULL,title_surface_view(surface),&view);
    if (!result) { desc[2]=view.height; desc[3]=view.width; desc[4]=view.image.pitch; desc[9]=(uint32_t)(uintptr_t)view.image.pixels; }
    menu_to_native(); return result;
}
static uint32_t WINAPI native_menu_unlock(uint32_t surface,void *data) {
    REQUIRE(!data); menu_from_native(); menu_unlock(NULL,title_surface_view(surface)); menu_to_native(); return 0;
}
static uint32_t native_text_depth;
#define TEXT_CALLBACK(name, number, address) \
static uint32_t native_menu_##name(uint32_t x,uint32_t y,uint32_t length,const unsigned char *text) { \
    menu_from_native(); if (!native_text_depth++) menu_text_record(number,x,y,length,text); \
    REQUIRE(spx_fixture_restore_entry(&install_font_##name##_hook)); \
    uint32_t result=((uint32_t (*)(uint32_t,uint32_t,uint32_t,const unsigned char *))(uintptr_t)address)(x,y,length,text); \
    install_font_##name##_hook.entry=NULL; REQUIRE(install_font_##name((void (*)(void))native_menu_##name)); \
    --native_text_depth; return result; \
}
TEXT_CALLBACK(line,0,0x40c6b0) TEXT_CALLBACK(center,1,0x40c720)
#define MENU_ROOT(name) static void native_root_menu_##name(void) { menu_from_native(); fixture_menu_##name(&menu); menu_to_native(); }
MENU_ROOT(enter) MENU_ROOT(redraw) MENU_ROOT(update) MENU_ROOT(initialize_dots) MENU_ROOT(animate)
static void native_root_menu_key(uint32_t key) { menu_from_native(); fixture_menu_key(&menu,key); menu_to_native(); }
static void native_root_menu_leave(uint32_t reason) { menu_from_native(); fixture_menu_leave(&menu,reason); menu_to_native(); }
static void menu_install(int source) {
    scene_install(source); scene_redraw_address=0x40af80;
    memcpy((void *)0x435750,cosine,sizeof(cosine));
    font_vtable[22]=(uint32_t)(uintptr_t)native_menu_describe;
    font_vtable[25]=(uint32_t)(uintptr_t)native_menu_lock; font_vtable[32]=(uint32_t)(uintptr_t)native_menu_unlock;
#define MENU_SERVICE(name) REQUIRE(install_menu_service_##name((void (*)(void))native_menu_##name));
    MENU_SERVICE(load_track) MENU_SERVICE(elapsed) MENU_SERVICE(now) MENU_SERVICE(damage)
    MENU_SERVICE(cycle_palette) MENU_SERVICE(cycle_dots_palette)
    if (!source) {
        REQUIRE(install_font_line((void (*)(void))native_menu_line));
        REQUIRE(install_font_center((void (*)(void))native_menu_center)); return;
    }
#define MENU_INSTALL(name) REQUIRE(install_menu_##name((void (*)(void))native_root_menu_##name));
    MENU_INSTALL(enter) MENU_INSTALL(redraw) MENU_INSTALL(update) MENU_INSTALL(key) MENU_INSTALL(leave)
    MENU_INSTALL(initialize_dots) MENU_INSTALL(animate)
}
#endif

#ifndef MENU_LIBRARY_ONLY
static void menu_snapshot(spx_observer *o) {
    spx_observe_object(o,NULL); spx_observe_array(o,"scene"); snapshot(o); spx_observe_end(o);
    uint32_t values[]={menu.score,menu.input_ready,menu.last_tick}; spx_observe_u32s(o,"fields",values,3);
    spx_observe_array(o,"dots");
    for (unsigned i=0;i<287;++i) {
        menu_dot *d=&menu.dots[i]; uint32_t words[]={d->x,d->y,d->phase,d->kind}; spx_observe_u32s(o,NULL,words,4);
    }
    spx_observe_end(o); spx_observe_array(o,"offsets");
    for (unsigned i=0;i<360;++i) spx_observe_u32s(o,NULL,menu.offsets[i],2);
    spx_observe_end(o); spx_observe_end(o);
}
int main(int argc,char **argv) {
    REQUIRE(argc == 4); uint32_t seed=(uint32_t)strtoul(argv[2],NULL,10);
    menu_mode=(uint32_t)strtoul(argv[3],NULL,10); REQUIRE(menu_mode < 12); font_setup(seed,0);
    for (unsigned i=0;i<361;++i) { samples[i]=(int32_t)((i*seed)%2049)-1024; cosine[i]=(int32_t)((i*31+seed)%2049)-1024; }
    memset(pixels,seed,sizeof(pixels)); memset(&palettes,seed,sizeof(palettes));
    flow.overlay=&surfaces[4]; flow.next_scene=4;
    title=(title_state){.font=&font,.palettes=&palettes,.flow=&flow,.primary=&surfaces[1],.software=&surfaces[2],
        .back=&surfaces[0],.message=message,.sine=samples,.length=sizeof(message),.palette_width=120,.fast=1};
    scene=(scene_state){.animation=&title,.flip=&surfaces[5],.presentation_mode=menu_mode%2,
        .mouse_x=menu_mode == 2 ? 600 : 0xffffffff,.mouse_y=menu_mode%2 ? 0xfffffffd : 448,.mouse_buttons=menu_mode%4};
    menu=(menu_state){.scene=&scene,.cosine=cosine,.score=menu_mode == 0 ? 0 : menu_mode == 1 ? 1 : 0xffffffffU-menu_mode,
        .input_ready=menu_mode%2,.last_tick=0xffffffdd}; clock_value=0xfffffff0;
    scene_image_name="mainmenu.pcx"; scene_bank_names[0]="mainmenu.sbk";
    scene_bank_names[1]="thefont.sbk"; scene_bank_names[2]="sfont.sbk"; scene_redraw_callback=menu_redraw_callback;
#ifndef DX_STANDALONE
    int source=!strcmp(argv[1],"source"); menu_install(source); menu_to_native();
#define MENU_CALL(name,address) ((void (*)(void))address)(); menu_from_native(); menu_snapshot(&o)
#define MENU_ARG(name,address,value) ((void (*)(uint32_t))address)(value); menu_from_native(); menu_snapshot(&o)
#else
    REQUIRE(!strcmp(argv[1],"source"));
#define MENU_CALL(name,address) fixture_menu_##name(&menu); menu_snapshot(&o)
#define MENU_ARG(name,address,value) fixture_menu_##name(&menu,value); menu_snapshot(&o)
#endif
    fputs("{\"menu\":",stdout); spx_observer o=spx_observe_begin(stdout); spx_observe_array(&o,"states");
    MENU_CALL(enter,0x40ae80); MENU_CALL(update,0x40b1f0);
    uint32_t keys[]={0x20,0x70,0xabcd0070,0x71}; MENU_ARG(key,0x40b2a0,keys[menu_mode%4]);
    MENU_CALL(redraw,0x40af80); MENU_CALL(initialize_dots,0x40b2d0); MENU_CALL(animate,0x40ba40);
    MENU_ARG(leave,0x40bbf0,menu_mode%2); spx_observe_end(&o);
    spx_observe_array(&o,"calls");
    for (uint32_t i=0;i<menu_count;++i) spx_observe_u32s(&o,NULL,menu_calls[i],8);
    spx_observe_end(&o); spx_observe_array(&o,"scene_calls");
    for (uint32_t i=0;i<scene_count;++i) spx_observe_u32s(&o,NULL,scene_calls[i],14);
    spx_observe_end(&o); spx_observe_array(&o,"blits");
    for (uint32_t i=0;i<call_count;++i) spx_observe_u32s(&o,NULL,title_calls[i],12);
    spx_observe_end(&o); spx_observe_array(&o,"font_blits");
    for (uint32_t i=0;i<blit_count;++i) spx_observe_u32s(&o,NULL,blits[i],12);
    spx_observe_end(&o); spx_observe_array(&o,"text");
    for (uint32_t i=0;i<text_count;++i) {
        spx_observe_object(&o,NULL); spx_observe_u32s(&o,"position",text_calls[i],4);
        spx_observe_bytes(&o,"bytes",text_bytes[i],text_lengths[i]); spx_observe_end(&o);
    }
    spx_observe_end(&o); spx_observe_bytes(&o,"pixels",pixels,sizeof(pixels)); REQUIRE(spx_observe_finish(&o));
    /* The cleanup consumer's first canary is BANK_BASE-4. That address is
     * offsets[359][1] in the larger menu boundary, so it is now an alias of
     * observed application state rather than independent guard storage. */
#ifndef DX_STANDALONE
    REQUIRE(guards[0] == menu.offsets[359][1]);
#endif
    guards[0] = menu.offsets[359][1];
    fputs(",\"objects\":",stdout); font_observe_objects(); fputs("}\n",stdout); REQUIRE(!active_lease);
#ifndef DX_STANDALONE
    if (source) {
        REQUIRE(install_menu_enter_intact() && install_menu_redraw_intact() && install_menu_update_intact()
            && install_menu_key_intact() && install_menu_leave_intact() && install_menu_initialize_dots_intact() && install_menu_animate_intact());
        for (unsigned i=0;i<7;++i) REQUIRE(menu_entries[i]);
    }
#endif
    return 0;
}

#ifndef DX_STANDALONE
static LONG WINAPI menu_fault(EXCEPTION_POINTERS *p) {
    fprintf(stderr,"native fault %08lx at %08lx\n",p->ExceptionRecord->ExceptionCode,p->ContextRecord->Eip);
    fflush(NULL); ExitProcess(86); return EXCEPTION_EXECUTE_HANDLER;
}
static void menu_run_case(void) {
    SetUnhandledExceptionFilter(menu_fault); int count; char **args,**environment; struct native_startupinfo startup={0};
    REQUIRE(__getmainargs(&count,&args,&environment,0,&startup) == 0);
    int result=main(count,args); fflush(NULL); ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_menu_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance; (void)reserved;
    return reason != DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL) == 0x400000 && install_startup(menu_run_case));
}
#endif
#endif /* MENU_LIBRARY_ONLY */
