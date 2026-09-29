/* Use the existing live scene consumer and actual native platform services. */
#define SCENE_NORMAL_LIBRARY_ONLY 1
#include "scene-normal-runtime.c"
#include "menu-runtime.h"

static menu_state menu = {.scene=&scene,.cosine=(const int32_t *)0x435750};
static uint32_t menu_entries[7], menu_depth, menu_count, menu_calls[32][25], menu_ticks[32];
void menu_enter(unsigned operation) { REQUIRE(operation < 7); ++menu_entries[operation]; }
#include "menu-native.h"
#define MENU_COMMON_PUSH() menu_to_native()
#define MENU_COMMON_PULL() menu_from_native()
#include "menu-common.h"
#define MENU_BEGIN() (void)unused; REQUIRE(s == &menu); menu_to_native()
#define MENU_END() menu_from_native()
void menu_text(void *unused,scene_state *s,uint32_t x,uint32_t y,uint32_t length,font_bytes *bytes) {
    menu_to_native(); scene_text(unused,s,x,y,length,bytes); menu_from_native();
}
void menu_center(void *unused,scene_state *s,uint32_t x,uint32_t y,uint32_t length,font_bytes *bytes) {
    menu_to_native(); scene_center(unused,s,x,y,length,bytes); menu_from_native();
}
void menu_load_track(void *unused,menu_state *s,asset_name *name,uint32_t mode) {
    MENU_BEGIN(); ((void (*)(const char *,uint32_t))0x402100)(name->text,mode); MENU_END();
}
uint32_t menu_elapsed(void *unused,menu_state *s,uint32_t previous,uint32_t delay) {
    MENU_BEGIN(); uint32_t result=((uint32_t (*)(uint32_t,uint32_t))0x40db80)(previous,delay); MENU_END(); return result;
}
uint32_t menu_now(void *unused,menu_state *s) {
    MENU_BEGIN(); uint32_t result=((uint32_t (*)(void))0x40db20)(); MENU_END(); return result;
}
void menu_blit_fast(void *unused,menu_state *s,font_surface *destination,uint32_t x,uint32_t y,
                    font_surface *source,font_rect *rectangle,uint32_t flags) {
    MENU_BEGIN(); title_blit_fast(unused,&title,destination,x,y,source,rectangle,flags); MENU_END();
}
void menu_describe(void *unused,font_surface *surface,pcx_view *view) {
    menu_to_native(); pcx_describe(unused,surface,view); menu_from_native();
}
uint32_t menu_lock(void *unused,font_surface *surface,pcx_view *view) {
    menu_to_native(); uint32_t result=pcx_lock(unused,surface,view); menu_from_native(); return result;
}
void menu_unlock(void *unused,font_surface *surface) {
    menu_to_native(); pcx_unlock(unused,surface); menu_from_native();
}
void menu_sprite(void *unused,menu_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    MENU_BEGIN(); live_transparent(slot,x,y); MENU_END();
}
void menu_damage(void *unused,menu_state *s,font_rect *rectangle) {
    MENU_BEGIN(); ((void (*)(font_rect))0x401350)(*rectangle); MENU_END();
}
#define MENU_PALETTE(name,address) \
void menu_##name(void *unused,menu_state *s,uint32_t first,uint32_t last,uint32_t step) { \
    MENU_BEGIN(); ((void (*)(uint32_t,uint32_t,uint32_t))(uintptr_t)address)(first,last,step); MENU_END(); \
}
MENU_PALETTE(cycle_palette,0x402a50) MENU_PALETTE(cycle_dots_palette,0x402af0)
static void menu_record(unsigned operation,uint32_t argument) {
    if (menu_count == 32) return;
    menu_from_native(); uint32_t index=menu_count++, *row=menu_calls[index];
    uint32_t values[]={operation,argument,menu.score,menu.input_ready,scene.presentation_mode,
        scene.mouse_x,scene.mouse_y,scene.cursor_x,scene.cursor_y,scene.mouse_buttons,
        flow.scene,flow.transition_pending,flow.next_scene};
    memcpy(row,values,sizeof(values)); menu_ticks[index]=menu.last_tick;
    uint64_t hashes[]={hash_bytes(UINT64_C(14695981039346656037),(const unsigned char *)menu.dots,sizeof(menu.dots)),
        hash_bytes(UINT64_C(14695981039346656037),(const unsigned char *)menu.offsets,sizeof(menu.offsets)),
        title_surface_hash(surface_address(title.primary)),title_surface_hash(surface_address(title.back)),
        hash_bytes(UINT64_C(14695981039346656037),(const unsigned char *)0x42c148,2048),
        hash_bytes(UINT64_C(14695981039346656037),(const unsigned char *)scene.palette_cycle,sizeof(scene.palette_cycle))};
    for (unsigned i=0;i<6;++i) { row[13+2*i]=(uint32_t)hashes[i]; row[14+2*i]=(uint32_t)(hashes[i]>>32); }
}
/* Source helper calls remain ordinary C calls. Observe complete outer operations
 * on both sides, rather than counting nested native entry wrappers as behavior. */
#define LIVE_MENU(name,operation,address,parameters,arguments,call,argument) \
static void live_menu_##name parameters { \
    unsigned outer=!menu_depth++; \
    if (source_side) { menu_from_native(); fixture_menu_##name call; menu_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_menu_##name##_hook)); \
        ((void (*) parameters)(uintptr_t)address) arguments; \
        install_menu_##name##_hook.entry=NULL; REQUIRE(install_menu_##name((void (*)(void))live_menu_##name)); } \
    --menu_depth; if (outer) menu_record(operation,argument); \
}
LIVE_MENU(enter,0,0x40ae80,(void),(),(&menu),0)
LIVE_MENU(redraw,1,0x40af80,(void),(),(&menu),0)
LIVE_MENU(update,2,0x40b1f0,(void),(),(&menu),0)
LIVE_MENU(key,3,0x40b2a0,(uint32_t value),(value),(&menu,value),value)
LIVE_MENU(leave,4,0x40bbf0,(uint32_t value),(value),(&menu,value),value)
LIVE_MENU(initialize_dots,5,0x40b2d0,(void),(),(&menu),0)
LIVE_MENU(animate,6,0x40ba40,(void),(),(&menu),0)
static void menu_observe(spx_observer *o) {
    scene_observe(o); spx_observe_array(o,"menu_scene");
    for (uint32_t i=0;i<menu_count;++i) spx_observe_u32s(o,NULL,menu_calls[i],25);
    spx_observe_end(o);
}
static void menu_diagnose(spx_observer *o) {
    scene_diagnose(o); spx_observe_u32s(o,"selected_menu",menu_entries,7);
    /* Absolute wall-clock readings are external inputs, retained as diagnostics.
     * Their resulting dot/palette/pixel effects remain in compared observations. */
    spx_observe_u32s(o,"menu_clock",menu_ticks,menu_count);
}
static void menu_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT"); if (!path) return;
    FILE *out=fopen(path,"wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out); menu_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o=spx_observe_begin(out);
    menu_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL menu_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!scene_main(instance,reason,reserved)) return FALSE;
    if (reason == DLL_PROCESS_DETACH) { menu_report(); return TRUE; }
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
#define MENU_INSTALL(name) REQUIRE(install_menu_##name((void (*)(void))live_menu_##name));
    MENU_INSTALL(enter) MENU_INSTALL(redraw) MENU_INSTALL(update) MENU_INSTALL(key) MENU_INSTALL(leave)
    MENU_INSTALL(initialize_dots) MENU_INSTALL(animate)
    return TRUE;
}
#ifndef MENU_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    return menu_main(instance,reason,reserved);
}
#endif
