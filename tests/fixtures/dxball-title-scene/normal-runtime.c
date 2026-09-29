/* Scene orchestration uses the existing real game consumer and platform calls. */
#define TITLE_NORMAL_LIBRARY_ONLY 1
#include "title-normal-runtime.c"
#include "scene-runtime.h"

static scene_state scene = {.animation=&title};
static uint32_t scene_entries[5], scene_count, scene_calls[32][28];
void scene_enter(unsigned operation) { REQUIRE(operation < 5); ++scene_entries[operation]; }
static void scene_parent_to_native(void) {
    /* These aliases name the same native surface cells. The scene's animation
     * view owns edits within this call; flow shares the updated objects. */
    flow.primary = title.primary; flow.back = title.back;
    flow_to_native(); title_to_native();
}
static void scene_parent_from_native(void) { flow_from_native(); title_from_native(); }
#include "scene-native.h"
#define BEGIN() (void)unused; REQUIRE(s == &scene); scene_to_native()
#define END() scene_from_native()
#define ZERO(name, address) void scene_##name(void *unused, scene_state *s) { \
    BEGIN(); ((void (*)(void))(uintptr_t)address)(); END(); }
#define ONE(name, address) void scene_##name(void *unused, scene_state *s, uint32_t value) { \
    BEGIN(); ((void (*)(uint32_t))(uintptr_t)address)(value); END(); }
#define SURFACE(name, address) void scene_##name(void *unused, scene_state *s, font_surface *surface) { \
    BEGIN(); ((void (*)(uint32_t))(uintptr_t)address)(surface_address(surface)); END(); }
ZERO(reset_damage, 0x401000) ZERO(restore_damage, 0x401430) ZERO(present, 0x401650)
ZERO(release_sounds, 0x402f90) ZERO(release_track, 0x402200)
ONE(wait, 0x402240) ONE(stop_sound, 0x403370)
SURFACE(damage_background, 0x401630) SURFACE(damage_destination, 0x401640)
void scene_clear(void *unused, scene_state *s, font_surface *surface, uint32_t color) {
    BEGIN(); ((void (*)(uint32_t,uint32_t))0x402710)(surface_address(surface), color); END();
}
void scene_image(void *unused, scene_state *s, font_surface *surface, asset_name *name, uint32_t palette, uint32_t x, uint32_t y) {
    BEGIN(); live_pcx_draw(surface_address(surface), name->text, palette, x, y); END();
}
void scene_load_bank(void *unused, scene_state *s, uint32_t bank, uint32_t mode, asset_name *name) {
    BEGIN(); live_load(bank, mode, name->text); END();
}
void scene_select_bank(void *unused, scene_state *s, uint32_t bank) { BEGIN(); native_select(bank); END(); }
void scene_select_font(void *unused, scene_state *s, uint32_t bank) { BEGIN(); native_font_select(bank); END(); }
void scene_load_sound(void *unused, scene_state *s, uint32_t slot, asset_name *name) {
    BEGIN(); ((void (*)(uint32_t,const char *))0x403000)(slot, name->text); END();
}
void scene_color_key(void *unused, scene_state *s, font_surface *surface, uint32_t low, uint32_t high) {
    BEGIN(); uint32_t key[] = {low, high}, address = surface_address(surface), *table = word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,uint32_t,uint32_t *))(uintptr_t)table[29])(address, 8, key); END();
}
void scene_redraw_scene(void *unused, scene_state *s) { BEGIN(); live_flow_redraw(); END(); }
void scene_play_sound(void *unused, scene_state *s, uint32_t slot, uint32_t a, uint32_t b, uint32_t c) {
    BEGIN(); ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))0x4032b0)(slot,a,b,c); END();
}
void scene_fade(void *unused, scene_state *s, uint32_t wait, uint32_t step, uint32_t first, uint32_t last, uint32_t direction) {
    BEGIN(); ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))0x402770)(wait,step,first,last,direction); END();
}
#define LINE(name, address) \
void scene_##name(void *unused, scene_state *s, font_surface *surface, uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2, uint32_t color) { \
    BEGIN(); ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))(uintptr_t)address) \
        (surface_address(surface),x1,y1,x2,y2,color); END(); }
LINE(fill, 0x40d990) LINE(line, 0x40d850)
void scene_blit(void *unused, scene_state *s, font_surface *destination, font_rect *dr, font_surface *source, font_rect *sr, uint32_t flags) {
    BEGIN(); uint32_t address = surface_address(destination), *table = word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,font_rect *,uint32_t,font_rect *,uint32_t,void *))(uintptr_t)table[5])
        (address,dr,surface_address(source),sr,flags,NULL); END();
}
#define ANIMATION(name) void scene_##name(void *unused, scene_state *s) { BEGIN(); live_title_##name(); END(); }
ANIMATION(wobble) ANIMATION(scroll) ANIMATION(wave) ANIMATION(cycle)
void scene_sprite_destination(void *unused, scene_state *s, font_surface *surface) {
    BEGIN(); live_destination(surface_address(surface)); END();
}
void scene_text(void *unused, scene_state *s, uint32_t x, uint32_t y, uint32_t length, font_bytes *bytes) {
    BEGIN(); live_line(x,y,length,bytes->data); END();
}
void scene_center(void *unused, scene_state *s, uint32_t x, uint32_t y, uint32_t length, font_bytes *bytes) {
    BEGIN(); live_center(x,y,length,bytes->data); END();
}
void scene_rotate_palette(void *unused, scene_state *s, uint32_t first, uint32_t count) {
    BEGIN(); ((void (*)(uint32_t,uint32_t,void *))0x402ba0)(first,count,(void *)0x417650); END();
}
void scene_release_banks(void *unused, scene_state *s) { BEGIN(); native_clear(); END(); }
static void scene_record(unsigned operation, uint32_t argument) {
    if (scene_count == 32) return;
    scene_from_native(); uint32_t *row = scene_calls[scene_count++];
    uint32_t values[] = {operation,argument,scene.presentation_mode,scene.no_hardware,scene.low_memory,scene.refresh_ok,
        scene.mouse_x,scene.mouse_y,scene.cursor_x,scene.cursor_y,scene.mouse_buttons,scene.scroll_auxiliary,
        flow.scene,flow.transition_pending,flow.next_scene,title.length,title.index,title.advance,title.palette_width,title.palette_phase};
    memcpy(row,values,sizeof(values));
    uint64_t hashes[] = {title_surface_hash(surface_address(title.primary)), title_surface_hash(surface_address(title.back)),
        hash_bytes(UINT64_C(14695981039346656037),(const unsigned char *)0x42c148,2048),
        hash_bytes(UINT64_C(14695981039346656037),(const unsigned char *)scene.palette_cycle,sizeof(scene.palette_cycle))};
    for (unsigned i = 0; i < 4; ++i) { row[20+2*i] = (uint32_t)hashes[i]; row[21+2*i] = (uint32_t)(hashes[i]>>32); }
}
#define LIVE_SCENE(name, operation, address, parameters, arguments, call, argument) \
static void live_scene_##name parameters { \
    if (source_side) { scene_from_native(); fixture_scene_##name call; scene_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_scene_##name##_hook)); \
        ((void (*) parameters)(uintptr_t)address) arguments; \
        install_scene_##name##_hook.entry = NULL; REQUIRE(install_scene_##name((void (*)(void))live_scene_##name)); } \
    scene_record(operation,argument); \
}
LIVE_SCENE(enter, 0, 0x40a0b0, (void), (), (&scene), 0)
LIVE_SCENE(redraw, 1, 0x40a200, (void), (), (&scene), 0)
LIVE_SCENE(update, 2, 0x40a510, (void), (), (&scene), 0)
LIVE_SCENE(key, 3, 0x40a5f0, (uint32_t value), (value), (&scene,value), value)
LIVE_SCENE(leave, 4, 0x40a610, (uint32_t value), (value), (&scene,value), value)
static void scene_observe(spx_observer *o) {
    title_observe(o); spx_observe_array(o,"title_scene");
    for (uint32_t i = 0; i < scene_count; ++i) spx_observe_u32s(o,NULL,scene_calls[i],28);
    spx_observe_end(o);
}
static void scene_diagnose(spx_observer *o) {
    title_diagnose(o); spx_observe_u32s(o,"selected_scene",scene_entries,5);
}
static void scene_report(void) {
    const char *path = getenv("SPX_COMPARISON_REPORT"); if (!path) return;
    FILE *out = fopen(path, "wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o = spx_observe_begin(out); scene_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o = spx_observe_begin(out);
    scene_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL scene_main(HINSTANCE instance, DWORD reason, void *reserved) {
    if (!title_main(instance,reason,reserved)) return FALSE;
    if (reason == DLL_PROCESS_DETACH) { scene_report(); return TRUE; }
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
#define SCENE_INSTALL(name) REQUIRE(install_scene_##name((void (*)(void))live_scene_##name));
    SCENE_INSTALL(enter) SCENE_INSTALL(redraw) SCENE_INSTALL(update) SCENE_INSTALL(key) SCENE_INSTALL(leave)
    return TRUE;
}
#ifndef SCENE_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved) {
    return scene_main(instance,reason,reserved);
}
#endif
