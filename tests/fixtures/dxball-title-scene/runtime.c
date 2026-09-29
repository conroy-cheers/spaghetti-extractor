/* Controlled platform services around the real scene and connected C units. */
#define TITLE_LIBRARY_ONLY 1
#define TITLE_SURFACE_COUNT 6
#include "title-runtime.c"
#include "scene-runtime.h"

static scene_state scene;
static uint32_t scene_entries[5], scene_mode, scene_calls[1600][14], scene_count, line_count;
static uint32_t background_id;
static const char *scene_image_name = "intro.pcx";
static const char *scene_bank_names[3] = {"candy.sbk", "chisel2.sbk", NULL};
static void (*scene_redraw_callback)(scene_state *) = fixture_scene_redraw;
#ifndef DX_STANDALONE
static uint32_t scene_redraw_address = 0x40a200;
#endif
void scene_enter(unsigned operation) { REQUIRE(operation < 5); ++scene_entries[operation]; }
#define RECORD(...) do { \
    const uint32_t values[] = {__VA_ARGS__}; REQUIRE(scene_count < 1600 && sizeof(values) <= sizeof(scene_calls[0])); \
    memcpy(scene_calls[scene_count++], values, sizeof(values)); \
} while (0)
#define STATE(s) REQUIRE((s) == &scene); (void)unused
static unsigned char *scene_pixels(font_surface *surface) {
    uint32_t id = surface_id(surface); REQUIRE(id && id <= TITLE_SURFACE_COUNT); return pixels[id-1];
}
static uint32_t name_hash(const unsigned char *data, uint32_t size) {
    uint32_t hash = 2166136261U;
    for (uint32_t i = 0; i < size; ++i) hash = (hash ^ data[i]) * 16777619U;
    return hash;
}
void scene_reset_damage(void *unused, scene_state *s) { STATE(s); RECORD(0); }
void scene_clear(void *unused, scene_state *s, font_surface *surface, uint32_t color) {
    STATE(s); RECORD(1, surface_id(surface), color); memset(scene_pixels(surface), color, 640*480);
}
void scene_image(void *unused, scene_state *s, font_surface *surface, asset_name *name, uint32_t palette, uint32_t x, uint32_t y) {
    STATE(s); REQUIRE(!strcmp(name->text, scene_image_name)); RECORD(2, surface_id(surface), palette, x, y);
    unsigned char *bytes = scene_pixels(surface);
    for (unsigned i = 0; i < 640*480; ++i) bytes[i] = (unsigned char)(i*7+3);
}
void scene_load_bank(void *unused, scene_state *s, uint32_t bank, uint32_t mode, asset_name *name) {
    STATE(s); REQUIRE(bank < 3 && scene_bank_names[bank]); REQUIRE(!strcmp(name->text, scene_bank_names[bank]));
    RECORD(3, bank, mode); /* Existing font objects are the admitted loaded bank. */
}
void scene_select_bank(void *unused, scene_state *s, uint32_t bank) {
    STATE(s); fixture_select(&state, bank);
}
void scene_select_font(void *unused, scene_state *s, uint32_t bank) {
    STATE(s); fixture_font_select(&font, bank);
}
void scene_load_sound(void *unused, scene_state *s, uint32_t slot, asset_name *name) {
    STATE(s); REQUIRE(!strcmp(name->text, "whine.wav")); RECORD(4, slot);
}
void scene_damage_background(void *unused, scene_state *s, font_surface *surface) {
    STATE(s); background_id = surface_id(surface); RECORD(5, background_id);
}
void scene_damage_destination(void *unused, scene_state *s, font_surface *surface) {
    STATE(s); title.software = surface; RECORD(6, surface_id(surface));
}
void scene_color_key(void *unused, scene_state *s, font_surface *surface, uint32_t low, uint32_t high) {
    STATE(s); RECORD(7, surface_id(surface), low, high);
}
void scene_redraw_scene(void *unused, scene_state *s) { STATE(s); RECORD(8); scene_redraw_callback(s); }
void scene_play_sound(void *unused, scene_state *s, uint32_t slot, uint32_t a, uint32_t b, uint32_t c) {
    STATE(s); RECORD(9, slot, a, b, c);
    if (scene_mode == 7) s->presentation_mode ^= 1;
}
void scene_fade(void *unused, scene_state *s, uint32_t wait, uint32_t step, uint32_t first, uint32_t last, uint32_t direction) {
    STATE(s); RECORD(10, wait, step, first, last, direction);
    memcpy(palettes.current, palettes.staged, sizeof(palettes.current));
}
static void fill_pixels(font_surface *surface, uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2, uint32_t color) {
    REQUIRE(x1 <= x2 && x2 < 640 && y1 <= y2 && y2 < 480);
    for (uint32_t y = y1; y <= y2; ++y) memset(scene_pixels(surface)+y*640+x1, color, x2-x1+1);
}
void scene_fill(void *unused, scene_state *s, font_surface *surface, uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2, uint32_t color) {
    STATE(s); RECORD(11, surface_id(surface), x1, y1, x2, y2, color); fill_pixels(surface, x1, y1, x2, y2, color);
}
void scene_blit(void *unused, scene_state *s, font_surface *destination, font_rect *dr, font_surface *source, font_rect *sr, uint32_t flags) {
    STATE(s); RECORD(12, surface_id(destination), dr->left, dr->top, dr->right, dr->bottom,
        surface_id(source), sr->left, sr->top, sr->right, sr->bottom, flags);
    REQUIRE(flags == 0x01000000 && dr->right-dr->left == sr->right-sr->left && dr->bottom-dr->top == sr->bottom-sr->top);
    REQUIRE(dr->left <= dr->right && dr->right <= 640 && dr->top <= dr->bottom && dr->bottom <= 480);
    REQUIRE(sr->left <= sr->right && sr->right <= 640 && sr->top <= sr->bottom && sr->bottom <= 480);
    for (uint32_t y = 0; y < sr->bottom-sr->top; ++y)
        memmove(scene_pixels(destination)+(dr->top+y)*640+dr->left, scene_pixels(source)+(sr->top+y)*640+sr->left, sr->right-sr->left);
}
void scene_wobble(void *unused, scene_state *s) { STATE(s); fixture_title_wobble(&title); }
void scene_scroll(void *unused, scene_state *s) { STATE(s); fixture_title_scroll(&title); }
void scene_wave(void *unused, scene_state *s) { STATE(s); fixture_title_wave(&title); }
void scene_cycle(void *unused, scene_state *s) { STATE(s); fixture_title_cycle(&title); }
void scene_line(void *unused, scene_state *s, font_surface *surface, uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2, uint32_t color) {
    STATE(s); RECORD(13, surface_id(surface), x1, y1, x2, y2, color);
    REQUIRE(x1 == x2 || y1 == y2); fill_pixels(surface, x1, y1, x2, y2, color);
    if (scene_mode == 7 && !line_count++) { title.palette_width = 2; title.primary = &surfaces[3]; }
}
void scene_sprite_destination(void *unused, scene_state *s, font_surface *surface) {
    STATE(s); fixture_sprite_destination(&font, surface);
}
void scene_text(void *unused, scene_state *s, uint32_t x, uint32_t y, uint32_t length, font_bytes *bytes) {
    STATE(s); fixture_font_line(&font, x, y, length, bytes);
}
void scene_center(void *unused, scene_state *s, uint32_t x, uint32_t y, uint32_t length, font_bytes *bytes) {
    STATE(s); fixture_font_center(&font, x, y, length, bytes);
}
void scene_wait(void *unused, scene_state *s, uint32_t count) { STATE(s); RECORD(14, count); }
void scene_restore_damage(void *unused, scene_state *s) {
    STATE(s); RECORD(15);
    if (scene_mode == 7) { s->mouse_x = 0xffffffff; s->mouse_y = 0xfffffffc; s->mouse_buttons = 1; }
}
void scene_present(void *unused, scene_state *s) { STATE(s); RECORD(16); }
void scene_rotate_palette(void *unused, scene_state *s, uint32_t first, uint32_t count) {
    STATE(s); REQUIRE(first == 189 && count == 66); RECORD(17, first, count);
    uint32_t saved = s->palette_cycle[0]; memmove(s->palette_cycle, s->palette_cycle+1, 65*sizeof(uint32_t)); s->palette_cycle[65] = saved;
}
void scene_stop_sound(void *unused, scene_state *s, uint32_t slot) { STATE(s); RECORD(18, slot); }
void scene_release_banks(void *unused, scene_state *s) { STATE(s); fixture_clear(&state); }
void scene_release_sounds(void *unused, scene_state *s) { STATE(s); RECORD(19); }
void scene_release_track(void *unused, scene_state *s) { STATE(s); RECORD(20); }

#ifndef DX_STANDALONE
#define scene_parent_to_native title_to_native
#define scene_parent_from_native title_from_native
#include "scene-native.h"
#define SCENE_CALLBACK(name, parameters, ...) static void native_scene_##name parameters { \
    scene_from_native(); scene_##name(NULL, &scene, __VA_ARGS__); scene_to_native(); }
#define SCENE_CALLBACK0(name) static void native_scene_##name(void) { \
    scene_from_native(); scene_##name(NULL, &scene); scene_to_native(); }
SCENE_CALLBACK0(reset_damage) SCENE_CALLBACK0(restore_damage) SCENE_CALLBACK0(present) SCENE_CALLBACK0(release_sounds) SCENE_CALLBACK0(release_track)
SCENE_CALLBACK(clear, (uint32_t surface, uint32_t color), title_surface_view(surface), color)
SCENE_CALLBACK(damage_background, (uint32_t surface), title_surface_view(surface))
SCENE_CALLBACK(damage_destination, (uint32_t surface), title_surface_view(surface))
SCENE_CALLBACK(play_sound, (uint32_t slot, uint32_t a, uint32_t b, uint32_t c), slot, a, b, c)
SCENE_CALLBACK(fade, (uint32_t wait, uint32_t step, uint32_t first, uint32_t last, uint32_t direction), wait, step, first, last, direction)
SCENE_CALLBACK(fill, (uint32_t surface, uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2, uint32_t color), title_surface_view(surface), x1, y1, x2, y2, color)
SCENE_CALLBACK(line, (uint32_t surface, uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2, uint32_t color), title_surface_view(surface), x1, y1, x2, y2, color)
SCENE_CALLBACK(wait, (uint32_t count), count) SCENE_CALLBACK(stop_sound, (uint32_t slot), slot)
static void native_scene_image(uint32_t surface, const char *name, uint32_t palette, uint32_t x, uint32_t y) {
    asset_name text = {name}; scene_from_native(); scene_image(NULL, &scene, title_surface_view(surface), &text, palette, x, y); scene_to_native();
}
static void native_scene_load_bank(uint32_t bank, uint32_t mode, const char *name) {
    asset_name text = {name}; scene_from_native(); scene_load_bank(NULL, &scene, bank, mode, &text); scene_to_native();
}
static void native_scene_load_sound(uint32_t slot, const char *name) {
    asset_name text = {name}; scene_from_native(); scene_load_sound(NULL, &scene, slot, &text); scene_to_native();
}
static void native_scene_rotate_palette(uint32_t first, uint32_t count, void *buffer) {
    REQUIRE(buffer == (void *)0x417650); scene_from_native(); scene_rotate_palette(NULL, &scene, first, count); scene_to_native();
}
static void native_scene_redraw_scene(void) { RECORD(8); ((void (*)(void))(uintptr_t)scene_redraw_address)(); }
static uint32_t WINAPI native_scene_color_key(uint32_t surface, uint32_t flags, uint32_t *key) {
    REQUIRE(flags == 8); scene_from_native(); scene_color_key(NULL, &scene, title_surface_view(surface), key[0], key[1]); scene_to_native(); return 0x80004005;
}
static uint32_t WINAPI native_scene_blit(uint32_t destination, font_rect *dr, uint32_t source, font_rect *sr, uint32_t flags, void *effects) {
    if (flags == 0x01008000) return native_blit(destination, dr, source, sr, flags, effects);
    REQUIRE(!effects); scene_from_native(); scene_blit(NULL, &scene, title_surface_view(destination), dr, title_surface_view(source), sr, flags);
    scene_to_native(); return 0x80004005;
}
#define ROOT(name) static void native_root_##name(void) { scene_from_native(); fixture_scene_##name(&scene); scene_to_native(); }
ROOT(enter) ROOT(redraw) ROOT(update)
static void native_root_key(uint32_t key) { scene_from_native(); fixture_scene_key(&scene, key); scene_to_native(); }
static void native_root_leave(uint32_t reason) { scene_from_native(); fixture_scene_leave(&scene, reason); scene_to_native(); }
static void scene_install(int source) {
    title_install(source); font_vtable[5] = (uint32_t)(uintptr_t)native_scene_blit;
    font_vtable[29] = (uint32_t)(uintptr_t)native_scene_color_key;
#define SERVICE(name) REQUIRE(install_service_##name((void (*)(void))native_scene_##name));
    SERVICE(reset_damage) SERVICE(clear) SERVICE(image) SERVICE(load_bank) SERVICE(load_sound)
    SERVICE(damage_background) SERVICE(damage_destination) SERVICE(redraw_scene) SERVICE(play_sound)
    SERVICE(fade) SERVICE(fill) SERVICE(line) SERVICE(wait) SERVICE(restore_damage) SERVICE(present)
    SERVICE(rotate_palette) SERVICE(stop_sound) SERVICE(release_sounds) SERVICE(release_track)
    if (!source) return;
#define SCENE_INSTALL(name) REQUIRE(install_scene_##name((void (*)(void))native_root_##name));
    SCENE_INSTALL(enter) SCENE_INSTALL(redraw) SCENE_INSTALL(update) SCENE_INSTALL(key) SCENE_INSTALL(leave)
}
#endif

static void snapshot(spx_observer *o) {
    spx_observe_object(o, NULL);
    uint32_t values[] = {scene.presentation_mode,scene.no_hardware,scene.low_memory,scene.refresh_ok,
        scene.mouse_x,scene.mouse_y,scene.cursor_x,scene.cursor_y,scene.mouse_buttons,scene.scroll_auxiliary,
        flow.transition_pending,flow.next_scene,background_id,surface_id(scene.flip)};
    spx_observe_u32s(o, "state", values, sizeof(values)/sizeof(*values));
    uint32_t animation[] = {title.length,title.index,title.advance,title.glyph_width,title.wobble_phase,
        title.first_offset,title.second_offset,title.palette_width,title.palette_phase,title.palette_offset,title.fast,
        surface_id(title.primary),surface_id(title.software),surface_id(title.back),font.bank,surface_id(font.destination)};
    spx_observe_u32s(o, "animation", animation, sizeof(animation)/sizeof(*animation));
    spx_observe_bytes(o, "palettes", (const unsigned char *)&palettes, sizeof(palettes));
    spx_observe_bytes(o, "rotation", (const unsigned char *)scene.palette_cycle, sizeof(scene.palette_cycle));
    uint32_t hashes[TITLE_SURFACE_COUNT];
    for (unsigned i = 0; i < TITLE_SURFACE_COUNT; ++i) hashes[i] = name_hash(pixels[i], sizeof(pixels[i]));
    spx_observe_u32s(o, "pixels", hashes, TITLE_SURFACE_COUNT); spx_observe_end(o);
}
#ifndef SCENE_LIBRARY_ONLY
int main(int argc, char **argv) {
    REQUIRE(argc == 4); uint32_t seed = (uint32_t)strtoul(argv[2], NULL, 10);
    scene_mode = (uint32_t)strtoul(argv[3], NULL, 10); REQUIRE(scene_mode < 12);
    font_setup(seed, 0);
    for (uint32_t i = 0; i < 361; ++i) samples[i] = (int32_t)((i*seed)%2049)-1024;
    memset(pixels, seed, sizeof(pixels)); memset(&palettes, seed, sizeof(palettes));
    flow.overlay = &surfaces[4]; flow.windowed = scene_mode == 6; flow.next_scene = 3;
    title = (title_state){.font=&font,.palettes=&palettes,.flow=&flow,.primary=&surfaces[1],.software=&surfaces[2],
        .back=&surfaces[0],.message=message,.sine=samples,.length=sizeof(message),.index=2,
        .advance=13,.glyph_width=11,.wobble_phase=17,.first_offset=3,.second_offset=4,
        .palette_width=scene_mode == 8 ? 0 : scene_mode == 9 ? 160 : 120,.palette_phase=359,.palette_offset=7,.fast=scene_mode%2};
    scene = (scene_state){.animation=&title,.flip=&surfaces[5],.presentation_mode=scene_mode%2,
        .no_hardware=scene_mode%4 == 0,.low_memory=scene_mode%4 == 1,.refresh_ok=scene_mode%4 == 3,
        .mouse_x=scene_mode == 10 ? 600 : scene_mode == 11 ? 8 : 0xffffffff,
        .mouse_y=scene_mode%2 ? 0xfffffff0 : 448,.mouse_buttons=scene_mode%4,.scroll_auxiliary=23};
    for (uint32_t i = 0; i < 66; ++i) scene.palette_cycle[i] = i*0x12345+seed;
#ifndef DX_STANDALONE
    int source = !strcmp(argv[1], "source"); scene_install(source); scene_to_native();
#define CALL(name, address) ((void (*)(void))address)(); scene_from_native(); snapshot(&o)
#define ARG(name, address, argument) ((void (*)(uint32_t))address)(argument); scene_from_native(); snapshot(&o)
#else
    REQUIRE(!strcmp(argv[1], "source"));
#define CALL(name, address) fixture_scene_##name(&scene); snapshot(&o)
#define ARG(name, address, argument) fixture_scene_##name(&scene, argument); snapshot(&o)
#endif
    fputs("{\"scene_state\":", stdout);
    spx_observer o = spx_observe_begin(stdout); spx_observe_array(&o, "scene");
    CALL(enter, 0x40a0b0); CALL(update, 0x40a510); ARG(key, 0x40a5f0, 0xfeed);
    CALL(redraw, 0x40a200); ARG(leave, 0x40a610, scene_mode%2);
    spx_observe_end(&o); spx_observe_bytes(&o, "pixels", (const unsigned char *)pixels, sizeof(pixels));
    spx_observe_array(&o, "calls");
    for (uint32_t i = 0; i < scene_count; ++i) spx_observe_u32s(&o, NULL, scene_calls[i], 14);
    spx_observe_end(&o); spx_observe_array(&o, "animation_calls");
    for (uint32_t i = 0; i < call_count; ++i) spx_observe_u32s(&o, NULL, title_calls[i], 12);
    spx_observe_end(&o); spx_observe_array(&o, "font_blits");
    for (uint32_t i = 0; i < blit_count; ++i) spx_observe_u32s(&o, NULL, blits[i], 12);
    spx_observe_end(&o); REQUIRE(spx_observe_finish(&o));
    fputs(",\"objects\":", stdout); font_observe_objects(); fputs("}\n", stdout);
#ifndef DX_STANDALONE
    if (source) {
        REQUIRE(install_scene_enter_intact() && install_scene_redraw_intact() && install_scene_update_intact()
            && install_scene_key_intact() && install_scene_leave_intact());
        for (unsigned i = 0; i < 5; ++i) REQUIRE(scene_entries[i]);
    }
#endif
    return 0;
}

#ifndef DX_STANDALONE
static LONG WINAPI scene_fault(EXCEPTION_POINTERS *p) {
    fprintf(stderr, "native fault %08lx at %08lx\n", p->ExceptionRecord->ExceptionCode, p->ContextRecord->Eip);
    fflush(NULL); ExitProcess(86); return EXCEPTION_EXECUTE_HANDLER;
}
static void scene_run_case(void) {
    SetUnhandledExceptionFilter(scene_fault);
    int count; char **args, **environment; struct native_startupinfo startup = {0};
    REQUIRE(__getmainargs(&count, &args, &environment, 0, &startup) == 0);
    int result = main(count, args); fflush(NULL); ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_scene_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved) {
    (void)instance; (void)reserved;
    return reason != DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL) == 0x400000 && install_startup(scene_run_case));
}
#endif
#endif /* SCENE_LIBRARY_ONLY */
