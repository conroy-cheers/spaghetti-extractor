/* Reuse the live sprite/frame/image network and its actual DirectDraw objects. */
#define PCX_NORMAL_LIBRARY_ONLY 1
#include "pcx-normal-runtime.c"
#include "title-runtime.h"

static title_state title = {.font=&font, .palettes=&palettes, .flow=&flow,
    .message=(const unsigned char *)0x4168b0, .sine=(const int32_t *)0x4351a8};
static uint32_t title_entries[4], title_calls[24][19], title_count;
void title_enter(unsigned operation) { REQUIRE(operation < 4); ++title_entries[operation]; }
#define title_surface_address surface_address
#define title_surface_view surface_view
#define title_font_to_native push
#define title_font_from_native pull
#define title_palettes_to_native pcx_push
#define title_palettes_from_native pcx_pull
#include "title-native.h"

void title_select_font(void *unused, font_state *s, uint32_t bank) {
    (void)unused; REQUIRE(s == &font); title_to_native(); native_font_select(bank); title_from_native();
}
void title_destination(void *unused, font_state *s, font_surface *surface) {
    (void)unused; REQUIRE(s == &font); title_to_native(); live_destination(surface_address(surface)); title_from_native();
}
uint32_t title_glyph(void *unused, font_state *s, uint32_t character, uint32_t x, uint32_t y) {
    (void)unused; REQUIRE(s == &font); title_to_native(); uint32_t result = live_glyph(character, x, y); title_from_native(); return result;
}
void title_blit_fast(void *unused, title_state *s, font_surface *destination, uint32_t x, uint32_t y,
                    font_surface *source, font_rect *rect, uint32_t flags) {
    (void)unused; REQUIRE(s == &title); title_to_native();
    uint32_t address = surface_address(destination), *table = word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,uint32_t,uint32_t,uint32_t,font_rect *,uint32_t))(uintptr_t)table[7])
        (address, x, y, surface_address(source), rect, flags); title_from_native();
}
void title_apply_palette(void *unused, title_state *s, uint32_t first, uint32_t count) {
    (void)unused; REQUIRE(s == &title); title_to_native();
    uint32_t address = *word(0x4349b8), *table = word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,uint32_t,uint32_t,uint32_t,void *))(uintptr_t)table[6])
        (address, 0, first, count, (void *)(uintptr_t)(0x42c148+4*first)); title_from_native();
}
static uint64_t title_surface_hash(uint32_t address) {
    uint32_t *table = word(*word(address)), desc[27] = {0}; desc[0] = sizeof(desc);
    REQUIRE(((uint32_t (WINAPI *)(uint32_t,void *,void *,uint32_t,void *))(uintptr_t)table[25])
        (address, NULL, desc, 0, NULL) == 0);
    REQUIRE(desc[3] <= desc[4] && desc[3] <= 4096 && desc[2] <= 4096);
    uint64_t hash = UINT64_C(14695981039346656037);
    for (uint32_t y = 0; y < desc[2]; ++y)
        hash = hash_bytes(hash, (const unsigned char *)(uintptr_t)desc[9]+y*desc[4], desc[3]);
    REQUIRE(((uint32_t (WINAPI *)(uint32_t,void *))(uintptr_t)table[32])(address, NULL) == 0);
    return hash;
}
static void title_record(unsigned operation) {
    if (title_count == 24) return;
    uint32_t *row = title_calls[title_count++]; title_from_native();
    uint32_t values[] = {operation, title.index, title.advance, title.glyph_width, title.wobble_phase,
        title.first_offset, title.second_offset, title.palette_phase, title.palette_offset, title.fast,
        title.flow->windowed, title.length, title.palette_width};
    memcpy(row, values, sizeof(values));
    uint64_t back = title_surface_hash(surface_address(title.back));
    uint64_t display = title_surface_hash(surface_address(title.fast ? title.primary : title.software));
    uint64_t palette = hash_bytes(UINT64_C(14695981039346656037), (const unsigned char *)0x42c148, 1024);
    row[13] = (uint32_t)back; row[14] = (uint32_t)(back >> 32);
    row[15] = (uint32_t)display; row[16] = (uint32_t)(display >> 32);
    row[17] = (uint32_t)palette; row[18] = (uint32_t)(palette >> 32);
}
#define LIVE(name, operation, address) \
static void live_title_##name(void) { \
    if (source_side) { title_from_native(); fixture_title_##name(&title); title_to_native(); } \
    else { \
        REQUIRE(spx_fixture_restore_entry(&install_title_##name##_hook)); ((void (*)(void))(uintptr_t)address)(); \
        install_title_##name##_hook.entry = NULL; REQUIRE(install_title_##name((void (*)(void))live_title_##name)); \
    } \
    title_record(operation); \
}
LIVE(scroll, 0, 0x40a780) LIVE(wave, 1, 0x40a6c0) LIVE(wobble, 2, 0x40a850) LIVE(cycle, 3, 0x40a970)
static void title_observe(spx_observer *o) {
    pcx_observe(o); spx_observe_array(o, "title");
    for (uint32_t i = 0; i < title_count; ++i) spx_observe_u32s(o, NULL, title_calls[i], 19);
    spx_observe_end(o);
}
static void title_diagnose(spx_observer *o) {
    pcx_diagnose(o); spx_observe_u32s(o, "selected_title", title_entries, 4);
}
static void title_report(void) {
    const char *path = getenv("SPX_COMPARISON_REPORT"); if (!path) return;
    FILE *out = fopen(path, "wb"); REQUIRE(out);
    fprintf(out, "{\"side\":\"%s\",\"exit_code\":0,\"observations\":", source_side ? "source" : "original");
    spx_observer o = spx_observe_begin(out); title_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":", out); o = spx_observe_begin(out);
    title_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n", out); fclose(out);
}
static BOOL title_main(HINSTANCE instance, DWORD reason, void *reserved) {
    if (!pcx_main(instance, reason, reserved)) return FALSE;
    if (reason == DLL_PROCESS_DETACH) { title_report(); return TRUE; }
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
#define TITLE_INSTALL(name) REQUIRE(install_title_##name((void (*)(void))live_title_##name));
    TITLE_INSTALL(scroll) TITLE_INSTALL(wave) TITLE_INSTALL(wobble) TITLE_INSTALL(cycle)
    return TRUE;
}
#ifndef TITLE_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved) {
    return title_main(instance, reason, reserved);
}
#endif
