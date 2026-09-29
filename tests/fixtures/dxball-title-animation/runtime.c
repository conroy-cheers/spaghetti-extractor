/* Connected font services and owned graphics storage around real native bodies. */
#define FONT_LIBRARY_ONLY 1
#include "font-runtime.c"
#include "title-runtime.h"
#include "drawing-runtime.h"

static title_state title;
static flow_state flow;
static pcx_state palettes;
static int32_t samples[361];
static const unsigned char message[] = {'A', 'B', 'X', 'C', 255, 0};
#ifndef TITLE_SURFACE_COUNT
#define TITLE_SURFACE_COUNT 4
#endif
static unsigned char pixels[TITLE_SURFACE_COUNT][640 * 480];
#ifndef TITLE_CALL_CAPACITY
#define TITLE_CALL_CAPACITY 400
#endif
static uint32_t title_entries[4], title_mode, phase_calls, call_count, title_calls[TITLE_CALL_CAPACITY][12];
void title_enter(unsigned operation) { REQUIRE(operation < 4); ++title_entries[operation]; }
void drawing_enter(unsigned operation) { REQUIRE(operation < 3); }
void title_select_font(void *unused, font_state *s, uint32_t bank) { (void)unused; fixture_font_select(s, bank); }
void title_destination(void *unused, font_state *s, font_surface *surface) { (void)unused; fixture_sprite_destination(s, surface); }
uint32_t title_glyph(void *unused, font_state *s, uint32_t character, uint32_t x, uint32_t y) {
    (void)unused; return fixture_font_glyph(s, character, x, y);
}
void title_blit_fast(void *unused, title_state *s, font_surface *destination, uint32_t x, uint32_t y,
                    font_surface *source, font_rect *rect, uint32_t flags) {
    (void)unused; REQUIRE(s == &title && call_count < TITLE_CALL_CAPACITY);
    uint32_t dst = surface_id(destination), src = surface_id(source);
    REQUIRE(dst && dst <= TITLE_SURFACE_COUNT && src && src <= TITLE_SURFACE_COUNT && (flags == 0x10 || flags == 0x11));
    REQUIRE(rect->left <= rect->right && rect->right <= 640 && rect->top <= rect->bottom && rect->bottom <= 480);
    uint32_t width = rect->right - rect->left, height = rect->bottom - rect->top;
    REQUIRE(x <= 640-width && y <= 480-height);
    uint32_t *row = title_calls[call_count++];
    uint32_t values[] = {0, dst, x, y, src, rect->left, rect->top, rect->right, rect->bottom, flags, s->fast, s->index};
    memcpy(row, values, sizeof(values));
    /* Each admitted self-copy shifts left in one row, so memmove retains overlap. */
    for (uint32_t line = 0; line < height; ++line) {
        unsigned char *out = pixels[dst-1]+(y+line)*640+x;
        const unsigned char *in = pixels[src-1]+(rect->top+line)*640+rect->left;
        if (flags == 0x10) memmove(out, in, width);
        else for (uint32_t column = 0; column < width; ++column) if (in[column]) out[column] = in[column];
    }
    if (title_mode == 3 && !phase_calls++) { s->fast ^= 1; s->primary = &surfaces[3]; }
}
uint32_t drawing_blit_fast(void *unused, font_state *s, font_sprite *sprite, uint32_t x, uint32_t y, uint32_t flags) {
    (void)unused; font_rect rect = {font_word(sprite,20), font_word(sprite,24), font_word(sprite,28), font_word(sprite,32)};
    title_blit_fast(NULL, &title, s->destination, x, y, sprite->surface, &rect, flags); return 0;
}
void title_apply_palette(void *unused, title_state *s, uint32_t first, uint32_t count) {
    (void)unused; REQUIRE(s == &title && call_count < TITLE_CALL_CAPACITY && first+count <= 256);
    uint32_t *row = title_calls[call_count++]; row[0] = 1; row[1] = first; row[2] = count;
    if (title_mode == 4) {
        s->palettes->current[first][1] ^= 0x77; s->palettes->staged[255][3] ^= 0x35;
        s->palette_phase += 13;
    }
}

#ifndef DX_STANDALONE
static uint32_t palette_vtable[7], native_palette;
static uint32_t title_surface_address(font_surface *surface) {
    return surface ? (uint32_t)(uintptr_t)&native_surfaces[surface_id(surface)-1] : 0;
}
static font_surface *title_surface_view(uint32_t address) {
    if (!address) return NULL;
    uint32_t id = native_surface_id(address); REQUIRE(id); return &surfaces[id-1];
}
static void title_palettes_to_native(void) { memcpy((void *)0x42c148, palettes.current, 1024); memcpy((void *)0x42c548, palettes.staged, 1024); }
static void title_palettes_from_native(void) { memcpy(palettes.current, (void *)0x42c148, 1024); memcpy(palettes.staged, (void *)0x42c548, 1024); }
#define title_font_to_native font_to_native
#define title_font_from_native font_from_native
#include "title-native.h"
static uint32_t WINAPI native_title_fast(uint32_t destination, uint32_t x, uint32_t y,
                                       uint32_t source, font_rect *rect, uint32_t flags) {
    title_from_native(); title_blit_fast(NULL, &title, title_surface_view(destination), x, y,
        title_surface_view(source), rect, flags); title_to_native(); return 0x88760001;
}
static uint32_t WINAPI native_title_palette(uint32_t object, uint32_t flags, uint32_t first, uint32_t count, void *entries) {
    REQUIRE(object == (uint32_t)(uintptr_t)&native_palette && flags == 0 && entries == (void *)(uintptr_t)(0x42c148+4*first));
    title_from_native(); title_apply_palette(NULL, &title, first, count); title_to_native(); return 0x80004005;
}
#define NATIVE(name) static void native_title_##name(void) { title_from_native(); fixture_title_##name(&title); title_to_native(); }
NATIVE(scroll) NATIVE(wave) NATIVE(wobble) NATIVE(cycle)
static void title_install(int source) {
    font_install(source); font_vtable[7] = (uint32_t)(uintptr_t)native_title_fast;
    palette_vtable[6] = (uint32_t)(uintptr_t)native_title_palette; native_palette = (uint32_t)(uintptr_t)palette_vtable;
    *word(0x4349b8) = (uint32_t)(uintptr_t)&native_palette;
    memcpy((void *)0x4351a8, samples, sizeof(samples)); memcpy((void *)0x4168b0, message, sizeof(message));
    if (!source) return;
#define INSTALL(name) REQUIRE(install_title_##name((void (*)(void))native_title_##name));
    INSTALL(scroll) INSTALL(wave) INSTALL(wobble) INSTALL(cycle)
}
#endif

#ifndef TITLE_LIBRARY_ONLY
int main(int argc, char **argv) {
    (void)font_observe_objects; /* This consumer supplies its own observation object. */
    REQUIRE(argc == 5); uint32_t seed = (uint32_t)strtoul(argv[2], NULL, 10);
    title_mode = (uint32_t)strtoul(argv[3], NULL, 10); REQUIRE(title_mode <= 6);
    uint32_t phase = (uint32_t)strtoul(argv[4], NULL, 10);
    font_setup(seed, title_mode == 1 ? 1 : 0);
    for (uint32_t i = 0; i < 361; ++i) samples[i] = (int32_t)((i*seed) % 2049) - 1024;
    for (unsigned i = 0; i < sizeof(pixels); ++i) ((unsigned char *)pixels)[i] = (unsigned char)(i*13+seed);
    for (unsigned i = 0; i < sizeof(palettes); ++i) ((unsigned char *)&palettes)[i] = (unsigned char)(i+seed);
    flow.windowed = title_mode == 2;
    title = (title_state){.font=&font, .palettes=&palettes, .flow=&flow,
        .primary=&surfaces[1], .software=&surfaces[2], .back=&surfaces[0], .message=message, .sine=samples,
        .length=sizeof(message), .index=title_mode == 1 ? 2 : sizeof(message)-1,
        .advance=0, .glyph_width=3, .wobble_phase=phase, .palette_phase=phase,
        .palette_width=title_mode == 5 ? 0 : title_mode == 6 ? 160 : 120, .fast=title_mode % 2};
#ifndef DX_STANDALONE
    int source = !strcmp(argv[1], "source"); title_install(source); title_to_native();
#else
    REQUIRE(!strcmp(argv[1], "source"));
#endif
    spx_observer observer = spx_observe_begin(stdout); spx_observe_array(&observer, "title");
    for (unsigned round = 0; round < 3; ++round) {
#define CALL(name, address) phase_calls = 0; TITLE_CALL(name, address)
#ifndef DX_STANDALONE
#define TITLE_CALL(name, address) ((void (*)(void))(uintptr_t)address)(); title_from_native();
#else
#define TITLE_CALL(name, address) fixture_title_##name(&title);
#endif
        CALL(scroll, 0x40a780) CALL(wave, 0x40a6c0) CALL(wobble, 0x40a850) CALL(cycle, 0x40a970)
        uint32_t values[] = {title.length,title.index,title.advance,title.glyph_width,title.wobble_phase,
            title.first_offset,title.second_offset,title.palette_width,title.palette_phase,title.palette_offset,title.fast,
            surface_id(title.primary),surface_id(title.software),surface_id(title.back),font.bank,surface_id(font.destination)};
        spx_observe_u32s(&observer, NULL, values, sizeof(values)/sizeof(*values));
    }
    spx_observe_end(&observer); spx_observe_bytes(&observer, "pixels", (const unsigned char *)pixels, sizeof(pixels));
    spx_observe_bytes(&observer, "palettes", (const unsigned char *)&palettes, sizeof(palettes));
    spx_observe_array(&observer, "calls");
    for (uint32_t i = 0; i < call_count; ++i) spx_observe_u32s(&observer, NULL, title_calls[i], 12);
    spx_observe_end(&observer); spx_observe_array(&observer, "font_blits");
    for (uint32_t i = 0; i < blit_count; ++i) spx_observe_u32s(&observer, NULL, blits[i], 12);
    spx_observe_end(&observer); REQUIRE(spx_observe_finish(&observer)); fputc('\n', stdout);
#ifndef DX_STANDALONE
    if (source) {
        REQUIRE(install_title_scroll_intact() && install_title_wave_intact() && install_title_wobble_intact() && install_title_cycle_intact());
        for (unsigned i = 0; i < 4; ++i) REQUIRE(title_entries[i] == 3);
    }
#endif
    return 0;
}

#ifndef DX_STANDALONE
static void title_run_case(void) {
    int count; char **args, **environment; struct native_startupinfo startup = {0};
    REQUIRE(__getmainargs(&count,&args,&environment,0,&startup) == 0);
    int result=main(count,args); fflush(NULL); ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_title_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved) {
    (void)instance; (void)reserved;
    return reason != DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(title_run_case));
}
#endif
#endif /* TITLE_LIBRARY_ONLY */
