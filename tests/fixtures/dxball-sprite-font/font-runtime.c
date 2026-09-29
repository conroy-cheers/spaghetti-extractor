/* Ordinary comparison adapter, sharing the established cleanup transport. */
#define main cleanup_driver_main
#define DllMain cleanup_driver_DllMain
#include "cleanup-runtime.c"
#undef main
#undef DllMain
#include "font-runtime.h"

static font_state font;
static uint32_t font_entries[6], font_mode;
static uint32_t blits[128][12], blit_count;
static void put_word(font_sprite *sprite, unsigned offset, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) sprite->retained[offset - 4 + i] = (unsigned char)(value >> (8 * i));
}
void font_enter(unsigned operation) { REQUIRE(operation < 6); ++font_entries[operation]; }
uint32_t font_service_find(void *unused, font_state *s, uint32_t character) {
    (void)unused; return fixture_font_find(s, character);
}
uint32_t font_service_measure(void *unused, font_state *s, uint32_t length, font_bytes *text) {
    (void)unused; return fixture_font_measure(s, length, text);
}
void font_service_blit(void *unused, font_state *s, font_rect *destination,
                       font_surface *source, font_rect *rectangle) {
    (void)unused; REQUIRE(s == &font && blit_count < 128);
    uint32_t *row = blits[blit_count++];
    row[0] = surface_id(s->destination); row[1] = surface_id(source);
    row[2] = destination->left; row[3] = destination->top;
    row[4] = destination->right; row[5] = destination->bottom;
    row[6] = rectangle->left; row[7] = rectangle->top;
    row[8] = rectangle->right; row[9] = rectangle->bottom;
    row[10] = s->bank; row[11] = s->spacing;
    if (font_mode == 3) { s->bank = (s->bank + 1) % 3; ++s->spacing; }
    if (font_mode == 4)
        for (uint32_t slot = 1; slot <= 5; ++slot) {
            font_sprite *p = s->objects->banks[s->bank].slots[slot];
            put_word(p, 8, font_width(p) + 7);
        }
}
static void font_setup(uint32_t seed, uint32_t mode) {
    static const unsigned char characters[] = {'A', 'B', 'C', 0, 255};
    font_mode = mode;
    setup(seed, 0); /* Retain the old table and frame initialization. */
    surfaces[0].identity = 1; refs[0] = 1; surface_count = 1;
    font.objects = &state; font.destination = &surfaces[0];
    font.bank = seed % 3; font.spacing = mode == 2 ? UINT32_MAX : seed % 4;
    for (uint32_t bank = 0; bank < 3; ++bank) {
        state.banks[bank].count = mode == 5 ? 1 : mode == 6 ? 0 : mode == 7 ? UINT32_MAX : 6;
        for (uint32_t slot = 1; slot <= 5; ++slot) {
            uint32_t id = object_count++, sid = surface_count++;
            font_sprite *p = &sprites[id];
            state.banks[bank].slots[slot] = p; live[id] = refs[sid] = 1;
            surfaces[sid].identity = sid + 1; p->surface = &surfaces[sid];
            memset(p->retained, (unsigned char)(seed + id), sizeof(p->retained));
            put_word(p, 8, mode == 1 ? 0 : mode == 2 ? UINT32_MAX - slot : 5 + slot + bank);
            put_word(p, 12, 9 + slot); put_word(p, 40, seed + slot);
            put_word(p, 20, slot); put_word(p, 24, 2 * slot);
            put_word(p, 28, 3 * slot); put_word(p, 32, 4 * slot);
            p->retained[32] = characters[slot - 1];
        }
    }
}

#ifndef DX_STANDALONE
static uint32_t font_vtable[40];
static void font_to_native(void) {
    guards[1] = (uint32_t)(uintptr_t)&native_surfaces[surface_id(font.destination) - 1];
    guards[3] = font.bank;
    to_native(); *word(0x4179f8) = font.spacing;
}
static void font_from_native(void) {
    from_native(); font.bank = guards[3]; font.spacing = *word(0x4179f8);
    uint32_t id = native_surface_id(guards[1]); REQUIRE(id);
    font.destination = &surfaces[id - 1];
}
static uint32_t WINAPI native_blit(uint32_t destination, font_rect *dr, uint32_t source,
                                   font_rect *sr, uint32_t flags, void *effects) {
    REQUIRE(destination == *word(0x434960) && flags == 0x01008000 && !effects);
    uint32_t sid = native_surface_id(source); REQUIRE(sid);
    font_from_native(); font_service_blit(NULL, &font, dr, &surfaces[sid - 1], sr); font_to_native();
    return 0;
}
static void native_font_select(uint32_t bank) {
    font_from_native(); fixture_font_select(&font, bank); font_to_native();
}
static uint32_t native_font_find(uint32_t character) {
    font_from_native(); uint32_t result = fixture_font_find(&font, character); font_to_native(); return result;
}
static uint32_t native_font_measure(uint32_t length, const unsigned char *text) {
    font_bytes bytes = {text}; font_from_native();
    uint32_t result = fixture_font_measure(&font, length, &bytes); font_to_native(); return result;
}
#if FONT_UNIT == 1
static uint32_t native_font_glyph(uint32_t character, uint32_t x, uint32_t y) {
    font_from_native(); uint32_t result = fixture_font_glyph(&font, character, x, y); font_to_native(); return result;
}
static uint32_t native_font_line(uint32_t x, uint32_t y, uint32_t length, const unsigned char *text) {
    font_bytes bytes = {text}; font_from_native();
    uint32_t result = fixture_font_line(&font, x, y, length, &bytes); font_to_native(); return result;
}
static uint32_t native_font_center(uint32_t x, uint32_t y, uint32_t length, const unsigned char *text) {
    font_bytes bytes = {text}; font_from_native();
    uint32_t result = fixture_font_center(&font, x, y, length, &bytes); font_to_native(); return result;
}
#endif
static void font_install(int source) {
    install(source);
    font_vtable[2] = (uint32_t)(uintptr_t)native_release;
    font_vtable[5] = (uint32_t)(uintptr_t)native_blit;
    for (uint32_t i = 0; i < OBJECTS; ++i) native_surfaces[i] = (uint32_t)(uintptr_t)font_vtable;
    if (!source) return;
    REQUIRE(install_font_select((void (*)(void))native_font_select));
    REQUIRE(install_font_find((void (*)(void))native_font_find));
    REQUIRE(install_font_measure((void (*)(void))native_font_measure));
#if FONT_UNIT == 1
    REQUIRE(install_font_glyph((void (*)(void))native_font_glyph));
    REQUIRE(install_font_line((void (*)(void))native_font_line));
    REQUIRE(install_font_center((void (*)(void))native_font_center));
#endif
}
#endif

static void font_observe_objects(void) {
    uint32_t previous = guards[1]; guards[1] = surface_id(font.destination); guards[3] = font.bank;
    observe(); guards[1] = previous;
}
#ifndef FONT_LIBRARY_ONLY
int main(int argc, char **argv) {
    REQUIRE(argc == 5 && (!strcmp(argv[1], "source") || !strcmp(argv[1], "original")));
    uint32_t seed = (uint32_t)strtoul(argv[2], NULL, 10);
    uint32_t mode = (uint32_t)strtoul(argv[3], NULL, 10);
    uint32_t length = (uint32_t)strtoul(argv[4], NULL, 10);
    REQUIRE(mode <= 7 && (length <= 7 || font_signed(length) < 0));
    unsigned char data[] = {'A', 'C', 'X', 0, 255, 'B', 'A'};
    uint32_t results[5]; font_setup(seed, mode);
#ifndef DX_STANDALONE
    int source = !strcmp(argv[1], "source"); font_install(source); font_to_native();
    ((void (*)(uint32_t))(uintptr_t)0x40bd80)(seed % 3);
    results[0] = ((uint32_t (*)(uint32_t))(uintptr_t)0x40c660)(0xabc00041);
    results[1] = ((uint32_t (*)(uint32_t, const unsigned char *))(uintptr_t)0x40c760)(length, data);
    results[2] = ((uint32_t (*)(uint32_t, uint32_t, uint32_t))(uintptr_t)0x40c5a0)('B', seed, seed * 3);
    results[3] = ((uint32_t (*)(uint32_t, uint32_t, uint32_t, const unsigned char *))(uintptr_t)0x40c6b0)(seed, seed * 5, length, data);
    results[4] = ((uint32_t (*)(uint32_t, uint32_t, uint32_t, const unsigned char *))(uintptr_t)0x40c720)(seed * 7, seed, length, data);
    font_from_native();
    if (source) {
        REQUIRE(install_font_select_intact() && install_font_find_intact() && install_font_measure_intact());
        for (unsigned i = 0; i < 3; ++i) REQUIRE(font_entries[i]);
#if FONT_UNIT == 1
        REQUIRE(install_font_glyph_intact() && install_font_line_intact() && install_font_center_intact());
        for (unsigned i = 3; i < 6; ++i) REQUIRE(font_entries[i]);
#endif
    }
#else
    REQUIRE(!strcmp(argv[1], "source")); font_bytes text = {data};
    fixture_font_select(&font, seed % 3);
    results[0] = fixture_font_find(&font, 0xabc00041);
    results[1] = fixture_font_measure(&font, length, &text);
    results[2] = fixture_font_glyph(&font, 'B', seed, seed * 3);
    results[3] = fixture_font_line(&font, seed, seed * 5, length, &text);
    results[4] = fixture_font_center(&font, seed * 7, seed, length, &text);
#endif
    fputs("{\"before_cleanup\":", stdout); font_observe_objects(); fputs(",\"font\":", stdout);
    spx_observer o = spx_observe_begin(stdout);
    spx_observe_u32s(&o, "results", results, 5);
    spx_observe_u64(&o, "bank", font.bank); spx_observe_u64(&o, "spacing", font.spacing);
    spx_observe_bytes(&o, "text", data, sizeof(data));
    spx_observe_array(&o, "blits");
    for (uint32_t i = 0; i < blit_count; ++i) spx_observe_u32s(&o, NULL, blits[i], 12);
    spx_observe_end(&o); REQUIRE(spx_observe_finish(&o));
#ifndef DX_STANDALONE
    font_to_native(); ((void (*)(void))(uintptr_t)0x40bcc0)(); font_from_native(); check_traps(source);
#else
    fixture_clear(&state);
#endif
    fputs(",\"after_cleanup\":", stdout); font_observe_objects(); fputs("}\n", stdout);
    fprintf(stderr, "FONT_SELECTED %u %u %u %u %u %u\n", font_entries[0], font_entries[1],
        font_entries[2], font_entries[3], font_entries[4], font_entries[5]);
    return 0;
}

#ifndef DX_STANDALONE
static LONG WINAPI font_fault(EXCEPTION_POINTERS *p) {
    fprintf(stderr, "native fault %08lx at %08lx\n", p->ExceptionRecord->ExceptionCode, p->ContextRecord->Eip);
    fflush(NULL); ExitProcess(86); return EXCEPTION_EXECUTE_HANDLER;
}
static void font_run_case(void) {
    SetUnhandledExceptionFilter(font_fault);
    int count; char **args, **environment; struct native_startupinfo startup = {0};
    REQUIRE(__getmainargs(&count, &args, &environment, 0, &startup) == 0);
    int result = main(count, args); fflush(NULL); ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_font_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved) {
    (void)instance; (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    return (uintptr_t)GetModuleHandleA(NULL) == 0x400000 && install_startup(font_run_case);
}
#endif
#endif /* FONT_LIBRARY_ONLY */
