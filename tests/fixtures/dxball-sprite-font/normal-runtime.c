/* Live-game adapter: original allocator/COM services, portable object views. */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "font-runtime.h"
#include "native-image.h"
#include "spx-observation.h"

enum { CAPACITY = 4096, RETAINED_CALLS = 32 };
static cleanup_state state;
static font_state font = {&state, 0, 0, NULL};
static cleanup_sprite sprites[CAPACITY];
static cleanup_surface surfaces[CAPACITY];
static uint32_t sprite_addresses[CAPACITY], surface_addresses[CAPACITY], sprite_count, surface_count;
static uint32_t selected[6], calls[RETAINED_CALLS][5], call_count, cleanup_entries[3];
static unsigned char texts[RETAINED_CALLS][64];
static uint32_t text_lengths[RETAINED_CALLS];
static int source_side;
void trial_require(int condition, const char *expression, unsigned line) {
    if (!condition) { fprintf(stderr, "normal-runtime.c:%u: %s\n", line, expression); fflush(NULL); ExitProcess(86); }
}
void trial_enter(unsigned unit) { REQUIRE(unit < 3); ++cleanup_entries[unit]; }
void font_enter(unsigned operation) { REQUIRE(operation < 6); ++selected[operation]; }
static uint32_t *word(uint32_t address) { return (uint32_t *)(uintptr_t)address; }
static cleanup_surface *surface_view(uint32_t address) {
    if (!address) return NULL;
    for (uint32_t i = 0; i < surface_count; ++i) if (surface_addresses[i] == address) return &surfaces[i];
    REQUIRE(surface_count < CAPACITY);
    uint32_t i = surface_count++; surface_addresses[i] = address; surfaces[i].identity = i + 1; return &surfaces[i];
}
static uint32_t surface_address(const cleanup_surface *p) {
    if (!p) return 0;
    REQUIRE(p >= surfaces && p < surfaces + surface_count); return surface_addresses[p - surfaces];
}
static cleanup_sprite *sprite_view(uint32_t address) {
    if (!address) return NULL;
    uint32_t i;
    for (i = 0; i < sprite_count; ++i) if (sprite_addresses[i] == address) break;
    if (i == sprite_count) { REQUIRE(sprite_count < CAPACITY); ++sprite_count; sprite_addresses[i] = address; }
    sprites[i].surface = surface_view(*word(address));
    memcpy(sprites[i].retained, (void *)(uintptr_t)(address + 4), 41); return &sprites[i];
}
static uint32_t sprite_address(const cleanup_sprite *p) {
    if (!p) return 0;
    REQUIRE(p >= sprites && p < sprites + sprite_count); return sprite_addresses[p - sprites];
}
static void pull(void) {
    state.current_bank = *word(0x434968); font.bank = *word(0x43496c); font.spacing = *word(0x4179f8);
    font.destination = surface_view(*word(0x434960));
    for (uint32_t b = 0; b < 3; ++b) {
        uint32_t *row = word(0x433d18 + b * 0x418);
        for (uint32_t slot = 0; slot < 255; ++slot) state.banks[b].slots[slot] = sprite_view(row[slot]);
        state.banks[b].count = row[255]; memcpy(state.banks[b].retained, row + 256, 24);
    }
}
static void push(void) {
    *word(0x434968) = state.current_bank; *word(0x43496c) = font.bank; *word(0x4179f8) = font.spacing;
    *word(0x434960) = surface_address(font.destination);
    for (uint32_t b = 0; b < 3; ++b) {
        uint32_t *row = word(0x433d18 + b * 0x418);
        for (uint32_t slot = 0; slot < 255; ++slot) {
            cleanup_sprite *p = state.banks[b].slots[slot]; uint32_t address = sprite_address(p); row[slot] = address;
            if (address) { *word(address) = surface_address(p->surface); memcpy((void *)(uintptr_t)(address + 4), p->retained, 41); }
        }
        row[255] = state.banks[b].count; memcpy(row + 256, state.banks[b].retained, 24);
    }
}
void trial_release(void *unused, cleanup_state *s, cleanup_surface *p) {
    (void)unused; REQUIRE(s == &state); uint32_t address = surface_address(p); REQUIRE(address);
    push(); uint32_t *table = word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t))(uintptr_t)table[2])(address); pull();
}
void trial_free_sprite(void *unused, cleanup_state *s, cleanup_sprite *p) {
    (void)unused; REQUIRE(s == &state); uint32_t address = sprite_address(p); REQUIRE(address);
    push(); ((void (*)(uint32_t))(uintptr_t)0x40e2a0)(address); sprite_addresses[p - sprites] = 0;
}
static void record(uint32_t operation, uint32_t argument, uint32_t result, const unsigned char *text) {
    if (call_count >= RETAINED_CALLS) return;
    uint32_t i = call_count++; calls[i][0] = operation; calls[i][1] = argument; calls[i][2] = result;
    calls[i][3] = *word(0x43496c); calls[i][4] = *word(0x4179f8);
    if (text && font_signed(argument) > 0) {
        text_lengths[i] = argument < 64 ? argument : 64; memcpy(texts[i], text, text_lengths[i]);
    }
}
static void native_select(uint32_t bank) { pull(); fixture_select(&state, bank); push(); }
static void native_dispose(uint32_t slot) { pull(); fixture_dispose(&state, slot); push(); }
static void native_clear(void) { pull(); fixture_clear(&state); push(); }
static void native_font_select(uint32_t bank) {
    if (source_side) { pull(); fixture_font_select(&font, bank); push(); }
    else {
        REQUIRE(spx_fixture_restore_entry(&install_font_select_hook));
        ((void (*)(uint32_t))(uintptr_t)0x40bd80)(bank);
        install_font_select_hook.entry = NULL; REQUIRE(install_font_select((void (*)(void))native_font_select));
    }
    record(0, bank, 0, NULL);
}
static uint32_t native_font_find(uint32_t character) {
    uint32_t result;
    if (source_side) { pull(); result = fixture_font_find(&font, character); push(); }
    else {
        REQUIRE(spx_fixture_restore_entry(&install_font_find_hook));
        result = ((uint32_t (*)(uint32_t))(uintptr_t)0x40c660)(character);
        install_font_find_hook.entry = NULL; REQUIRE(install_font_find((void (*)(void))native_font_find));
    }
    record(1, character & 255, result, NULL); return result;
}
static uint32_t native_font_measure(uint32_t length, const unsigned char *text) {
    uint32_t result;
    if (source_side) { font_bytes bytes = {text}; pull(); result = fixture_font_measure(&font, length, &bytes); push(); }
    else {
        REQUIRE(spx_fixture_restore_entry(&install_font_measure_hook));
        result = ((uint32_t (*)(uint32_t, const unsigned char *))(uintptr_t)0x40c760)(length, text);
        install_font_measure_hook.entry = NULL; REQUIRE(install_font_measure((void (*)(void))native_font_measure));
    }
    record(2, length, result, text); return result;
}
static void report(void) {
    const char *path = getenv("SPX_COMPARISON_REPORT"); if (!path) return;
    FILE *out = fopen(path, "wb"); REQUIRE(out);
    fprintf(out, "{\"side\":\"%s\",\"exit_code\":0,\"observations\":", source_side ? "source" : "original");
    spx_observer o = spx_observe_begin(out); spx_observe_array(&o, "calls");
    for (uint32_t i = 0; i < call_count; ++i) {
        spx_observe_object(&o, NULL); spx_observe_u32s(&o, "values", calls[i], 5);
        spx_observe_bytes(&o, "text_prefix", texts[i], text_lengths[i]); spx_observe_end(&o);
    }
    spx_observe_end(&o); REQUIRE(spx_observe_finish(&o));
    fputs(",\"diagnostics\":", out); o = spx_observe_begin(out);
    spx_observe_u32s(&o, "selected_metrics", selected, 3); spx_observe_u32s(&o, "selected_cleanup", cleanup_entries, 3);
    spx_observe_u64(&o, "calls_retained", call_count); REQUIRE(spx_observe_finish(&o)); fputs("}\n", out); fclose(out);
}
static LONG WINAPI normal_fault(EXCEPTION_POINTERS *p) {
    fprintf(stderr, "normal fault %08lx at %08lx\n", p->ExceptionRecord->ExceptionCode, p->ContextRecord->Eip);
    fflush(NULL); ExitProcess(86); return EXCEPTION_EXECUTE_HANDLER;
}
__declspec(dllexport) void dx_normal_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved) {
    (void)instance; (void)reserved;
    if (reason == DLL_PROCESS_DETACH) { report(); return TRUE; }
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    REQUIRE((uintptr_t)GetModuleHandleA(NULL) == 0x400000);
    source_side = getenv("SPX_COMPARISON_SIDE") && !strcmp(getenv("SPX_COMPARISON_SIDE"), "source");
    SetUnhandledExceptionFilter(normal_fault);
    REQUIRE(install_font_select((void (*)(void))native_font_select));
    REQUIRE(install_font_find((void (*)(void))native_font_find));
    REQUIRE(install_font_measure((void (*)(void))native_font_measure));
    if (source_side) {
        REQUIRE(install_select((void (*)(void))native_select));
        REQUIRE(install_dispose((void (*)(void))native_dispose)); REQUIRE(install_clear(native_clear));
    }
    return TRUE;
}
