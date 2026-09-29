/* Comparison adapter. No original operation is reimplemented here. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runtime.h"
#include "case-unit.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif

enum { OBJECTS = 765, EVENTS = 2 * OBJECTS, BANK_BASE = 0x433d18 };
static cleanup_state state;
static cleanup_sprite sprites[OBJECTS];
static cleanup_surface surfaces[OBJECTS];
static uint32_t live[OBJECTS], refs[OBJECTS], object_count, surface_count;
static uint32_t events[EVENTS][6], event_count, guards[4], entered[3];
static uint32_t scenario, callback_done;

void trial_require(int condition, const char *expression, unsigned line) {
    if (!condition) {
        fprintf(stderr, "runtime.c:%u: adapter premise failed: %s\n", line, expression);
        exit(3);
    }
}
void trial_enter(unsigned unit) { REQUIRE(unit < 3); ++entered[unit]; }
static uint32_t sprite_id(const cleanup_sprite *p) {
    if (!p) return 0;
    for (uint32_t i = 0; i < object_count; ++i) if (p == &sprites[i]) return i + 1;
    REQUIRE(0); return 0;
}
static uint32_t surface_id(const cleanup_surface *p) {
    if (!p) return 0;
    for (uint32_t i = 0; i < surface_count; ++i) if (p == &surfaces[i]) return i + 1;
    REQUIRE(0); return 0;
}
static void event(uint32_t kind, uint32_t id, uint32_t detail, uint32_t alive) {
    REQUIRE(event_count < EVENTS && state.current_bank < 3);
    uint32_t *e = events[event_count++];
    e[0] = kind; e[1] = id; e[2] = state.current_bank;
    e[3] = state.banks[state.current_bank].count; e[4] = detail; e[5] = alive;
}
void trial_release(void *unused, cleanup_state *s, cleanup_surface *p) {
    (void)unused; REQUIRE(s == &state);
    uint32_t id = surface_id(p); REQUIRE(id && refs[id - 1]);
    event(1, id, refs[id - 1], 1);
    --refs[id - 1];
    if (scenario == 5 && !callback_done++) state.current_bank = (state.current_bank + 1) % 3;
}
void trial_free_sprite(void *unused, cleanup_state *s, cleanup_sprite *p) {
    (void)unused; REQUIRE(s == &state);
    uint32_t id = sprite_id(p); REQUIRE(id && live[id - 1]);
    event(2, id, surface_id(p->surface), live[id - 1]);
    live[id - 1] = 0;
    /* Keep a tombstone so dangling identities can be observed without reading
     * freed host storage. Production allocator internals are outside scope. */
    memset(p->retained, 0xdd, sizeof(p->retained));
    if (scenario == 6 && !callback_done++) state.current_bank = (state.current_bank + 1) % 3;
}
static void setup(uint32_t seed, uint32_t kind) {
    scenario = kind;
    state.current_bank = seed % 3;
    for (uint32_t i = 0; i < 4; ++i) guards[i] = 0xa55a0010U + i;
    for (uint32_t b = 0; b < 3; ++b) {
        state.banks[b].count = seed + 31 * b;
        for (uint32_t j = 0; j < 6; ++j) state.banks[b].retained[j] = seed ^ (0x5a000000U + 16 * b + j);
        for (uint32_t slot = 0; slot < 255; ++slot) {
            if (kind == 0 || (kind != 7 && slot != 0 && slot != 1 && slot != 127 && slot != 254 && slot != seed % 255)) continue;
            uint32_t i = object_count++;
            REQUIRE(object_count <= OBJECTS); live[i] = 1;
            state.banks[b].slots[slot] = &sprites[i];
            for (unsigned j = 0; j < sizeof(sprites[i].retained); ++j)
                sprites[i].retained[j] = (unsigned char)(seed + i * 13 + j);
            if (kind != 2) {
                uint32_t sid = kind == 3 ? 0 : surface_count;
                if (sid == surface_count) surfaces[surface_count++].identity = sid + 1;
                sprites[i].surface = &surfaces[sid]; ++refs[sid];
            }
        }
    }
    if (kind == 4) {
        /* Retain the displaced object as an allocation outside the slot table.
         * The aliased slot survives one disposal as a dangling identity. */
        state.banks[state.current_bank].slots[1] = state.banks[state.current_bank].slots[0];
    }
}

#ifndef DX_STANDALONE
struct native_sprite { uint32_t surface; unsigned char retained[41]; };
static struct native_sprite native_sprites[OBJECTS];
static uint32_t native_surfaces[OBJECTS], vtable[3];
static uint32_t *word(uint32_t address) { return (uint32_t *)(uintptr_t)address; }
static const uint32_t guard_addresses[] = {BANK_BASE - 4, 0x434960, 0x434964, 0x43496c};
static uint32_t native_sprite_id(uint32_t p) {
    if (!p) return 0;
    for (uint32_t i = 0; i < object_count; ++i) if (p == (uint32_t)(uintptr_t)&native_sprites[i]) return i + 1;
    REQUIRE(0); return 0;
}
static uint32_t native_surface_id(uint32_t p) {
    if (!p) return 0;
    for (uint32_t i = 0; i < surface_count; ++i) if (p == (uint32_t)(uintptr_t)&native_surfaces[i]) return i + 1;
    REQUIRE(0); return 0;
}
static void to_native(void) {
    for (uint32_t b = 0; b < 3; ++b) {
        uint32_t *row = word(BANK_BASE + b * 0x418);
        for (uint32_t j = 0; j < 255; ++j) {
            uint32_t id = sprite_id(state.banks[b].slots[j]);
            row[j] = id ? (uint32_t)(uintptr_t)&native_sprites[id - 1] : 0;
        }
        row[255] = state.banks[b].count;
        memcpy(row + 256, state.banks[b].retained, 24);
    }
    *word(0x434968) = state.current_bank;
    for (uint32_t i = 0; i < 4; ++i) *word(guard_addresses[i]) = guards[i];
    for (uint32_t i = 0; i < object_count; ++i) {
        uint32_t id = surface_id(sprites[i].surface);
        native_sprites[i].surface = id ? (uint32_t)(uintptr_t)&native_surfaces[id - 1] : 0;
        memcpy(native_sprites[i].retained, sprites[i].retained, 41);
    }
}
static void from_native(void) {
    for (uint32_t b = 0; b < 3; ++b) {
        uint32_t *row = word(BANK_BASE + b * 0x418);
        for (uint32_t j = 0; j < 255; ++j) {
            uint32_t id = native_sprite_id(row[j]);
            state.banks[b].slots[j] = id ? &sprites[id - 1] : NULL;
        }
        state.banks[b].count = row[255];
        memcpy(state.banks[b].retained, row + 256, 24);
    }
    state.current_bank = *word(0x434968);
    for (uint32_t i = 0; i < 4; ++i) guards[i] = *word(guard_addresses[i]);
    for (uint32_t i = 0; i < object_count; ++i) {
        uint32_t id = native_surface_id(native_sprites[i].surface);
        sprites[i].surface = id ? &surfaces[id - 1] : NULL;
        memcpy(sprites[i].retained, native_sprites[i].retained, 41);
    }
}
static uint32_t WINAPI native_release(uint32_t p) {
    uint32_t id = native_surface_id(p); REQUIRE(id);
    from_native(); trial_release(NULL, &state, &surfaces[id - 1]); to_native();
    return refs[id - 1];
}
static void native_free(uint32_t p) {
    uint32_t id = native_sprite_id(p); REQUIRE(id);
    from_native(); trial_free_sprite(NULL, &state, &sprites[id - 1]); to_native();
}
#if DX_UNIT == 0 || DX_UNIT == 2
static void native_select(uint32_t bank) {
    from_native(); fixture_select(&state, bank); to_native();
}
#endif
#if DX_UNIT == 1 || DX_UNIT == 2
static void native_dispose(uint32_t slot) {
    from_native(); fixture_dispose(&state, slot); to_native();
}
#endif
#if DX_UNIT == 2
static void native_clear(void) {
    from_native(); fixture_clear(&state); to_native();
}
#endif
static void install(int source) {
    REQUIRE(install_free((void (*)(void))native_free));
    vtable[2] = (uint32_t)(uintptr_t)native_release;
    for (uint32_t i = 0; i < OBJECTS; ++i) native_surfaces[i] = (uint32_t)(uintptr_t)vtable;
    if (!source) return;
#if DX_UNIT == 0 || DX_UNIT == 2
    REQUIRE(install_select((void (*)(void))native_select));
#endif
#if DX_UNIT == 1 || DX_UNIT == 2
    REQUIRE(install_dispose((void (*)(void))native_dispose));
#endif
#if DX_UNIT == 2
    REQUIRE(install_clear(native_clear));
#endif
}
static void check_traps(int source) {
    REQUIRE(install_free_intact());
    if (!source) return;
#if DX_UNIT == 0 || DX_UNIT == 2
    REQUIRE(install_select_intact() && entered[0]);
#endif
#if DX_UNIT == 1 || DX_UNIT == 2
    REQUIRE(install_dispose_intact() && entered[1]);
#endif
#if DX_UNIT == 2
    REQUIRE(install_clear_intact() && entered[2]);
#endif
}
#endif

static void observe(void) {
    spx_observer o = spx_observe_begin(stdout);
    spx_observe_u64(&o, "current_bank", state.current_bank);
    spx_observe_array(&o, "banks");
    for (uint32_t b = 0; b < 3; ++b) {
        spx_observe_array(&o, NULL);
        for (uint32_t j = 0; j < 255; ++j) spx_observe_u64(&o, NULL, sprite_id(state.banks[b].slots[j]));
        spx_observe_u64(&o, NULL, state.banks[b].count);
        for (uint32_t j = 0; j < 6; ++j) spx_observe_u64(&o, NULL, state.banks[b].retained[j]);
        spx_observe_end(&o);
    }
    spx_observe_end(&o);
    spx_observe_array(&o, "objects");
    for (uint32_t i = 0; i < object_count; ++i) {
        spx_observe_object(&o, NULL);
        spx_observe_u64(&o, "surface", surface_id(sprites[i].surface));
        spx_observe_u64(&o, "live", live[i]);
        spx_observe_bytes(&o, "retained", sprites[i].retained, sizeof(sprites[i].retained));
        spx_observe_end(&o);
    }
    spx_observe_end(&o);
    spx_observe_u32s(&o, "surface_refs", refs, surface_count);
    spx_observe_u32s(&o, "guards", guards, 4);
    spx_observe_array(&o, "services");
    for (uint32_t i = 0; i < event_count; ++i) spx_observe_u32s(&o, NULL, events[i], 6);
    spx_observe_end(&o);
    REQUIRE(spx_observe_finish(&o));
}
int main(int argc, char **argv) {
    REQUIRE(argc == 6 && (!strcmp(argv[1], "source") || !strcmp(argv[1], "original")));
    uint32_t seed = (uint32_t)strtoul(argv[2], NULL, 10);
    uint32_t kind = (uint32_t)strtoul(argv[3], NULL, 10);
    uint32_t slot = (uint32_t)strtoul(argv[4], NULL, 10);
    uint32_t caller = (uint32_t)strtoul(argv[5], NULL, 10);
    REQUIRE(kind <= 7 && slot < 255 && caller <= 2 && !(kind == 4 && caller));
    setup(seed, kind);
#ifndef DX_STANDALONE
    int source = !strcmp(argv[1], "source");
    install(source); to_native();
    if (DX_UNIT == 2 || caller == 1) ((void (*)(void))(uintptr_t)0x40bcc0)();
    else if (DX_UNIT == 0) ((void (*)(uint32_t))(uintptr_t)0x40bd70)(seed);
    else {
        ((void (*)(uint32_t))(uintptr_t)0x40c510)(slot);
        if (caller == 2) ((void (*)(uint32_t))(uintptr_t)0x40c510)(slot);
    }
    from_native(); check_traps(source);
#else
    /* Linked source consumer; its observations are compared with retained x86. */
    REQUIRE(!strcmp(argv[1], "source") && DX_UNIT == 2);
    fixture_clear(&state);
#endif
    observe();
    fprintf(stderr, "TRIAL_SELECTED %u %u %u\n", entered[0], entered[1], entered[2]);
    return 0;
}

#ifndef DX_STANDALONE
struct native_startupinfo { int newmode; };
int __cdecl __getmainargs(int *, char ***, char ***, int, struct native_startupinfo *);
static void run_case(void) {
    int count; char **args, **environment; struct native_startupinfo startup = {0};
    REQUIRE(__getmainargs(&count, &args, &environment, 0, &startup) == 0);
    int result = main(count, args); fflush(NULL); ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_cleanup_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved) {
    (void)instance; (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    return (uintptr_t)GetModuleHandleA(NULL) == 0x400000 && install_startup(run_case);
}
#endif
