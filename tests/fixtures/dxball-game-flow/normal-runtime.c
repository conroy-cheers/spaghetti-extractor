/* Real scene/platform services, with the same shared state as the local consumer. */
#define LIFECYCLE_NORMAL_LIBRARY_ONLY 1
#include "lifecycle-normal-runtime.c"
#include "flow-runtime.h"

struct spx_opaque_flow_audio_v5 { uint32_t address; };
static flow_audio audio_views[32];
static unsigned audio_count;
static flow_state flow = {.sprites=&assets};
static uint32_t flow_entries[8], flow_calls[32][12], flow_count, flow_depth;
void flow_enter(unsigned operation) { REQUIRE(operation < 8); ++flow_entries[operation]; }
static uint32_t flow_audio_address(flow_audio *audio) { return audio ? audio->address : 0; }
static flow_audio *flow_audio_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i = 0; i < audio_count; ++i) if (audio_views[i].address == address) return &audio_views[i];
    REQUIRE(audio_count < 32); audio_views[audio_count].address = address; return &audio_views[audio_count++];
}
#define flow_surface_address surface_address
#define flow_surface_view surface_view
#define flow_assets_to_native asset_push
#define flow_assets_from_native asset_pull
#include "flow-native.h"

void flow_initialize(void *unused, flow_state *s) {
    (void)unused; REQUIRE(s == &flow); flow_to_native(); ((void (*)(void))(uintptr_t)0x40ad10)(); flow_from_native();
}
static const uint32_t scene_functions[5][5] = {
    {0x40ae80, 0x404120, 0x403570, 0x409410, 0x40a0b0},
    {0x40b1f0, 0x4044d0, 0x403750, 0x4096a0, 0x40a510},
    {0x40b2a0, 0x404ad0, 0x403a00, 0x4098e0, 0x40a5f0},
    {0x40bbf0, 0x408f70, 0x403f30, 0x40bbf0, 0x40a610},
    {0x40af80, 0x4043d0, 0x403660, 0x409510, 0x40a200}
};
#define SCENE_ZERO(name, operation) \
void flow_scene_##name(void *unused, flow_state *s, uint32_t scene) { \
    (void)unused; REQUIRE(s == &flow && scene < 5); flow_to_native(); \
    ((void (*)(void))(uintptr_t)scene_functions[operation][scene])(); flow_from_native(); \
}
#define SCENE_WORD(name, operation) \
void flow_scene_##name(void *unused, flow_state *s, uint32_t scene, uint32_t value) { \
    (void)unused; REQUIRE(s == &flow && scene < 5); flow_to_native(); \
    ((void (*)(uint32_t))(uintptr_t)scene_functions[operation][scene])(value); flow_from_native(); \
}
SCENE_ZERO(enter, 0) SCENE_ZERO(update, 1) SCENE_WORD(key, 2) SCENE_WORD(leave, 3) SCENE_ZERO(redraw, 4)
uint32_t flow_surface_status(void *unused, flow_state *s, font_surface *surface) {
    (void)unused; REQUIRE(s == &flow); flow_to_native();
    uint32_t address = surface_address(surface), *table = word(*word(address));
    uint32_t result = ((uint32_t (WINAPI *)(uint32_t,uint32_t))(uintptr_t)table[13])(address, 1);
    flow_from_native(); return result;
}
uint32_t flow_surface_restore(void *unused, flow_state *s, font_surface *surface) {
    (void)unused; REQUIRE(s == &flow); flow_to_native();
    uint32_t address = surface_address(surface), *table = word(*word(address));
    uint32_t result = ((uint32_t (WINAPI *)(uint32_t))(uintptr_t)table[27])(address);
    flow_from_native(); return result;
}
void flow_restore_banks(void *unused, asset_state *s) {
    (void)unused; REQUIRE(s == &assets); flow_to_native(); live_restore(); flow_from_native();
}
uint32_t flow_audio_status(void *unused, flow_state *s, flow_audio *audio) {
    (void)unused; REQUIRE(s == &flow); flow_to_native();
    uint32_t address = flow_audio_address(audio), *table = word(*word(address)), status;
    ((uint32_t (WINAPI *)(uint32_t,void *))(uintptr_t)table[9])(address, &status);
    flow_from_native(); return status;
}
void flow_audio_restore(void *unused, flow_state *s, flow_audio *audio) {
    (void)unused; REQUIRE(s == &flow); flow_to_native();
    uint32_t address = flow_audio_address(audio), *table = word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t))(uintptr_t)table[20])(address); flow_from_native();
}
void flow_release(void *unused, flow_state *s, font_surface *surface) {
    (void)unused; REQUIRE(s == &flow); flow_to_native();
    uint32_t address = surface_address(surface), *table = word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t))(uintptr_t)table[2])(address); flow_from_native();
}
static void flow_record(unsigned operation, uint32_t before, uint32_t argument, uint32_t result) {
    if (flow_count == 32) return;
    uint32_t *row = flow_calls[flow_count++];
    row[0] = operation; row[1] = before; row[2] = *word(0x431fd0); row[3] = argument; row[4] = result;
    row[5] = *word(0x417a00); row[6] = *word(0x431fc4); row[7] = *word(0x431fc8);
    row[8] = *word(0x4349a4); row[9] = *word(0x434114); row[10] = *word(0x43452c); row[11] = *word(0x434944);
}
#define LIVE_FLOW(name, number, address, declaration, call) \
static void live_flow_##name declaration { \
    unsigned outer = !flow_depth++; uint32_t before = *word(0x431fd0); \
    if (source_side) { flow_from_native(); fixture_flow_##name call; flow_to_native(); } \
    else { \
        REQUIRE(spx_fixture_restore_entry(&install_flow_##name##_hook)); \
        ((void (*) declaration)(uintptr_t)address) native_arguments; \
        install_flow_##name##_hook.entry = NULL; REQUIRE(install_flow_##name((void (*)(void))live_flow_##name)); \
    } \
    --flow_depth; if (outer) flow_record(number, before, record_argument, 0); \
}
#define native_arguments ()
#define record_argument 0
LIVE_FLOW(enter, 2, 0x40ac60, (void), (&flow))
LIVE_FLOW(redraw, 4, 0x40aad0, (void), (&flow))
LIVE_FLOW(restore, 5, 0x40aaa0, (void), (&flow))
LIVE_FLOW(check_surfaces, 6, 0x40aa50, (void), (&flow))
#undef native_arguments
#undef record_argument
#define native_arguments (value)
#define record_argument value
LIVE_FLOW(key, 1, 0x40abf0, (uint32_t value), (&flow, value))
LIVE_FLOW(leave, 3, 0x40aca0, (uint32_t value), (&flow, value))
LIVE_FLOW(shutdown, 7, 0x40ae50, (uint32_t value), (&flow, value))
#undef native_arguments
#undef record_argument
static uint32_t live_flow_frame(void) {
    unsigned outer = !flow_depth++; uint32_t before = *word(0x431fd0), result;
    if (source_side) { flow_from_native(); result = fixture_flow_frame(&flow); flow_to_native(); }
    else {
        REQUIRE(spx_fixture_restore_entry(&install_flow_frame_hook)); result = ((uint32_t (*)(void))(uintptr_t)0x40ab10)();
        install_flow_frame_hook.entry = NULL; REQUIRE(install_flow_frame((void (*)(void))live_flow_frame));
    }
    --flow_depth; if (outer) flow_record(0, before, 0, result); return result;
}
static void flow_observe(spx_observer *o) {
    lifecycle_observe(o); spx_observe_array(o, "flow");
    for (uint32_t i = 0; i < flow_count; ++i) spx_observe_u32s(o, NULL, flow_calls[i], 12);
    spx_observe_end(o);
}
static void flow_diagnose(spx_observer *o) {
    lifecycle_diagnose(o); spx_observe_u32s(o, "selected_flow", flow_entries, 8);
}
static void flow_report(void) {
    const char *path = getenv("SPX_COMPARISON_REPORT"); if (!path) return;
    FILE *out = fopen(path, "wb"); REQUIRE(out);
    fprintf(out, "{\"side\":\"%s\",\"exit_code\":0,\"observations\":", source_side ? "source" : "original");
    spx_observer o = spx_observe_begin(out); flow_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":", out); o = spx_observe_begin(out);
    flow_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n", out); fclose(out);
}
static BOOL flow_main(HINSTANCE instance, DWORD reason, void *reserved) {
    if (!lifecycle_main(instance, reason, reserved)) return FALSE;
    if (reason == DLL_PROCESS_DETACH) { flow_report(); return TRUE; }
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
#define INSTALL(name) REQUIRE(install_flow_##name((void (*)(void))live_flow_##name));
    INSTALL(frame) INSTALL(key) INSTALL(enter) INSTALL(leave) INSTALL(redraw)
    INSTALL(restore) INSTALL(check_surfaces) INSTALL(shutdown)
    return TRUE;
}
#ifndef FLOW_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved) {
    return flow_main(instance, reason, reserved);
}
#endif
