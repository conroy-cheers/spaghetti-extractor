/* Controlled, alias-preserving services around the original game dispatcher. */
#define LIFECYCLE_LIBRARY_ONLY 1
#include "lifecycle-runtime.c"
#include "flow-runtime.h"

struct spx_opaque_flow_audio_v5 { uint32_t identity; };
static flow_audio audio_objects[2] = {{1}, {2}};
static flow_state flow;
static uint32_t flow_mode, flow_entries[8], flow_events[128][9], flow_event_count;
static font_surface *flow_back, *flow_overlay, *flow_spare;

void flow_enter(unsigned operation) { REQUIRE(operation < 8); ++flow_entries[operation]; }
static void flow_event(uint32_t kind, uint32_t object, uint32_t argument) {
    REQUIRE(flow_event_count < 128);
    uint32_t *row = flow_events[flow_event_count++];
    row[0] = kind; row[1] = object; row[2] = argument; row[3] = flow.scene;
    row[4] = flow.next_scene; row[5] = flow.transition_pending; row[6] = flow.first_frame;
    row[7] = flow.refresh_needed; row[8] = flow.audio->identity;
}
void flow_initialize(void *unused, flow_state *s) {
    (void)unused; REQUIRE(s == &flow); flow_event(0, 0, 0);
    s->scene = s->next_scene = 4; s->transition_pending = 0;
}
void flow_scene_enter(void *unused, flow_state *s, uint32_t scene) {
    (void)unused; REQUIRE(s == &flow); flow_event(1, scene, 0);
    if (flow_mode == 2) s->transition_pending = 9;
    if (flow_mode == 1) { s->first_frame = 7; s->refresh_needed = 1; }
}
void flow_scene_update(void *unused, flow_state *s, uint32_t scene) {
    (void)unused; REQUIRE(s == &flow); flow_event(2, scene, 0);
    if (flow_mode == 2 || flow_mode == 12) {
        s->next_scene = flow_mode == 2 ? 1 : UINT32_MAX; s->transition_pending = 2;
    }
}
void flow_scene_key(void *unused, flow_state *s, uint32_t scene, uint32_t key) {
    (void)unused; REQUIRE(s == &flow); flow_event(3, scene, key);
}
void flow_scene_leave(void *unused, flow_state *s, uint32_t scene, uint32_t reason) {
    (void)unused; REQUIRE(s == &flow); flow_event(4, scene, reason);
    if (flow_mode == 2) s->next_scene = 3;
}
void flow_scene_redraw(void *unused, flow_state *s, uint32_t scene) {
    (void)unused; REQUIRE(s == &flow); flow_event(5, scene, 0);
    if (flow_mode == 10 || flow_mode == 11) s->refresh_needed = 2;
}
uint32_t flow_surface_status(void *unused, flow_state *s, font_surface *surface) {
    (void)unused; REQUIRE(s == &flow);
    uint32_t result = flow_mode == 5 || flow_mode == 10 ? 0x887601c2 : 0x88760001;
    flow_event(6, surface_id(surface), result); return result;
}
uint32_t flow_surface_restore(void *unused, flow_state *s, font_surface *surface) {
    (void)unused; REQUIRE(s == &flow);
    uint32_t result = ((flow_mode == 6 && surface == s->primary) ||
                       (flow_mode == 7 && surface == flow_back)) ? 0x88760002 : 0;
    flow_event(7, surface_id(surface), result);
    if (flow_mode == 10 && surface == s->primary) s->back = flow_spare;
    return result;
}
uint32_t flow_audio_status(void *unused, flow_state *s, flow_audio *audio) {
    (void)unused; REQUIRE(s == &flow); uint32_t result = flow_mode == 3 ? 2 : 4;
    flow_event(8, audio->identity, result);
    if (flow_mode == 3) s->audio = &audio_objects[1];
    return result;
}
void flow_audio_restore(void *unused, flow_state *s, flow_audio *audio) {
    (void)unused; REQUIRE(s == &flow); flow_event(9, audio->identity, 0);
}
void flow_restore_banks(void *unused, asset_state *s) {
    (void)unused; REQUIRE(s == &assets); fixture_sprite_restore(s);
}
void flow_release(void *unused, flow_state *s, font_surface *surface) {
    (void)unused; REQUIRE(s == &flow); flow_event(10, surface_id(surface), 0);
    trial_release(NULL, &state, surface); s->overlay = flow_spare;
}

#ifndef DX_STANDALONE
static uint32_t audio_vtable[21], native_audio[2];
static uint32_t flow_surface_address(font_surface *surface) {
    uint32_t id = surface_id(surface); return id ? (uint32_t)(uintptr_t)&native_surfaces[id-1] : 0;
}
static font_surface *flow_surface_view(uint32_t address) {
    uint32_t id = native_surface_id(address); return id ? &surfaces[id-1] : NULL;
}
static uint32_t flow_audio_address(flow_audio *audio) {
    REQUIRE(audio == &audio_objects[0] || audio == &audio_objects[1]);
    return (uint32_t)(uintptr_t)&native_audio[audio->identity-1];
}
static flow_audio *flow_audio_view(uint32_t address) {
    for (unsigned i = 0; i < 2; ++i) if (address == (uint32_t)(uintptr_t)&native_audio[i]) return &audio_objects[i];
    REQUIRE(0); return NULL;
}
#define flow_assets_to_native asset_to_native
#define flow_assets_from_native asset_from_native
#include "flow-native.h"

static void native_flow_initialize(void) { flow_from_native(); flow_initialize(NULL, &flow); flow_to_native(); }
#define SCENE_ZERO(name, number) \
static void native_scene_##name##_##number(void) { \
    flow_from_native(); flow_scene_##name(NULL, &flow, number); flow_to_native(); \
}
#define SCENE_WORD(name, number) \
static void native_scene_##name##_##number(uint32_t value) { \
    flow_from_native(); flow_scene_##name(NULL, &flow, number, value); flow_to_native(); \
}
#define SCENE(number) SCENE_ZERO(enter, number) SCENE_ZERO(update, number) \
    SCENE_ZERO(redraw, number) SCENE_WORD(key, number)
SCENE(0) SCENE(1) SCENE(2) SCENE(3) SCENE(4)
SCENE_WORD(leave, 1) SCENE_WORD(leave, 2) SCENE_WORD(leave, 4)
static void native_scene_leave_0(uint32_t value) {
    flow_from_native(); REQUIRE(flow.scene == 0 || flow.scene == 3);
    flow_scene_leave(NULL, &flow, flow.scene, value); flow_to_native();
}
static uint32_t WINAPI native_flow_status(uint32_t address, uint32_t flags) {
    REQUIRE(flags == 1); flow_from_native();
    uint32_t result = flow_surface_status(NULL, &flow, flow_surface_view(address)); flow_to_native(); return result;
}
static uint32_t WINAPI native_flow_surface_restore(uint32_t address) {
    font_surface *surface = flow_surface_view(address);
    if (surface != &surfaces[0] && surface != flow_back && surface != flow_spare)
        return native_lifecycle_restore_surface(address);
    flow_from_native(); uint32_t result = flow_surface_restore(NULL, &flow, surface); flow_to_native(); return result;
}
static uint32_t WINAPI native_flow_release(uint32_t address) {
    if (flow_surface_view(address) != flow_overlay) return native_release(address);
    flow_from_native(); flow_release(NULL, &flow, flow_overlay); flow_to_native(); return 0;
}
static uint32_t WINAPI native_flow_audio_status(uint32_t address, uint32_t *status) {
    flow_from_native(); *status = flow_audio_status(NULL, &flow, flow_audio_view(address)); flow_to_native();
    return 0x80004005; /* HRESULT is ignored; the status output remains defined. */
}
static uint32_t WINAPI native_flow_audio_restore(uint32_t address) {
    flow_from_native(); flow_audio_restore(NULL, &flow, flow_audio_view(address)); flow_to_native(); return 0;
}
#define FLOW_ZERO(name) \
static void native_flow_##name(void) { flow_from_native(); fixture_flow_##name(&flow); flow_to_native(); }
#define FLOW_WORD(name) \
static void native_flow_##name(uint32_t value) { flow_from_native(); fixture_flow_##name(&flow, value); flow_to_native(); }
FLOW_ZERO(enter) FLOW_ZERO(redraw) FLOW_ZERO(restore) FLOW_ZERO(check_surfaces)
FLOW_WORD(key) FLOW_WORD(leave) FLOW_WORD(shutdown)
static uint32_t native_flow_frame(void) {
    flow_from_native(); uint32_t result = fixture_flow_frame(&flow); flow_to_native(); return result;
}
static void flow_install(int source) {
    lifecycle_install(source);
    font_vtable[2] = (uint32_t)(uintptr_t)native_flow_release;
    font_vtable[13] = (uint32_t)(uintptr_t)native_flow_status;
    font_vtable[27] = (uint32_t)(uintptr_t)native_flow_surface_restore;
    audio_vtable[9] = (uint32_t)(uintptr_t)native_flow_audio_status;
    audio_vtable[20] = (uint32_t)(uintptr_t)native_flow_audio_restore;
    for (unsigned i = 0; i < 2; ++i) native_audio[i] = (uint32_t)(uintptr_t)audio_vtable;
    REQUIRE(install_flow_initialize(native_flow_initialize));
#define INSTALL_SCENE_OP(name, number) REQUIRE(install_scene_##name##_##number((void (*)(void))native_scene_##name##_##number));
#define INSTALL_SCENE(number) INSTALL_SCENE_OP(enter, number) INSTALL_SCENE_OP(update, number) \
    INSTALL_SCENE_OP(key, number) INSTALL_SCENE_OP(redraw, number)
    INSTALL_SCENE(0) INSTALL_SCENE(1) INSTALL_SCENE(2) INSTALL_SCENE(3) INSTALL_SCENE(4)
    INSTALL_SCENE_OP(leave, 0) INSTALL_SCENE_OP(leave, 1) INSTALL_SCENE_OP(leave, 2) INSTALL_SCENE_OP(leave, 4)
    if (!source) return;
#define INSTALL_FLOW(name) REQUIRE(install_flow_##name((void (*)(void))native_flow_##name));
    INSTALL_FLOW(frame) INSTALL_FLOW(key) INSTALL_FLOW(enter) INSTALL_FLOW(leave)
    INSTALL_FLOW(redraw) INSTALL_FLOW(restore) INSTALL_FLOW(check_surfaces) INSTALL_FLOW(shutdown)
}
#endif

static void observe_flow_state(spx_observer *o, const char *name) {
    uint32_t values[] = {flow.first_frame, flow.scene, flow.next_scene, flow.transition_pending,
        flow.windowed, flow.refresh_needed, flow.audio_enabled, flow.audio->identity,
        surface_id(flow.primary), surface_id(flow.back), surface_id(flow.overlay)};
    spx_observe_u32s(o, name, values, sizeof(values)/sizeof(*values));
}

int main(int argc, char **argv) {
    REQUIRE(argc == 4); uint32_t scene = (uint32_t)strtoul(argv[2], NULL, 10);
    flow_mode = (uint32_t)strtoul(argv[3], NULL, 10); REQUIRE(flow_mode < 14);
    font_setup(17, 0); assets.objects = &state;
    name_bank(0, "Sysfont.sbk", 1); name_bank(1, "Sfont.sbk", 2); name_bank(2, "Thefont.sbk", 1);
    for (unsigned i = 0; i < 3; ++i) {
        surfaces[surface_count].identity = surface_count+1; refs[surface_count++] = 1;
    }
    flow_back = &surfaces[surface_count-3]; flow_overlay = &surfaces[surface_count-2]; flow_spare = &surfaces[surface_count-1];
    flow = (flow_state){.scene=scene, .next_scene=scene, .first_frame=flow_mode == 1,
        .windowed=flow_mode != 5 && flow_mode != 9 && flow_mode != 10,
        .refresh_needed=flow_mode >= 4 && flow_mode <= 11 ? (flow_mode == 8 ? 2 : 1) : 0,
        .audio_enabled=flow_mode == 3 || flow_mode == 12 ? 2 : 0, .audio=&audio_objects[0],
        .primary=&surfaces[0], .back=flow_back, .overlay=flow_overlay, .sprites=&assets};
    uint32_t frame_result;
#ifndef DX_STANDALONE
    int source = !strcmp(argv[1], "source"); flow_install(source); flow_to_native();
    frame_result = ((uint32_t (*)(void))(uintptr_t)0x40ab10)(); flow_from_native();
#else
    REQUIRE(!strcmp(argv[1], "source")); frame_result = fixture_flow_frame(&flow);
#endif
    fputs("{\"flow\":", stdout); spx_observer o = spx_observe_begin(stdout);
    spx_observe_u64(&o, "frame_result", frame_result); observe_flow_state(&o, "after_frame");
    if (flow_mode == 13) flow.first_frame = 2;
#ifndef DX_STANDALONE
    flow_to_native();
    ((void (*)(uint32_t))(uintptr_t)0x40abf0)(0x12345678);
    ((void (*)(void))(uintptr_t)0x40ac60)();
    ((void (*)(uint32_t))(uintptr_t)0x40aca0)(UINT32_MAX);
    ((void (*)(void))(uintptr_t)0x40aad0)();
    ((void (*)(uint32_t))(uintptr_t)0x40ae50)(7); flow_from_native();
    if (source) REQUIRE(install_flow_frame_intact() && install_flow_restore_intact() && install_flow_key_intact()
        && install_flow_enter_intact() && install_flow_leave_intact() && install_flow_redraw_intact()
        && install_flow_check_surfaces_intact() && install_flow_shutdown_intact());
#else
    fixture_flow_key(&flow, 0x12345678); fixture_flow_enter(&flow); fixture_flow_leave(&flow, UINT32_MAX);
    fixture_flow_redraw(&flow); fixture_flow_shutdown(&flow, 7);
#endif
    observe_flow_state(&o, "after_dispatch"); spx_observe_array(&o, "events");
    for (uint32_t i = 0; i < flow_event_count; ++i) spx_observe_u32s(&o, NULL, flow_events[i], 9);
    spx_observe_end(&o); REQUIRE(spx_observe_finish(&o));
    guards[2] = assets.file ? 1 : 0;
    fputs(",\"objects\":", stdout); font_observe_objects(); fputs(",\"assets\":", stdout); o = spx_observe_begin(stdout);
    spx_observe_u64(&o, "file_position", file.position); spx_observe_u64(&o, "file_closed", file.closed);
    spx_observe_array(&o, "events");
    for (uint32_t i = 0; i < asset_event_count; ++i) spx_observe_u32s(&o, NULL, asset_events[i], 5);
    spx_observe_end(&o); spx_observe_array(&o, "pixels");
    for (uint32_t i = 0; i < surface_count; ++i) spx_observe_bytes(&o, NULL, surface_pixels[i], surface_sizes[i]);
    spx_observe_end(&o); REQUIRE(spx_observe_finish(&o));
#ifndef DX_STANDALONE
    flow_to_native(); ((void (*)(void))(uintptr_t)0x40bcc0)(); flow_from_native(); check_traps(source);
#else
    fixture_clear(&state);
#endif
    guards[2] = assets.file ? 1 : 0;
    fputs(",\"after_cleanup\":", stdout); font_observe_objects(); fputs("}\n", stdout);
    fprintf(stderr, "FLOW_SELECTED %u; lifecycle %u; loader %u\n", flow_entries[0], lifecycle_entries[1], loader_entries);
    return 0;
}
#ifndef DX_STANDALONE
static void flow_run_case(void) {
    int count; char **arguments, **environment; struct native_startupinfo startup = {0};
    REQUIRE(__getmainargs(&count, &arguments, &environment, 0, &startup) == 0);
    int result = main(count, arguments); fflush(NULL); ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_flow_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved) {
    (void)instance; (void)reserved;
    return reason != DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL) == 0x400000 && install_startup(flow_run_case));
}
#endif
