/* Reusable ordinary C environment for the native and lifted asset loader. */
#define FONT_LIBRARY_ONLY 1
#include "font-runtime.c"
#include "asset-runtime.h"

struct spx_opaque_asset_file_v5 { FILE *stream; uint32_t position, closed; };
static asset_state assets;
static asset_file file;
static asset_buffer buffers[255];
static uint32_t buffer_live[255], buffer_count, loader_entries;
static unsigned char *surface_pixels[OBJECTS];
static uint32_t surface_sizes[OBJECTS], pitches[OBJECTS], describe_attempts[OBJECTS], lock_attempts[OBJECTS];
static uint32_t asset_events[4096][5], asset_event_count, creates, fail_at, retries;
void asset_enter(void) { ++loader_entries; }
static void asset_event(uint32_t kind, uint32_t a, uint32_t b, uint32_t c) {
    REQUIRE(asset_event_count < 4096);
    uint32_t *e = asset_events[asset_event_count++];
    e[0] = kind; e[1] = a; e[2] = b; e[3] = c; e[4] = state.current_bank;
}
asset_file *asset_open(void *unused, asset_state *s, asset_name *name) {
    (void)unused; REQUIRE(s == &assets && (!file.stream || file.closed) && strlen(name->text) < 20);
    file.stream = fopen(name->text, "rb"); REQUIRE(file.stream);
    file.position = file.closed = 0;
    asset_event(1, 0, 0, 0); return &file;
}
uint32_t asset_read(void *unused, asset_state *s, asset_buffer *buffer, uint32_t size, uint32_t count) {
    (void)unused; REQUIRE(s == &assets && s->file == &file && !file.closed);
    REQUIRE(size && count <= buffer->size / size);
    uint32_t result = (uint32_t)fread(buffer->data, size, count, file.stream);
    REQUIRE(result == count); file.position += size * result;
    asset_event(2, size, count, file.position); return result;
}
void asset_close(void *unused, asset_state *s) {
    (void)unused; REQUIRE(s == &assets && s->file == &file && !file.closed);
    REQUIRE(fclose(file.stream) == 0); file.closed = 1;
    asset_event(3, file.position, 0, 0);
}
asset_buffer *asset_allocate_pixels(void *unused, asset_state *s, uint32_t bytes) {
    (void)unused; REQUIRE(s == &assets && buffer_count < 255 && bytes < 1024 * 1024);
    uint32_t id = buffer_count++; asset_buffer *buffer = &buffers[id];
    buffer->data = malloc(bytes); REQUIRE(buffer->data); buffer->size = bytes; buffer_live[id] = 1;
    memset(buffer->data, 0x33, bytes); asset_event(4, id + 1, bytes, 0); return buffer;
}
font_sprite *asset_allocate_sprite(void *unused, asset_state *s) {
    (void)unused; REQUIRE(s == &assets && object_count < OBJECTS);
    uint32_t id = object_count++; live[id] = 1;
    memset(&sprites[id], 0, sizeof(sprites[id]));
    asset_event(5, id + 1, 45, 0); return &sprites[id];
}
void asset_free_pixels(void *unused, asset_state *s, asset_buffer *buffer) {
    (void)unused; REQUIRE(s == &assets);
    uint32_t id = (uint32_t)(buffer - buffers); REQUIRE(id < buffer_count && buffer_live[id]);
    buffer_live[id] = 0; asset_event(6, id + 1, buffer->size, 0);
    /* Retain a tombstone's storage solely for post-call byte observations. */
}
uint32_t asset_create(void *unused, asset_state *s, font_sprite *sprite, uint32_t caps) {
    (void)unused; REQUIRE(s == &assets && (caps == 0x40 || caps == 0x840));
    ++creates; asset_event(7, sprite_id(sprite), caps, creates == fail_at ? 0x88760001 : 0);
    if (creates == fail_at) return 0x88760001;
    REQUIRE(surface_count < OBJECTS);
    uint32_t id = surface_count++, width = font_width(sprite), height = font_height(sprite);
    REQUIRE(width < 2048 && height < 2048);
    uint32_t pitch = width + 3, size = pitch * height;
    surface_pixels[id] = malloc(size ? size : 1); REQUIRE(surface_pixels[id]);
    memset(surface_pixels[id], 0x77, size); surface_sizes[id] = size; pitches[id] = pitch;
    surfaces[id].identity = id + 1; refs[id] = 1; sprite->surface = &surfaces[id];
    return 0;
}
void asset_color_key(void *unused, asset_state *s, font_surface *surface) {
    (void)unused; REQUIRE(s == &assets); asset_event(8, surface_id(surface), 8, 0);
}
uint32_t asset_describe(void *unused, asset_state *s, font_surface *surface, asset_view *view) {
    (void)unused; REQUIRE(s == &assets); uint32_t id = surface_id(surface); REQUIRE(id);
    uint32_t result = describe_attempts[id - 1]++ < retries;
    asset_event(9, id, result, pitches[id - 1]); view->pitch = pitches[id - 1]; return result;
}
uint32_t asset_lock(void *unused, asset_state *s, font_surface *surface, asset_view *view) {
    (void)unused; REQUIRE(s == &assets); uint32_t id = surface_id(surface); REQUIRE(id);
    uint32_t result = lock_attempts[id - 1]++ < retries;
    asset_event(10, id, result, pitches[id - 1]);
    view->pitch = pitches[id - 1]; view->pixels = surface_pixels[id - 1]; return result;
}
void asset_unlock(void *unused, asset_state *s, font_surface *surface) {
    (void)unused; REQUIRE(s == &assets); asset_event(11, surface_id(surface), 0, 0);
}

#ifndef DX_STANDALONE
static uint32_t allocation_phase;
static uint32_t draw_vtable[7], native_draw;
static void asset_to_native(void) {
    font_to_native(); *word(0x434964) = (uint32_t)(uintptr_t)assets.file;
}
static void asset_from_native(void) {
    font_from_native(); assets.file = (asset_file *)(uintptr_t)*word(0x434964);
    REQUIRE(!assets.file || assets.file == &file);
}
static uint32_t native_asset_open(const char *name, const char *mode) {
    REQUIRE(!strcmp(mode, "rb")); asset_name input = {name}; asset_from_native();
    asset_file *result = asset_open(NULL, &assets, &input); asset_to_native(); return (uint32_t)(uintptr_t)result;
}
static uint32_t native_asset_read(void *p, uint32_t size, uint32_t count, asset_file *f) {
    REQUIRE(f == &file); asset_buffer buffer = {p, size * count}; asset_from_native();
    uint32_t result = asset_read(NULL, &assets, &buffer, size, count); asset_to_native(); return result;
}
static uint32_t native_asset_close(asset_file *f) {
    REQUIRE(f == &file); asset_from_native(); asset_close(NULL, &assets); asset_to_native(); return 0;
}
static uint32_t native_asset_allocate(uint32_t bytes) {
    asset_from_native(); uint32_t result;
    if (!(allocation_phase++ % 2)) result = (uint32_t)(uintptr_t)asset_allocate_pixels(NULL, &assets, bytes)->data;
    else {
        REQUIRE(bytes == 45); font_sprite *p = asset_allocate_sprite(NULL, &assets);
        result = (uint32_t)(uintptr_t)&native_sprites[sprite_id(p) - 1];
    }
    asset_to_native(); return result;
}
static void native_asset_free(uint32_t p) {
    for (uint32_t i = 0; i < buffer_count; ++i) if (p == (uint32_t)(uintptr_t)buffers[i].data) {
        asset_from_native(); asset_free_pixels(NULL, &assets, &buffers[i]); asset_to_native(); return;
    }
    native_free(p);
}
static uint32_t WINAPI native_asset_create(uint32_t draw, uint32_t *desc, uint32_t *out, uint32_t outer) {
    REQUIRE(draw == (uint32_t)(uintptr_t)&native_draw && !outer && desc[0] == 0x6c && desc[1] == 0xf);
    uint32_t id = native_sprite_id((uint32_t)(uintptr_t)out); REQUIRE(id);
    asset_from_native(); font_sprite *p = &sprites[id - 1];
    REQUIRE(desc[2] == font_height(p) && desc[3] == font_width(p));
    uint32_t result = asset_create(NULL, &assets, p, desc[26]); asset_to_native(); return result;
}
static uint32_t WINAPI native_asset_color_key(uint32_t p, uint32_t flags, uint32_t *key) {
    REQUIRE(flags == 8 && !key[0] && !key[1]); uint32_t id = native_surface_id(p); REQUIRE(id);
    asset_from_native(); asset_color_key(NULL, &assets, &surfaces[id - 1]); asset_to_native(); return 0;
}
static uint32_t WINAPI native_asset_describe(uint32_t p, uint32_t *desc) {
    uint32_t id = native_surface_id(p); REQUIRE(id && desc[0] == 0x6c); asset_view view = {0};
    asset_from_native(); uint32_t result = asset_describe(NULL, &assets, &surfaces[id - 1], &view);
    desc[4] = view.pitch; asset_to_native(); return result;
}
static uint32_t WINAPI native_asset_lock(uint32_t p, void *rect, uint32_t *desc, uint32_t flags, void *handle) {
    uint32_t id = native_surface_id(p); REQUIRE(id && !rect && !flags && !handle); asset_view view = {0};
    asset_from_native(); uint32_t result = asset_lock(NULL, &assets, &surfaces[id - 1], &view);
    desc[9] = (uint32_t)(uintptr_t)view.pixels; asset_to_native(); return result;
}
static uint32_t WINAPI native_asset_unlock(uint32_t p, void *pixels) {
    uint32_t id = native_surface_id(p); REQUIRE(id && !pixels);
    asset_from_native(); asset_unlock(NULL, &assets, &surfaces[id - 1]); asset_to_native(); return 0;
}
static void native_load(uint32_t bank, uint32_t mode, const char *name) {
    asset_name input = {name}; asset_from_native(); fixture_sprite_load(&assets, bank, mode, &input); asset_to_native();
}
static void asset_install(int source) {
    font_install(source);
    /* Extend the environment's free adapter to also handle pixel buffers. */
    REQUIRE(spx_fixture_restore_entry(&install_free_hook));
    REQUIRE(install_asset_free((void (*)(void))native_asset_free));
    REQUIRE(install_asset_open((void (*)(void))native_asset_open));
    REQUIRE(install_asset_read((void (*)(void))native_asset_read));
    REQUIRE(install_asset_close((void (*)(void))native_asset_close));
    REQUIRE(install_asset_allocate((void (*)(void))native_asset_allocate));
    font_vtable[29] = (uint32_t)(uintptr_t)native_asset_color_key;
    font_vtable[22] = (uint32_t)(uintptr_t)native_asset_describe;
    font_vtable[25] = (uint32_t)(uintptr_t)native_asset_lock;
    font_vtable[32] = (uint32_t)(uintptr_t)native_asset_unlock;
    draw_vtable[6] = (uint32_t)(uintptr_t)native_asset_create;
    native_draw = (uint32_t)(uintptr_t)draw_vtable; *word(0x4349a8) = (uint32_t)(uintptr_t)&native_draw;
    if (source) REQUIRE(install_load((void (*)(void))native_load));
}
#endif

#ifndef ASSET_LIBRARY_ONLY
int main(int argc, char **argv) {
    REQUIRE(argc == 7); uint32_t seed = (uint32_t)strtoul(argv[2], NULL, 10);
    uint32_t bank = seed % 3, mode = (uint32_t)strtoul(argv[3], NULL, 10);
    fail_at = (uint32_t)strtoul(argv[5], NULL, 10); retries = (uint32_t)strtoul(argv[6], NULL, 10);
    font_setup(seed, 0); assets.objects = &state;
    state.current_bank = (bank + 1) % 3;
    /* The two slots excluded from loader cleanup stay allocated and observable. */
    state.banks[bank].slots[0] = asset_allocate_sprite(NULL, &assets);
    state.banks[bank].slots[254] = asset_allocate_sprite(NULL, &assets);
    unsigned char data[] = "DX-Ball 123"; uint32_t results[2] = {0};
#ifndef DX_STANDALONE
    int source = !strcmp(argv[1], "source"); asset_install(source); asset_to_native();
    ((void (*)(uint32_t, uint32_t, const char *))(uintptr_t)0x40c080)(bank, mode, argv[4]);
    if (!fail_at) {
        ((void (*)(uint32_t))(uintptr_t)0x40bd80)(bank);
        results[0] = ((uint32_t (*)(uint32_t, const unsigned char *))(uintptr_t)0x40c760)(10, data);
        results[1] = ((uint32_t (*)(uint32_t, uint32_t, uint32_t, const unsigned char *))(uintptr_t)0x40c720)(100, 50, 10, data);
    }
    asset_from_native();
    if (source) REQUIRE(install_load_intact() && loader_entries && entered[0] && entered[1]);
#else
    REQUIRE(!strcmp(argv[1], "source")); asset_name name = {argv[4]}; font_bytes text = {data};
    fixture_sprite_load(&assets, bank, mode, &name);
    if (!fail_at) {
        fixture_font_select(&font, bank); results[0] = fixture_font_measure(&font, 10, &text);
        results[1] = fixture_font_center(&font, 100, 50, 10, &text);
    }
#endif
    guards[2] = assets.file ? 1 : 0;
    fputs("{\"loaded\":", stdout); font_observe_objects(); fputs(",\"assets\":", stdout);
    spx_observer o = spx_observe_begin(stdout);
    spx_observe_u64(&o, "file_position", file.position); spx_observe_u64(&o, "file_closed", file.closed);
    spx_observe_u32s(&o, "results", results, 2); spx_observe_u32s(&o, "buffer_live", buffer_live, buffer_count);
    spx_observe_array(&o, "events");
    for (uint32_t i = 0; i < asset_event_count; ++i) spx_observe_u32s(&o, NULL, asset_events[i], 5);
    spx_observe_end(&o); spx_observe_array(&o, "pixels");
    for (uint32_t i = 0; i < surface_count; ++i) spx_observe_bytes(&o, NULL, surface_pixels[i], surface_sizes[i]);
    spx_observe_end(&o); spx_observe_array(&o, "blits");
    for (uint32_t i = 0; i < blit_count; ++i) spx_observe_u32s(&o, NULL, blits[i], 12);
    spx_observe_end(&o); REQUIRE(spx_observe_finish(&o));
#ifndef DX_STANDALONE
    asset_to_native(); ((void (*)(void))(uintptr_t)0x40bcc0)(); asset_from_native(); check_traps(source);
#else
    fixture_clear(&state);
#endif
    guards[2] = assets.file ? 1 : 0;
    fputs(",\"after_cleanup\":", stdout); font_observe_objects(); fputs("}\n", stdout);
    fprintf(stderr, "LOADER_SELECTED %u; assets %u; glyph calls %u\n", loader_entries, creates, font_entries[3]);
    return 0;
}

#ifndef DX_STANDALONE
static LONG WINAPI asset_fault(EXCEPTION_POINTERS *p) {
    fprintf(stderr, "native fault %08lx at %08lx\n", p->ExceptionRecord->ExceptionCode, p->ContextRecord->Eip);
    fflush(NULL); ExitProcess(86); return EXCEPTION_EXECUTE_HANDLER;
}
static void asset_run_case(void) {
    SetUnhandledExceptionFilter(asset_fault);
    int count; char **args, **environment; struct native_startupinfo startup = {0};
    REQUIRE(__getmainargs(&count, &args, &environment, 0, &startup) == 0);
    int result = main(count, args); fflush(NULL); ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_asset_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved) {
    (void)instance; (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    return (uintptr_t)GetModuleHandleA(NULL) == 0x400000 && install_startup(asset_run_case);
}
#endif
#endif /* ASSET_LIBRARY_ONLY */
