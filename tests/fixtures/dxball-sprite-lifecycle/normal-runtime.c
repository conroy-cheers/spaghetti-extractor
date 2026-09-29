/* Live allocator, files and DirectDraw behind the shared asset contracts. */
#define DRAWING_NORMAL_LIBRARY_ONLY 1
#include "drawing-normal-runtime.c"
#include "lifecycle-runtime.h"

static asset_state assets = {&state, NULL};
static uint32_t lifecycle_entries[2], loader_entries, lifecycle_calls[24][10], lifecycle_count;
static unsigned char loaded_names[24][20];
void lifecycle_enter(unsigned operation) { REQUIRE(operation < 2); ++lifecycle_entries[operation]; }
void asset_enter(void) { ++loader_entries; }
static void asset_pull(void) { pull(); assets.file = (asset_file *)(uintptr_t)*word(0x434964); }
static void asset_push(void) { push(); *word(0x434964) = (uint32_t)(uintptr_t)assets.file; }

asset_file *asset_open(void *unused, asset_state *s, asset_name *name) {
    (void)unused; REQUIRE(s == &assets); asset_push();
    uint32_t result = ((uint32_t (*)(const char *, const char *))(uintptr_t)0x40e190)(name->text, "rb");
    asset_pull(); return (asset_file *)(uintptr_t)result;
}
uint32_t asset_read(void *unused, asset_state *s, asset_buffer *buffer, uint32_t size, uint32_t count) {
    (void)unused; REQUIRE(s == &assets); asset_push();
    uint32_t result = ((uint32_t (*)(void *,uint32_t,uint32_t,void *))(uintptr_t)0x40e580)
        (buffer->data, size, count, s->file);
    asset_pull(); return result;
}
void asset_close(void *unused, asset_state *s) {
    (void)unused; REQUIRE(s == &assets); asset_push();
    ((int (*)(void *))(uintptr_t)0x40df50)(s->file); asset_pull();
}
font_sprite *asset_allocate_sprite(void *unused, asset_state *s) {
    (void)unused; REQUIRE(s == &assets); asset_push();
    uint32_t address = ((uint32_t (*)(uint32_t))(uintptr_t)0x40e2f0)(45);
    asset_pull(); return sprite_view(address);
}
asset_buffer *asset_allocate_pixels(void *unused, asset_state *s, uint32_t bytes) {
    (void)unused; REQUIRE(s == &assets); asset_push();
    uint32_t address = ((uint32_t (*)(uint32_t))(uintptr_t)0x40e2f0)(bytes);
    asset_pull(); if (!address) return NULL;
    asset_buffer *view = malloc(sizeof(*view)); REQUIRE(view);
    view->data = (unsigned char *)(uintptr_t)address; view->size = bytes; return view;
}
void asset_free_pixels(void *unused, asset_state *s, asset_buffer *buffer) {
    (void)unused; REQUIRE(s == &assets); asset_push();
    ((void (*)(void *))(uintptr_t)0x40e2a0)(buffer->data); free(buffer); asset_pull();
}
uint32_t asset_create(void *unused, asset_state *s, font_sprite *sprite, uint32_t caps) {
    (void)unused; REQUIRE(s == &assets); asset_push();
    uint32_t draw = *word(0x4349a8), *table = word(*word(draw));
    uint32_t desc[27] = {0}; desc[0] = sizeof(desc); desc[1] = 0xf;
    desc[2] = font_height(sprite); desc[3] = font_width(sprite); desc[26] = caps;
    uint32_t result = ((uint32_t (WINAPI *)(uint32_t,void *,void *,void *))(uintptr_t)table[6])
        (draw, desc, word(sprite_address(sprite)), NULL);
    asset_pull(); return result;
}
void asset_color_key(void *unused, asset_state *s, font_surface *surface) {
    (void)unused; REQUIRE(s == &assets); asset_push();
    uint32_t address = surface_address(surface), *table = word(*word(address)), key[2] = {0};
    ((uint32_t (WINAPI *)(uint32_t,uint32_t,void *))(uintptr_t)table[29])(address, 8, key); asset_pull();
}
uint32_t asset_describe(void *unused, asset_state *s, font_surface *surface, asset_view *view) {
    (void)unused; REQUIRE(s == &assets); asset_push();
    uint32_t address = surface_address(surface), *table = word(*word(address)), desc[27] = {0};
    desc[0] = sizeof(desc); desc[1] = 0x1ff9ee;
    uint32_t result = ((uint32_t (WINAPI *)(uint32_t,void *))(uintptr_t)table[22])(address, desc);
    view->pitch = desc[4]; asset_pull(); return result;
}
uint32_t asset_lock(void *unused, asset_state *s, font_surface *surface, asset_view *view) {
    (void)unused; REQUIRE(s == &assets); asset_push();
    uint32_t address = surface_address(surface), *table = word(*word(address)), desc[27] = {0};
    desc[0] = sizeof(desc);
    uint32_t result = ((uint32_t (WINAPI *)(uint32_t,void *,void *,uint32_t,void *))(uintptr_t)table[25])
        (address, NULL, desc, 0, NULL);
    view->pixels = (unsigned char *)(uintptr_t)desc[9]; view->pitch = desc[4]; asset_pull(); return result;
}
void asset_unlock(void *unused, asset_state *s, font_surface *surface) {
    (void)unused; REQUIRE(s == &assets); asset_push();
    uint32_t address = surface_address(surface), *table = word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,void *))(uintptr_t)table[32])(address, NULL); asset_pull();
}
uint32_t lifecycle_copy(void *unused, asset_state *s, font_state *drawing, font_sprite *sprite, font_rect *source) {
    (void)unused; REQUIRE(s == &assets && drawing == &font); asset_push();
    uint32_t object = sprite_address(sprite), surface = *word(object), *table = word(*word(surface));
    uint32_t result = ((uint32_t (WINAPI *)(uint32_t,void *,uint32_t,void *,uint32_t,void *))(uintptr_t)table[5])
        (surface, (void *)(uintptr_t)(object+20), surface_address(drawing->destination), source, 0x01000000, NULL);
    asset_pull(); return result;
}
uint32_t lifecycle_restore_surface(void *unused, asset_state *s, font_surface *surface) {
    (void)unused; REQUIRE(s == &assets); asset_push();
    uint32_t address = surface_address(surface), *table = word(*word(address));
    uint32_t result = ((uint32_t (WINAPI *)(uint32_t))(uintptr_t)table[27])(address); asset_pull(); return result;
}

static void live_load(uint32_t bank, uint32_t mode, const char *name);
void lifecycle_reload(void *unused, asset_state *s, uint32_t bank) {
    (void)unused; REQUIRE(s == &assets); asset_push();
    live_load(bank, 1, (const char *)(uintptr_t)(0x433d18+bank*0x418+0x404)); asset_pull();
}
static void live_load(uint32_t bank, uint32_t mode, const char *name) {
    unsigned char retained[20] = {0};
    for (unsigned i = 0; i < sizeof(retained)-1 && name[i]; ++i) retained[i] = (unsigned char)name[i];
    if (source_side) {
        asset_name input = {name}; asset_pull(); fixture_sprite_load(&assets, bank, mode, &input); asset_push();
    } else {
        REQUIRE(spx_fixture_restore_entry(&install_load_hook));
        ((void (*)(uint32_t,uint32_t,const char *))(uintptr_t)0x40c080)(bank, mode, name);
        install_load_hook.entry = NULL; REQUIRE(install_load((void (*)(void))live_load));
    }
    if (lifecycle_count < 24) {
        uint32_t i = lifecycle_count++; lifecycle_calls[i][0] = 0; lifecycle_calls[i][1] = bank;
        lifecycle_calls[i][2] = mode; lifecycle_calls[i][3] = *word(0x433d18+bank*0x418+0x3fc);
        memcpy(loaded_names[i], retained, sizeof(retained));
    }
}
static uint32_t live_capture(uint32_t slot, uint32_t x, uint32_t y, uint32_t width, uint32_t height) {
    uint32_t result;
    if (source_side) { asset_pull(); result = fixture_sprite_capture(&assets, &font, slot, x, y, width, height); asset_push(); }
    else {
        REQUIRE(spx_fixture_restore_entry(&install_capture_hook));
        result = ((uint32_t (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))(uintptr_t)0x40be10)(slot,x,y,width,height);
        install_capture_hook.entry = NULL; REQUIRE(install_capture((void (*)(void))live_capture));
    }
    if (lifecycle_count < 24) {
        uint32_t *row = lifecycle_calls[lifecycle_count++]; row[0] = 1; row[1] = slot;
        row[2] = x; row[3] = y; row[4] = width; row[5] = height; row[6] = result; row[7] = *word(0x434968);
        uint32_t object = *word(0x433d18+row[7]*0x418+slot*4); row[8] = *word(object+16);
    }
    return result;
}
static void live_restore(void) {
    if (source_side) { asset_pull(); fixture_sprite_restore(&assets); asset_push(); }
    else {
        REQUIRE(spx_fixture_restore_entry(&install_restore_hook)); ((void (*)(void))(uintptr_t)0x40bd00)();
        install_restore_hook.entry = NULL; REQUIRE(install_restore(live_restore));
    }
    if (lifecycle_count < 24) lifecycle_calls[lifecycle_count++][0] = 2;
}
static void lifecycle_observe(spx_observer *o) {
    spx_observe_array(o, "metrics");
    for (uint32_t i = 0; i < call_count; ++i) {
        spx_observe_object(o, NULL); spx_observe_u32s(o, "values", calls[i], 5);
        spx_observe_bytes(o, "text_prefix", texts[i], text_lengths[i]); spx_observe_end(o);
    }
    spx_observe_end(o); spx_observe_array(o, "graphics");
    for (uint32_t i = 0; i < graphics_count; ++i) spx_observe_u32s(o, NULL, graphics[i], 6);
    spx_observe_end(o); spx_observe_array(o, "lifecycle");
    for (uint32_t i = 0; i < lifecycle_count; ++i) {
        spx_observe_object(o, NULL); spx_observe_u32s(o, "values", lifecycle_calls[i], 10);
        spx_observe_bytes(o, "name", loaded_names[i], 20); spx_observe_end(o);
    }
    spx_observe_end(o);
}
static void lifecycle_diagnose(spx_observer *o) {
    spx_observe_u32s(o, "selected_lifecycle", lifecycle_entries, 2); spx_observe_u64(o, "selected_loader", loader_entries);
    spx_observe_u32s(o, "selected_drawing", drawing_entries, 3); spx_observe_u32s(o, "selected_font", selected, 6);
    spx_observe_u32s(o, "selected_cleanup", cleanup_entries, 3);
}
static void lifecycle_report(void) {
    const char *path = getenv("SPX_COMPARISON_REPORT"); if (!path) return;
    FILE *out = fopen(path, "wb"); REQUIRE(out);
    fprintf(out, "{\"side\":\"%s\",\"exit_code\":0,\"observations\":", source_side ? "source" : "original");
    spx_observer o = spx_observe_begin(out); lifecycle_observe(&o); REQUIRE(spx_observe_finish(&o));
    fputs(",\"diagnostics\":", out); o = spx_observe_begin(out); lifecycle_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n", out); fclose(out);
}
static BOOL lifecycle_main(HINSTANCE instance, DWORD reason, void *reserved) {
    if (!drawing_main(instance, reason, reserved)) return FALSE;
    if (reason == DLL_PROCESS_DETACH) { lifecycle_report(); return TRUE; }
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    REQUIRE(install_load((void (*)(void))live_load)); REQUIRE(install_capture((void (*)(void))live_capture));
    REQUIRE(install_restore(live_restore)); return TRUE;
}
#ifndef LIFECYCLE_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved) {
    return lifecycle_main(instance, reason, reserved);
}
#endif
