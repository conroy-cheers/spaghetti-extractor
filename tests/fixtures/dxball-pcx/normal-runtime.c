/* Actual CRT streams and DirectDraw storage behind the portable PCX contracts. */
#define FLOW_NORMAL_LIBRARY_ONLY 1
#include "flow-normal-runtime.c"
#include "pcx-runtime.h"

static pcx_state palettes;
static uint32_t pcx_entries[3], pcx_depth, pcx_count, pcx_calls[24][13];
static unsigned char pcx_names[24][32];
struct pcx_native_file { pcx_file view; uint32_t address; };
struct pcx_native_lease { pcx_view *view; font_surface *surface; uint32_t desc[27]; struct pcx_native_lease *next; };
static struct pcx_native_lease *pcx_leases;
void pcx_enter(unsigned operation) { REQUIRE(operation < 3); ++pcx_entries[operation]; }
static void pcx_pull(void) { memcpy(palettes.current, (void *)0x42c148, 1024); memcpy(palettes.staged, (void *)0x42c548, 1024); }
static void pcx_push(void) { memcpy((void *)0x42c148, palettes.current, 1024); memcpy((void *)0x42c548, palettes.staged, 1024); }
static void file_pull(struct pcx_native_file *file) {
    file->view.cursor = (const unsigned char *)(uintptr_t)*word(file->address);
    file->view.available = *word(file->address+4);
}
static void file_push(struct pcx_native_file *file) {
    *word(file->address) = (uint32_t)(uintptr_t)file->view.cursor;
    *word(file->address+4) = file->view.available;
}
pcx_file *pcx_open(void *unused, asset_name *name) {
    (void)unused; struct pcx_native_file *file = malloc(sizeof(*file)); REQUIRE(file);
    file->address = ((uint32_t (*)(const char *,const char *))(uintptr_t)0x40e190)(name->text, "rb");
    REQUIRE(file->address); file_pull(file); return &file->view;
}
uint32_t pcx_refill(void *unused, pcx_file *view) {
    (void)unused; struct pcx_native_file *file = (struct pcx_native_file *)view; file_push(file);
    uint32_t result = ((uint32_t (*)(uint32_t))(uintptr_t)0x40dfd0)(file->address);
    file_pull(file); return result;
}
void pcx_seek(void *unused, pcx_file *view, uint32_t offset, uint32_t origin) {
    (void)unused; struct pcx_native_file *file = (struct pcx_native_file *)view; file_push(file);
    ((uint32_t (*)(uint32_t,uint32_t,uint32_t))(uintptr_t)0x40e0c0)(file->address, offset, origin); file_pull(file);
}
void pcx_close(void *unused, pcx_file *view) {
    (void)unused; struct pcx_native_file *file = (struct pcx_native_file *)view; file_push(file);
    ((uint32_t (*)(uint32_t))(uintptr_t)0x40df50)(file->address); free(file);
}
void pcx_describe(void *unused, font_surface *surface, pcx_view *view) {
    (void)unused; struct pcx_native_lease *lease = calloc(1, sizeof(*lease)); REQUIRE(lease);
    lease->view = view; lease->surface = surface; lease->desc[0] = sizeof(lease->desc); lease->desc[1] = 0xe;
    uint32_t address = surface_address(surface), *table = word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,void *))(uintptr_t)table[22])(address, lease->desc);
    view->width = lease->desc[3]; view->height = lease->desc[2]; view->image.pitch = lease->desc[4];
    view->image.pixels = NULL; lease->next = pcx_leases; pcx_leases = lease;
}
uint32_t pcx_lock(void *unused, font_surface *surface, pcx_view *view) {
    (void)unused; struct pcx_native_lease *lease = pcx_leases;
    while (lease && lease->view != view) lease = lease->next;
    REQUIRE(lease && lease->surface == surface);
    uint32_t address = surface_address(surface), *table = word(*word(address));
    uint32_t result = ((uint32_t (WINAPI *)(uint32_t,void *,void *,uint32_t,void *))(uintptr_t)table[25])
        (address, NULL, lease->desc, 0, NULL);
    view->width = lease->desc[3]; view->height = lease->desc[2]; view->image.pitch = lease->desc[4];
    view->image.pixels = (unsigned char *)(uintptr_t)lease->desc[9]; return result;
}
void pcx_unlock(void *unused, font_surface *surface) {
    (void)unused; struct pcx_native_lease **link = &pcx_leases;
    while (*link && (*link)->surface != surface) link = &(*link)->next;
    REQUIRE(*link); struct pcx_native_lease *lease = *link;
    uint32_t address = surface_address(surface), *table = word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,void *))(uintptr_t)table[32])(address, NULL);
    *link = lease->next; free(lease);
}
void pcx_apply(void *unused, pcx_state *state) {
    (void)unused; REQUIRE(state == &palettes); pcx_push();
    uint32_t address = *word(0x4349b8), *table = word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,uint32_t,uint32_t,uint32_t,void *))(uintptr_t)table[6])
        (address, 0, 0, 256, (void *)0x42c148); pcx_pull();
}
static uint64_t hash_bytes(uint64_t hash, const unsigned char *bytes, uint32_t size) {
    for (uint32_t i = 0; i < size; ++i) hash = (hash ^ bytes[i]) * UINT64_C(1099511628211);
    return hash;
}
static void pcx_record(unsigned operation, uint32_t surface, const char *name, uint32_t palette, uint32_t x, uint32_t y) {
    if (pcx_count == 24) return;
    uint32_t index = pcx_count++, *row = pcx_calls[index];
    row[0] = operation; row[1] = surface ? observed_surface(surface) : 0; row[2] = palette; row[3] = x; row[4] = y;
    for (unsigned i = 0; i < 31 && name[i]; ++i) pcx_names[index][i] = (unsigned char)name[i];
    if (surface) {
        /* Observe visible bytes after the operation. Both instrumented sides
         * take this extra read lock; the plain control remains untouched. */
        uint32_t *table = word(*word(surface)), desc[27] = {0}; desc[0] = sizeof(desc);
        REQUIRE(((uint32_t (WINAPI *)(uint32_t,void *,void *,uint32_t,void *))(uintptr_t)table[25])
            (surface, NULL, desc, 0, NULL) == 0);
        row[5] = desc[3]; row[6] = desc[2]; REQUIRE(row[5] <= desc[4] && row[5] <= 4096 && row[6] <= 4096);
        uint64_t hash = UINT64_C(14695981039346656037);
        for (uint32_t line = 0; line < row[6]; ++line)
            hash = hash_bytes(hash, (const unsigned char *)(uintptr_t)desc[9]+line*desc[4], row[5]);
        row[7] = (uint32_t)hash; row[8] = (uint32_t)(hash >> 32);
        REQUIRE(((uint32_t (WINAPI *)(uint32_t,void *))(uintptr_t)table[32])(surface, NULL) == 0);
    }
    uint64_t current = hash_bytes(UINT64_C(14695981039346656037), (const unsigned char *)0x42c148, 1024);
    uint64_t staged = hash_bytes(UINT64_C(14695981039346656037), (const unsigned char *)0x42c548, 1024);
    row[9] = (uint32_t)current; row[10] = (uint32_t)(current >> 32);
    row[11] = (uint32_t)staged; row[12] = (uint32_t)(staged >> 32);
}
static void live_pcx_draw(uint32_t surface, const char *name, uint32_t palette, uint32_t x, uint32_t y) {
    unsigned outer = !pcx_depth++;
    if (source_side) {
        pcx_pull(); asset_name input = {name}; fixture_pcx_draw(&palettes, surface_view(surface), &input, palette, x, y); pcx_push();
    } else {
        REQUIRE(spx_fixture_restore_entry(&install_pcx_draw_hook));
        ((void (*)(uint32_t,const char *,uint32_t,uint32_t,uint32_t))(uintptr_t)0x402490)(surface, name, palette, x, y);
        install_pcx_draw_hook.entry = NULL; REQUIRE(install_pcx_draw((void (*)(void))live_pcx_draw));
    }
    --pcx_depth; if (outer) pcx_record(0, surface, name, palette, x, y);
}
#define PALETTE(name, operation, address) \
static void live_pcx_##name(const char *text) { \
    unsigned outer = !pcx_depth++; \
    if (source_side) { pcx_pull(); asset_name input = {text}; fixture_pcx_##name(&palettes, &input); pcx_push(); } \
    else { \
        REQUIRE(spx_fixture_restore_entry(&install_pcx_##name##_hook)); ((void (*)(const char *))(uintptr_t)address)(text); \
        install_pcx_##name##_hook.entry = NULL; REQUIRE(install_pcx_##name((void (*)(void))live_pcx_##name)); \
    } \
    --pcx_depth; if (outer) pcx_record(operation, 0, text, 0, 0, 0); \
}
PALETTE(palette_current, 1, 0x402320) PALETTE(palette_staged, 2, 0x4023e0)
static void pcx_observe(spx_observer *o) {
    flow_observe(o); spx_observe_array(o, "images");
    for (uint32_t i = 0; i < pcx_count; ++i) {
        spx_observe_object(o, NULL); spx_observe_u32s(o, "values", pcx_calls[i], 13);
        spx_observe_bytes(o, "name", pcx_names[i], 32); spx_observe_end(o);
    }
    spx_observe_end(o);
}
static void pcx_diagnose(spx_observer *o) {
    flow_diagnose(o); spx_observe_u32s(o, "selected_pcx", pcx_entries, 3);
}
static void pcx_report(void) {
    const char *path = getenv("SPX_COMPARISON_REPORT"); if (!path) return;
    FILE *out = fopen(path, "wb"); REQUIRE(out);
    fprintf(out, "{\"side\":\"%s\",\"exit_code\":0,\"observations\":", source_side ? "source" : "original");
    spx_observer o = spx_observe_begin(out); pcx_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":", out); o = spx_observe_begin(out);
    pcx_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n", out); fclose(out);
}
static BOOL pcx_main(HINSTANCE instance, DWORD reason, void *reserved) {
    if (!flow_main(instance, reason, reserved)) return FALSE;
    if (reason == DLL_PROCESS_DETACH) { REQUIRE(!pcx_leases); pcx_report(); return TRUE; }
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    REQUIRE(install_pcx_draw((void (*)(void))live_pcx_draw));
    REQUIRE(install_pcx_palette_current((void (*)(void))live_pcx_palette_current));
    REQUIRE(install_pcx_palette_staged((void (*)(void))live_pcx_palette_staged)); return TRUE;
}
#ifndef PCX_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved) {
    return pcx_main(instance, reason, reserved);
}
#endif
