/* Portable comparison services. Native inline getc uses this same owned buffer. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pcx-runtime.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
#define REQUIRE(value) do { if (!(value)) { fprintf(stderr, "pcx runtime %u: %s\n", __LINE__, #value); exit(3); } } while (0)
static pcx_state palettes;
static font_surface surface = {1};
static unsigned char *storage, *pixels;
static uint32_t width, height, pitch, storage_size, mode, lock_calls, entries[3];
static uint32_t service_events[64][6], service_count, applied_count;
static unsigned char applied[4][1024];
struct file_backend { pcx_file view; FILE *stream; unsigned char buffer[1024]; uint32_t refills, closed, position; };
static struct file_backend files[8];
static uint32_t file_count, chunk;
void pcx_enter(unsigned operation) { REQUIRE(operation < 3); ++entries[operation]; }
static void service_event(uint32_t kind, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e) {
    REQUIRE(service_count < 64); uint32_t *row = service_events[service_count++];
    row[0] = kind; row[1] = a; row[2] = b; row[3] = c; row[4] = d; row[5] = e;
}
static struct file_backend *backend(pcx_file *view) {
    for (unsigned i = 0; i < file_count; ++i) if (&files[i].view == view) return &files[i];
    REQUIRE(0); return NULL;
}
pcx_file *pcx_open(void *unused, asset_name *name) {
    (void)unused; REQUIRE(file_count < 8); struct file_backend *file = &files[file_count++];
    file->stream = fopen(name->text, "rb"); REQUIRE(file->stream);
    file->view.cursor = file->buffer; file->view.available = 0;
    service_event(1, file_count, 0, 0, 0, 0); return &file->view;
}
uint32_t pcx_refill(void *unused, pcx_file *view) {
    (void)unused; struct file_backend *file = backend(view); REQUIRE(!file->closed);
    ++file->refills; size_t count = fread(file->buffer, 1, chunk, file->stream);
    view->cursor = file->buffer; view->available = (uint32_t)count;
    if (!count) return UINT32_MAX;
    --view->available; return *view->cursor++;
}
void pcx_seek(void *unused, pcx_file *view, uint32_t offset, uint32_t origin) {
    (void)unused; struct file_backend *file = backend(view); REQUIRE(!file->closed && origin == 2);
    int result = fseek(file->stream, (long)font_signed(offset), SEEK_END);
    view->cursor = file->buffer; view->available = 0;
    service_event(2, (uint32_t)(file-files)+1, offset, origin, result ? 1 : 0, 0);
}
void pcx_close(void *unused, pcx_file *view) {
    (void)unused; struct file_backend *file = backend(view); REQUIRE(!file->closed);
    long physical = ftell(file->stream); REQUIRE(physical >= 0);
    file->position = (uint32_t)physical - (font_signed(view->available) > 0 ? view->available : 0);
    REQUIRE(fclose(file->stream) == 0); file->closed = 1;
    service_event(3, (uint32_t)(file-files)+1, file->position, file->refills, 0, 0);
}
void pcx_describe(void *unused, font_surface *s, pcx_view *view) {
    (void)unused; REQUIRE(s == &surface);
    *view = (pcx_view){{NULL, pitch}, width, height};
    service_event(4, width, height, pitch, 0, 0);
}
uint32_t pcx_lock(void *unused, font_surface *s, pcx_view *view) {
    (void)unused; REQUIRE(s == &surface);
    uint32_t result = mode == 1 && lock_calls < 2 ? 0x88760001 : 0; ++lock_calls;
    view->image.pixels = pixels;
    if (mode == 3) { view->image.pitch = 1; view->width = 2; view->height = 2; }
    service_event(5, lock_calls, result, view->width, view->height, view->image.pitch); return result;
}
void pcx_unlock(void *unused, font_surface *s) { (void)unused; REQUIRE(s == &surface); service_event(6, 0, 0, 0, 0, 0); }
void pcx_apply(void *unused, pcx_state *state) {
    (void)unused; REQUIRE(state == &palettes && applied_count < 4);
    memcpy(applied[applied_count++], state->current, 1024); service_event(7, applied_count, 0, 0, 0, 0);
    if (mode == 4) { state->current[7][3] ^= 0xff; state->current[2][1] ^= 17; }
}

#ifndef DX_STANDALONE
static uint32_t native_surface, surface_vtable[33], native_palette, palette_vtable[7];
static void palette_to_native(void) { memcpy((void *)0x42c148, palettes.current, 1024); memcpy((void *)0x42c548, palettes.staged, 1024); }
static void palette_from_native(void) { memcpy(palettes.current, (void *)0x42c148, 1024); memcpy(palettes.staged, (void *)0x42c548, 1024); }
static pcx_file *native_open(const char *name, const char *access) {
    REQUIRE(!strcmp(access, "rb")); asset_name input = {name}; return pcx_open(NULL, &input);
}
static uint32_t native_refill(pcx_file *file) { return pcx_refill(NULL, file); }
static uint32_t native_seek(pcx_file *file, uint32_t offset, uint32_t origin) { pcx_seek(NULL, file, offset, origin); return 0; }
static uint32_t native_close(pcx_file *file) { pcx_close(NULL, file); return 0; }
static uint32_t WINAPI native_describe(uint32_t object, uint32_t *desc) {
    REQUIRE(object == (uint32_t)(uintptr_t)&native_surface && desc[0] == 0x6c && desc[1] == 0xe);
    pcx_view view; pcx_describe(NULL, &surface, &view);
    desc[2] = view.height; desc[3] = view.width; desc[4] = view.image.pitch; return 0x80004005;
}
static uint32_t WINAPI native_lock(uint32_t object, void *rect, uint32_t *desc, uint32_t flags, void *event) {
    REQUIRE(object == (uint32_t)(uintptr_t)&native_surface && !rect && !flags && !event && desc[0] == 0x6c);
    pcx_view view = {{NULL, desc[4]}, desc[3], desc[2]};
    uint32_t result = pcx_lock(NULL, &surface, &view);
    desc[2] = view.height; desc[3] = view.width; desc[4] = view.image.pitch;
    desc[9] = (uint32_t)(uintptr_t)view.image.pixels; return result;
}
static uint32_t WINAPI native_unlock(uint32_t object, void *pointer) {
    REQUIRE(object == (uint32_t)(uintptr_t)&native_surface && !pointer); pcx_unlock(NULL, &surface); return 0;
}
static uint32_t WINAPI native_apply(uint32_t object, uint32_t flags, uint32_t start, uint32_t count, void *values) {
    REQUIRE(object == (uint32_t)(uintptr_t)&native_palette && !flags && !start && count == 256 && values == (void *)0x42c148);
    palette_from_native(); pcx_apply(NULL, &palettes); palette_to_native(); return 0;
}
static void native_draw(uint32_t object, const char *name, uint32_t palette, uint32_t x, uint32_t y) {
    REQUIRE(object == (uint32_t)(uintptr_t)&native_surface); asset_name input = {name}; palette_from_native();
    fixture_pcx_draw(&palettes, &surface, &input, palette, x, y); palette_to_native();
}
static void native_current(const char *name) {
    asset_name input = {name}; palette_from_native(); fixture_pcx_palette_current(&palettes, &input); palette_to_native();
}
static void native_staged(const char *name) {
    asset_name input = {name}; palette_from_native(); fixture_pcx_palette_staged(&palettes, &input); palette_to_native();
}
static void install(int source) {
    surface_vtable[22] = (uint32_t)(uintptr_t)native_describe;
    surface_vtable[25] = (uint32_t)(uintptr_t)native_lock;
    surface_vtable[32] = (uint32_t)(uintptr_t)native_unlock;
    native_surface = (uint32_t)(uintptr_t)surface_vtable;
    palette_vtable[6] = (uint32_t)(uintptr_t)native_apply; native_palette = (uint32_t)(uintptr_t)palette_vtable;
    *(uint32_t *)0x4349b8 = (uint32_t)(uintptr_t)&native_palette;
    REQUIRE(install_pcx_open((void (*)(void))native_open)); REQUIRE(install_pcx_refill((void (*)(void))native_refill));
    REQUIRE(install_pcx_seek((void (*)(void))native_seek)); REQUIRE(install_pcx_close((void (*)(void))native_close));
    if (source) {
        REQUIRE(install_pcx_draw((void (*)(void))native_draw));
        REQUIRE(install_pcx_palette_current((void (*)(void))native_current));
        REQUIRE(install_pcx_palette_staged((void (*)(void))native_staged));
    }
}
#endif

static void observe_palette(spx_observer *o, const char *name) {
    spx_observe_object(o, name); spx_observe_bytes(o, "current", palettes.current, sizeof(palettes.current));
    spx_observe_bytes(o, "staged", palettes.staged, sizeof(palettes.staged)); spx_observe_end(o);
}
int main(int argc, char **argv) {
    REQUIRE(argc == 7); asset_name name = {argv[2]};
    uint32_t palette = (uint32_t)strtoul(argv[3], NULL, 10), x = (uint32_t)strtoul(argv[4], NULL, 10), y = (uint32_t)strtoul(argv[5], NULL, 10);
    mode = (uint32_t)strtoul(argv[6], NULL, 10); REQUIRE(mode < 5);
    int real = name.text[0] >= 'A' && name.text[0] <= 'Z';
    width = real ? 640 : 17; height = real ? 480 : 9; pitch = width+3;
    storage_size = pitch*height+32; storage = malloc(storage_size); REQUIRE(storage); memset(storage, 0x6d, storage_size); pixels = storage+16;
    for (unsigned i = 0; i < 256; ++i) for (unsigned channel = 0; channel < 4; ++channel) {
        palettes.current[i][channel] = (unsigned char)(i+channel*41); palettes.staged[i][channel] = (unsigned char)(3*i+channel*57);
    }
    chunk = mode == 1 ? 7 : mode == 2 ? 1 : 1024;
#ifndef DX_STANDALONE
    int source = !strcmp(argv[1], "source"); install(source); palette_to_native();
    ((void (*)(uint32_t,const char *,uint32_t,uint32_t,uint32_t))(uintptr_t)0x402490)
        ((uint32_t)(uintptr_t)&native_surface, name.text, palette, x, y); palette_from_native();
#else
    REQUIRE(!strcmp(argv[1], "source")); fixture_pcx_draw(&palettes, &surface, &name, palette, x, y);
#endif
    spx_observer o = spx_observe_begin(stdout); spx_observe_bytes(&o, "pixels", storage, storage_size);
    observe_palette(&o, "after_draw");
#ifndef DX_STANDALONE
    ((void (*)(const char *))(uintptr_t)0x402320)(name.text); ((void (*)(const char *))(uintptr_t)0x4023e0)(name.text); palette_from_native();
    if (source) REQUIRE(install_pcx_draw_intact() && install_pcx_palette_current_intact() && install_pcx_palette_staged_intact()
                        && entries[0] && entries[1] && entries[2]);
#else
    fixture_pcx_palette_current(&palettes, &name); fixture_pcx_palette_staged(&palettes, &name);
#endif
    observe_palette(&o, "after_palettes"); spx_observe_array(&o, "files");
    for (unsigned i = 0; i < file_count; ++i) {
        uint32_t row[] = {files[i].refills, files[i].closed, files[i].position, files[i].view.available};
        spx_observe_u32s(&o, NULL, row, 4);
    }
    spx_observe_end(&o); spx_observe_object(&o, "services"); spx_observe_array(&o, "events");
    for (unsigned i = 0; i < service_count; ++i) spx_observe_u32s(&o, NULL, service_events[i], 6);
    spx_observe_end(&o); spx_observe_array(&o, "applied");
    for (unsigned i = 0; i < applied_count; ++i) spx_observe_bytes(&o, NULL, applied[i], 1024);
    spx_observe_end(&o); spx_observe_end(&o); REQUIRE(spx_observe_finish(&o)); fputs("\n", stdout);
    fprintf(stderr, "PCX_SELECTED %u %u %u\n", entries[0], entries[1], entries[2]); free(storage); return 0;
}
#ifndef DX_STANDALONE
struct native_startupinfo { int newmode; };
extern int __cdecl __getmainargs(int *, char ***, char ***, int, struct native_startupinfo *);
static void run_case(void) {
    int count; char **arguments, **environment; struct native_startupinfo startup = {0};
    REQUIRE(__getmainargs(&count, &arguments, &environment, 0, &startup) == 0);
    int result = main(count, arguments); fflush(NULL); ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_pcx_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved) {
    (void)instance; (void)reserved;
    return reason != DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL) == 0x400000 && install_startup(run_case));
}
#endif
