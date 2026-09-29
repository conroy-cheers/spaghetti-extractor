/* Standard C file/storage bindings. Application layouts stay in the component
 * views; no executable addresses or original CRT objects are required. */
#include <stdlib.h>
#include <string.h>
#include "file-storage.h"
#include "asset-runtime.h"
#include "pcx-runtime.h"
#include "reader-runtime.h"
#include "wave-runtime.h"
#include "audio-runtime.h"

struct spx_opaque_asset_file_v5 { struct dxball_program_file file; };
typedef struct { pcx_file view; FILE *stream; unsigned char bytes[4096]; } pcx_input;
typedef struct { struct dxball_program_file file; reader_handle view; } reader_input;
#define OWNER(pointer, type, field) ((type *)((unsigned char *)(pointer)-offsetof(type, field)))

FILE *dxball_asset_open(const char *name) {
    size_t size = strlen(name) + 1;
    char *path = malloc(size);
    if (!path) return NULL;
    for (size_t i = 0; i < size; ++i) path[i] = name[i] == '\\' ? '/' : name[i];
    FILE *stream = fopen(path, "rb");
    free(path);
    return stream;
}
asset_file *asset_open(void *u, asset_state *s, asset_name *name) {
    (void)u;
    asset_file *file = malloc(sizeof(*file));
    return dxball_file_opened(DXBALL_OWNER(s, assets), file ? &file->file : NULL,
                             dxball_asset_open(name->text)) ? file : NULL;
}
uint32_t asset_read(void *u, asset_state *s, asset_buffer *buffer, uint32_t size, uint32_t count) {
    (void)u;
    return (uint32_t)fread(buffer->data, size, count, s->file->file.stream);
}
void asset_close(void *u, asset_state *s) {
    (void)u;
    (void)fclose(s->file->file.stream);
    s->file->file.stream = NULL;
}
asset_buffer *asset_allocate_pixels(void *u, asset_state *s, uint32_t bytes) {
    (void)u; (void)s;
    asset_buffer *view = malloc(sizeof(*view));
    if (!view) return NULL;
    view->data = malloc(bytes); view->size = bytes;
    if (!view->data) { free(view); return NULL; }
    return view;
}
void asset_free_pixels(void *u, asset_state *s, asset_buffer *buffer) {
    (void)u; (void)s;
    free(buffer->data); free(buffer);
}
font_sprite *asset_allocate_sprite(void *u, asset_state *s) {
    (void)u; (void)s; return malloc(sizeof(font_sprite));
}
void trial_free_sprite(void *u, struct spx_opaque_cleanup_state_v5 *s, font_sprite *sprite) {
    (void)u; (void)s; free(sprite);
}
pcx_file *pcx_open(void *u, asset_name *name) {
    (void)u;
    FILE *stream = dxball_asset_open(name->text);
    if (!stream) return NULL;
    pcx_input *file = malloc(sizeof(*file));
    if (!file) { fclose(stream); return NULL; }
    file->view = (pcx_file){NULL, 0}; file->stream = stream;
    return &file->view;
}
uint32_t pcx_refill(void *u, pcx_file *file) {
    (void)u;
    pcx_input *owned = OWNER(file, pcx_input, view);
    size_t count = fread(owned->bytes, 1, sizeof(owned->bytes), owned->stream);
    file->available = count ? (uint32_t)count - 1 : 0;
    file->cursor = owned->bytes + (count != 0);
    return count ? owned->bytes[0] : UINT32_MAX;
}
void pcx_seek(void *u, pcx_file *file, uint32_t offset, uint32_t origin) {
    (void)u;
    int64_t distance = font_signed(offset);
    if (origin == SEEK_CUR) distance -= file->available;
    (void)fseek(OWNER(file, pcx_input, view)->stream, (long)distance, (int)origin);
    file->available = 0;
}
void pcx_close(void *u, pcx_file *file) {
    (void)u;
    pcx_input *owned = OWNER(file, pcx_input, view);
    fclose(owned->stream); free(owned);
}

reader_handle *reader_open(void *u, reader_name *name, uint32_t access, uint32_t share,
                           uint32_t disposition, uint32_t attributes) {
    if (!u || access != 0x80000000 || share != 1 || disposition != 3 || attributes != 0x80) abort();
    /* The file token must be first: the program owner disposes that allocation. */
    reader_input *file = malloc(sizeof(*file));
    if (!dxball_file_opened(u, file ? &file->file : NULL, dxball_asset_open(name->text))) return NULL;
    file->view.value = (uintptr_t)file->file.stream;
    return &file->view;
}
uint32_t reader_size(void *u, reader_handle *handle) {
    (void)u;
    struct dxball_program_file *file = &OWNER(handle, reader_input, view)->file;
    long position = ftell(file->stream);
    if (position < 0 || fseek(file->stream, 0, SEEK_END)) return UINT32_MAX;
    long size = ftell(file->stream);
    if (fseek(file->stream, position, SEEK_SET) || size < 0) return UINT32_MAX;
    return (uint32_t)(unsigned long)size;
}
reader_bytes *reader_allocate(void *u, uint32_t bytes) {
    dxball_program *p = u;
    if (!p) abort();
    struct dxball_program_bytes *owned = malloc(sizeof(*owned));
    if (!owned) return NULL;
    unsigned char *data = malloc(bytes ? bytes : 1);
    if (!data) { free(owned); return NULL; }
    *owned = (struct dxball_program_bytes){{data}, {data}, 1, p->file_bytes};
    p->file_bytes = owned;
    return &owned->reader;
}
uint32_t reader_read(void *u, reader_handle *handle, reader_bytes *buffer, uint32_t size) {
    (void)u;
    struct dxball_program_file *file = &OWNER(handle, reader_input, view)->file;
    size_t transferred = fread(buffer->bytes, 1, size, file->stream);
    (void)transferred;
    /* Synchronous ReadFile succeeds at EOF even when the count is short. */
    return !ferror(file->stream);
}
void reader_free(void *u, reader_bytes *buffer) {
    dxball_program *p = u;
    if (!p) abort();
    for (struct dxball_program_bytes *owned = p->file_bytes; owned; owned = owned->next)
        if (&owned->reader == buffer) { owned->live = 0; break; }
    /* Preserve the original's free on read failure even for a supplied buffer.
     * Retained view fields are not cleared as an accidental lifetime repair. */
    free(buffer->bytes);
}
void reader_close(void *u, reader_handle *handle) {
    (void)u;
    struct dxball_program_file *file = &OWNER(handle, reader_input, view)->file;
    (void)fclose(file->stream); file->stream = NULL;
}
void dxball_program_dispose_bytes(dxball_program *p) {
    while (p->file_bytes) {
        struct dxball_program_bytes *owned = p->file_bytes;
        p->file_bytes = owned->next;
        if (owned->live) free(owned->reader.bytes);
        free(owned);
    }
}
wave_bytes *wave_read_file(void *u, audio_state *s, audio_name *name, uint32_t supplied, uint32_t allocate) {
    (void)u;
    if (supplied || allocate != 1) abort();
    reader_name path = {name->text};
    reader_bytes *bytes = dxball_program_file_read(DXBALL_OWNER(s, audio), &path, NULL, 1);
    return bytes ? &OWNER(bytes, struct dxball_program_bytes, reader)->wave : NULL;
}
void wave_free_file(void *u, audio_state *s, wave_bytes *bytes) {
    (void)u;
    struct dxball_program_bytes *owned = OWNER(bytes, struct dxball_program_bytes, wave);
    reader_free(DXBALL_OWNER(s, audio), &owned->reader);
}
audio_sample *wave_allocate(void *u, audio_state *s, uint32_t size) {
    (void)u; (void)s;
    if (size != 37) abort();
    return malloc(sizeof(audio_sample));
}
void audio_free_sample(void *u, audio_state *s, audio_sample *sample) { (void)u; (void)s; free(sample); }
void wave_free_sample(void *u, audio_state *s, audio_sample *sample) { audio_free_sample(u, s, sample); }
void wave_terminate(void *u, uint32_t status) { (void)u; exit((int)status); }
