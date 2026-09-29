/* Owned portable views of LocalAlloc/GlobalAlloc records used by MDS.
 * The parser and event conversion remain the existing lifted C. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "mds-storage.h"
#include "mds-loader-runtime.h"
#include "mds-parser-runtime.h"
#include "mds-events-runtime.h"
#include "mds-stream-runtime.h"

typedef struct {
    mds_info view;
    struct dxball_program *program;
    void *attachment;
    void (*dispose_attachment)(void *);
} owned_info;
struct spx_opaque_mds_memory_v5 {
    mds_buffers view;
    unsigned char *bytes;
    uint32_t size;
    unsigned locked;
};
#define OWNER(pointer, type, field) ((type *)((unsigned char *)(pointer)-offsetof(type, field)))

void dxball_mds_attach(mds_info *info, struct dxball_program *p) {
    OWNER(info, owned_info, view)->program = p;
}
struct dxball_program *dxball_mds_program(mds_info *info) {
    return OWNER(info, owned_info, view)->program;
}
void *dxball_mds_attachment(mds_info *info) { return OWNER(info, owned_info, view)->attachment; }
void dxball_mds_set_attachment(mds_info *info, void *attachment, void (*dispose)(void *)) {
    owned_info *owned = OWNER(info, owned_info, view);
    if (owned->attachment) abort();
    owned->attachment=attachment; owned->dispose_attachment=dispose;
}
mds_info *loader_allocate(void *u, uint32_t flags, uint32_t size) {
    (void)u;
    if (flags != 0x40 || size != 36) abort();
    /* LPTR zero initialization, with actual C pointers instead of PE32 words. */
    owned_info *info = calloc(1, sizeof(*info));
    return info ? &info->view : NULL;
}
mds_info *loader_free(void *u, mds_info *info) {
    (void)u;
    if (info) {
        owned_info *owned = OWNER(info, owned_info, view);
        if (owned->dispose_attachment) owned->dispose_attachment(owned->attachment);
        free(owned);
    }
    return NULL;
}
mds_memory *parser_allocate(void *u, uint32_t flags, uint32_t bytes) {
    (void)u;
    if (flags != 0x2002) abort();
    mds_memory *memory = calloc(1, sizeof(*memory));
    if (!memory) return NULL;
    memory->size = bytes;
    /* A zero-byte moveable allocation is discarded and cannot be locked. */
    if (bytes) {
        memory->bytes = malloc(bytes);
        if (!memory->bytes) { free(memory); return NULL; }
    }
    return memory;
}
mds_buffers *parser_lock(void *u, mds_info *info, mds_memory *memory) {
    (void)u;
    if (!memory || !memory->bytes) return NULL;
    uint64_t stride = (uint64_t)info->capacity + 64;
    if ((info->count && stride > memory->size / info->count) ||
        (uint64_t)info->count * sizeof(mds_buffer) > SIZE_MAX) {
        fputs("MDS header view exceeds its allocated span; unchecked native overflow needs explicit memory transport\n", stderr);
        abort();
    }
    if (!memory->view.headers) {
        memory->view.headers = malloc((size_t)info->count * sizeof(mds_buffer));
        if (!memory->view.headers) return NULL;
        for (uint32_t i = 0; i < info->count; ++i)
            memory->view.headers[i].payload = memory->bytes + (size_t)i * (size_t)stride + 64;
    }
    ++memory->locked;
    return &memory->view;
}
mds_memory *parser_allocation(void *u, mds_buffers *buffers) {
    (void)u;
    return buffers ? OWNER(buffers, mds_memory, view) : NULL;
}
uint32_t parser_unlock(void *u, mds_memory *memory) {
    (void)u;
    if (!memory || !memory->locked) return 0;
    return --memory->locked != 0;
}
mds_memory *parser_free(void *u, mds_memory *memory) {
    (void)u;
    if (memory) { free(memory->view.headers); free(memory->bytes); free(memory); }
    return NULL;
}
uint32_t loader_parse(void *u, mds_info *info, mds_file *file, uint32_t length) {
    (void)u; return fixture_mds_parse(info, file, length);
}
uint32_t parser_expand(void *u, mds_event_block *input, mds_event_block *output) {
    (void)u; return fixture_mds_expand(input, output);
}
mds_info *stream_free_info(void *u, mds_info *info) { return loader_free(u, info); }
mds_memory *stream_allocation(void *u, mds_buffers *buffers) { return parser_allocation(u, buffers); }
uint32_t stream_unlock(void *u, mds_memory *memory) { return parser_unlock(u, memory); }
mds_memory *stream_free_buffers(void *u, mds_memory *memory) { return parser_free(u, memory); }
