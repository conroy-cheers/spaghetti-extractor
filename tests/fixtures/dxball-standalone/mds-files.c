/* Portable read-only asset mappings for the MDS loader. File and mapping
 * handles retain the stream independently; mapped bytes live until unmap. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "mds-loader-runtime.h"
#include "file-storage.h"

typedef struct { FILE *stream; unsigned references; } file_owner;
typedef struct { mds_handle view; file_owner *file; unsigned mapping; } file_handle;
typedef struct { mds_file view; unsigned char bytes[]; } mapped_file;
#define OWNER(pointer, type, field) ((type *)((unsigned char *)(pointer)-offsetof(type, field)))

static long file_size(file_owner *file) {
    long position = ftell(file->stream);
    if (position < 0 || fseek(file->stream, 0, SEEK_END)) return -1;
    long result = ftell(file->stream);
    if (fseek(file->stream, position, SEEK_SET)) return -1;
    return result;
}
mds_handle *loader_open(void *u, mds_input *input, uint32_t access, uint32_t share,
                        uint32_t disposition, uint32_t attributes) {
    (void)u;
    if (access != 0x80000000 || share != 1 || disposition != 3 || attributes != 0x80) abort();
    FILE *stream = dxball_asset_open((const char *)input->data);
    if (!stream) return NULL;
    file_owner *file = malloc(sizeof(*file));
    file_handle *handle = malloc(sizeof(*handle));
    if (!file || !handle) { free(file); free(handle); fclose(stream); return NULL; }
    *file = (file_owner){stream, 1};
    *handle = (file_handle){{(uintptr_t)stream}, file, 0};
    return &handle->view;
}
uint32_t loader_size(void *u, mds_handle *handle) {
    (void)u;
    long size = file_size(OWNER(handle, file_handle, view)->file);
    return size < 0 ? UINT32_MAX : (uint32_t)(unsigned long)size;
}
mds_handle *loader_mapping(void *u, mds_handle *handle, uint32_t flags) {
    (void)u;
    if (flags != 2) abort();
    file_owner *file = OWNER(handle, file_handle, view)->file;
    if (file_size(file) <= 0) return NULL;
    file_handle *mapping = malloc(sizeof(*mapping));
    if (!mapping) return NULL;
    *mapping = (file_handle){{(uintptr_t)mapping}, file, 1};
    ++file->references;
    return &mapping->view;
}
mds_file *loader_map(void *u, mds_handle *handle, uint32_t flags) {
    (void)u;
    file_handle *mapping = OWNER(handle, file_handle, view);
    if (flags != 4 || !mapping->mapping) abort();
    long length = file_size(mapping->file);
    if (length <= 0 || (uintmax_t)length > SIZE_MAX-sizeof(mapped_file)) return NULL;
    mapped_file *view = malloc(sizeof(*view)+(size_t)length);
    if (!view) return NULL;
    if (fseek(mapping->file->stream, 0, SEEK_SET) ||
        fread(view->bytes, 1, (size_t)length, mapping->file->stream) != (size_t)length) {
        free(view); return NULL;
    }
    view->view.data = view->bytes;
    return &view->view;
}
uint32_t loader_unmap(void *u, mds_file *file) {
    (void)u;
    if (!file) return 0;
    free(OWNER(file, mapped_file, view));
    return 1;
}
uint32_t loader_close(void *u, mds_handle *handle) {
    (void)u;
    if (!handle) return 0;
    file_handle *owned = OWNER(handle, file_handle, view);
    file_owner *file = owned->file;
    free(owned);
    int result = 0;
    if (!--file->references) { result = fclose(file->stream); free(file); }
    return result == 0;
}
