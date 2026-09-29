#include "windows-1252.h"
#include "portable-component-implementation.h"
#include "stream-view.h"
#include <errno.h>
#include <stdlib.h>

typedef struct spx_opaque_io_stream_v5 Stream;
static FILE *borrow(Stream *stream) {
    FILE *file=spx_stream_borrow(stream);
    if (!file) _Exit(125);
    return file;
}
static uint32_t pending(void *context,Stream *stream) {
    (void)context;return spx_target_stream_pending(borrow(stream));
}
static int32_t error(void *context,Stream *stream) {
    (void)context;return spx_target_stream_error(borrow(stream));
}
static int32_t close_stream(void *context,Stream *stream) {
    (void)context;FILE *file=spx_stream_take(stream);
    if (!file) _Exit(125);
    return spx_target_stream_close(file);
}
static uint32_t bad_descriptor(void *context) { (void)context;return errno==EBADF; }
static void clear_errno(void *context) { (void)context;errno=0; }

int spx_target_close(FILE *file) {
    Stream stream={file,1};
    const spx_stream_close_services_v5 services={.pending=pending,.error=error,.close=close_stream,
        .bad_descriptor=bad_descriptor,.clear_errno=clear_errno};
    spx_stream_close_context_v5 context={.services=&services};
    return lifted_stream_close(&context,&stream);
}
