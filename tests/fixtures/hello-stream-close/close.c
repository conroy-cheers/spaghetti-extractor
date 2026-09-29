#include "portable-component-implementation.h"

int32_t lifted_stream_close(spx_stream_close_context_v5 *context,
                            struct spx_opaque_io_stream_v5 *stream) {
    const spx_stream_close_services_v5 *services = context->services;
    uint32_t pending = services->pending(services->context, stream);
    int32_t failed = services->error(services->context, stream);
    int32_t closed = services->close(services->context, stream);
    if (failed) {
        if (!closed) services->clear_errno(services->context);
        return -1;
    }
    if (closed && (pending || !services->bad_descriptor(services->context))) return -1;
    return 0;
}
