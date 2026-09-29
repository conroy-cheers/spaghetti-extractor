/* Call-scoped view of an existing stream. It never creates or copies its FILE. */
#ifndef SPX_STREAM_VIEW_H
#define SPX_STREAM_VIEW_H
#include <stdint.h>

struct spx_opaque_io_stream_v5 { void *handle; uint32_t live; };
static inline void *spx_stream_borrow(struct spx_opaque_io_stream_v5 *view) {
    return view && view->live ? view->handle : 0;
}
static inline void *spx_stream_take(struct spx_opaque_io_stream_v5 *view) {
    void *handle = spx_stream_borrow(view);
    if (handle) { view->handle = 0; view->live = 0; }
    return handle;
}
#endif
