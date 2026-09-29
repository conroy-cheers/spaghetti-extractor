#ifndef SPX_JQ_OBJECT_MUTABLE_VIEW_H
#define SPX_JQ_OBJECT_MUTABLE_VIEW_H
#include "object-view.h"

/* Obtained after copy-on-write has established an exclusive table owner.
 * Shared key/value allocations retain their own references. The view ends at
 * return and must not survive resize, release or a reentrant mutation. */
struct spx_opaque_mutable_object_table_v5 {
    unsigned char *slots;
    unsigned char *buckets;
    size_t stride;
    uint32_t capacity;
};
#endif
