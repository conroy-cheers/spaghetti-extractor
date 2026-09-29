#ifndef SPX_JQ_OBJECT_VIEW_H
#define SPX_JQ_OBJECT_VIEW_H
#include <stddef.h>
#include <stdint.h>

/* Borrow the actual object's table, without copying or rebuilding its heap.
 * Slots start with a signed next index and a cached hash; the remaining native
 * fields are accessed by the shared adapters. The owner stays live until the
 * lookup finishes. No mutation, resize or reentrant caller may overlap a view. */
struct spx_opaque_object_table_v5 {
    const unsigned char *slots;
    const unsigned char *buckets;
    size_t stride;
    uint32_t capacity;
};
struct jq_object_link { int32_t next; uint32_t hash; };
_Static_assert(sizeof(struct jq_object_link) == 8, "object slot prefix");
#endif
