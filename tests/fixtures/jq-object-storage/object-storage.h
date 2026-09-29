#ifndef SPX_JQ_OBJECT_STORAGE_H
#define SPX_JQ_OBJECT_STORAGE_H
#include "value-layout.h"

/* Live native storage remains shared with unlifted readers. Descriptors and
 * nested values use the array subsystem's existing representation boundary. */
struct jq_object_slot { int32_t next; uint32_t hash; jq_native_value key, value; };
struct jq_object_storage {
    struct jv_refcnt refcnt;
    int32_t next_free;
    struct jq_object_slot slots[];
};
_Static_assert(offsetof(struct jq_object_storage, slots) == 8 &&
    sizeof(struct jq_object_slot) == 40, "jq object slot layout");
struct spx_opaque_object_memory_v5;
typedef struct spx_opaque_jq_value_v5 jq_object_cell;
static inline struct jq_object_storage *jq_object_data(jq_object_cell *value) {
    return (struct jq_object_storage *)value->value.u.ptr;
}
static inline int32_t *jq_object_buckets(struct jq_object_storage *object, uint32_t capacity) {
    return (int32_t *)(object->slots + capacity);
}
#endif
