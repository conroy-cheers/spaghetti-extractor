#ifndef SPX_JQ_OBJECT_NATIVE_H
#define SPX_JQ_OBJECT_NATIVE_H
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "jv.h"
#pragma GCC diagnostic pop
#include "object-view.h"

/* jq 1.8.1 layout, shared by every adapter below. Read through character storage
 * and memcpy: the native allocation is not an object of our private C struct
 * type. Pointer transport alone would not establish these layout/lifetime facts. */
struct jq_object_slot_layout { int next; uint32_t hash; jv string, value; };
struct jq_object_layout { int references, next_free; struct jq_object_slot_layout slots[]; };
_Static_assert(CHAR_BIT == 8 && sizeof(int) == 4 && sizeof(jv) == 16, "jq value widths");
_Static_assert(offsetof(struct jq_object_layout, slots) == 8 &&
               offsetof(struct jq_object_slot_layout, string) == 8 &&
               offsetof(struct jq_object_slot_layout, value) == 24 &&
               sizeof(struct jq_object_slot_layout) == 40, "jq object layout");

static inline void object_contents(jv object, struct spx_opaque_object_table_v5 *view) {
    if (jv_get_kind(object) != JV_KIND_OBJECT || object.size <= 0 ||
        ((unsigned)object.size & ((unsigned)object.size - 1U))) abort();
    view->capacity = (uint32_t)object.size;
    view->stride = sizeof(struct jq_object_slot_layout);
    view->slots = (const unsigned char *)object.u.ptr + offsetof(struct jq_object_layout, slots);
    view->buckets = view->slots + view->stride * view->capacity;
}
static inline struct jq_object_slot_layout object_slot(struct spx_opaque_object_table_v5 *view, int32_t index) {
    struct jq_object_slot_layout slot;
    if (index < 0 || (uint32_t)index >= view->capacity) abort();
    memcpy(&slot, view->slots + view->stride * (uint32_t)index, sizeof(slot));
    return slot;
}
static inline uint32_t object_key_hash(jv key) {
    /* The public consuming service releases this temporary reference. It can
     * populate the original string's hash cache, as the native lookup does. */
    return (uint32_t)jv_string_hash(jv_copy(key));
}
static inline uint32_t object_key_equal(jv key, struct spx_opaque_object_table_v5 *view, int32_t index) {
    return (uint32_t)jv_equal(jv_copy(key), jv_copy(object_slot(view, index).string));
}
static inline jv object_value_copy(struct spx_opaque_object_table_v5 *view, int32_t index) {
    return jv_copy(object_slot(view, index).value);
}
jv fixture_object_get(jv, jv);
#endif
