#ifndef SPX_JQ_OBJECT_MUTABLE_NATIVE_H
#define SPX_JQ_OBJECT_MUTABLE_NATIVE_H
#include "object-native.h"
#include "object-mutable-view.h"

/* Native and source backends supply the same reviewed ownership operation. */
jv spx_object_unshare(jv value);

static inline struct spx_opaque_object_table_v5 object_read_view(
        struct spx_opaque_mutable_object_table_v5 *view) {
    struct spx_opaque_object_table_v5 result = {
        view->slots, view->buckets, view->stride, view->capacity
    };
    return result;
}
static inline jv object_unshare_view(jv value, struct spx_opaque_mutable_object_table_v5 *view) {
    value = spx_object_unshare(value);
    struct spx_opaque_object_table_v5 readable;
    object_contents(value, &readable);
    view->slots = (unsigned char *)readable.slots;
    view->buckets = (unsigned char *)readable.buckets;
    view->stride = readable.stride;
    view->capacity = readable.capacity;
    return value;
}
static inline uint32_t object_mutable_equal(jv key, struct spx_opaque_mutable_object_table_v5 *view, int32_t index) {
    struct spx_opaque_object_table_v5 readable = object_read_view(view);
    return object_key_equal(key, &readable, index);
}
static inline void object_erase_slot(struct spx_opaque_mutable_object_table_v5 *view, int32_t index) {
    struct spx_opaque_object_table_v5 readable = object_read_view(view);
    struct jq_object_slot_layout slot = object_slot(&readable, index);
    jv_free(slot.string);
    jv empty = jv_null();
    memcpy(view->slots + view->stride * (uint32_t)index + offsetof(struct jq_object_slot_layout, string),
           &empty, sizeof(empty));
    jv_free(slot.value);
}
jv fixture_object_delete(jv, jv);
#endif
