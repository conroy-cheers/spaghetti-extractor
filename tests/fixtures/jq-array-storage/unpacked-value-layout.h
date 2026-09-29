#ifndef SPX_JQ_ARRAY_VALUE_LAYOUT_H
#define SPX_JQ_ARRAY_VALUE_LAYOUT_H
#include "native-storage.h"

/* Private authored descriptor: tag and flags are separate ordinary C fields,
 * the view offset is a full word, and payload placement differs from native jv.
 * Existing pointers retain the original live objects. No heap is reconstructed.
 * Native-backed elements cross the explicit load/store conversion below. */
typedef struct {
    jq_payload u;
    int size;
    unsigned offset;
    unsigned kind;
    unsigned flags;
    unsigned padding;
} jq_value;
struct spx_opaque_jq_value_v5 { jq_value value; };

static inline unsigned jq_kind(jq_value value) { return value.kind; }
static inline int jq_allocated(jq_value value) { return (value.flags & 128U) != 0; }
static inline jq_value jq_value_load(jq_native_value value) {
    jq_value result = {value.u, value.size, value.offset,
                      value.kind_flags & 15U, value.kind_flags & 240U, value.pad_};
    return result;
}
static inline jq_native_value jq_value_store(jq_value value) {
    jq_native_value result = {(unsigned char)(value.kind | value.flags),
        (unsigned char)value.padding, (unsigned short)value.offset, value.size, value.u};
    return result;
}
static inline jq_value jq_array_value(jq_array *array) {
    jq_value result = {{.ptr = &array->refcnt}, 0, 0, 6, 128, 0};
    return result;
}
static inline jq_value jq_null_value(void) {
    jq_value result = {{.number = 0}, 0, 0, 1, 0, 0};
    return result;
}
static inline jq_value jq_invalid_value(void) {
    jq_value result = {{.number = 0}, 0, 0, 0, 0, 0};
    return result;
}
#endif
