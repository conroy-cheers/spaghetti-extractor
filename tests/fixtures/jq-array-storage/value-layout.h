#ifndef SPX_JQ_ARRAY_VALUE_LAYOUT_H
#define SPX_JQ_ARRAY_VALUE_LAYOUT_H
#include "native-storage.h"

/* Public jq descriptor and private array layout, transcribed from jq 1.8.1.
 * The PE32 adapter checks every offset. Algorithms use real C pointers; a
 * descriptor never reconstructs a heap object from an integer token.
 * See COPYING.jq for upstream licensing and README.md for the boundary. */
typedef jq_native_value jq_value;
struct spx_opaque_jq_value_v5 { jq_value value; };
static inline unsigned jq_kind(jq_value value) { return value.kind_flags & 15U; }
static inline int jq_allocated(jq_value value) { return (value.kind_flags & 128U) != 0; }
static inline jq_value jq_value_load(jq_native_value value) { return value; }
static inline jq_native_value jq_value_store(jq_value value) { return value; }
static inline jq_value jq_array_value(jq_array *array) {
    jq_value result = {134, 0, 0, 0, {.ptr = &array->refcnt}};
    return result;
}
static inline jq_value jq_null_value(void) {
    jq_value result = {1, 0, 0, 0, {.number = 0}};
    return result;
}
static inline jq_value jq_invalid_value(void) {
    jq_value result = {0, 0, 0, 0, {.number = 0}};
    return result;
}
#endif
