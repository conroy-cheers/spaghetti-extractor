#ifndef SPX_JQ_ARRAY_NATIVE_H
#define SPX_JQ_ARRAY_NATIVE_H
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "jv.h"
#pragma GCC diagnostic pop
#include <string.h>
#include "runtime.h"

_Static_assert(sizeof(jv)==sizeof(jq_native_value), "value size mismatch");
_Static_assert(offsetof(jv,kind_flags)==offsetof(jq_native_value,kind_flags), "kind offset mismatch");
_Static_assert(offsetof(jv,pad_)==offsetof(jq_native_value,pad_), "reserved byte offset mismatch");
_Static_assert(offsetof(jv,offset)==offsetof(jq_native_value,offset), "slice offset mismatch");
_Static_assert(offsetof(jv,size)==offsetof(jq_native_value,size), "length offset mismatch");
_Static_assert(offsetof(jv,u)==offsetof(jq_native_value,u), "payload offset mismatch");
_Static_assert(sizeof(jv)==16 && offsetof(jq_array,elements)==16,
               "pinned native array header/value size mismatch");
static inline jq_cell storage_pack(jv value) {
    jq_native_value native; memcpy(&native,&value,sizeof(value));
    jq_cell result = {jq_value_load(native)}; return result;
}
static inline jv storage_unpack(jq_cell value) {
    jq_native_value native = jq_value_store(value.value);
    jv result; memcpy(&result,&native,sizeof(result)); return result;
}
void *jv_mem_alloc(size_t);
void jv_mem_free(void *);
#endif
