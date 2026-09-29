#ifndef SPX_JQ_OBJECT_STORAGE_NATIVE_H
#define SPX_JQ_OBJECT_STORAGE_NATIVE_H
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "jv.h"
#pragma GCC diagnostic pop
#include "object-runtime.h"
_Static_assert(sizeof(jv) == sizeof(jq_native_value) && sizeof(jv) == 16 &&
    offsetof(jv, u) == offsetof(jq_native_value, u) &&
    offsetof(jv, size) == offsetof(jq_native_value, size) &&
    offsetof(jv, offset) == offsetof(jq_native_value, offset), "live jq descriptor transport");
static inline jq_object_cell object_pack(jv value) {
    jq_native_value native; memcpy(&native, &value, sizeof(native));
    jq_object_cell cell = {jq_value_load(native)}; return cell;
}
static inline jv object_unpack(jq_object_cell cell) {
    jq_native_value native = jq_value_store(cell.value); jv value;
    memcpy(&value, &native, sizeof(value)); return value;
}
void *jv_mem_alloc(size_t);
void jv_mem_free(void *);
static inline jq_object_memory *object_allocate(void *context, uint32_t capacity) {
    (void)context;
    if (!capacity || (capacity & (capacity - 1U)) ||
        capacity > (UINT32_MAX - sizeof(struct jq_object_storage)) /
            (sizeof(struct jq_object_slot) + 2U * sizeof(int32_t))) abort();
    return (jq_object_memory *)jv_mem_alloc(sizeof(struct jq_object_storage) +
        capacity * (sizeof(struct jq_object_slot) + 2U * sizeof(int32_t)));
}
static inline void object_dispose(void *context, jq_object_memory *memory) {
    (void)context; jv_mem_free(memory);
}
static inline void object_copy_value(void *context, jq_object_cell *input, jq_object_cell *output) {
    (void)context; *output = object_pack(jv_copy(object_unpack(*input)));
}
static inline void object_release_value(void *context, jq_object_cell *input) {
    (void)context; jv_free(object_unpack(*input));
}
#endif
