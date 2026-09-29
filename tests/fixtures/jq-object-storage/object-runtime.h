#ifndef SPX_JQ_OBJECT_RUNTIME_H
#define SPX_JQ_OBJECT_RUNTIME_H
#include "object-storage.h"
typedef struct spx_opaque_object_memory_v5 jq_object_memory;
void fixture_object_create(uint32_t, jq_object_cell *);
void fixture_object_release(jq_object_cell *);
void fixture_object_unshare(jq_object_cell *, jq_object_cell *);
static inline jq_object_memory *object_allocate(void *context, uint32_t capacity);
static inline void object_dispose(void *context, jq_object_memory *memory);
static inline void object_copy_value(void *context, jq_object_cell *input, jq_object_cell *output);
static inline void object_release_value(void *context, jq_object_cell *input);
static inline void object_create(void *context, uint32_t capacity, jq_object_cell *output) {
    (void)context; fixture_object_create(capacity, output);
}
static inline void object_release(void *context, jq_object_cell *input) {
    (void)context; fixture_object_release(input);
}
#endif
