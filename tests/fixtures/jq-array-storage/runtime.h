#ifndef SPX_JQ_ARRAY_RUNTIME_H
#define SPX_JQ_ARRAY_RUNTIME_H
#include "value-layout.h"
typedef struct spx_opaque_jq_value_v5 jq_cell;
typedef struct spx_opaque_jq_memory_v5 jq_memory;
void storage_copy(void *, jq_cell *, jq_cell *);
void storage_release(void *, jq_cell *);
void storage_foreign_release(void *, jq_cell *);
void storage_create(void *, uint32_t, jq_cell *);
int32_t storage_length(void *, jq_cell *);
void storage_get(void *, jq_cell *, int32_t, jq_cell *);
void storage_set(void *, jq_cell *, int32_t, jq_cell *, jq_cell *);
void storage_slice(void *, jq_cell *, int32_t, int32_t, jq_cell *);
void storage_error(void *, uint32_t, jq_cell *);
jq_memory *storage_allocate(void *, uint32_t);
void storage_dispose(void *, jq_memory *);
void fixture_storage_copy(jq_cell *, jq_cell *);
void fixture_storage_release(jq_cell *);
void fixture_storage_create(uint32_t, jq_cell *);
int32_t fixture_storage_length(jq_cell *);
void fixture_storage_get(jq_cell *, int32_t, jq_cell *);
void fixture_storage_set(jq_cell *, int32_t, jq_cell *, jq_cell *);
void fixture_storage_slice(jq_cell *, int32_t, int32_t, jq_cell *);
extern unsigned storage_calls[7];
extern int storage_selected;
#endif
