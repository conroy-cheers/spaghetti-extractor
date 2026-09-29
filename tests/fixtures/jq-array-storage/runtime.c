#include <stdio.h>
#include <stdlib.h>
#include "native.h"
#include "comparison-selection.h"

unsigned storage_calls[7];
int storage_selected;

void storage_copy(void *environment, jq_cell *input, jq_cell *output) {
    (void)environment;
#ifdef SPX_SELECTED_STORAGE_COPY
    if (storage_selected) { ++storage_calls[0]; fixture_storage_copy(input,output); return; }
#endif
    *output=storage_pack(jv_copy(storage_unpack(*input)));
}
void storage_release(void *environment, jq_cell *input) {
    (void)environment;
#ifdef SPX_SELECTED_STORAGE_RELEASE
    if (storage_selected) { ++storage_calls[1]; fixture_storage_release(input); return; }
#endif
    jv_free(storage_unpack(*input));
}
void storage_foreign_release(void *environment, jq_cell *input) {
    (void)environment;
    if (jq_kind(input->value)==6U) {
        fputs("array reached the foreign release service\n",stderr); exit(84);
    }
    jv_free(storage_unpack(*input));
}
void storage_create(void *environment, uint32_t capacity, jq_cell *output) {
    (void)environment;
#ifdef SPX_SELECTED_STORAGE_CREATE
    if (storage_selected) { ++storage_calls[2]; fixture_storage_create(capacity,output); return; }
#endif
    *output=storage_pack(jv_array_sized(jq_signed_word(capacity)));
}
int32_t storage_length(void *environment, jq_cell *input) {
    (void)environment;
#ifdef SPX_SELECTED_STORAGE_LENGTH
    if (storage_selected) { ++storage_calls[6]; return fixture_storage_length(input); }
#endif
    return jv_array_length(storage_unpack(*input));
}
void storage_get(void *environment, jq_cell *input, int32_t index, jq_cell *output) {
    (void)environment;
#ifdef SPX_SELECTED_STORAGE_GET
    if (storage_selected) { ++storage_calls[3]; fixture_storage_get(input,index,output); return; }
#endif
    *output=storage_pack(jv_array_get(storage_unpack(*input),index));
}
void storage_set(void *environment, jq_cell *input, int32_t index, jq_cell *item, jq_cell *output) {
    (void)environment;
#ifdef SPX_SELECTED_STORAGE_SET
    if (storage_selected) { ++storage_calls[4]; fixture_storage_set(input,index,item,output); return; }
#endif
    *output=storage_pack(jv_array_set(storage_unpack(*input),index,storage_unpack(*item)));
}
void storage_slice(void *environment, jq_cell *input, int32_t start, int32_t end, jq_cell *output) {
    (void)environment;
#ifdef SPX_SELECTED_STORAGE_SLICE
    if (storage_selected) { ++storage_calls[5]; fixture_storage_slice(input,start,end,output); return; }
#endif
    *output=storage_pack(jv_array_slice(storage_unpack(*input),start,end));
}
void storage_error(void *environment, uint32_t code, jq_cell *output) {
    (void)environment;
    *output=storage_pack(jv_invalid_with_msg(jv_string(code==1U ?
        "Out of bounds negative array index" : "Array index too large")));
}
jq_memory *storage_allocate(void *environment, uint32_t capacity) {
    (void)environment;
    if (capacity>(UINT32_MAX-sizeof(jq_array))/sizeof(jq_native_value)) {
        fputs("array allocation exceeds the represented nonwrapping live-object domain\n",stderr);
        exit(84);
    }
    return (jq_memory *)jv_mem_alloc(sizeof(jq_array)+sizeof(jq_native_value)*capacity);
}
void storage_dispose(void *environment, jq_memory *memory) {
    (void)environment; jv_mem_free(memory);
}
