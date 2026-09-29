#ifndef SPX_JQ_ARRAY_PATH_BRIDGE_H
#define SPX_JQ_ARRAY_PATH_BRIDGE_H
/* Semantic adaptation only: the actual array algorithms stay in their own
 * selected source units. No JSON reconstruction or copying of heap contents. */
#include "array-native.h"
static inline jv path_storage_copy(jv value) {
    jq_cell input=storage_pack(value),output; storage_selected=1;
    storage_copy(0,&input,&output); return storage_unpack(output);
}
static inline void path_storage_release(jv value) {
    jq_cell input=storage_pack(value); storage_selected=1;storage_release(0,&input);
}
static inline uint32_t path_storage_length(jv value) {
    jq_cell input=storage_pack(value); storage_selected=1;return (uint32_t)storage_length(0,&input);
}
static inline jv path_storage_array(void) {
    jq_cell output;storage_selected=1;storage_create(0,16U,&output);return storage_unpack(output);
}
static inline jv path_storage_array_get(jv value,int index) {
    jq_cell input=storage_pack(value),output;storage_selected=1;
    storage_get(0,&input,index,&output);return storage_unpack(output);
}
static inline jv path_storage_array_set(jv value,int index,jv item) {
    jq_cell input=storage_pack(value),element=storage_pack(item),output;storage_selected=1;
    storage_set(0,&input,index,&element,&output);return storage_unpack(output);
}
static inline jv path_storage_array_slice(jv value,int start,int end) {
    jq_cell input=storage_pack(value),output;storage_selected=1;
    storage_slice(0,&input,start,end,&output);return storage_unpack(output);
}
#endif
