/* Portable runtime binding. Selected operations never fall back to the backend. */
#include <stdio.h>
#include <stdlib.h>
#include "array-native.h"

void backend_free(jv);
unsigned storage_calls[7];
int storage_selected = 1;
void storage_copy(void *e, jq_cell *v, jq_cell *out) {
    (void)e; fixture_storage_copy(v,out);
}
void storage_release(void *e, jq_cell *v) {
    (void)e; fixture_storage_release(v);
}
void storage_foreign_release(void *e, jq_cell *v) {
    (void)e;
    if (jq_kind(v->value)==6U) {
        fputs("array reached the foreign release service\n",stderr); exit(84);
    }
    backend_free(storage_unpack(*v));
}
void storage_create(void *e, uint32_t n, jq_cell *out) {
    (void)e; fixture_storage_create(n,out);
}
int32_t storage_length(void *e, jq_cell *v) {
    (void)e; return fixture_storage_length(v);
}
void storage_get(void *e, jq_cell *v, int32_t i, jq_cell *out) {
    (void)e; fixture_storage_get(v,i,out);
}
void storage_set(void *e, jq_cell *v, int32_t i, jq_cell *item, jq_cell *out) {
    (void)e; fixture_storage_set(v,i,item,out);
}
void storage_slice(void *e, jq_cell *v, int32_t a, int32_t b, jq_cell *out) {
    (void)e; fixture_storage_slice(v,a,b,out);
}
void storage_error(void *e, uint32_t code, jq_cell *out) {
    (void)e;
    *out=storage_pack(jv_invalid_with_msg(jv_string(code==1U ?
        "Out of bounds negative array index" : "Array index too large")));
}
jq_memory *storage_allocate(void *e, uint32_t n) {
    (void)e;
    if (n>(UINT32_MAX-sizeof(jq_array))/sizeof(jq_native_value)) {
        fputs("array allocation exceeds the represented nonwrapping live-object domain\n",stderr);
        exit(84);
    }
    return (jq_memory *)jv_mem_alloc(sizeof(jq_array)+sizeof(jq_native_value)*n);
}
void storage_dispose(void *e, jq_memory *p) { (void)e; jv_mem_free(p); }

jv jv_copy(jv value) {
    jq_cell in=storage_pack(value),out; storage_copy(0,&in,&out); return storage_unpack(out);
}
void jv_free(jv value) { jq_cell in=storage_pack(value); storage_release(0,&in); }
jv jv_array_sized(int n) {
    jq_cell out; storage_create(0,(uint32_t)n,&out); return storage_unpack(out);
}
int jv_array_length(jv value) {
    jq_cell in=storage_pack(value); return storage_length(0,&in);
}
jv jv_array_get(jv value, int i) {
    jq_cell in=storage_pack(value),out; storage_get(0,&in,i,&out); return storage_unpack(out);
}
jv jv_array_set(jv value, int i, jv item) {
    jq_cell in=storage_pack(value),element=storage_pack(item),out;
    storage_set(0,&in,i,&element,&out); return storage_unpack(out);
}
jv jv_array_slice(jv value, int a, int b) {
    jq_cell in=storage_pack(value),out; storage_slice(0,&in,a,b,&out); return storage_unpack(out);
}

jv path_dispatch_get(jv v, jv key) { return jv_get(v,key); }
jv path_dispatch_set(jv v, jv key, jv item) { return jv_set(v,key,item); }
jv path_dispatch_getpath(jv v, jv path) { return jv_getpath(v,path); }
