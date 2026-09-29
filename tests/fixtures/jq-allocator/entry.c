/* Ordinary C entry adapters shared by native comparison and source assembly. */
#include "portable-component-implementation.h"
#include "allocator-inputs.h"
#include "entry-observation.h"

void ALLOCATOR_ENTRY(jv_nomem_handler)(jv_nomem_handler_f handler, void *data) {
    spx_allocator_runtime_context_v5 context={0};
    struct spx_opaque_registration_v5 registration={handler,data};
    allocator_entry_observation(0);
    (void)&jv_is_valid;
    lifted_allocator_runtime_configure(&context,&registration);
}

void *ALLOCATOR_ENTRY(jv_mem_alloc)(size_t size) {
    spx_allocator_runtime_context_v5 context={0};
    struct spx_opaque_memory_request_v5 request={.size=size};
    struct spx_opaque_memory_result_v5 output;
    allocator_entry_observation(1);
    lifted_allocator_runtime_allocate(&context,&request,&output);
    return output.pointer;
}

void *ALLOCATOR_ENTRY(jv_mem_alloc_unguarded)(size_t size) {
    spx_allocator_runtime_context_v5 context={0};
    struct spx_opaque_memory_request_v5 request={.size=size};
    struct spx_opaque_memory_result_v5 output;
    allocator_entry_observation(2);
    lifted_allocator_runtime_allocate_unguarded(&context,&request,&output);
    return output.pointer;
}

void *ALLOCATOR_ENTRY(jv_mem_calloc)(size_t count,size_t size) {
    spx_allocator_runtime_context_v5 context={0};
    struct spx_opaque_memory_request_v5 request={.size=size,.count=count};
    struct spx_opaque_memory_result_v5 output;
    allocator_entry_observation(3);
    lifted_allocator_runtime_zeroed(&context,&request,&output);
    return output.pointer;
}

void *ALLOCATOR_ENTRY(jv_mem_calloc_unguarded)(size_t count,size_t size) {
    spx_allocator_runtime_context_v5 context={0};
    struct spx_opaque_memory_request_v5 request={.size=size,.count=count};
    struct spx_opaque_memory_result_v5 output;
    allocator_entry_observation(4);
    lifted_allocator_runtime_zeroed_unguarded(&context,&request,&output);
    return output.pointer;
}

char *ALLOCATOR_ENTRY(jv_mem_strdup)(const char *text) {
    spx_allocator_runtime_context_v5 context={0};
    struct spx_opaque_memory_request_v5 request={.text=text};
    struct spx_opaque_memory_result_v5 output;
    allocator_entry_observation(5);
    lifted_allocator_runtime_duplicate(&context,&request,&output);
    return output.pointer;
}

char *ALLOCATOR_ENTRY(jv_mem_strdup_unguarded)(const char *text) {
    spx_allocator_runtime_context_v5 context={0};
    struct spx_opaque_memory_request_v5 request={.text=text};
    struct spx_opaque_memory_result_v5 output;
    allocator_entry_observation(6);
    lifted_allocator_runtime_duplicate_unguarded(&context,&request,&output);
    return output.pointer;
}

void ALLOCATOR_ENTRY(jv_mem_free)(void *pointer) {
    spx_allocator_runtime_context_v5 context={0};
    struct spx_opaque_memory_request_v5 request={.pointer=pointer};
    allocator_entry_observation(7);
    lifted_allocator_runtime_release(&context,&request);
}

void *ALLOCATOR_ENTRY(jv_mem_realloc)(void *pointer,size_t size) {
    spx_allocator_runtime_context_v5 context={0};
    struct spx_opaque_memory_request_v5 request={.pointer=pointer,.size=size};
    struct spx_opaque_memory_result_v5 output;
    allocator_entry_observation(8);
    lifted_allocator_runtime_resize(&context,&request,&output);
    return output.pointer;
}
