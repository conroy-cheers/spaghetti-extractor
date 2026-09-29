#include <pthread.h>
#include "portable-component-implementation.h"
#include "context-inputs.h"
#include "observations.h"
void jv_tsd_dec_ctx_init(void) {
    static unsigned slot; portable_component_entry("runtime-contexts", &slot);
    spx_runtime_contexts_context_v5 context={0};
    struct spx_opaque_context_result_v5 output;
    lifted_runtime_contexts_decimal_initialize(&context,&output);
}
void jv_tsd_dec_ctx_fini(void) {
    static unsigned slot; portable_component_entry("runtime-contexts", &slot);
    spx_runtime_contexts_context_v5 context={0};
    struct spx_opaque_context_result_v5 output;
    lifted_runtime_contexts_decimal_finalize(&context,&output);
}
decContext * tsd_dec_ctx_get(pthread_key_t *key) {
    (void)key; /* Only the retained module-key marker reaches this adapter. */
    static unsigned slot; portable_component_entry("runtime-contexts", &slot);
    spx_runtime_contexts_context_v5 context={0};
    struct spx_opaque_context_result_v5 output;
    lifted_runtime_contexts_decimal_get(&context,&output);
    return output.decimal;
}
void jv_tsd_dtoa_ctx_init(void) {
    static unsigned slot; portable_component_entry("runtime-contexts", &slot);
    spx_runtime_contexts_context_v5 context={0};
    struct spx_opaque_context_result_v5 output;
    lifted_runtime_contexts_dtoa_initialize(&context,&output);
}
void jv_tsd_dtoa_ctx_fini(void) {
    static unsigned slot; portable_component_entry("runtime-contexts", &slot);
    spx_runtime_contexts_context_v5 context={0};
    struct spx_opaque_context_result_v5 output;
    lifted_runtime_contexts_dtoa_finalize(&context,&output);
}
struct dtoa_context * tsd_dtoa_context_get(void) {
    static unsigned slot; portable_component_entry("runtime-contexts", &slot);
    spx_runtime_contexts_context_v5 context={0};
    struct spx_opaque_context_result_v5 output;
    lifted_runtime_contexts_dtoa_get(&context,&output);
    return output.dtoa;
}
uint32_t jvp_hash_seed(void) {
    static unsigned slot; portable_component_entry("runtime-contexts", &slot);
    spx_runtime_contexts_context_v5 context={0};
    struct spx_opaque_context_result_v5 output;
    lifted_runtime_contexts_hash_seed(&context,&output);
    return output.seed;
}
