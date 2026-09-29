#include "portable-component-implementation.h"
#include "context-inputs.h"
void lifted_runtime_contexts_decimal_initialize(spx_runtime_contexts_context_v5 *context, struct spx_opaque_context_result_v5 *output) {
    (void)context; (void)output;
    portable_decimal_initialize();
}
void lifted_runtime_contexts_decimal_finalize(spx_runtime_contexts_context_v5 *context, struct spx_opaque_context_result_v5 *output) {
    (void)context; (void)output;
    portable_decimal_finalize();
}
void lifted_runtime_contexts_decimal_get(spx_runtime_contexts_context_v5 *context, struct spx_opaque_context_result_v5 *output) {
    (void)context; (void)output;
    output->decimal=portable_decimal_context();
}
void lifted_runtime_contexts_dtoa_initialize(spx_runtime_contexts_context_v5 *context, struct spx_opaque_context_result_v5 *output) {
    (void)context; (void)output;
    portable_dtoa_initialize();
}
void lifted_runtime_contexts_dtoa_finalize(spx_runtime_contexts_context_v5 *context, struct spx_opaque_context_result_v5 *output) {
    (void)context; (void)output;
    portable_dtoa_finalize();
}
void lifted_runtime_contexts_dtoa_get(spx_runtime_contexts_context_v5 *context, struct spx_opaque_context_result_v5 *output) {
    (void)context; (void)output;
    output->dtoa=portable_dtoa_context();
}
void lifted_runtime_contexts_hash_seed(spx_runtime_contexts_context_v5 *context, struct spx_opaque_context_result_v5 *output) {
    (void)context; (void)output;
    output->seed=portable_hash_seed();
}
