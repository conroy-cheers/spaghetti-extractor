#include "portable-component-implementation.h"
#include "context-inputs.h"
#include <windows.h>
#define NATIVE_ENTRY __attribute__((no_caller_saved_registers, target("general-regs-only")))
void spx_observe_context_entry(unsigned);
void *spx_native_address(uint32_t);
NATIVE_ENTRY void spx_entry_jv_tsd_dec_ctx_init(void) {
    spx_observe_context_entry(0);
    spx_runtime_contexts_context_v5 context={0};
    struct spx_opaque_context_result_v5 output;
    lifted_runtime_contexts_decimal_initialize(&context,&output);
}
NATIVE_ENTRY void spx_entry_jv_tsd_dec_ctx_fini(void) {
    spx_observe_context_entry(1);
    spx_runtime_contexts_context_v5 context={0};
    struct spx_opaque_context_result_v5 output;
    lifted_runtime_contexts_decimal_finalize(&context,&output);
}
NATIVE_ENTRY __attribute__((regparm(1))) decContext * spx_entry_tsd_dec_ctx_get(void *key) {
    spx_observe_context_entry(2);
    if (key!=spx_native_address(0x7501c)) ExitProcess(84);
    spx_runtime_contexts_context_v5 context={0};
    struct spx_opaque_context_result_v5 output;
    lifted_runtime_contexts_decimal_get(&context,&output);
    return output.decimal;
}
NATIVE_ENTRY void spx_entry_jv_tsd_dtoa_ctx_init(void) {
    spx_observe_context_entry(3);
    spx_runtime_contexts_context_v5 context={0};
    struct spx_opaque_context_result_v5 output;
    lifted_runtime_contexts_dtoa_initialize(&context,&output);
}
NATIVE_ENTRY void spx_entry_jv_tsd_dtoa_ctx_fini(void) {
    spx_observe_context_entry(4);
    spx_runtime_contexts_context_v5 context={0};
    struct spx_opaque_context_result_v5 output;
    lifted_runtime_contexts_dtoa_finalize(&context,&output);
}
NATIVE_ENTRY struct dtoa_context * spx_entry_tsd_dtoa_context_get(void) {
    spx_observe_context_entry(5);
    spx_runtime_contexts_context_v5 context={0};
    struct spx_opaque_context_result_v5 output;
    lifted_runtime_contexts_dtoa_get(&context,&output);
    return output.dtoa;
}
NATIVE_ENTRY uint32_t spx_entry_jvp_hash_seed(void) {
    spx_observe_context_entry(6);
    spx_runtime_contexts_context_v5 context={0};
    struct spx_opaque_context_result_v5 output;
    lifted_runtime_contexts_hash_seed(&context,&output);
    return output.seed;
}
