#include "portable-component-implementation.h"
#include "builtin-inputs.h"
void spx_observe_builtin_entry(const char *);
#define NATIVE_ENTRY __attribute__((no_caller_saved_registers, target("general-regs-only")))
NATIVE_ENTRY jv spx_entry_binop_plus(jv left, jv right) {
    spx_observe_builtin_entry("binop_plus");
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_plus(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_binop_minus(jv left, jv right) {
    spx_observe_builtin_entry("binop_minus");
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_minus(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_binop_multiply(jv left, jv right) {
    spx_observe_builtin_entry("binop_multiply");
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_multiply(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_binop_divide(jv left, jv right) {
    spx_observe_builtin_entry("binop_divide");
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_divide(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_binop_mod(jv left, jv right) {
    spx_observe_builtin_entry("binop_mod");
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_mod(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_binop_equal(jv left, jv right) {
    spx_observe_builtin_entry("binop_equal");
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_equal(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_binop_notequal(jv left, jv right) {
    spx_observe_builtin_entry("binop_notequal");
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_notequal(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_binop_less(jv left, jv right) {
    spx_observe_builtin_entry("binop_less");
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_less(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_binop_lesseq(jv left, jv right) {
    spx_observe_builtin_entry("binop_lesseq");
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_lesseq(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_binop_greater(jv left, jv right) {
    spx_observe_builtin_entry("binop_greater");
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_greater(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_binop_greatereq(jv left, jv right) {
    spx_observe_builtin_entry("binop_greatereq");
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_greatereq(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY int spx_entry_builtins_bind(jq_state * state, block * program) {
    spx_observe_builtin_entry("builtins_bind");
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.state=state, .program=program};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_builtins_bind(&context,&input,&output);
    return output.errors;
}
