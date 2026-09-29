#include "portable-component-implementation.h"
#include "builtin-inputs.h"
#include "observations.h"
jv binop_plus(jv left, jv right) {
    static unsigned slot; portable_component_entry("builtin-library", &slot);
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_plus(&context,&input,&output);
    return output.value;
}
jv binop_minus(jv left, jv right) {
    static unsigned slot; portable_component_entry("builtin-library", &slot);
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_minus(&context,&input,&output);
    return output.value;
}
jv binop_multiply(jv left, jv right) {
    static unsigned slot; portable_component_entry("builtin-library", &slot);
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_multiply(&context,&input,&output);
    return output.value;
}
jv binop_divide(jv left, jv right) {
    static unsigned slot; portable_component_entry("builtin-library", &slot);
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_divide(&context,&input,&output);
    return output.value;
}
jv binop_mod(jv left, jv right) {
    static unsigned slot; portable_component_entry("builtin-library", &slot);
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_mod(&context,&input,&output);
    return output.value;
}
jv binop_equal(jv left, jv right) {
    static unsigned slot; portable_component_entry("builtin-library", &slot);
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_equal(&context,&input,&output);
    return output.value;
}
jv binop_notequal(jv left, jv right) {
    static unsigned slot; portable_component_entry("builtin-library", &slot);
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_notequal(&context,&input,&output);
    return output.value;
}
jv binop_less(jv left, jv right) {
    static unsigned slot; portable_component_entry("builtin-library", &slot);
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_less(&context,&input,&output);
    return output.value;
}
jv binop_lesseq(jv left, jv right) {
    static unsigned slot; portable_component_entry("builtin-library", &slot);
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_lesseq(&context,&input,&output);
    return output.value;
}
jv binop_greater(jv left, jv right) {
    static unsigned slot; portable_component_entry("builtin-library", &slot);
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_greater(&context,&input,&output);
    return output.value;
}
jv binop_greatereq(jv left, jv right) {
    static unsigned slot; portable_component_entry("builtin-library", &slot);
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.left=left, .right=right};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_binop_greatereq(&context,&input,&output);
    return output.value;
}
int builtins_bind(jq_state * state, block * program) {
    static unsigned slot; portable_component_entry("builtin-library", &slot);
    spx_builtin_library_context_v5 context={0};
    struct spx_opaque_builtin_input_v5 input={.state=state, .program=program};
    struct spx_opaque_builtin_output_v5 output; (void)&jv_is_valid;
    lifted_builtin_library_builtins_bind(&context,&input,&output);
    return output.errors;
}
