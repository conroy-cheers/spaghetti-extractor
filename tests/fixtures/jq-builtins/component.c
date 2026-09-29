#include "portable-component-implementation.h"
#include "builtin-inputs.h"
void lifted_builtin_library_binop_plus(spx_builtin_library_context_v5 *context, struct spx_opaque_builtin_input_v5 *input, struct spx_opaque_builtin_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value=portable_binop_plus(input->left, input->right);
}
void lifted_builtin_library_binop_minus(spx_builtin_library_context_v5 *context, struct spx_opaque_builtin_input_v5 *input, struct spx_opaque_builtin_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value=portable_binop_minus(input->left, input->right);
}
void lifted_builtin_library_binop_multiply(spx_builtin_library_context_v5 *context, struct spx_opaque_builtin_input_v5 *input, struct spx_opaque_builtin_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value=portable_binop_multiply(input->left, input->right);
}
void lifted_builtin_library_binop_divide(spx_builtin_library_context_v5 *context, struct spx_opaque_builtin_input_v5 *input, struct spx_opaque_builtin_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value=portable_binop_divide(input->left, input->right);
}
void lifted_builtin_library_binop_mod(spx_builtin_library_context_v5 *context, struct spx_opaque_builtin_input_v5 *input, struct spx_opaque_builtin_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value=portable_binop_mod(input->left, input->right);
}
void lifted_builtin_library_binop_equal(spx_builtin_library_context_v5 *context, struct spx_opaque_builtin_input_v5 *input, struct spx_opaque_builtin_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value=portable_binop_equal(input->left, input->right);
}
void lifted_builtin_library_binop_notequal(spx_builtin_library_context_v5 *context, struct spx_opaque_builtin_input_v5 *input, struct spx_opaque_builtin_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value=portable_binop_notequal(input->left, input->right);
}
void lifted_builtin_library_binop_less(spx_builtin_library_context_v5 *context, struct spx_opaque_builtin_input_v5 *input, struct spx_opaque_builtin_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value=portable_binop_less(input->left, input->right);
}
void lifted_builtin_library_binop_lesseq(spx_builtin_library_context_v5 *context, struct spx_opaque_builtin_input_v5 *input, struct spx_opaque_builtin_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value=portable_binop_lesseq(input->left, input->right);
}
void lifted_builtin_library_binop_greater(spx_builtin_library_context_v5 *context, struct spx_opaque_builtin_input_v5 *input, struct spx_opaque_builtin_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value=portable_binop_greater(input->left, input->right);
}
void lifted_builtin_library_binop_greatereq(spx_builtin_library_context_v5 *context, struct spx_opaque_builtin_input_v5 *input, struct spx_opaque_builtin_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value=portable_binop_greatereq(input->left, input->right);
}
void lifted_builtin_library_builtins_bind(spx_builtin_library_context_v5 *context, struct spx_opaque_builtin_input_v5 *input, struct spx_opaque_builtin_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->errors=portable_builtins_bind(input->state, input->program);
}
