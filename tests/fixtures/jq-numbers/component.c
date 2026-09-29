#include "portable-component-implementation.h"
#include "number-inputs.h"
void lifted_number_values_create(spx_number_values_context_v5 *context, struct spx_opaque_number_input_v5 *input, struct spx_opaque_number_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value=portable_jv_number(input->number);
}
void lifted_number_values_parse(spx_number_values_context_v5 *context, struct spx_opaque_number_input_v5 *input, struct spx_opaque_number_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value=portable_jv_number_with_literal(input->text);
}
void lifted_number_values_has_literal(spx_number_values_context_v5 *context, struct spx_opaque_number_input_v5 *input, struct spx_opaque_number_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->integer=portable_jv_number_has_literal(input->first);
}
void lifted_number_values_literal(spx_number_values_context_v5 *context, struct spx_opaque_number_input_v5 *input, struct spx_opaque_number_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->text=portable_jv_number_get_literal(input->first);
}
void lifted_number_values_value(spx_number_values_context_v5 *context, struct spx_opaque_number_input_v5 *input, struct spx_opaque_number_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->number=portable_jv_number_value(input->first);
}
void lifted_number_values_integer(spx_number_values_context_v5 *context, struct spx_opaque_number_input_v5 *input, struct spx_opaque_number_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->integer=portable_jv_is_integer(input->first);
}
void lifted_number_values_is_nan(spx_number_values_context_v5 *context, struct spx_opaque_number_input_v5 *input, struct spx_opaque_number_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->integer=portable_jvp_number_is_nan(input->first);
}
void lifted_number_values_absolute(spx_number_values_context_v5 *context, struct spx_opaque_number_input_v5 *input, struct spx_opaque_number_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value=portable_jv_number_abs(input->first);
}
void lifted_number_values_negate(spx_number_values_context_v5 *context, struct spx_opaque_number_input_v5 *input, struct spx_opaque_number_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value=portable_jv_number_negate(input->first);
}
void lifted_number_values_compare(spx_number_values_context_v5 *context, struct spx_opaque_number_input_v5 *input, struct spx_opaque_number_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->integer=portable_jvp_number_cmp(input->first, input->second);
}
void lifted_number_values_release(spx_number_values_context_v5 *context, struct spx_opaque_number_input_v5 *input, struct spx_opaque_number_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    (void)output; portable_jvp_number_free(input->first);
}
