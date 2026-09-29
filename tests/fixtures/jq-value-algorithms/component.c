#include "portable-component-implementation.h"
#include "value-algorithms.h"
void lifted_value_algorithms_has(spx_value_algorithms_context_v5 *context,
    struct spx_opaque_input_v5 *input, struct spx_opaque_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value = portable_jv_has(input->first, input->second);
}
void lifted_value_algorithms_delete(spx_value_algorithms_context_v5 *context,
    struct spx_opaque_input_v5 *input, struct spx_opaque_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value = portable_jv_delpaths(input->first, input->second);
}
void lifted_value_algorithms_keys(spx_value_algorithms_context_v5 *context,
    struct spx_opaque_input_v5 *input, struct spx_opaque_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value = portable_jv_keys(input->first);
}
void lifted_value_algorithms_keys_unsorted(spx_value_algorithms_context_v5 *context,
    struct spx_opaque_input_v5 *input, struct spx_opaque_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value = portable_jv_keys_unsorted(input->first);
}
void lifted_value_algorithms_compare(spx_value_algorithms_context_v5 *context,
    struct spx_opaque_input_v5 *input, struct spx_opaque_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->comparison = portable_jv_cmp(input->first, input->second);
}
void lifted_value_algorithms_sort(spx_value_algorithms_context_v5 *context,
    struct spx_opaque_input_v5 *input, struct spx_opaque_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value = portable_jv_sort(input->first, input->second);
}
void lifted_value_algorithms_group(spx_value_algorithms_context_v5 *context,
    struct spx_opaque_input_v5 *input, struct spx_opaque_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value = portable_jv_group(input->first, input->second);
}
void lifted_value_algorithms_unique(spx_value_algorithms_context_v5 *context,
    struct spx_opaque_input_v5 *input, struct spx_opaque_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value = portable_jv_unique(input->first, input->second);
}
