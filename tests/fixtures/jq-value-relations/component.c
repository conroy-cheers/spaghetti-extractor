#include "portable-component-implementation.h"
#include "value-relations.h"
void lifted_value_relations_equal(spx_value_relations_context_v5 *context,
    struct spx_opaque_input_v5 *input, struct spx_opaque_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->comparison = portable_jv_equal(input->first, input->second);
}
void lifted_value_relations_identical(spx_value_relations_context_v5 *context,
    struct spx_opaque_input_v5 *input, struct spx_opaque_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->comparison = portable_jv_identical(input->first, input->second);
}
void lifted_value_relations_contains(spx_value_relations_context_v5 *context,
    struct spx_opaque_input_v5 *input, struct spx_opaque_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->comparison = portable_jv_contains(input->first, input->second);
}
void lifted_value_relations_merge(spx_value_relations_context_v5 *context,
    struct spx_opaque_input_v5 *input, struct spx_opaque_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value = portable_jv_object_merge(input->first, input->second);
}
void lifted_value_relations_merge_recursive(spx_value_relations_context_v5 *context,
    struct spx_opaque_input_v5 *input, struct spx_opaque_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value = portable_jv_object_merge_recursive(input->first, input->second);
}
