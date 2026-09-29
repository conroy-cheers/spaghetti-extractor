#include "portable-component-implementation.h"
#include "value-relations.h"
#include "entry-observations.h"
int spx_entry_equal(jv first, jv second) {
    spx_observe_entry();
    spx_value_relations_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {first, second};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_relations_equal(&context, &input, &output);
    return output.comparison;
}
int spx_entry_identical(jv first, jv second) {
    spx_observe_entry();
    spx_value_relations_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {first, second};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_relations_identical(&context, &input, &output);
    return output.comparison;
}
int spx_entry_contains(jv first, jv second) {
    spx_observe_entry();
    spx_value_relations_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {first, second};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_relations_contains(&context, &input, &output);
    return output.comparison;
}
jv spx_entry_object_merge(jv first, jv second) {
    spx_observe_entry();
    spx_value_relations_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {first, second};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_relations_merge(&context, &input, &output);
    return output.value;
}
jv spx_entry_object_merge_recursive(jv first, jv second) {
    spx_observe_entry();
    spx_value_relations_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {first, second};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_relations_merge_recursive(&context, &input, &output);
    return output.value;
}
