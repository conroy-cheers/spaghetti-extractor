#include "portable-component-implementation.h"
#include "value-algorithms.h"
#include "entry-observations.h"
jv spx_entry_has(jv first, jv second) {
    spx_observe_entry();
    spx_value_algorithms_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {.first = first, .second = second};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_algorithms_has(&context, &input, &output);
    return output.value;
}
jv spx_entry_delpaths(jv first, jv second) {
    spx_observe_entry();
    spx_value_algorithms_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {.first = first, .second = second};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_algorithms_delete(&context, &input, &output);
    return output.value;
}
jv spx_entry_keys(jv first) {
    spx_observe_entry();
    spx_value_algorithms_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {.first = first};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_algorithms_keys(&context, &input, &output);
    return output.value;
}
jv spx_entry_keys_unsorted(jv first) {
    spx_observe_entry();
    spx_value_algorithms_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {.first = first};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_algorithms_keys_unsorted(&context, &input, &output);
    return output.value;
}
int spx_entry_cmp(jv first, jv second) {
    spx_observe_entry();
    spx_value_algorithms_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {.first = first, .second = second};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_algorithms_compare(&context, &input, &output);
    return output.comparison;
}
jv spx_entry_sort(jv first, jv second) {
    spx_observe_entry();
    spx_value_algorithms_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {.first = first, .second = second};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_algorithms_sort(&context, &input, &output);
    return output.value;
}
jv spx_entry_group(jv first, jv second) {
    spx_observe_entry();
    spx_value_algorithms_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {.first = first, .second = second};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_algorithms_group(&context, &input, &output);
    return output.value;
}
jv spx_entry_unique(jv first, jv second) {
    spx_observe_entry();
    spx_value_algorithms_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {.first = first, .second = second};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_algorithms_unique(&context, &input, &output);
    return output.value;
}
