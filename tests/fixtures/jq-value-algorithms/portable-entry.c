#include "portable-component-implementation.h"
#include "value-algorithms.h"
#include "observations.h"
jv jv_has(jv first, jv second) {
    static unsigned slot;
    portable_component_entry("value-algorithms", &slot);
    spx_value_algorithms_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {.first = first, .second = second};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_algorithms_has(&context, &input, &output);
    return output.value;
}
jv jv_delpaths(jv first, jv second) {
    static unsigned slot;
    portable_component_entry("value-algorithms", &slot);
    spx_value_algorithms_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {.first = first, .second = second};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_algorithms_delete(&context, &input, &output);
    return output.value;
}
jv jv_keys(jv first) {
    static unsigned slot;
    portable_component_entry("value-algorithms", &slot);
    spx_value_algorithms_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {.first = first};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_algorithms_keys(&context, &input, &output);
    return output.value;
}
jv jv_keys_unsorted(jv first) {
    static unsigned slot;
    portable_component_entry("value-algorithms", &slot);
    spx_value_algorithms_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {.first = first};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_algorithms_keys_unsorted(&context, &input, &output);
    return output.value;
}
int jv_cmp(jv first, jv second) {
    static unsigned slot;
    portable_component_entry("value-algorithms", &slot);
    spx_value_algorithms_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {.first = first, .second = second};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_algorithms_compare(&context, &input, &output);
    return output.comparison;
}
jv jv_sort(jv first, jv second) {
    static unsigned slot;
    portable_component_entry("value-algorithms", &slot);
    spx_value_algorithms_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {.first = first, .second = second};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_algorithms_sort(&context, &input, &output);
    return output.value;
}
jv jv_group(jv first, jv second) {
    static unsigned slot;
    portable_component_entry("value-algorithms", &slot);
    spx_value_algorithms_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {.first = first, .second = second};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_algorithms_group(&context, &input, &output);
    return output.value;
}
jv jv_unique(jv first, jv second) {
    static unsigned slot;
    portable_component_entry("value-algorithms", &slot);
    spx_value_algorithms_context_v5 context = {0};
    struct spx_opaque_input_v5 input = {.first = first, .second = second};
    struct spx_opaque_output_v5 output;
    (void)&jv_is_valid;
    lifted_value_algorithms_unique(&context, &input, &output);
    return output.value;
}
