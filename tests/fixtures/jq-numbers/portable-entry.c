#include <string.h>
#include "portable-component-implementation.h"
#include "number-inputs.h"
#include "observations.h"
jv jv_number(double number) {
    static unsigned slot; portable_component_entry("number-values", &slot);
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    memcpy(&input.number, &number, sizeof(number));
    lifted_number_values_create(&context,&input,&output);
    return output.value;
}
jv jv_number_with_literal(const char *text) {
    static unsigned slot; portable_component_entry("number-values", &slot);
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    input.text=text;
    lifted_number_values_parse(&context,&input,&output);
    return output.value;
}
int jv_number_has_literal(jv first) {
    static unsigned slot; portable_component_entry("number-values", &slot);
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_number_values_has_literal(&context,&input,&output);
    return output.integer;
}
const char * jv_number_get_literal(jv first) {
    static unsigned slot; portable_component_entry("number-values", &slot);
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_number_values_literal(&context,&input,&output);
    return output.text;
}
double jv_number_value(jv first) {
    static unsigned slot; portable_component_entry("number-values", &slot);
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_number_values_value(&context,&input,&output);
    return output.number;
}
int jv_is_integer(jv first) {
    static unsigned slot; portable_component_entry("number-values", &slot);
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_number_values_integer(&context,&input,&output);
    return output.integer;
}
int jvp_number_is_nan(jv first) {
    static unsigned slot; portable_component_entry("number-values", &slot);
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_number_values_is_nan(&context,&input,&output);
    return output.integer;
}
jv jv_number_abs(jv first) {
    static unsigned slot; portable_component_entry("number-values", &slot);
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_number_values_absolute(&context,&input,&output);
    return output.value;
}
jv jv_number_negate(jv first) {
    static unsigned slot; portable_component_entry("number-values", &slot);
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_number_values_negate(&context,&input,&output);
    return output.value;
}
int jvp_number_cmp(jv first, jv second) {
    static unsigned slot; portable_component_entry("number-values", &slot);
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.second=second;
    lifted_number_values_compare(&context,&input,&output);
    return output.integer;
}
void jvp_number_free(jv first) {
    static unsigned slot; portable_component_entry("number-values", &slot);
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_number_values_release(&context,&input,&output);
}
