#include <string.h>
#include "portable-component-implementation.h"
#include "number-inputs.h"
void spx_observe_number_entry(const char *);
#define NATIVE_ENTRY __attribute__((no_caller_saved_registers, target("general-regs-only")))
NATIVE_ENTRY jv spx_entry_jv_number(double number) {
    spx_observe_number_entry("jv_number");
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    memcpy(&input.number, &number, sizeof(number));
    lifted_number_values_create(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_number_with_literal(const char *text) {
    spx_observe_number_entry("jv_number_with_literal");
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    input.text=text;
    lifted_number_values_parse(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY int spx_entry_jv_number_has_literal(jv first) {
    spx_observe_number_entry("jv_number_has_literal");
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_number_values_has_literal(&context,&input,&output);
    return output.integer;
}
NATIVE_ENTRY const char * spx_entry_jv_number_get_literal(jv first) {
    spx_observe_number_entry("jv_number_get_literal");
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_number_values_literal(&context,&input,&output);
    return output.text;
}
double spx_call_jv_number_value(jv first) {
    spx_observe_number_entry("jv_number_value");
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_number_values_value(&context,&input,&output);
    return output.number;
}
NATIVE_ENTRY int spx_entry_jv_is_integer(jv first) {
    spx_observe_number_entry("jv_is_integer");
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_number_values_integer(&context,&input,&output);
    return output.integer;
}
NATIVE_ENTRY int spx_entry_jvp_number_is_nan(jv first) {
    spx_observe_number_entry("jvp_number_is_nan");
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_number_values_is_nan(&context,&input,&output);
    return output.integer;
}
NATIVE_ENTRY jv spx_entry_jv_number_abs(jv first) {
    spx_observe_number_entry("jv_number_abs");
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_number_values_absolute(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_number_negate(jv first) {
    spx_observe_number_entry("jv_number_negate");
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_number_values_negate(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY int spx_entry_jvp_number_cmp(jv first, jv second) {
    spx_observe_number_entry("jvp_number_cmp");
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.second=second;
    lifted_number_values_compare(&context,&input,&output);
    return output.integer;
}
NATIVE_ENTRY void spx_entry_jvp_number_free(jv first) {
    spx_observe_number_entry("jvp_number_free");
    spx_number_values_context_v5 context={0};
    struct spx_opaque_number_input_v5 input={0};
    struct spx_opaque_number_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_number_values_release(&context,&input,&output);
}
/* Native-only ABI bridge; the authored implementation is portable C. */
__asm__(".text\n\t.globl _spx_entry_jv_number_value\n_spx_entry_jv_number_value:\n\t"
            "push %eax\n\tpush %ecx\n\tpush %edx\n\tsub $16, %esp\n\t"
            "mov 32(%esp), %eax\n\tmov %eax, 0(%esp)\n\t"
            "mov 36(%esp), %eax\n\tmov %eax, 4(%esp)\n\t"
            "mov 40(%esp), %eax\n\tmov %eax, 8(%esp)\n\t"
            "mov 44(%esp), %eax\n\tmov %eax, 12(%esp)\n\t"
            "call _spx_call_jv_number_value\n\tadd $16, %esp\n\t"
            "pop %edx\n\tpop %ecx\n\tpop %eax\n\tret\n");
