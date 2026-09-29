#include "portable-component-implementation.h"
#include "value-runtime-inputs.h"
void spx_observe_value_entry(const char *);
#define NATIVE_ENTRY __attribute__((no_caller_saved_registers, target("general-regs-only")))
NATIVE_ENTRY void spx_entry_jv_free(jv value) {
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={.first=value};
    struct spx_opaque_value_output_v5 output;
    extern void spx_observe_value_entry(const char *);
    spx_observe_value_entry("jv_free");
    lifted_value_runtime_release(&context,&input,&output);
}
NATIVE_ENTRY jv_kind spx_entry_jv_get_kind(jv first) {
    spx_observe_value_entry("jv_get_kind");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_kind(&context,&input,&output);
    return output.kind;
}
NATIVE_ENTRY const char * spx_entry_jv_kind_name(jv_kind kind) {
    spx_observe_value_entry("jv_kind_name");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.kind=kind;
    lifted_value_runtime_kind_name(&context,&input,&output);
    return output.text;
}
NATIVE_ENTRY jv spx_entry_jv_true(void) {
    spx_observe_value_entry("jv_true");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    lifted_value_runtime_true(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_false(void) {
    spx_observe_value_entry("jv_false");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    lifted_value_runtime_false(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_null(void) {
    spx_observe_value_entry("jv_null");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    lifted_value_runtime_null(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_bool(int count) {
    spx_observe_value_entry("jv_bool");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.count=count;
    lifted_value_runtime_boolean(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_invalid(void) {
    spx_observe_value_entry("jv_invalid");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    lifted_value_runtime_invalid(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_invalid_with_msg(jv first) {
    spx_observe_value_entry("jv_invalid_with_msg");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_invalid_message(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_invalid_get_msg(jv first) {
    spx_observe_value_entry("jv_invalid_get_msg");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_invalid_get_message(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY int spx_entry_jv_invalid_has_msg(jv first) {
    spx_observe_value_entry("jv_invalid_has_msg");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_invalid_has_message(&context,&input,&output);
    return output.integer;
}
NATIVE_ENTRY void spx_entry_jvp_invalid_free(jv first) {
    spx_observe_value_entry("jvp_invalid_free");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_invalid_release(&context,&input,&output);
}
NATIVE_ENTRY jv spx_entry_jv_array(void) {
    spx_observe_value_entry("jv_array");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    lifted_value_runtime_array(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_array_append(jv first, jv second) {
    spx_observe_value_entry("jv_array_append");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.second=second;
    lifted_value_runtime_array_append(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_array_concat(jv first, jv second) {
    spx_observe_value_entry("jv_array_concat");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.second=second;
    lifted_value_runtime_array_concat(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_string_sized(const char *text, int count) {
    spx_observe_value_entry("jv_string_sized");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.text=text;
    input.count=count;
    lifted_value_runtime_string_sized(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_string_empty(int count) {
    spx_observe_value_entry("jv_string_empty");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.count=count;
    lifted_value_runtime_string_empty(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_string(const char *text) {
    spx_observe_value_entry("jv_string");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.text=text;
    lifted_value_runtime_string(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_string_repeat(jv first, int count) {
    spx_observe_value_entry("jv_string_repeat");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.count=count;
    lifted_value_runtime_string_repeat(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_string_explode(jv first) {
    spx_observe_value_entry("jv_string_explode");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_string_explode(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_string_implode(jv first) {
    spx_observe_value_entry("jv_string_implode");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_string_implode(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY unsigned long spx_entry_jv_string_hash(jv first) {
    spx_observe_value_entry("jv_string_hash");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_string_hash(&context,&input,&output);
    return output.hash;
}
NATIVE_ENTRY const char * spx_entry_jv_string_value(jv first) {
    spx_observe_value_entry("jv_string_value");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_string_value(&context,&input,&output);
    return output.text;
}
NATIVE_ENTRY jv spx_entry_jv_string_concat(jv first, jv second) {
    spx_observe_value_entry("jv_string_concat");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.second=second;
    lifted_value_runtime_string_concat(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_string_append_buf(jv first, const char *text, int count) {
    spx_observe_value_entry("jv_string_append_buf");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.text=text;
    input.count=count;
    lifted_value_runtime_string_append_buf(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_string_append_codepoint(jv first, uint32_t codepoint) {
    spx_observe_value_entry("jv_string_append_codepoint");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.codepoint=codepoint;
    lifted_value_runtime_string_append_codepoint(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_string_append_str(jv first, const char *text) {
    spx_observe_value_entry("jv_string_append_str");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.text=text;
    lifted_value_runtime_string_append_str(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_string_vfmt(const char *text, va_list args) {
    spx_observe_value_entry("jv_string_vfmt");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    va_list local;
    va_copy(local,args);
    input.text=text;
    input.args=&local;
    lifted_value_runtime_format(&context,&input,&output);
    va_end(local);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_string_fmt(const char *text, ...) {
    spx_observe_value_entry("jv_string_fmt");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    va_list local;
    va_start(local,text);
    input.text=text;
    input.args=&local;
    lifted_value_runtime_format(&context,&input,&output);
    va_end(local);
    return output.value;
}
NATIVE_ENTRY void spx_entry_jvp_string_free(jv first) {
    spx_observe_value_entry("jvp_string_free");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_string_release(&context,&input,&output);
}
NATIVE_ENTRY jv spx_entry_jv_object(void) {
    spx_observe_value_entry("jv_object");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    lifted_value_runtime_object(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY int spx_entry_jv_object_has(jv first, jv second) {
    spx_observe_value_entry("jv_object_has");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.second=second;
    lifted_value_runtime_object_has(&context,&input,&output);
    return output.integer;
}
NATIVE_ENTRY jv spx_entry_jv_object_set(jv first, jv second, jv third) {
    spx_observe_value_entry("jv_object_set");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.second=second;
    input.third=third;
    lifted_value_runtime_object_set(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY int spx_entry_jv_object_length(jv first) {
    spx_observe_value_entry("jv_object_length");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_object_length(&context,&input,&output);
    return output.integer;
}
NATIVE_ENTRY int spx_entry_jv_object_iter(jv first) {
    spx_observe_value_entry("jv_object_iter");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_object_iter(&context,&input,&output);
    return output.integer;
}
NATIVE_ENTRY int spx_entry_jv_object_iter_valid(jv first, int count) {
    spx_observe_value_entry("jv_object_iter_valid");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.count=count;
    lifted_value_runtime_object_iter_valid(&context,&input,&output);
    return output.integer;
}
NATIVE_ENTRY int spx_entry_jv_object_iter_next(jv first, int count) {
    spx_observe_value_entry("jv_object_iter_next");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.count=count;
    lifted_value_runtime_object_iter_next(&context,&input,&output);
    return output.integer;
}
NATIVE_ENTRY jv spx_entry_jv_object_iter_key(jv first, int count) {
    spx_observe_value_entry("jv_object_iter_key");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.count=count;
    lifted_value_runtime_object_iter_key(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jv_object_iter_value(jv first, int count) {
    spx_observe_value_entry("jv_object_iter_value");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.count=count;
    lifted_value_runtime_object_iter_value(&context,&input,&output);
    return output.value;
}
NATIVE_ENTRY int spx_entry_jv_get_refcnt(jv first) {
    spx_observe_value_entry("jv_get_refcnt");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_reference_count(&context,&input,&output);
    return output.integer;
}

/* Private ABI: hidden result in EAX, values and output pointers on stack. */
NATIVE_ENTRY __attribute__((regparm(1))) void spx_entry_parse_slice(jv *result, jv value, jv slice, int *start, int *end) {
    spx_observe_value_entry("parse_slice");
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={.first=value,.second=slice,.start=start,.end=end};
    struct spx_opaque_value_output_v5 output;
    lifted_value_runtime_slice_bounds(&context,&input,&output);
    *result=output.value;
}
