#include "portable-component-implementation.h"
#include <assert.h>
#include "array-native.h"
#include "value-runtime-inputs.h"
#include "observations.h"

/* The existing array-storage boundary owns public jv_free. Its foreign-release
 * service admits only non-arrays; this is the checked dispatcher's restriction
 * to that domain, not a second public jv_free provider. */
void backend_free(jv value) {
    assert(jv_get_kind(value)!=JV_KIND_ARRAY);
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={.first=value};
    struct spx_opaque_value_output_v5 output;
    lifted_value_runtime_release(&context,&input,&output);
}
void spx_value_array_release(jv value) {
    assert(jv_get_kind(value)==JV_KIND_ARRAY);
    jq_cell input=storage_pack(value);
    fixture_storage_release(&input);
}
jv_kind jv_get_kind(jv first) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_kind(&context,&input,&output);
    return output.kind;
}
const char * jv_kind_name(jv_kind kind) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.kind=kind;
    lifted_value_runtime_kind_name(&context,&input,&output);
    return output.text;
}
jv jv_true(void) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    lifted_value_runtime_true(&context,&input,&output);
    return output.value;
}
jv jv_false(void) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    lifted_value_runtime_false(&context,&input,&output);
    return output.value;
}
jv jv_null(void) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    lifted_value_runtime_null(&context,&input,&output);
    return output.value;
}
jv jv_bool(int count) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.count=count;
    lifted_value_runtime_boolean(&context,&input,&output);
    return output.value;
}
jv jv_invalid(void) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    lifted_value_runtime_invalid(&context,&input,&output);
    return output.value;
}
jv jv_invalid_with_msg(jv first) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_invalid_message(&context,&input,&output);
    return output.value;
}
jv jv_invalid_get_msg(jv first) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_invalid_get_message(&context,&input,&output);
    return output.value;
}
int jv_invalid_has_msg(jv first) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_invalid_has_message(&context,&input,&output);
    return output.integer;
}
void jvp_invalid_free(jv first) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_invalid_release(&context,&input,&output);
}
jv jv_array(void) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    lifted_value_runtime_array(&context,&input,&output);
    return output.value;
}
jv jv_array_append(jv first, jv second) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.second=second;
    lifted_value_runtime_array_append(&context,&input,&output);
    return output.value;
}
jv jv_array_concat(jv first, jv second) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.second=second;
    lifted_value_runtime_array_concat(&context,&input,&output);
    return output.value;
}
jv jv_string_sized(const char *text, int count) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.text=text;
    input.count=count;
    lifted_value_runtime_string_sized(&context,&input,&output);
    return output.value;
}
jv jv_string_empty(int count) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.count=count;
    lifted_value_runtime_string_empty(&context,&input,&output);
    return output.value;
}
jv jv_string(const char *text) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.text=text;
    lifted_value_runtime_string(&context,&input,&output);
    return output.value;
}
jv jv_string_repeat(jv first, int count) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.count=count;
    lifted_value_runtime_string_repeat(&context,&input,&output);
    return output.value;
}
jv jv_string_explode(jv first) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_string_explode(&context,&input,&output);
    return output.value;
}
jv jv_string_implode(jv first) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_string_implode(&context,&input,&output);
    return output.value;
}
#ifndef SPX_EXISTING_JV_STRING_HASH
unsigned long jv_string_hash(jv first) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_string_hash(&context,&input,&output);
    return output.hash;
}
#endif
const char * jv_string_value(jv first) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_string_value(&context,&input,&output);
    return output.text;
}
jv jv_string_concat(jv first, jv second) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.second=second;
    lifted_value_runtime_string_concat(&context,&input,&output);
    return output.value;
}
jv jv_string_append_buf(jv first, const char *text, int count) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.text=text;
    input.count=count;
    lifted_value_runtime_string_append_buf(&context,&input,&output);
    return output.value;
}
jv jv_string_append_codepoint(jv first, uint32_t codepoint) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.codepoint=codepoint;
    lifted_value_runtime_string_append_codepoint(&context,&input,&output);
    return output.value;
}
jv jv_string_append_str(jv first, const char *text) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.text=text;
    lifted_value_runtime_string_append_str(&context,&input,&output);
    return output.value;
}
jv jv_string_vfmt(const char *text, va_list args) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
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
jv jv_string_fmt(const char *text, ...) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
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
void jvp_string_free(jv first) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_string_release(&context,&input,&output);
}
jv jv_object(void) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    lifted_value_runtime_object(&context,&input,&output);
    return output.value;
}
int jv_object_has(jv first, jv second) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.second=second;
    lifted_value_runtime_object_has(&context,&input,&output);
    return output.integer;
}
jv jv_object_set(jv first, jv second, jv third) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.second=second;
    input.third=third;
    lifted_value_runtime_object_set(&context,&input,&output);
    return output.value;
}
int jv_object_length(jv first) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_object_length(&context,&input,&output);
    return output.integer;
}
int jv_object_iter(jv first) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_object_iter(&context,&input,&output);
    return output.integer;
}
int jv_object_iter_valid(jv first, int count) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.count=count;
    lifted_value_runtime_object_iter_valid(&context,&input,&output);
    return output.integer;
}
int jv_object_iter_next(jv first, int count) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.count=count;
    lifted_value_runtime_object_iter_next(&context,&input,&output);
    return output.integer;
}
jv jv_object_iter_key(jv first, int count) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.count=count;
    lifted_value_runtime_object_iter_key(&context,&input,&output);
    return output.value;
}
jv jv_object_iter_value(jv first, int count) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    input.count=count;
    lifted_value_runtime_object_iter_value(&context,&input,&output);
    return output.value;
}
int jv_get_refcnt(jv first) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={0};
    struct spx_opaque_value_output_v5 output; (void)&jv_is_valid;
    input.first=first;
    lifted_value_runtime_reference_count(&context,&input,&output);
    return output.integer;
}

jv parse_slice(jv value,jv slice,int *start,int *end) {
    static unsigned slot; portable_component_entry("value-runtime", &slot);
    spx_value_runtime_context_v5 context={0};
    struct spx_opaque_value_input_v5 input={.first=value,.second=slice,.start=start,.end=end};
    struct spx_opaque_value_output_v5 output;
    lifted_value_runtime_slice_bounds(&context,&input,&output);
    return output.value;
}
