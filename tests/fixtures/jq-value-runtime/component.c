#include "portable-component-implementation.h"
#include "value-runtime-inputs.h"
void lifted_value_runtime_kind(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->kind=portable_jv_get_kind(input->first);
}
void lifted_value_runtime_kind_name(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->text=portable_jv_kind_name(input->kind);
}
void lifted_value_runtime_true(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_true();
}
void lifted_value_runtime_false(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_false();
}
void lifted_value_runtime_null(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_null();
}
void lifted_value_runtime_boolean(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_bool(input->count);
}
void lifted_value_runtime_invalid(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_invalid();
}
void lifted_value_runtime_invalid_message(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_invalid_with_msg(input->first);
}
void lifted_value_runtime_invalid_get_message(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_invalid_get_msg(input->first);
}
void lifted_value_runtime_invalid_has_message(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->integer=portable_jv_invalid_has_msg(input->first);
}
void lifted_value_runtime_invalid_release(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    (void)output; portable_jvp_invalid_free(input->first);
}
void lifted_value_runtime_array(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_array();
}
void lifted_value_runtime_array_append(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_array_append(input->first, input->second);
}
void lifted_value_runtime_array_concat(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_array_concat(input->first, input->second);
}
void lifted_value_runtime_string_sized(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_string_sized(input->text, input->count);
}
void lifted_value_runtime_string_empty(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_string_empty(input->count);
}
void lifted_value_runtime_string(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_string(input->text);
}
void lifted_value_runtime_string_repeat(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_string_repeat(input->first, input->count);
}
void lifted_value_runtime_string_explode(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_string_explode(input->first);
}
void lifted_value_runtime_string_implode(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_string_implode(input->first);
}
void lifted_value_runtime_string_hash(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->hash=portable_jv_string_hash(input->first);
}
void lifted_value_runtime_string_value(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->text=portable_jv_string_value(input->first);
}
void lifted_value_runtime_string_concat(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_string_concat(input->first, input->second);
}
void lifted_value_runtime_string_append_buf(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_string_append_buf(input->first, input->text, input->count);
}
void lifted_value_runtime_string_append_codepoint(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_string_append_codepoint(input->first, input->codepoint);
}
void lifted_value_runtime_string_append_str(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_string_append_str(input->first, input->text);
}
void lifted_value_runtime_format(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_string_vfmt(input->text, *input->args);
}
void lifted_value_runtime_string_release(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    (void)output; portable_jvp_string_free(input->first);
}
void lifted_value_runtime_object(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_object();
}
void lifted_value_runtime_object_has(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->integer=portable_jv_object_has(input->first, input->second);
}
void lifted_value_runtime_object_set(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_object_set(input->first, input->second, input->third);
}
void lifted_value_runtime_object_length(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->integer=portable_jv_object_length(input->first);
}
void lifted_value_runtime_object_iter(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->integer=portable_jv_object_iter(input->first);
}
void lifted_value_runtime_object_iter_valid(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->integer=portable_jv_object_iter_valid(input->first, input->count);
}
void lifted_value_runtime_object_iter_next(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->integer=portable_jv_object_iter_next(input->first, input->count);
}
void lifted_value_runtime_object_iter_key(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_object_iter_key(input->first, input->count);
}
void lifted_value_runtime_object_iter_value(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_jv_object_iter_value(input->first, input->count);
}
void lifted_value_runtime_reference_count(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->integer=portable_jv_get_refcnt(input->first);
}
void lifted_value_runtime_release(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context; (void)output; (void)&jv_is_valid;
    portable_jv_free(input->first);
}

void lifted_value_runtime_slice_bounds(spx_value_runtime_context_v5 *context, struct spx_opaque_value_input_v5 *input, struct spx_opaque_value_output_v5 *output) {
    (void)context;
    output->value=portable_parse_slice(input->first,input->second,input->start,input->end);
}
