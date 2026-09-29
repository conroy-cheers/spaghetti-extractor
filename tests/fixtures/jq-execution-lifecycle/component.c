#include "portable-component-implementation.h"
#include "lifecycle-inputs.h"
void lifted_execution_lifecycle_jq_init(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->state = portable_jq_init();
}
void lifted_execution_lifecycle_jq_set_error_cb(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    portable_jq_set_error_cb(input->state0, input->message_callback0, input->data0);
}
void lifted_execution_lifecycle_jq_get_error_cb(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    portable_jq_get_error_cb(input->state0, input->message_callback_out0, input->data_out0);
}
void lifted_execution_lifecycle_jq_set_nomem_handler(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    portable_jq_set_nomem_handler(input->state0, input->handler0, input->data0);
}
void lifted_execution_lifecycle_jq_format_error(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->value = portable_jq_format_error(input->value0);
}
void lifted_execution_lifecycle_jq_report_error(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    portable_jq_report_error(input->state0, input->value0);
}
void lifted_execution_lifecycle_jq_compile(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->integer = portable_jq_compile(input->state0, input->text0);
}
void lifted_execution_lifecycle_jq_compile_args(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->integer = portable_jq_compile_args(input->state0, input->text0, input->value0);
}
void lifted_execution_lifecycle_jq_dump_disassembly(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    portable_jq_dump_disassembly(input->state0, input->integer0);
}
void lifted_execution_lifecycle_jq_start(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    portable_jq_start(input->state0, input->value0, input->integer0);
}
void lifted_execution_lifecycle_jq_teardown(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    portable_jq_teardown(input->owner0);
}
void lifted_execution_lifecycle_jq_halt(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    portable_jq_halt(input->state0, input->value0, input->value1);
}
void lifted_execution_lifecycle_jq_halted(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->integer = portable_jq_halted(input->state0);
}
void lifted_execution_lifecycle_jq_get_exit_code(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->value = portable_jq_get_exit_code(input->state0);
}
void lifted_execution_lifecycle_jq_get_error_message(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->value = portable_jq_get_error_message(input->state0);
}
void lifted_execution_lifecycle_jq_set_input_cb(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    portable_jq_set_input_cb(input->state0, input->input_callback0, input->data0);
}
void lifted_execution_lifecycle_jq_get_input_cb(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    portable_jq_get_input_cb(input->state0, input->input_callback_out0, input->data_out0);
}
void lifted_execution_lifecycle_jq_set_debug_cb(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    portable_jq_set_debug_cb(input->state0, input->message_callback0, input->data0);
}
void lifted_execution_lifecycle_jq_get_debug_cb(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    portable_jq_get_debug_cb(input->state0, input->message_callback_out0, input->data_out0);
}
void lifted_execution_lifecycle_jq_set_stderr_cb(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    portable_jq_set_stderr_cb(input->state0, input->message_callback0, input->data0);
}
void lifted_execution_lifecycle_jq_get_stderr_cb(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    portable_jq_get_stderr_cb(input->state0, input->message_callback_out0, input->data_out0);
}
void lifted_execution_lifecycle_jq_set_attrs(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    portable_jq_set_attrs(input->state0, input->value0);
}
void lifted_execution_lifecycle_jq_get_jq_origin(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->value = portable_jq_get_jq_origin(input->state0);
}
void lifted_execution_lifecycle_jq_get_prog_origin(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->value = portable_jq_get_prog_origin(input->state0);
}
void lifted_execution_lifecycle_jq_get_lib_dirs(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->value = portable_jq_get_lib_dirs(input->state0);
}
void lifted_execution_lifecycle_jq_set_attr(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    portable_jq_set_attr(input->state0, input->value0, input->value1);
}
void lifted_execution_lifecycle_jq_get_attr(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->value = portable_jq_get_attr(input->state0, input->value0);
}
void lifted_execution_lifecycle_path_append(spx_execution_lifecycle_context_v5 *context,
    struct spx_opaque_lifecycle_input_v5 *input, struct spx_opaque_lifecycle_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value = portable__jq_path_append(input->state0, input->value0, input->value1, input->value2);
}
