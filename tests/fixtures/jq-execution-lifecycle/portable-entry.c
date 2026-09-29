#include "portable-component-implementation.h"
#include "lifecycle-inputs.h"
#include "observations.h"
jq_state * jq_init(void) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {0};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_init(&context, &input, &output);
    return output.state;
}
void jq_set_error_cb(jq_state * state, jq_msg_cb callback, void * data) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .message_callback0 = callback, .data0 = data};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_set_error_cb(&context, &input, &output);

}
void jq_get_error_cb(jq_state * state, jq_msg_cb * callback, void ** data) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .message_callback_out0 = callback, .data_out0 = data};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_get_error_cb(&context, &input, &output);

}
void jq_set_nomem_handler(jq_state * state, spx_nomem_handler handler, void * data) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .handler0 = handler, .data0 = data};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_set_nomem_handler(&context, &input, &output);

}
jv jq_format_error(jv value) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.value0 = value};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_format_error(&context, &input, &output);
    return output.value;
}
void jq_report_error(jq_state * state, jv value) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .value0 = value};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_report_error(&context, &input, &output);

}
int jq_compile(jq_state * state, const char * program) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .text0 = program};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_compile(&context, &input, &output);
    return output.integer;
}
int jq_compile_args(jq_state * state, const char * program, jv arguments) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .text0 = program, .value0 = arguments};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_compile_args(&context, &input, &output);
    return output.integer;
}
void jq_dump_disassembly(jq_state * state, int indent) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .integer0 = indent};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_dump_disassembly(&context, &input, &output);

}
void jq_start(jq_state * state, jv value, int flags) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .value0 = value, .integer0 = flags};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_start(&context, &input, &output);

}
void jq_teardown(jq_state ** owner) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.owner0 = owner};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_teardown(&context, &input, &output);

}
void jq_halt(jq_state * state, jv exit_code, jv message) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .value0 = exit_code, .value1 = message};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_halt(&context, &input, &output);

}
int jq_halted(jq_state * state) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_halted(&context, &input, &output);
    return output.integer;
}
jv jq_get_exit_code(jq_state * state) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_get_exit_code(&context, &input, &output);
    return output.value;
}
jv jq_get_error_message(jq_state * state) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_get_error_message(&context, &input, &output);
    return output.value;
}
void jq_set_input_cb(jq_state * state, jq_input_cb callback, void * data) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .input_callback0 = callback, .data0 = data};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_set_input_cb(&context, &input, &output);

}
void jq_get_input_cb(jq_state * state, jq_input_cb * callback, void ** data) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .input_callback_out0 = callback, .data_out0 = data};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_get_input_cb(&context, &input, &output);

}
void jq_set_debug_cb(jq_state * state, jq_msg_cb callback, void * data) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .message_callback0 = callback, .data0 = data};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_set_debug_cb(&context, &input, &output);

}
void jq_get_debug_cb(jq_state * state, jq_msg_cb * callback, void ** data) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .message_callback_out0 = callback, .data_out0 = data};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_get_debug_cb(&context, &input, &output);

}
void jq_set_stderr_cb(jq_state * state, jq_msg_cb callback, void * data) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .message_callback0 = callback, .data0 = data};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_set_stderr_cb(&context, &input, &output);

}
void jq_get_stderr_cb(jq_state * state, jq_msg_cb * callback, void ** data) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .message_callback_out0 = callback, .data_out0 = data};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_get_stderr_cb(&context, &input, &output);

}
void jq_set_attrs(jq_state * state, jv attributes) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .value0 = attributes};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_set_attrs(&context, &input, &output);

}
jv jq_get_jq_origin(jq_state * state) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_get_jq_origin(&context, &input, &output);
    return output.value;
}
jv jq_get_prog_origin(jq_state * state) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_get_prog_origin(&context, &input, &output);
    return output.value;
}
jv jq_get_lib_dirs(jq_state * state) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_get_lib_dirs(&context, &input, &output);
    return output.value;
}
void jq_set_attr(jq_state * state, jv key, jv value) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .value0 = key, .value1 = value};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_set_attr(&context, &input, &output);

}
jv jq_get_attr(jq_state * state, jv key) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .value0 = key};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_get_attr(&context, &input, &output);
    return output.value;
}
jv _jq_path_append(jq_state *state, jv value, jv path, jv value_at_path) {
    static unsigned slot;
    portable_component_entry("execution-lifecycle", &slot);
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0=state,.value0=value,.value1=path,.value2=value_at_path};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_path_append(&context, &input, &output);
    return output.value;
}
