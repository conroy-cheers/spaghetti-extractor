#include "portable-component-implementation.h"
#include "lifecycle-inputs.h"
/* Native optimized callers may preserve volatile GPRs across leaf calls. */
#define NATIVE_ENTRY __attribute__((no_caller_saved_registers, target("general-regs-only")))
void spx_observe_lifecycle_entry(const char *);
NATIVE_ENTRY jq_state * spx_entry_jq_init(void) {
    spx_observe_lifecycle_entry("jq_init");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {0};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_init(&context, &input, &output);
    return output.state;
}
NATIVE_ENTRY void spx_entry_jq_set_error_cb(jq_state * state, jq_msg_cb callback, void * data) {
    spx_observe_lifecycle_entry("jq_set_error_cb");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .message_callback0 = callback, .data0 = data};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_set_error_cb(&context, &input, &output);

}
NATIVE_ENTRY void spx_entry_jq_get_error_cb(jq_state * state, jq_msg_cb * callback, void ** data) {
    spx_observe_lifecycle_entry("jq_get_error_cb");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .message_callback_out0 = callback, .data_out0 = data};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_get_error_cb(&context, &input, &output);

}
NATIVE_ENTRY void spx_entry_jq_set_nomem_handler(jq_state * state, spx_nomem_handler handler, void * data) {
    spx_observe_lifecycle_entry("jq_set_nomem_handler");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .handler0 = handler, .data0 = data};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_set_nomem_handler(&context, &input, &output);

}
NATIVE_ENTRY jv spx_entry_jq_format_error(jv value) {
    spx_observe_lifecycle_entry("jq_format_error");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.value0 = value};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_format_error(&context, &input, &output);
    return output.value;
}
NATIVE_ENTRY void spx_entry_jq_report_error(jq_state * state, jv value) {
    spx_observe_lifecycle_entry("jq_report_error");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .value0 = value};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_report_error(&context, &input, &output);

}
NATIVE_ENTRY int spx_entry_jq_compile(jq_state * state, const char * program) {
    spx_observe_lifecycle_entry("jq_compile");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .text0 = program};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_compile(&context, &input, &output);
    return output.integer;
}
NATIVE_ENTRY int spx_entry_jq_compile_args(jq_state * state, const char * program, jv arguments) {
    spx_observe_lifecycle_entry("jq_compile_args");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .text0 = program, .value0 = arguments};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_compile_args(&context, &input, &output);
    return output.integer;
}
NATIVE_ENTRY void spx_entry_jq_dump_disassembly(jq_state * state, int indent) {
    spx_observe_lifecycle_entry("jq_dump_disassembly");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .integer0 = indent};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_dump_disassembly(&context, &input, &output);

}
NATIVE_ENTRY void spx_entry_jq_start(jq_state * state, jv value, int flags) {
    spx_observe_lifecycle_entry("jq_start");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .value0 = value, .integer0 = flags};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_start(&context, &input, &output);

}
NATIVE_ENTRY void spx_entry_jq_teardown(jq_state ** owner) {
    spx_observe_lifecycle_entry("jq_teardown");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.owner0 = owner};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_teardown(&context, &input, &output);

}
NATIVE_ENTRY void spx_entry_jq_halt(jq_state * state, jv exit_code, jv message) {
    spx_observe_lifecycle_entry("jq_halt");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .value0 = exit_code, .value1 = message};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_halt(&context, &input, &output);

}
NATIVE_ENTRY int spx_entry_jq_halted(jq_state * state) {
    spx_observe_lifecycle_entry("jq_halted");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_halted(&context, &input, &output);
    return output.integer;
}
NATIVE_ENTRY jv spx_entry_jq_get_exit_code(jq_state * state) {
    spx_observe_lifecycle_entry("jq_get_exit_code");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_get_exit_code(&context, &input, &output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jq_get_error_message(jq_state * state) {
    spx_observe_lifecycle_entry("jq_get_error_message");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_get_error_message(&context, &input, &output);
    return output.value;
}
NATIVE_ENTRY void spx_entry_jq_set_input_cb(jq_state * state, jq_input_cb callback, void * data) {
    spx_observe_lifecycle_entry("jq_set_input_cb");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .input_callback0 = callback, .data0 = data};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_set_input_cb(&context, &input, &output);

}
NATIVE_ENTRY void spx_entry_jq_get_input_cb(jq_state * state, jq_input_cb * callback, void ** data) {
    spx_observe_lifecycle_entry("jq_get_input_cb");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .input_callback_out0 = callback, .data_out0 = data};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_get_input_cb(&context, &input, &output);

}
NATIVE_ENTRY void spx_entry_jq_set_debug_cb(jq_state * state, jq_msg_cb callback, void * data) {
    spx_observe_lifecycle_entry("jq_set_debug_cb");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .message_callback0 = callback, .data0 = data};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_set_debug_cb(&context, &input, &output);

}
NATIVE_ENTRY void spx_entry_jq_get_debug_cb(jq_state * state, jq_msg_cb * callback, void ** data) {
    spx_observe_lifecycle_entry("jq_get_debug_cb");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .message_callback_out0 = callback, .data_out0 = data};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_get_debug_cb(&context, &input, &output);

}
NATIVE_ENTRY void spx_entry_jq_set_stderr_cb(jq_state * state, jq_msg_cb callback, void * data) {
    spx_observe_lifecycle_entry("jq_set_stderr_cb");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .message_callback0 = callback, .data0 = data};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_set_stderr_cb(&context, &input, &output);

}
NATIVE_ENTRY void spx_entry_jq_get_stderr_cb(jq_state * state, jq_msg_cb * callback, void ** data) {
    spx_observe_lifecycle_entry("jq_get_stderr_cb");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .message_callback_out0 = callback, .data_out0 = data};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_get_stderr_cb(&context, &input, &output);

}
NATIVE_ENTRY void spx_entry_jq_set_attrs(jq_state * state, jv attributes) {
    spx_observe_lifecycle_entry("jq_set_attrs");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .value0 = attributes};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_set_attrs(&context, &input, &output);

}
NATIVE_ENTRY jv spx_entry_jq_get_jq_origin(jq_state * state) {
    spx_observe_lifecycle_entry("jq_get_jq_origin");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_get_jq_origin(&context, &input, &output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jq_get_prog_origin(jq_state * state) {
    spx_observe_lifecycle_entry("jq_get_prog_origin");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_get_prog_origin(&context, &input, &output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_jq_get_lib_dirs(jq_state * state) {
    spx_observe_lifecycle_entry("jq_get_lib_dirs");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_get_lib_dirs(&context, &input, &output);
    return output.value;
}
NATIVE_ENTRY void spx_entry_jq_set_attr(jq_state * state, jv key, jv value) {
    spx_observe_lifecycle_entry("jq_set_attr");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .value0 = key, .value1 = value};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_set_attr(&context, &input, &output);

}
NATIVE_ENTRY jv spx_entry_jq_get_attr(jq_state * state, jv key) {
    spx_observe_lifecycle_entry("jq_get_attr");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0 = state, .value0 = key};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_jq_get_attr(&context, &input, &output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry__jq_path_append(jq_state *state, jv value, jv path, jv value_at_path) {
    spx_observe_lifecycle_entry("_jq_path_append");
    spx_execution_lifecycle_context_v5 context = {0};
    struct spx_opaque_lifecycle_input_v5 input = {.state0=state,.value0=value,.value1=path,.value2=value_at_path};
    struct spx_opaque_lifecycle_output_v5 output;
    (void)&jv_is_valid;
    lifted_execution_lifecycle_path_append(&context, &input, &output);
    return output.value;
}
