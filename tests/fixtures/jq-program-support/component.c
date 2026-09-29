#include "portable-component-implementation.h"
#include "support-inputs.h"
void lifted_program_support_utf8_backtrack(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->cursor=portable_jvp_utf8_backtrack(input->text, input->limit, input->integer_pointer);
}
void lifted_program_support_utf8_next(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->cursor=portable_jvp_utf8_next(input->text, input->limit, input->integer_pointer);
}
void lifted_program_support_utf8_is_valid(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->integer=portable_jvp_utf8_is_valid(input->text, input->limit);
}
void lifted_program_support_utf8_decode_length(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->integer=portable_jvp_utf8_decode_length(input->integer);
}
void lifted_program_support_utf8_encode_length(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->integer=portable_jvp_utf8_encode_length(input->integer);
}
void lifted_program_support_utf8_encode(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->integer=portable_jvp_utf8_encode(input->integer, input->buffer);
}
void lifted_program_support_codepoint_is_whitespace(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->integer=portable_jvp_codepoint_is_whitespace(input->integer);
}
void lifted_program_support_opcode_describe(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->description=portable_opcode_describe(input->integer);
}
void lifted_program_support_bytecode_operation_length(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->integer=portable_bytecode_operation_length(input->code);
}
void lifted_program_support_dump_disassembly(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    (void)output; portable_dump_disassembly(input->integer, input->bytecode);
}
void lifted_program_support_dump_operation(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    (void)output; portable_dump_operation(input->bytecode, input->code);
}
void lifted_program_support_bytecode_free(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    (void)output; portable_bytecode_free(input->bytecode);
}
void lifted_program_support_locfile_init(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->file=portable_locfile_init(input->jq, input->name, input->text, input->integer);
}
void lifted_program_support_locfile_retain(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->file=portable_locfile_retain(input->file);
}
void lifted_program_support_locfile_free(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    (void)output; portable_locfile_free(input->file);
}
void lifted_program_support_locfile_get_line(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->integer=portable_locfile_get_line(input->file, input->integer);
}
void lifted_program_support_locfile_locate(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    (void)output; portable_locfile_vlocate(input->file, input->location, input->text, *input->format_args);
}

void lifted_program_support_get_home(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_get_home();
}

void lifted_program_support_expand_path(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->value=portable_expand_path(input->value);
}

void lifted_program_support_memory_search(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)input; (void)&jv_is_valid;
    output->cursor=portable_jq_memmem(input->text,input->length,input->name,input->needle_length);
}

void lifted_program_support_canonical_path(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value=portable_jq_realpath(input->value);
}

void lifted_program_support_path_dirname(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->cursor=spx_path_dirname(input->buffer);
}

void lifted_program_support_path_basename(spx_program_support_context_v5 *context, struct spx_opaque_support_input_v5 *input, struct spx_opaque_support_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->cursor=spx_path_basename(input->buffer);
}
