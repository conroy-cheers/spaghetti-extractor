#include "portable-component-implementation.h"
#include "support-inputs.h"
#define NATIVE_ENTRY __attribute__((no_caller_saved_registers, target("general-regs-only")))
void spx_observe_support_entry(unsigned);
NATIVE_ENTRY const char * spx_entry_jvp_utf8_backtrack(const char * start, const char * min, int * missing) {
    spx_observe_support_entry(0);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.text=start;
    input.limit=min;
    input.integer_pointer=missing;
    lifted_program_support_utf8_backtrack(&context,&input,&output);
    return output.cursor;
}
NATIVE_ENTRY const char * spx_entry_jvp_utf8_next(const char * in, const char * end, int * codepoint) {
    spx_observe_support_entry(1);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.text=in;
    input.limit=end;
    input.integer_pointer=codepoint;
    lifted_program_support_utf8_next(&context,&input,&output);
    return output.cursor;
}
NATIVE_ENTRY int spx_entry_jvp_utf8_is_valid(const char * in, const char * end) {
    spx_observe_support_entry(2);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.text=in;
    input.limit=end;
    lifted_program_support_utf8_is_valid(&context,&input,&output);
    return output.integer;
}
NATIVE_ENTRY int spx_entry_jvp_utf8_decode_length(char first) {
    spx_observe_support_entry(3);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.integer=first;
    lifted_program_support_utf8_decode_length(&context,&input,&output);
    return output.integer;
}
NATIVE_ENTRY int spx_entry_jvp_utf8_encode_length(int codepoint) {
    spx_observe_support_entry(4);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.integer=codepoint;
    lifted_program_support_utf8_encode_length(&context,&input,&output);
    return output.integer;
}
NATIVE_ENTRY int spx_entry_jvp_utf8_encode(int codepoint, char * out) {
    spx_observe_support_entry(5);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.integer=codepoint;
    input.buffer=out;
    lifted_program_support_utf8_encode(&context,&input,&output);
    return output.integer;
}
NATIVE_ENTRY int spx_entry_jvp_codepoint_is_whitespace(int codepoint) {
    spx_observe_support_entry(6);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.integer=codepoint;
    lifted_program_support_codepoint_is_whitespace(&context,&input,&output);
    return output.integer;
}
NATIVE_ENTRY const struct opcode_description * spx_entry_opcode_describe(opcode op) {
    spx_observe_support_entry(7);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.integer=op;
    lifted_program_support_opcode_describe(&context,&input,&output);
    return output.description;
}
NATIVE_ENTRY int spx_entry_bytecode_operation_length(uint16_t * code) {
    spx_observe_support_entry(8);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.code=code;
    lifted_program_support_bytecode_operation_length(&context,&input,&output);
    return output.integer;
}
NATIVE_ENTRY void spx_entry_dump_disassembly(int indent, struct bytecode * bytecode) {
    spx_observe_support_entry(9);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.integer=indent;
    input.bytecode=bytecode;
    lifted_program_support_dump_disassembly(&context,&input,&output);
}
NATIVE_ENTRY void spx_entry_dump_operation(struct bytecode * bytecode, uint16_t * code) {
    spx_observe_support_entry(10);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.bytecode=bytecode;
    input.code=code;
    lifted_program_support_dump_operation(&context,&input,&output);
}
NATIVE_ENTRY void spx_entry_bytecode_free(struct bytecode * bytecode) {
    spx_observe_support_entry(11);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.bytecode=bytecode;
    lifted_program_support_bytecode_free(&context,&input,&output);
}
NATIVE_ENTRY struct locfile * spx_entry_locfile_init(jq_state * jq, const char * name, const char * text, int length) {
    spx_observe_support_entry(12);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.jq=jq;
    input.name=name;
    input.text=text;
    input.integer=length;
    lifted_program_support_locfile_init(&context,&input,&output);
    return output.file;
}
NATIVE_ENTRY struct locfile * spx_entry_locfile_retain(struct locfile * file) {
    spx_observe_support_entry(13);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.file=file;
    lifted_program_support_locfile_retain(&context,&input,&output);
    return output.file;
}
NATIVE_ENTRY void spx_entry_locfile_free(struct locfile * file) {
    spx_observe_support_entry(14);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.file=file;
    lifted_program_support_locfile_free(&context,&input,&output);
}
NATIVE_ENTRY int spx_entry_locfile_get_line(struct locfile * file, int position) {
    spx_observe_support_entry(15);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.file=file;
    input.integer=position;
    lifted_program_support_locfile_get_line(&context,&input,&output);
    return output.integer;
}
NATIVE_ENTRY void spx_entry_locfile_locate(struct locfile * file, location location, const char * format, ...) {
    spx_observe_support_entry(16);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.file=file;
    input.location=location;
    input.text=format;
    va_list args; va_start(args, format); input.format_args=&args;
    lifted_program_support_locfile_locate(&context,&input,&output);
    va_end(args);
}

NATIVE_ENTRY jv spx_entry_get_home(void) {
    spx_observe_support_entry(17);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;

    lifted_program_support_get_home(&context,&input,&output);
    return output.value;
}

NATIVE_ENTRY jv spx_entry_expand_path(jv path) {
    spx_observe_support_entry(18);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.value=path;
    lifted_program_support_expand_path(&context,&input,&output);
    return output.value;
}

NATIVE_ENTRY const void * spx_entry__jq_memmem(const void *haystack, size_t length, const void *needle, size_t needle_length) {
    spx_observe_support_entry(19);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.text=haystack; input.length=length; input.name=needle; input.needle_length=needle_length;
    lifted_program_support_memory_search(&context,&input,&output);
    return output.cursor;
}

NATIVE_ENTRY jv spx_entry_jq_realpath(jv path) {
    spx_observe_support_entry(20);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output;
    input.value=path;
    lifted_program_support_canonical_path(&context,&input,&output);
    return output.value;
}

NATIVE_ENTRY char * spx_entry_dirname(char *path) {
    spx_observe_support_entry(21);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output;
    input.buffer=path;
    lifted_program_support_path_dirname(&context,&input,&output);
    return (char *)output.cursor;
}

NATIVE_ENTRY char * spx_entry_basename(char *path) {
    spx_observe_support_entry(22);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output;
    input.buffer=path;
    lifted_program_support_path_basename(&context,&input,&output);
    return (char *)output.cursor;
}
