#include "portable-component-implementation.h"
#include "support-inputs.h"
#include "observations.h"
const char * jvp_utf8_backtrack(const char * start, const char * min, int * missing) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.text=start;
    input.limit=min;
    input.integer_pointer=missing;
    lifted_program_support_utf8_backtrack(&context,&input,&output);
    return output.cursor;
}
const char * jvp_utf8_next(const char * in, const char * end, int * codepoint) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.text=in;
    input.limit=end;
    input.integer_pointer=codepoint;
    lifted_program_support_utf8_next(&context,&input,&output);
    return output.cursor;
}
int jvp_utf8_is_valid(const char * in, const char * end) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.text=in;
    input.limit=end;
    lifted_program_support_utf8_is_valid(&context,&input,&output);
    return output.integer;
}
int jvp_utf8_decode_length(char first) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.integer=first;
    lifted_program_support_utf8_decode_length(&context,&input,&output);
    return output.integer;
}
int jvp_utf8_encode_length(int codepoint) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.integer=codepoint;
    lifted_program_support_utf8_encode_length(&context,&input,&output);
    return output.integer;
}
int jvp_utf8_encode(int codepoint, char * out) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.integer=codepoint;
    input.buffer=out;
    lifted_program_support_utf8_encode(&context,&input,&output);
    return output.integer;
}
int jvp_codepoint_is_whitespace(int codepoint) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.integer=codepoint;
    lifted_program_support_codepoint_is_whitespace(&context,&input,&output);
    return output.integer;
}
const struct opcode_description * opcode_describe(opcode op) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.integer=op;
    lifted_program_support_opcode_describe(&context,&input,&output);
    return output.description;
}
int bytecode_operation_length(uint16_t * code) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.code=code;
    lifted_program_support_bytecode_operation_length(&context,&input,&output);
    return output.integer;
}
void dump_disassembly(int indent, struct bytecode * bytecode) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.integer=indent;
    input.bytecode=bytecode;
    lifted_program_support_dump_disassembly(&context,&input,&output);
}
void dump_operation(struct bytecode * bytecode, uint16_t * code) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.bytecode=bytecode;
    input.code=code;
    lifted_program_support_dump_operation(&context,&input,&output);
}
void bytecode_free(struct bytecode * bytecode) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.bytecode=bytecode;
    lifted_program_support_bytecode_free(&context,&input,&output);
}
struct locfile * locfile_init(jq_state * jq, const char * name, const char * text, int length) {
    static unsigned slot; portable_component_entry("program-support", &slot);
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
struct locfile * locfile_retain(struct locfile * file) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.file=file;
    lifted_program_support_locfile_retain(&context,&input,&output);
    return output.file;
}
void locfile_free(struct locfile * file) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.file=file;
    lifted_program_support_locfile_free(&context,&input,&output);
}
int locfile_get_line(struct locfile * file, int position) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.file=file;
    input.integer=position;
    lifted_program_support_locfile_get_line(&context,&input,&output);
    return output.integer;
}
void locfile_locate(struct locfile * file, location location, const char * format, ...) {
    static unsigned slot; portable_component_entry("program-support", &slot);
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

jv get_home(void) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;

    lifted_program_support_get_home(&context,&input,&output);
    return output.value;
}

jv expand_path(jv path) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.value=path;
    lifted_program_support_expand_path(&context,&input,&output);
    return output.value;
}

const void * _jq_memmem(const void *haystack, size_t length, const void *needle, size_t needle_length) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output; (void)&jv_is_valid;
    input.text=haystack; input.length=length; input.name=needle; input.needle_length=needle_length;
    lifted_program_support_memory_search(&context,&input,&output);
    return output.cursor;
}

jv jq_realpath(jv path) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output;
    input.value=path;
    lifted_program_support_canonical_path(&context,&input,&output);
    return output.value;
}

char * dirname(char *path) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output;
    input.buffer=path;
    lifted_program_support_path_dirname(&context,&input,&output);
    return (char *)output.cursor;
}

char * basename(char *path) {
    static unsigned slot; portable_component_entry("program-support", &slot);
    spx_program_support_context_v5 context={0};
    struct spx_opaque_support_input_v5 input={0};
    struct spx_opaque_support_output_v5 output;
    input.buffer=path;
    lifted_program_support_path_basename(&context,&input,&output);
    return (char *)output.cursor;
}

char *__xpg_basename(char *path) { return basename(path); }
