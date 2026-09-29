#ifndef SPX_JQ_SUPPORT_INPUTS_H
#define SPX_JQ_SUPPORT_INPUTS_H
#include <stdarg.h>
#include <stddef.h>
#include "bytecode.h"
#include "locfile.h"
#include "jv_unicode.h"
#include "windows-paths.h"
struct spx_opaque_support_input_v5 {
    const char *text, *limit, *name;
    char *buffer;
    int integer, *integer_pointer;
    uint16_t *code;
    struct bytecode *bytecode;
    struct locfile *file;
    jq_state *jq;
    location location;
    va_list *format_args;
    jv value;
    size_t length, needle_length;
};
struct spx_opaque_support_output_v5 {
    const char *cursor;
    int integer;
    const struct opcode_description *description;
    struct locfile *file;
    jv value;
};
const char * portable_jvp_utf8_backtrack(const char * start, const char * min, int * missing);
const char * portable_jvp_utf8_next(const char * in, const char * end, int * codepoint);
int portable_jvp_utf8_is_valid(const char * in, const char * end);
int portable_jvp_utf8_decode_length(char first);
int portable_jvp_utf8_encode_length(int codepoint);
int portable_jvp_utf8_encode(int codepoint, char * out);
int portable_jvp_codepoint_is_whitespace(int codepoint);
const struct opcode_description * portable_opcode_describe(opcode op);
int portable_bytecode_operation_length(uint16_t * code);
void portable_dump_disassembly(int indent, struct bytecode * bytecode);
void portable_dump_operation(struct bytecode * bytecode, uint16_t * code);
void portable_bytecode_free(struct bytecode * bytecode);
struct locfile * portable_locfile_init(jq_state * jq, const char * name, const char * text, int length);
struct locfile * portable_locfile_retain(struct locfile * file);
void portable_locfile_free(struct locfile * file);
int portable_locfile_get_line(struct locfile * file, int position);
void portable_locfile_vlocate(struct locfile * file, location location, const char * format, va_list args);
jv portable_get_home(void);
jv portable_expand_path(jv path);
jv portable_jq_realpath(jv path);
const void *portable_jq_memmem(const void *haystack, size_t haystack_length,
                              const void *needle, size_t needle_length);
#endif
