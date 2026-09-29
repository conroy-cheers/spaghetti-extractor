#ifndef SPX_JQ_SUPPORT_ENTRIES_H
#define SPX_JQ_SUPPORT_ENTRIES_H
#include "support-inputs.h"
const char * spx_entry_jvp_utf8_backtrack(const char * start, const char * min, int * missing);
const char * spx_entry_jvp_utf8_next(const char * in, const char * end, int * codepoint);
int spx_entry_jvp_utf8_is_valid(const char * in, const char * end);
int spx_entry_jvp_utf8_decode_length(char first);
int spx_entry_jvp_utf8_encode_length(int codepoint);
int spx_entry_jvp_utf8_encode(int codepoint, char * out);
int spx_entry_jvp_codepoint_is_whitespace(int codepoint);
const struct opcode_description * spx_entry_opcode_describe(opcode op);
int spx_entry_bytecode_operation_length(uint16_t * code);
void spx_entry_dump_disassembly(int indent, struct bytecode * bytecode);
void spx_entry_dump_operation(struct bytecode * bytecode, uint16_t * code);
void spx_entry_bytecode_free(struct bytecode * bytecode);
struct locfile * spx_entry_locfile_init(jq_state * jq, const char * name, const char * text, int length);
struct locfile * spx_entry_locfile_retain(struct locfile * file);
void spx_entry_locfile_free(struct locfile * file);
int spx_entry_locfile_get_line(struct locfile * file, int position);
void spx_entry_locfile_locate(struct locfile * file, location location, const char * format, ...);
jv spx_entry_get_home(void);
jv get_home(void);
jv spx_entry_expand_path(jv path);
jv expand_path(jv path);
const void * spx_entry__jq_memmem(const void *haystack, size_t length, const void *needle, size_t needle_length);
const void * _jq_memmem(const void *haystack, size_t length, const void *needle, size_t needle_length);
jv spx_entry_jq_realpath(jv path);
jv spx_probe_jq_realpath(jv path);
char * spx_entry_dirname(char *path);
char * spx_probe_dirname(char *path);
char * spx_entry_basename(char *path);
char * spx_probe_basename(char *path);
#endif
