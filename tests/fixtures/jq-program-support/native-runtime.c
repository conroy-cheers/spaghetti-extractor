#include <stdint.h>
#include <windows.h>
#include "support-inputs.h"
static void *entry(uint32_t rva) { (void)&jv_is_valid; HMODULE module=GetModuleHandleA("libjq-1.dll"); if(!module)ExitProcess(84); return (unsigned char *)module+rva; }
const char * jvp_utf8_backtrack(const char * start, const char * min, int * missing) { return ((const char * (*)(const char *, const char *, int *))entry(0x3fc60))(start, min, missing); }
const char * jvp_utf8_next(const char * in, const char * end, int * codepoint) { return ((const char * (*)(const char *, const char *, int *))entry(0x3fcf9))(in, end, codepoint); }
int jvp_utf8_is_valid(const char * in, const char * end) { return ((int (*)(const char *, const char *))entry(0x3fe35))(in, end); }
int jvp_utf8_decode_length(char first) { return ((int (*)(char))entry(0x3fe76))(first); }
int jvp_utf8_encode_length(int codepoint) { return ((int (*)(int))entry(0x3feb3))(codepoint); }
int jvp_utf8_encode(int codepoint, char * out) { return ((int (*)(int, char *))entry(0x3fedf))(codepoint, out); }
int jvp_codepoint_is_whitespace(int codepoint) { return ((int (*)(int))entry(0x3ffce))(codepoint); }
const struct opcode_description * opcode_describe(opcode op) { return ((const struct opcode_description * (*)(opcode))entry(0x13d10))(op); }
int bytecode_operation_length(uint16_t * code) { return ((int (*)(uint16_t *))entry(0x13d2e))(code); }
void dump_disassembly(int indent, struct bytecode * bytecode) { ((void (*)(int, struct bytecode *))entry(0x14440))(indent, bytecode); }
void dump_operation(struct bytecode * bytecode, uint16_t * code) { ((void (*)(struct bytecode *, uint16_t *))entry(0x13d63))(bytecode, code); }
void bytecode_free(struct bytecode * bytecode) { ((void (*)(struct bytecode *))entry(0x147cb))(bytecode); }
struct locfile * locfile_init(jq_state * jq, const char * name, const char * text, int length) { return ((struct locfile * (*)(jq_state *, const char *, const char *, int))entry(0x442ea))(jq, name, text, length); }
struct locfile * locfile_retain(struct locfile * file) { return ((struct locfile * (*)(struct locfile *))entry(0x44410))(file); }
void locfile_free(struct locfile * file) { ((void (*)(struct locfile *))entry(0x44419))(file); }
int locfile_get_line(struct locfile * file, int position) { return ((int (*)(struct locfile *, int))entry(0x44470))(file, position); }
jv get_home(void) { return ((jv (*)(void))entry(0x44f46))(); }
jv expand_path(jv path) { return ((jv (*)(jv path))entry(0x45016))(path); }
const void * _jq_memmem(const void *haystack, size_t length, const void *needle, size_t needle_length) { return ((const void * (*)(const void *haystack, size_t length, const void *needle, size_t needle_length))entry(0x4538f))(haystack, length, needle, needle_length); }

jv spx_probe_jq_realpath(jv path) { return ((jv (*)(jv path))entry(0x452ae))(path); }

char * spx_probe_dirname(char *path) { return ((char * (*)(char *path))entry(0x59e90))(path); }

char * spx_probe_basename(char *path) { return ((char * (*)(char *path))entry(0x59fb0))(path); }
