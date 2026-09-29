/* Reviewed private native dependencies for comparison only. */
#include <stdint.h>
#include <windows.h>
#include "compile.h"

static void *entry(uint32_t rva) {
  (void)&jv_is_valid;
  HMODULE module = GetModuleHandleA("libjq-1.dll");
  if (!module) ExitProcess(84);
  return (unsigned char *)module + rva;
}
struct locfile *locfile_init(jq_state *state, const char *name, const char *text, int length) {
  return ((struct locfile *(*)(jq_state *, const char *, const char *, int))entry(0x442ea))(state, name, text, length);
}
void locfile_free(struct locfile *file) {
  ((void (*)(struct locfile *))entry(0x44419))(file);
}
int load_program(jq_state *state, struct locfile *file, block *program) {
  return ((int (*)(jq_state *, struct locfile *, block *))entry(0x43d5e))(state, file, program);
}
int builtins_bind(jq_state *state, block *program) {
  return ((int (*)(jq_state *, block *))entry(0x13bbb))(state, program);
}
int block_compile(block program, struct bytecode **code, struct locfile *file, jv arguments) {
  return ((int (*)(block, struct bytecode **, struct locfile *, jv))entry(0x1a2dc))(program, code, file, arguments);
}
int bytecode_operation_length(uint16_t *code) {
  return ((int (*)(uint16_t *))entry(0x13d2e))(code);
}
void bytecode_free(struct bytecode *code) {
  ((void (*)(struct bytecode *))entry(0x147cb))(code);
}
void dump_disassembly(int indent, struct bytecode *code) {
  ((void (*)(int, struct bytecode *))entry(0x14440))(indent, code);
}
