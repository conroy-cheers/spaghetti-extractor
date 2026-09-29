#ifndef SPX_COMPILER_INSTRUCTION_LAYOUT_H
#define SPX_COMPILER_INSTRUCTION_LAYOUT_H
#include "compile.h"
struct inst {
  struct inst* next;
  struct inst* prev;

  opcode op;

  struct {
    uint16_t intval;
    struct inst* target;
    jv constant;
    const struct cfunction* cfunc;
  } imm;

  struct locfile* locfile;
  location source;

  // Binding
  // An instruction requiring binding (for parameters/variables/functions)
  // is in one of three states:
  //   inst->bound_by = NULL  - Unbound free variable
  //   inst->bound_by = inst  - This instruction binds a variable
  //   inst->bound_by = other - Uses variable bound by other instruction
  // Unbound instructions (references to other things that may or may not
  // exist) are created by "gen_foo_unbound", and bindings are created by
  // block_bind(definition, body), which binds all instructions in
  // body which are unbound and refer to "definition" by name.
  struct inst* bound_by;
  char* symbol;
  int any_unbound;
  int referenced;

  int nformals;
  int nactuals;

  block subfn;   // used by CLOSURE_CREATE (body of function)
  block arglist; // used by CLOSURE_CREATE (formals) and CALL_JQ (arguments)

  // This instruction is compiled as part of which function?
  // (only used during block_compile)
  struct bytecode* compiled;

  int bytecode_pos; // position just after this insn
};

#endif
