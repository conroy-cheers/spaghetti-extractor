#ifndef SPX_JQ_STATE_LAYOUT_H
#define SPX_JQ_STATE_LAYOUT_H
#include "jq.h"
#include "bytecode.h"
#include "execution-stack.h"
struct jq_state {
  void (*nomem_handler)(void *);
  void *nomem_handler_data;
  struct bytecode* bc;

  jq_msg_cb err_cb;
  void *err_cb_data;
  jv error;

  struct stack stk;
  stack_ptr curr_frame;
  stack_ptr stk_top;
  stack_ptr fork_top;

  jv path;
  jv value_at_path;
  int subexp_nest;
  int debug_trace_enabled;
  int initial_execution;
  unsigned next_label;

  int halted;
  jv exit_code;
  jv error_message;

  jv attrs;
  jq_input_cb input_cb;
  void *input_cb_data;
  jq_msg_cb debug_cb;
  void *debug_cb_data;
  jq_msg_cb stderr_cb;
  void *stderr_cb_data;
};

struct closure {
  struct bytecode* bc;  // jq bytecode
  stack_ptr env;        // jq stack address of closed frame
};

// locals for any function called: either a closure or a local variable
union frame_entry {
  struct closure closure;
  jv localvar;
};

// jq function call frame
struct frame {
  struct bytecode* bc;      // jq bytecode for callee
  stack_ptr env;            // jq stack address of frame to return to
  stack_ptr retdata;        // jq stack address to unwind to on RET
  uint16_t* retaddr;        // jq bytecode return address
  union frame_entry entries[]; // nclosures + nlocals
};

#endif
