#ifndef SPX_JQ_LIFECYCLE_ENTRIES_H
#define SPX_JQ_LIFECYCLE_ENTRIES_H
#include "lifecycle-api.h"
jq_state * spx_entry_jq_init(void);
void spx_entry_jq_set_error_cb(jq_state * state, jq_msg_cb callback, void * data);
void spx_entry_jq_get_error_cb(jq_state * state, jq_msg_cb * callback, void ** data);
void spx_entry_jq_set_nomem_handler(jq_state * state, spx_nomem_handler handler, void * data);
jv spx_entry_jq_format_error(jv value);
void spx_entry_jq_report_error(jq_state * state, jv value);
int spx_entry_jq_compile(jq_state * state, const char * program);
int spx_entry_jq_compile_args(jq_state * state, const char * program, jv arguments);
void spx_entry_jq_dump_disassembly(jq_state * state, int indent);
void spx_entry_jq_start(jq_state * state, jv value, int flags);
void spx_entry_jq_teardown(jq_state ** owner);
void spx_entry_jq_halt(jq_state * state, jv exit_code, jv message);
int spx_entry_jq_halted(jq_state * state);
jv spx_entry_jq_get_exit_code(jq_state * state);
jv spx_entry_jq_get_error_message(jq_state * state);
void spx_entry_jq_set_input_cb(jq_state * state, jq_input_cb callback, void * data);
void spx_entry_jq_get_input_cb(jq_state * state, jq_input_cb * callback, void ** data);
void spx_entry_jq_set_debug_cb(jq_state * state, jq_msg_cb callback, void * data);
void spx_entry_jq_get_debug_cb(jq_state * state, jq_msg_cb * callback, void ** data);
void spx_entry_jq_set_stderr_cb(jq_state * state, jq_msg_cb callback, void * data);
void spx_entry_jq_get_stderr_cb(jq_state * state, jq_msg_cb * callback, void ** data);
void spx_entry_jq_set_attrs(jq_state * state, jv attributes);
jv spx_entry_jq_get_jq_origin(jq_state * state);
jv spx_entry_jq_get_prog_origin(jq_state * state);
jv spx_entry_jq_get_lib_dirs(jq_state * state);
void spx_entry_jq_set_attr(jq_state * state, jv key, jv value);
jv spx_entry_jq_get_attr(jq_state * state, jv key);
jv spx_entry__jq_path_append(jq_state *, jv, jv, jv);
#endif
