#ifndef SPX_JQ_LIFECYCLE_API_H
#define SPX_JQ_LIFECYCLE_API_H
#include "jq.h"
typedef void (*spx_nomem_handler)(void *);
jq_state * portable_jq_init(void);
void portable_jq_set_error_cb(jq_state * state, jq_msg_cb callback, void * data);
void portable_jq_get_error_cb(jq_state * state, jq_msg_cb * callback, void ** data);
void portable_jq_set_nomem_handler(jq_state * state, spx_nomem_handler handler, void * data);
jv portable_jq_format_error(jv value);
void portable_jq_report_error(jq_state * state, jv value);
int portable_jq_compile(jq_state * state, const char * program);
int portable_jq_compile_args(jq_state * state, const char * program, jv arguments);
void portable_jq_dump_disassembly(jq_state * state, int indent);
void portable_jq_start(jq_state * state, jv value, int flags);
void portable_jq_teardown(jq_state ** owner);
void portable_jq_halt(jq_state * state, jv exit_code, jv message);
int portable_jq_halted(jq_state * state);
jv portable_jq_get_exit_code(jq_state * state);
jv portable_jq_get_error_message(jq_state * state);
void portable_jq_set_input_cb(jq_state * state, jq_input_cb callback, void * data);
void portable_jq_get_input_cb(jq_state * state, jq_input_cb * callback, void ** data);
void portable_jq_set_debug_cb(jq_state * state, jq_msg_cb callback, void * data);
void portable_jq_get_debug_cb(jq_state * state, jq_msg_cb * callback, void ** data);
void portable_jq_set_stderr_cb(jq_state * state, jq_msg_cb callback, void * data);
void portable_jq_get_stderr_cb(jq_state * state, jq_msg_cb * callback, void ** data);
void portable_jq_set_attrs(jq_state * state, jv attributes);
jv portable_jq_get_jq_origin(jq_state * state);
jv portable_jq_get_prog_origin(jq_state * state);
jv portable_jq_get_lib_dirs(jq_state * state);
void portable_jq_set_attr(jq_state * state, jv key, jv value);
jv portable_jq_get_attr(jq_state * state, jv key);
jv portable__jq_path_append(jq_state *, jv, jv, jv);
#endif
