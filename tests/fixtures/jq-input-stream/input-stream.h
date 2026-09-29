#ifndef SPX_JQ_INPUT_STREAM_H
#define SPX_JQ_INPUT_STREAM_H
#include "jq.h"
struct spx_opaque_input_v5 {
 jq_util_input_state *state; jq_util_input_state **owner; jq_state *jq;
 jq_util_msg_cb error_callback; void *error_data; jv_parser *parser;
 const char *filename; int slurp;
};
struct spx_opaque_output_v5 { jq_util_input_state *state; jv value; int errors; };
#include "windows-files.h"
spx_input *spx_runtime_stdin(void);
void spx_input_callback_assertion(void);
jq_input_cb spx_input_callback_entry(void);
jq_util_input_state *portable_jq_util_input_init(jq_util_msg_cb, void *);
void portable_jq_util_input_set_parser(jq_util_input_state *, jv_parser *, int);
void portable_jq_util_input_free(jq_util_input_state **);
void portable_jq_util_input_add_input(jq_util_input_state *, const char *);
int portable_jq_util_input_errors(jq_util_input_state *);
jv portable_jq_util_input_next_input(jq_util_input_state *);
jv portable_jq_util_input_next_input_cb(jq_state *, void *);
jv portable_jq_util_input_get_position(jq_state*);
jv portable_jq_util_input_get_current_filename(jq_state*);
jv portable_jq_util_input_get_current_line(jq_state*);
#endif
