#include "input-stream.h"
jq_util_input_state * spx_entry_init(jq_util_msg_cb cb,void *data);
void spx_entry_set_parser(jq_util_input_state *state,jv_parser *parser,int slurp);
void spx_entry_free(jq_util_input_state **owner);
void spx_entry_add_input(jq_util_input_state *state,const char *filename);
int spx_entry_errors(jq_util_input_state *state);
jv spx_entry_get_position(jq_state *jq);
jv spx_entry_get_current_filename(jq_state *jq);
jv spx_entry_get_current_line(jq_state *jq);
jv spx_entry_next_input(jq_util_input_state *state);
jv spx_entry_next_input_cb(jq_state *jq,void *data);
