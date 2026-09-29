#include "portable-component-implementation.h"
#include "input-stream.h"
jq_util_input_state * spx_entry_init(jq_util_msg_cb cb,void *data) {
 spx_input_stream_context_v5 context={0};(void)&jv_is_valid; struct spx_opaque_input_v5 input={.error_callback=cb,.error_data=data};
 struct spx_opaque_output_v5 output;lifted_input_stream_create(&context,&input,&output);return output.state;
}
void spx_entry_set_parser(jq_util_input_state *state,jv_parser *parser,int slurp) {
 spx_input_stream_context_v5 context={0};(void)&jv_is_valid; struct spx_opaque_input_v5 input={.state=state,.parser=parser,.slurp=slurp};
 struct spx_opaque_output_v5 output;lifted_input_stream_parser(&context,&input,&output);
}
void spx_entry_free(jq_util_input_state **owner) {
 spx_input_stream_context_v5 context={0};(void)&jv_is_valid; struct spx_opaque_input_v5 input={.owner=owner};
 struct spx_opaque_output_v5 output;lifted_input_stream_destroy(&context,&input,&output);
}
void spx_entry_add_input(jq_util_input_state *state,const char *filename) {
 spx_input_stream_context_v5 context={0};(void)&jv_is_valid; struct spx_opaque_input_v5 input={.state=state,.filename=filename};
 struct spx_opaque_output_v5 output;lifted_input_stream_add(&context,&input,&output);
}
int spx_entry_errors(jq_util_input_state *state) {
 spx_input_stream_context_v5 context={0};(void)&jv_is_valid; struct spx_opaque_input_v5 input={.state=state};
 struct spx_opaque_output_v5 output;lifted_input_stream_errors(&context,&input,&output);return output.errors;
}
jv spx_entry_get_position(jq_state *jq) {
 spx_input_stream_context_v5 context={0};(void)&jv_is_valid; struct spx_opaque_input_v5 input={.jq=jq};
 struct spx_opaque_output_v5 output;lifted_input_stream_position(&context,&input,&output);return output.value;
}
jv spx_entry_get_current_filename(jq_state *jq) {
 spx_input_stream_context_v5 context={0};(void)&jv_is_valid; struct spx_opaque_input_v5 input={.jq=jq};
 struct spx_opaque_output_v5 output;lifted_input_stream_filename(&context,&input,&output);return output.value;
}
jv spx_entry_get_current_line(jq_state *jq) {
 spx_input_stream_context_v5 context={0};(void)&jv_is_valid; struct spx_opaque_input_v5 input={.jq=jq};
 struct spx_opaque_output_v5 output;lifted_input_stream_line(&context,&input,&output);return output.value;
}
jv spx_entry_next_input(jq_util_input_state *state) {
 spx_input_stream_context_v5 context={0};(void)&jv_is_valid; struct spx_opaque_input_v5 input={.state=state};
 struct spx_opaque_output_v5 output;lifted_input_stream_next(&context,&input,&output);return output.value;
}
jv spx_entry_next_input_cb(jq_state *jq,void *data) {
 spx_input_stream_context_v5 context={0};(void)&jv_is_valid; struct spx_opaque_input_v5 input={.state=data};
 struct spx_opaque_output_v5 output;lifted_input_stream_next(&context,&input,&output);(void)jq;return output.value;
}
