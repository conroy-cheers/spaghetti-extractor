#include <stdlib.h>
#include "portable-component-implementation.h"
#include "input-stream.h"
#include "observations.h"
jq_util_input_state * jq_util_input_init(jq_util_msg_cb cb,void *data) {
 static unsigned slot;portable_component_entry("input-stream",&slot);
 spx_input_stream_context_v5 context={0};(void)&jv_is_valid; struct spx_opaque_input_v5 input={.error_callback=cb,.error_data=data};
 struct spx_opaque_output_v5 output;lifted_input_stream_create(&context,&input,&output);return output.state;
}
void jq_util_input_set_parser(jq_util_input_state *state,jv_parser *parser,int slurp) {
 static unsigned slot;portable_component_entry("input-stream",&slot);
 spx_input_stream_context_v5 context={0};(void)&jv_is_valid; struct spx_opaque_input_v5 input={.state=state,.parser=parser,.slurp=slurp};
 struct spx_opaque_output_v5 output;lifted_input_stream_parser(&context,&input,&output);
}
void jq_util_input_free(jq_util_input_state **owner) {
 static unsigned slot;portable_component_entry("input-stream",&slot);
 spx_input_stream_context_v5 context={0};(void)&jv_is_valid; struct spx_opaque_input_v5 input={.owner=owner};
 struct spx_opaque_output_v5 output;lifted_input_stream_destroy(&context,&input,&output);
}
void jq_util_input_add_input(jq_util_input_state *state,const char *filename) {
 static unsigned slot;portable_component_entry("input-stream",&slot);
 spx_input_stream_context_v5 context={0};(void)&jv_is_valid; struct spx_opaque_input_v5 input={.state=state,.filename=filename};
 struct spx_opaque_output_v5 output;lifted_input_stream_add(&context,&input,&output);
}
int jq_util_input_errors(jq_util_input_state *state) {
 static unsigned slot;portable_component_entry("input-stream",&slot);
 spx_input_stream_context_v5 context={0};(void)&jv_is_valid; struct spx_opaque_input_v5 input={.state=state};
 struct spx_opaque_output_v5 output;lifted_input_stream_errors(&context,&input,&output);return output.errors;
}
jv jq_util_input_get_position(jq_state *jq) {
 static unsigned slot;portable_component_entry("input-stream",&slot);
 spx_input_stream_context_v5 context={0};(void)&jv_is_valid; struct spx_opaque_input_v5 input={.jq=jq};
 struct spx_opaque_output_v5 output;lifted_input_stream_position(&context,&input,&output);return output.value;
}
jv jq_util_input_get_current_filename(jq_state *jq) {
 static unsigned slot;portable_component_entry("input-stream",&slot);
 spx_input_stream_context_v5 context={0};(void)&jv_is_valid; struct spx_opaque_input_v5 input={.jq=jq};
 struct spx_opaque_output_v5 output;lifted_input_stream_filename(&context,&input,&output);return output.value;
}
jv jq_util_input_get_current_line(jq_state *jq) {
 static unsigned slot;portable_component_entry("input-stream",&slot);
 spx_input_stream_context_v5 context={0};(void)&jv_is_valid; struct spx_opaque_input_v5 input={.jq=jq};
 struct spx_opaque_output_v5 output;lifted_input_stream_line(&context,&input,&output);return output.value;
}
jv jq_util_input_next_input(jq_util_input_state *state) {
 static unsigned slot;portable_component_entry("input-stream",&slot);
 spx_input_stream_context_v5 context={0};(void)&jv_is_valid; struct spx_opaque_input_v5 input={.state=state};
 struct spx_opaque_output_v5 output;lifted_input_stream_next(&context,&input,&output);return output.value;
}
jv jq_util_input_next_input_cb(jq_state *jq,void *data) {
 static unsigned slot;portable_component_entry("input-stream",&slot);
 spx_input_stream_context_v5 context={0};(void)&jv_is_valid; struct spx_opaque_input_v5 input={.state=data};
 struct spx_opaque_output_v5 output;lifted_input_stream_next(&context,&input,&output);(void)jq;return output.value;
}

/* One CLI-selected stdin policy, configured before reading. Named files keep
 * their explicit text mode. This is runtime configuration, not lifted state. */
static int stdin_text_mode = 1;
void spx_stdin_set_binary(int enabled) { stdin_text_mode = !enabled; }
static spx_input *standard_input;
static void detach_stdin(void) {
 if(standard_input)(void)spx_input_detach(standard_input);
}
spx_input *spx_runtime_stdin(void) {
 if(!standard_input) {
  standard_input=spx_input_attach(stdin,stdin_text_mode,0);
  if(standard_input)atexit(detach_stdin);
 }
 return standard_input;
}
jq_input_cb spx_input_callback_entry(void) { return jq_util_input_next_input_cb; }
