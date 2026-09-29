#include "portable-component-implementation.h"
#include "input-stream.h"
void lifted_input_stream_create(spx_input_stream_context_v5 *context,
 struct spx_opaque_input_v5 *input,struct spx_opaque_output_v5 *output) {
 (void)context;(void)output;(void)&jv_is_valid;output->state=portable_jq_util_input_init(input->error_callback,input->error_data);
}
void lifted_input_stream_parser(spx_input_stream_context_v5 *context,
 struct spx_opaque_input_v5 *input,struct spx_opaque_output_v5 *output) {
 (void)context;(void)output;(void)&jv_is_valid;portable_jq_util_input_set_parser(input->state,input->parser,input->slurp);
}
void lifted_input_stream_add(spx_input_stream_context_v5 *context,
 struct spx_opaque_input_v5 *input,struct spx_opaque_output_v5 *output) {
 (void)context;(void)output;(void)&jv_is_valid;portable_jq_util_input_add_input(input->state,input->filename);
}
void lifted_input_stream_next(spx_input_stream_context_v5 *context,
 struct spx_opaque_input_v5 *input,struct spx_opaque_output_v5 *output) {
 (void)context;(void)output;(void)&jv_is_valid;output->value=portable_jq_util_input_next_input(input->state);
}
void lifted_input_stream_destroy(spx_input_stream_context_v5 *context,
 struct spx_opaque_input_v5 *input,struct spx_opaque_output_v5 *output) {
 (void)context;(void)output;(void)&jv_is_valid;portable_jq_util_input_free(input->owner);
}
void lifted_input_stream_errors(spx_input_stream_context_v5 *context,
 struct spx_opaque_input_v5 *input,struct spx_opaque_output_v5 *output) {
 (void)context;(void)output;(void)&jv_is_valid;output->errors=portable_jq_util_input_errors(input->state);
}
void lifted_input_stream_position(spx_input_stream_context_v5 *context,
 struct spx_opaque_input_v5 *input,struct spx_opaque_output_v5 *output) {
 (void)context;(void)output;(void)&jv_is_valid;output->value=portable_jq_util_input_get_position(input->jq);
}
void lifted_input_stream_filename(spx_input_stream_context_v5 *context,
 struct spx_opaque_input_v5 *input,struct spx_opaque_output_v5 *output) {
 (void)context;(void)output;(void)&jv_is_valid;output->value=portable_jq_util_input_get_current_filename(input->jq);
}
void lifted_input_stream_line(spx_input_stream_context_v5 *context,
 struct spx_opaque_input_v5 *input,struct spx_opaque_output_v5 *output) {
 (void)context;(void)output;(void)&jv_is_valid;output->value=portable_jq_util_input_get_current_line(input->jq);
}
