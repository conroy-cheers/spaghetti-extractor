#include "portable-component-implementation.h"
#include "file-input.h"
#include "observations.h"
jv jv_load_file(const char *filename,int raw) {
 static unsigned slot;portable_component_entry("file-input",&slot);(void)&jv_is_valid;
 spx_file_input_context_v5 context={0};struct spx_opaque_input_v5 input={filename,raw};
 struct spx_opaque_output_v5 output;lifted_file_input_load(&context,&input,&output);return output.value;
}
