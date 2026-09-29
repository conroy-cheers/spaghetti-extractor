#ifndef SPX_BUILTIN_INPUTS_H
#define SPX_BUILTIN_INPUTS_H
#include "builtin-api.h"
struct spx_opaque_builtin_input_v5 { jv left, right; jq_state *state; block *program; };
struct spx_opaque_builtin_output_v5 { jv value; int errors; };
#endif
