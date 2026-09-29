#ifndef SPX_JQ_NUMBER_INPUTS_H
#define SPX_JQ_NUMBER_INPUTS_H
#include "jv.h"
struct spx_opaque_number_input_v5 { jv first, second; double number; const char *text; };
struct spx_opaque_number_output_v5 { jv value; double number; const char *text; int integer; };
jv portable_jv_number(double number);
jv portable_jv_number_with_literal(const char *text);
int portable_jv_number_has_literal(jv first);
const char * portable_jv_number_get_literal(jv first);
double portable_jv_number_value(jv first);
int portable_jv_is_integer(jv first);
int portable_jvp_number_is_nan(jv first);
jv portable_jv_number_abs(jv first);
jv portable_jv_number_negate(jv first);
int portable_jvp_number_cmp(jv first, jv second);
void portable_jvp_number_free(jv first);
#endif
