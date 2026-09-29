#ifndef SPX_JQ_NUMBER_ENTRIES_H
#define SPX_JQ_NUMBER_ENTRIES_H
#include "jv.h"
jv spx_entry_jv_number(double number);
jv jv_number(double number);
jv spx_entry_jv_number_with_literal(const char *text);
jv jv_number_with_literal(const char *text);
int spx_entry_jv_number_has_literal(jv first);
int jv_number_has_literal(jv first);
const char * spx_entry_jv_number_get_literal(jv first);
const char * jv_number_get_literal(jv first);
double spx_entry_jv_number_value(jv first);
double jv_number_value(jv first);
int spx_entry_jv_is_integer(jv first);
int jv_is_integer(jv first);
int spx_entry_jvp_number_is_nan(jv first);
int jvp_number_is_nan(jv first);
jv spx_entry_jv_number_abs(jv first);
jv jv_number_abs(jv first);
jv spx_entry_jv_number_negate(jv first);
jv jv_number_negate(jv first);
int spx_entry_jvp_number_cmp(jv first, jv second);
int jvp_number_cmp(jv first, jv second);
void spx_entry_jvp_number_free(jv first);
void jvp_number_free(jv first);
#endif
