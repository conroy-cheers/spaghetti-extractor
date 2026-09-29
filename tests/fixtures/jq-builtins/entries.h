#ifndef SPX_BUILTIN_ENTRIES_H
#define SPX_BUILTIN_ENTRIES_H
#include "builtin-api.h"
jv spx_entry_binop_plus(jv left, jv right);
jv spx_entry_binop_minus(jv left, jv right);
jv spx_entry_binop_multiply(jv left, jv right);
jv spx_entry_binop_divide(jv left, jv right);
jv spx_entry_binop_mod(jv left, jv right);
jv spx_entry_binop_equal(jv left, jv right);
jv spx_entry_binop_notequal(jv left, jv right);
jv spx_entry_binop_less(jv left, jv right);
jv spx_entry_binop_lesseq(jv left, jv right);
jv spx_entry_binop_greater(jv left, jv right);
jv spx_entry_binop_greatereq(jv left, jv right);
int spx_entry_builtins_bind(jq_state * state, block * program);
#endif
