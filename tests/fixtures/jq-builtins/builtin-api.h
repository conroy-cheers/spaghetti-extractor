#ifndef SPX_BUILTIN_API_H
#define SPX_BUILTIN_API_H
#include "compile.h"
jv portable_binop_plus(jv left, jv right);
jv portable_binop_minus(jv left, jv right);
jv portable_binop_multiply(jv left, jv right);
jv portable_binop_divide(jv left, jv right);
jv portable_binop_mod(jv left, jv right);
jv portable_binop_equal(jv left, jv right);
jv portable_binop_notequal(jv left, jv right);
jv portable_binop_less(jv left, jv right);
jv portable_binop_lesseq(jv left, jv right);
jv portable_binop_greater(jv left, jv right);
jv portable_binop_greatereq(jv left, jv right);
int portable_builtins_bind(jq_state * state, block * program);
#endif
