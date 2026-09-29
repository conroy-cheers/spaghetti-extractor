#ifndef SPX_JQ_VALUE_RELATIONS_H
#define SPX_JQ_VALUE_RELATIONS_H
#include "jv.h"
struct spx_opaque_input_v5 { jv first, second; };
struct spx_opaque_output_v5 { jv value; int comparison; };
int portable_jv_equal(jv first, jv second);
int portable_jv_identical(jv first, jv second);
int portable_jv_contains(jv first, jv second);
jv portable_jv_object_merge(jv first, jv second);
jv portable_jv_object_merge_recursive(jv first, jv second);
#endif
