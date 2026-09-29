#ifndef SPX_JQ_VALUE_ALGORITHMS_H
#define SPX_JQ_VALUE_ALGORITHMS_H
#include "jv.h"
struct spx_opaque_input_v5 { jv first, second; };
struct spx_opaque_output_v5 { jv value; int comparison; };
jv portable_jv_has(jv first, jv second);
jv portable_jv_delpaths(jv first, jv second);
jv portable_jv_keys(jv first);
jv portable_jv_keys_unsorted(jv first);
int portable_jv_cmp(jv first, jv second);
jv portable_jv_sort(jv first, jv second);
jv portable_jv_group(jv first, jv second);
jv portable_jv_unique(jv first, jv second);
#endif
