#ifndef SPX_PATH_NATIVE_API_H
#define SPX_PATH_NATIVE_API_H
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "jv.h"
#pragma GCC diagnostic pop
typedef struct { jv status; int start; int end; } path_native_range;
path_native_range path_slice_bounds(jv value, jv key);
jv path_error(unsigned code);
void path_abandon(jv value);
jv path_index_error(jv value, jv key);
jv path_update_error(jv value, jv key, jv item);
jv path_dispatch_get(jv value, jv key);
jv path_dispatch_set(jv value, jv key, jv item);
jv path_dispatch_getpath(jv value, jv key);
jv fixture_value_get(jv value, jv key);
jv fixture_value_set(jv value, jv key, jv item);
jv fixture_path_get(jv value, jv key);
jv fixture_path_set(jv value, jv key, jv item);
extern int path_use_selected;
#endif
