/* The resolved selection controls native/source dispatch. Leaf inclusion is
 * derived transitively; this file does not repeat the dependency graph. */
#include "native-api.h"
#include "comparison-selection.h"
int path_use_selected;
jv path_dispatch_get(jv value,jv key) {
#ifdef SPX_SELECTED_VALUE_GET
  if(path_use_selected) return fixture_value_get(value,key);
#endif
  return jv_get(value,key);
}
jv path_dispatch_set(jv value,jv key,jv item) {
#ifdef SPX_SELECTED_VALUE_SET
  if(path_use_selected) return fixture_value_set(value,key,item);
#endif
  return jv_set(value,key,item);
}
jv path_dispatch_getpath(jv value,jv key) {
#ifdef SPX_SELECTED_PATH_GET
  if(path_use_selected) return fixture_path_get(value,key);
#endif
  return jv_getpath(value,key);
}
