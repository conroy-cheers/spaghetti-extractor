/* Target-specific record conversion. Shared code generates the
 * service wrappers, outcome partition checks and observation scaffolding. */
#ifndef SPX_PATH_NATIVE_SERVICES_H
#define SPX_PATH_NATIVE_SERVICES_H
#include <limits.h>
static inline int path_value_invalid(spx_jv_value_v2 value) { return !spx_value_valid(value); }
static inline int path_range_valid(spx_slice_range_v2 value) { return spx_value_valid(value.status); }
static inline int path_range_invalid(spx_slice_range_v2 value) { return !spx_value_valid(value.status); }
static inline spx_slice_range_v2 path_portable_slice_bounds(spx_jv_value_v2 value,spx_jv_value_v2 key) {
  path_native_range r=path_slice_bounds(spx_value_take(value),spx_value_take(key));
  return (spx_slice_range_v2){spx_value_pack(r.status),r.start,r.end};
}
#endif
