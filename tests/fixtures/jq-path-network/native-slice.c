/* Retained jq 1.8.1 parse_slice implementation; see COPYING.jq.
 * Unlifted fixture dependency shared by get/set, not authored component code. */
#include <assert.h>
#include <limits.h>
#include <math.h>
#include "native-api.h"
static jv parse_slice(jv j, jv slice, int* pstart, int* pend) {
  // Array slices
  jv start_jv = jv_object_get(jv_copy(slice), jv_string("start"));
  jv end_jv = jv_object_get(slice, jv_string("end"));
  if (jv_get_kind(start_jv) == JV_KIND_NULL) {
    jv_free(start_jv);
    start_jv = jv_number(0);
  }
  int len;
  if (jv_get_kind(j) == JV_KIND_ARRAY) {
    len = jv_array_length(j);
  } else if (jv_get_kind(j) == JV_KIND_STRING) {
    len = jv_string_length_codepoints(j);
  } else {
    /*
     * XXX This should be dead code because callers shouldn't call this
     * function if `j' is neither an array nor a string.
     */
    jv_free(j);
    jv_free(start_jv);
    jv_free(end_jv);
    return jv_invalid_with_msg(jv_string("Only arrays and strings can be sliced"));
  }
  if (jv_get_kind(end_jv) == JV_KIND_NULL) {
    jv_free(end_jv);
    end_jv = jv_number(len);
  }
  if (jv_get_kind(start_jv) != JV_KIND_NUMBER ||
      jv_get_kind(end_jv) != JV_KIND_NUMBER) {
    jv_free(start_jv);
    jv_free(end_jv);
    return jv_invalid_with_msg(jv_string("Array/string slice indices must be integers"));
  }

  double dstart = jv_number_value(start_jv);
  double dend = jv_number_value(end_jv);
  int start, end;

  jv_free(start_jv);
  jv_free(end_jv);
  if (isnan(dstart)) dstart = 0;
  if (dstart < 0)    dstart += len;
  if (dstart < 0)    dstart = 0;
  if (dstart > len)  dstart = len;
  start = dstart > INT_MAX ? INT_MAX : (int)dstart; // Rounds down

  if (isnan(dend))   dend = len;
  if (dend < 0)      dend += len;
  if (dend < 0)      dend  = start;
  end = dend > INT_MAX ? INT_MAX : (int)dend;
  if (end > len)     end = len;
  if (end < len)     end += end < dend ? 1 : 0; // We round start down
                                                // but round end up

  if (end < start) end = start;
  assert(0 <= start && start <= end && end <= len);
  *pstart = start;
  *pend = end;
  return jv_true();
}

path_native_range path_slice_bounds(jv value, jv key) {
  path_native_range range = {jv_invalid(), 0, 0};
  range.status = parse_slice(value, key, &range.start, &range.end);
  return range;
}
