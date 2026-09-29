#ifndef SPX_PATH_NUMERIC_INDEX_H
#define SPX_PATH_NUMERIC_INDEX_H
#include <stdint.h>

/* Original jq index behavior, expressed without an out-of-range C cast.
 * NaN is an explicit outcome; infinities and finite extremes saturate. */
static inline spx_numeric_index_v2 path_numeric_index(double number) {
  spx_numeric_index_v2 result = {0, number != number};
  if (!result.is_nan) {
    if (number < INT32_MIN) number = INT32_MIN;
    if (number > INT32_MAX) number = INT32_MAX;
    result.index = (int32_t)number;
  }
  return result;
}
#endif
