#ifndef SPX_JQ_INDEXES_NATIVE_H
#define SPX_JQ_INDEXES_NATIVE_H
#include "string-native.h"
/* The original loop uses these two public lower operations in this order.
 * This adapter owns no state and contains none of the search algorithm. */
static jv indexes_append(jv array, uint32_t index) {
    return jv_array_append(array, jv_number((double)index));
}
#endif
