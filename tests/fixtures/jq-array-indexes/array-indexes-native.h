#ifndef SPX_ARRAY_INDEXES_NATIVE_H
#define SPX_ARRAY_INDEXES_NATIVE_H
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "jv.h"
#pragma GCC diagnostic pop

static inline jv array_indexes_append(jv array, uint32_t index) {
    return jv_array_append(array, jv_number((double)index));
}
jv fixture_array_indexes(jv, jv);
/* Outcome predicates receive the transported value after the native return. */
#define array_indexes_invalid(value) (!spx_value_valid(value))
#endif
