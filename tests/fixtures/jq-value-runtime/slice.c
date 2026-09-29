/* Slice range conversion, source-assisted from jq 1.8.1; see COPYING. */
#include <limits.h>
#include <math.h>
#include "value-runtime-inputs.h"

jv portable_parse_slice(jv value, jv slice, int *first, int *last) {
    (void)&jv_is_valid;
    jv lower = jv_object_get(jv_copy(slice), jv_string("start"));
    jv upper = jv_object_get(slice, jv_string("end"));
    if (jv_get_kind(lower) == JV_KIND_NULL) {
        jv_free(lower);
        lower = jv_number(0);
    }
    int length;
    switch (jv_get_kind(value)) {
    case JV_KIND_ARRAY: length = jv_array_length(value); break;
    case JV_KIND_STRING: length = jv_string_length_codepoints(value); break;
    default:
        jv_free(value);
        jv_free(lower);
        jv_free(upper);
        return jv_invalid_with_msg(jv_string("Only arrays and strings can be sliced"));
    }
    if (jv_get_kind(upper) == JV_KIND_NULL) {
        jv_free(upper);
        upper = jv_number(length);
    }
    if (jv_get_kind(lower) != JV_KIND_NUMBER || jv_get_kind(upper) != JV_KIND_NUMBER) {
        jv_free(lower);
        jv_free(upper);
        return jv_invalid_with_msg(jv_string("Array/string slice indices must be integers"));
    }
    double start = jv_number_value(lower), end = jv_number_value(upper);
    jv_free(lower);
    jv_free(upper);
    if (isnan(start)) start = 0;
    if (start < 0) start += length;
    if (start < 0) start = 0;
    if (start > length) start = length;
    int begin = start > INT_MAX ? INT_MAX : (int)start;

    if (isnan(end)) end = length;
    if (end < 0) end += length;
    if (end < 0) end = begin;
    int finish = end > INT_MAX ? INT_MAX : (int)end;
    if (finish > length) finish = length;
    if (finish < length && finish < end) ++finish;
    if (finish < begin) finish = begin;
    /* Commit only after validation. The two output pointers may alias. */
    *first = begin;
    *last = finish;
    return jv_true();
}
