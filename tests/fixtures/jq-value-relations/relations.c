/* Source-assisted jq 1.8.1 lifting, expressed through the shared value API.
 * See COPYING. No private array, string or object allocation layout is copied. */
#include <assert.h>
#include <string.h>
#include "value-relations.h"
#include "jv_private.h"

/* Allocation ownership is a property of the existing jv handle ABI. */
static int allocated(jv value) { return (value.kind_flags & 0x80) != 0; }

static int arrays_equal(jv first, jv second) {
    int length = jv_array_length(jv_copy(first));
    if (length != jv_array_length(jv_copy(second))) return 0;
    if (first.u.ptr == second.u.ptr && first.offset == second.offset) return 1;
    for (int i = 0; i < length; ++i)
        if (!portable_jv_equal(jv_array_get(jv_copy(first), i),
                               jv_array_get(jv_copy(second), i))) return 0;
    return 1;
}

static int objects_equal(jv first, jv second) {
    int count = 0;
    jv_object_foreach(first, key, value) {
        /* Presence and an invalid-valued slot are distinct in the native API. */
        if (!jv_object_has(jv_copy(second), jv_copy(key))) {
            jv_free(key); jv_free(value);
            return 0;
        }
        if (!portable_jv_equal(value, jv_object_get(jv_copy(second), key))) return 0;
        ++count;
    }
    return count == jv_object_length(jv_copy(second));
}

int portable_jv_equal(jv first, jv second) {
    int equal;
    jv_kind kind = jv_get_kind(first);
    if (kind != jv_get_kind(second)) equal = 0;
    else if (allocated(first) && allocated(second) &&
             first.kind_flags == second.kind_flags && first.size == second.size &&
             first.u.ptr == second.u.ptr) {
        /* Preserve the pinned implementation's fast path, including its lack
         * of an offset check for equal-length views of one backing array. */
        equal = 1;
    } else {
        switch (kind) {
        case JV_KIND_NUMBER:
            equal = jvp_number_cmp(first, second) == 0;
            break;
        case JV_KIND_ARRAY:
            equal = arrays_equal(first, second);
            break;
        case JV_KIND_OBJECT:
            equal = objects_equal(first, second);
            break;
        case JV_KIND_STRING: {
            int length = jv_string_length_bytes(jv_copy(first));
            equal = length == jv_string_length_bytes(jv_copy(second)) &&
                memcmp(jv_string_value(first), jv_string_value(second), length) == 0;
            break;
        }
        default:
            equal = 1;
        }
    }
    jv_free(first); jv_free(second);
    return equal;
}

int portable_jv_identical(jv first, jv second) {
    int identical = 0;
    if (first.kind_flags == second.kind_flags && first.offset == second.offset &&
        first.size == second.size) {
        identical = allocated(first) ? first.u.ptr == second.u.ptr :
            memcmp(&first.u, &second.u, sizeof(first.u)) == 0;
    }
    jv_free(first); jv_free(second);
    return identical;
}

static int arrays_contain(jv first, jv second) {
    jv_array_foreach(second, bi, wanted) {
        int found = 0;
        jv_array_foreach(first, ai, candidate) {
            if (portable_jv_contains(candidate, jv_copy(wanted))) {
                found = 1;
                break;
            }
        }
        jv_free(wanted);
        if (!found) return 0;
    }
    return 1;
}

static int objects_contain(jv first, jv second) {
    jv_object_foreach(second, key, value)
        if (!portable_jv_contains(jv_object_get(jv_copy(first), key), value)) return 0;
    return 1;
}

static int strings_contain(jv first, jv second) {
    int length = jv_string_length_bytes(jv_copy(first));
    int wanted = jv_string_length_bytes(jv_copy(second));
    const char *bytes = jv_string_value(first), *needle = jv_string_value(second);
    if (!wanted) return 1;
    for (int i = 0; i <= length - wanted; ++i)
        if (memcmp(bytes + i, needle, wanted) == 0) return 1;
    return 0;
}

int portable_jv_contains(jv first, jv second) {
    int contains;
    jv_kind kind = jv_get_kind(first);
    if (kind != jv_get_kind(second)) contains = 0;
    else {
        switch (kind) {
        case JV_KIND_OBJECT: contains = objects_contain(first, second); break;
        case JV_KIND_ARRAY: contains = arrays_contain(first, second); break;
        case JV_KIND_STRING: contains = strings_contain(first, second); break;
        default: contains = portable_jv_equal(jv_copy(first), jv_copy(second));
        }
    }
    jv_free(first); jv_free(second);
    return contains;
}

jv portable_jv_object_merge(jv first, jv second) {
    assert(jv_get_kind(first) == JV_KIND_OBJECT);
    jv_object_foreach(second, key, value) {
        first = jv_object_set(first, key, value);
        if (!jv_is_valid(first)) break;
    }
    jv_free(second);
    return first;
}

jv portable_jv_object_merge_recursive(jv first, jv second) {
    assert(jv_get_kind(first) == JV_KIND_OBJECT);
    assert(jv_get_kind(second) == JV_KIND_OBJECT);
    jv_object_foreach(second, key, value) {
        jv previous = jv_object_get(jv_copy(first), jv_copy(key));
        if (jv_is_valid(previous) && jv_get_kind(previous) == JV_KIND_OBJECT &&
            jv_get_kind(value) == JV_KIND_OBJECT) {
            value = portable_jv_object_merge_recursive(previous, value);
        } else {
            jv_free(previous);
        }
        first = jv_object_set(first, key, value);
        if (!jv_is_valid(first)) break;
    }
    jv_free(second);
    return first;
}
