#include <limits.h>
#include "portable-component-implementation.h"

/* The original adds 32-bit indices. Spell its signed interpretation without
 * relying on signed overflow or an out-of-range unsigned-to-signed C cast. */
static int32_t machine_index(uint32_t bits) {
    return bits <= INT32_MAX ? (int32_t)bits : -1 - (int32_t)(UINT32_MAX - bits);
}

spx_jv_value_v2 lifted_array_indexes(spx_array_indexes_context_v5 *boundary,
                                    spx_jv_value_v2 value, spx_jv_value_v2 needle) {
    const spx_array_indexes_services_v5 *s = boundary->services;
    void *e = s->context;
    spx_jv_value_v2 result = s->array(e);
    uint32_t length = s->length(e, s->copy(e, value));
    for (uint32_t start = 0; start < length; ++start) {
        int32_t match = -1;
        uint32_t count = s->length(e, s->copy(e, needle));
        for (uint32_t offset = 0; offset < count; ++offset) {
            spx_jv_value_v2 expected = s->array_get(e, s->copy(e, needle), (int32_t)offset);
            spx_jv_value_v2 actual = s->array_get(e, s->copy(e, value), machine_index(start + offset));
            /* Preserve the original's comparisons after a mismatch too. */
            if (!s->equal(e, actual, expected)) match = -1;
            else if (offset == 0 && match == -1) match = (int32_t)start;
        }
        if (match >= 0) result = s->append_index(e, result, (uint32_t)match);
    }
    s->release(e, value);
    s->release(e, needle);
    return result;
}
