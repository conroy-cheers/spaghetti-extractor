#include "portable-component-implementation.h"
#include "string-view.h"

/* Return the next byte boundary, rejecting malformed Unicode encodings. */
static int advance(const struct spx_opaque_string_bytes_v5 *bytes, uint32_t *offset) {
    uint32_t at = *offset, first = bytes->data[at], count, codepoint, minimum;
    if (first < 0x80U) { *offset = at + 1; return 1; }
    if (first >= 0xc2U && first <= 0xdfU) { count = 2; codepoint = first & 31U; minimum = 0x80U; }
    else if (first >= 0xe0U && first <= 0xefU) { count = 3; codepoint = first & 15U; minimum = 0x800U; }
    else if (first >= 0xf0U && first <= 0xf4U) { count = 4; codepoint = first & 7U; minimum = 0x10000U; }
    else return 0;
    if (count > bytes->length - at) return 0;
    for (uint32_t i = 1; i < count; ++i) {
        uint32_t byte = bytes->data[at + i];
        if ((byte & 0xc0U) != 0x80U) return 0;
        codepoint = (codepoint << 6) | (byte & 63U);
    }
    if (codepoint < minimum || codepoint > 0x10ffffU ||
        (codepoint >= 0xd800U && codepoint <= 0xdfffU)) return 0;
    *offset = at + count;
    return 1;
}

spx_jv_value_v2 lifted_string_slice(spx_string_slice_context_v5 *boundary,
                                  spx_jv_value_v2 value, int32_t start, int32_t end) {
    const spx_string_slice_services_v5 *services = boundary->services;
    void *context = services->context;
    struct spx_opaque_string_bytes_v5 bytes;
    services->contents(context, value, &bytes);
    /* The native operation normalizes against bytes, then walks codepoints.
     * Higher jq callers perform their own codepoint-based normalization first. */
    int64_t first = start < 0 ? (int64_t)bytes.length + start : start;
    int64_t last = end < 0 ? (int64_t)bytes.length + end : end;
    if (first < 0) first = 0;
    if (first > bytes.length) first = bytes.length;
    if (last > bytes.length) last = bytes.length;
    if (last < first) last = first;
    uint32_t begin = 0, index = 0;
    while (index < (uint32_t)first) {
        if (begin == bytes.length) {
            services->release(context, value);
            return services->empty(context);
        }
        if (!advance(&bytes, &begin)) goto invalid;
        ++index;
    }
    uint32_t finish = begin;
    while (index < (uint32_t)last && finish < bytes.length) {
        if (!advance(&bytes, &finish)) goto invalid;
        ++index;
    }
    spx_jv_value_v2 result = services->create(context, value, begin, finish - begin);
    services->release(context, value);
    return result;
invalid:
    services->release(context, value);
    return services->invalid(context);
}
