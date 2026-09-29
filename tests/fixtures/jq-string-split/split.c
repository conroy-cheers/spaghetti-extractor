#include "portable-component-implementation.h"
#include "string-view.h"

/* The empty-separator branch admits well-formed UTF-8. Decode one character
 * locally; construction and allocation remain explicit boundary services. */
static uint32_t next_character(const unsigned char *text, uint32_t *position) {
    unsigned char first = text[(*position)++];
    uint32_t value;
    unsigned remaining;
    if (first < 0x80U) return first;
    if (first < 0xe0U) { value = first & 0x1fU; remaining = 1; }
    else if (first < 0xf0U) { value = first & 0x0fU; remaining = 2; }
    else { value = first & 0x07U; remaining = 3; }
    while (remaining--) value = (value << 6) | (text[(*position)++] & 0x3fU);
    return value;
}

spx_jv_value_v2 lifted_string_split(spx_string_split_context_v5 *boundary,
                                   spx_jv_value_v2 value, spx_jv_value_v2 separator) {
    const spx_string_split_services_v5 *services = boundary->services;
    struct spx_opaque_string_bytes_v5 text, pattern;
    services->contents(services->context, value, &text);
    services->contents(services->context, separator, &pattern);
    spx_jv_value_v2 result = services->array(services->context);
    uint32_t start = 0;
    if (pattern.length == 0) {
        while (start < text.length) {
            uint32_t character = next_character(text.data, &start);
            spx_jv_value_v2 item = services->codepoint(services->context, character);
            result = services->append(services->context, result, item);
            if (!services->valid(services->context, result)) break;
        }
    } else {
        while (start < text.length) {
            uint32_t end = start;
            while (end < text.length) {
                if (pattern.length > text.length - end) { end = text.length; break; }
                uint32_t matched = 0;
                while (matched < pattern.length && text.data[end + matched] == pattern.data[matched]) ++matched;
                if (matched == pattern.length) break;
                ++end;
            }
            spx_jv_value_v2 item = services->create(services->context, value, start, end - start);
            result = services->append(services->context, result, item);
            if (!services->valid(services->context, result)) break;
            if (end == text.length) break;
            start = end + pattern.length;
            if (start == text.length) {
                item = services->empty(services->context);
                result = services->append(services->context, result, item);
            }
        }
    }
    services->release(services->context, value);
    services->release(services->context, separator);
    return result;
}
