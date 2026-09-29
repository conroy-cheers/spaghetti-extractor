#include "portable-component-implementation.h"
#include "string-view.h"

static uint32_t character_width(unsigned char first) {
    if ((first & 0x80U) == 0) return 1;
    if ((first & 0xe0U) == 0xc0U) return 2;
    if ((first & 0xf0U) == 0xe0U) return 3;
    return 4;
}

spx_jv_value_v2 lifted_string_indexes(spx_string_indexes_context_v5 *boundary,
                                      spx_jv_value_v2 value, spx_jv_value_v2 needle) {
    const spx_string_indexes_services_v5 *services = boundary->services;
    struct spx_opaque_string_bytes_v5 text, pattern;
    services->contents(services->context, value, &text);
    services->contents(services->context, needle, &pattern);
    spx_jv_value_v2 result = services->array(services->context);
    uint32_t cursor = 0, character = 0;
    if (pattern.length != 0 && pattern.length <= text.length) {
        for (uint32_t start = 0; start <= text.length - pattern.length; ++start) {
            uint32_t matched = 0;
            while (matched < pattern.length && text.data[start + matched] == pattern.data[matched])
                ++matched;
            if (matched != pattern.length) continue;
            /* Advance as the machine's lead-byte helper does, including raw
             * malformed bytes. Integer offsets avoid out-of-object pointers. */
            while (cursor < start) {
                cursor += character_width(text.data[cursor]);
                ++character;
            }
            result = services->append_index(services->context, result, character);
            if (!services->valid(services->context, result)) break;
        }
    }
    services->release(services->context, value);
    services->release(services->context, needle);
    return result;
}
