#ifndef SPX_JQ_SPLIT_NATIVE_H
#define SPX_JQ_SPLIT_NATIVE_H
#include <stdlib.h>
#include "string-native.h"

/* Constructors used by the original. These contain no splitting/search logic.
 * In particular, empty construction is jv_string("") rather than the slice
 * boundary's different preallocated-empty service. */
static jv split_empty(void) { return jv_string(""); }
static jv split_codepoint(uint32_t codepoint) {
    return jv_string_append_codepoint(jv_string(""), codepoint);
}
static jv split_create(jv value, uint32_t start, uint32_t length) {
    struct spx_opaque_string_bytes_v5 bytes;
    string_contents(value, &bytes);
    if (start > bytes.length || length > bytes.length - start) abort();
    return jv_string_sized((const char *)bytes.data + start, (int)length);
}
#endif
