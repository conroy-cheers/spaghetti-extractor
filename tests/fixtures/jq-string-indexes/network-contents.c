/* Isolate the reviewed network's borrowed-contents service from its slice-entry
 * installation code. The byte-length operation remains an original lower service.
 * This adapter neither installs nor calls the search operation being replaced. */
#include <stdio.h>
#include <stdlib.h>
#include "string-native.h"

void string_contents(jv value, struct spx_opaque_string_bytes_v5 *bytes) {
    if (jv_get_kind(value) != JV_KIND_STRING) {
        fputs("string boundary: expected live string\n", stderr);
        exit(84);
    }
    bytes->data = (const unsigned char *)jv_string_value(value);
    bytes->length = (uint32_t)jv_string_length_bytes(jv_copy(value));
}
