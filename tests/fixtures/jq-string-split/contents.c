/* A borrowed view of the original allocation, using retained lower services.
 * This is shared adapter work, not the neighboring slice operation's body. */
#include <stdlib.h>
#include "string-native.h"
void string_contents(jv value, struct spx_opaque_string_bytes_v5 *bytes) {
    if (jv_get_kind(value) != JV_KIND_STRING) abort();
    bytes->data = (const unsigned char *)jv_string_value(value);
    bytes->length = (uint32_t)jv_string_length_bytes(jv_copy(value));
}
