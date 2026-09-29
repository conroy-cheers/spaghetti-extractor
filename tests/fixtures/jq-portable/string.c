#include <stdio.h>
#include <stdlib.h>
#include "string-native.h"
#include "string-storage.h"

void string_contents(jv value, struct spx_opaque_string_bytes_v5 *bytes) {
    if (jv_get_kind(value)!=JV_KIND_STRING) {
        fputs("string boundary: expected live string\n",stderr); exit(84);
    }
    spx_jq_string_contents(value,bytes);
}
jv string_create(jv value, uint32_t start, uint32_t length) {
    struct spx_opaque_string_bytes_v5 bytes;
    string_contents(value,&bytes);
    if (start>bytes.length || length>bytes.length-start) {
        fputs("string boundary: constructor range outside borrowed contents\n",stderr); exit(84);
    }
    return jv_string_sized((const char *)bytes.data+start,(int)length);
}
jv string_empty(void) { return jv_string_empty(16); }
jv string_invalid(void) { return jv_invalid_with_msg(jv_string("Invalid UTF-8 string")); }
