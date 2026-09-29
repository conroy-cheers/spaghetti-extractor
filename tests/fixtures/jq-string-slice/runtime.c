#include <stdio.h>
#include <stdlib.h>
#include "string-native.h"
#include "string-storage.h"
#include "pe32-entry-hook.h"

unsigned string_slice_calls;
static spx_fixture_entry_hook slice_hook;
void string_contents(jv value, struct spx_opaque_string_bytes_v5 *bytes) {
    if (jv_get_kind(value) != JV_KIND_STRING) { fputs("string boundary: expected live string\n",stderr); exit(84); }
    spx_jq_string_contents(value,bytes);
}
jv string_create(jv value, uint32_t start, uint32_t length) {
    struct spx_opaque_string_bytes_v5 bytes;
    string_contents(value,&bytes);
    if (start > bytes.length || length > bytes.length-start) {
        fputs("string boundary: constructor range outside borrowed contents\n",stderr); exit(84);
    }
    return jv_string_sized((const char *)bytes.data+start,(int)length);
}
jv string_empty(void) { return jv_string_empty(16); }
jv string_invalid(void) { return jv_invalid_with_msg(jv_string("Invalid UTF-8 string")); }
static jv counted_slice(jv value, int start, int end) {
    ++string_slice_calls;
    return fixture_string_slice(value,start,end);
}
void string_slice_install(void) {
    static const unsigned char prefix[5]={0x55,0x57,0x56,0x53,0x81};
    if (slice_hook.entry || !spx_fixture_redirect_body(&slice_hook,"libjq-1.dll","jv_string_slice",
        prefix,0x33b,(void(*)(void))counted_slice)) {
        fputs("string boundary: pinned complete body interception failed\n",stderr); exit(85);
    }
    for (size_t i=5;i<slice_hook.length;++i) if (slice_hook.entry[i]!=0xcc) exit(85);
}
void string_slice_report(void) { fprintf(stderr,"authored-string-slice-calls=%u\n",string_slice_calls); }
