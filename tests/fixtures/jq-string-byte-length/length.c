#include "portable-component-implementation.h"
#include "string-view.h"

int32_t lifted_string_byte_length(spx_string_byte_length_context_v5 *boundary, spx_jv_value_v2 value) {
    const spx_string_byte_length_services_v5 *services=boundary->services;
    struct spx_opaque_string_bytes_v5 bytes;
    services->contents(services->context,value,&bytes);
    int32_t length=(int32_t)bytes.length;
    services->release(services->context,value);
    return length;
}
