#include "portable-component-implementation.h"
#include "string-view.h"

int32_t lifted_string_length(spx_string_length_context_v5 *boundary, spx_jv_value_v2 value) {
    const spx_string_length_services_v5 *services=boundary->services;
    struct spx_opaque_string_bytes_v5 bytes;
    services->contents(services->context,value,&bytes);
    uint32_t offset=0,count=0;
    while (offset<bytes.length) {
        uint32_t first=bytes.data[offset],width=1;
        if (first>=0xc2U && first<=0xdfU) width=2;
        else if (first>=0xe0U && first<=0xefU) width=3;
        else if (first>=0xf0U && first<=0xf4U) width=4;
        /* The original counts decoder advances, including malformed groups.
         * A truncated group consumes the remaining bytes before inspecting
         * continuation bytes; a complete group stops at its first noncontinuation. */
        uint32_t step=width;
        if (width>bytes.length-offset) step=bytes.length-offset;
        else for (uint32_t i=1;i<width;++i) {
            if ((bytes.data[offset+i]&0xc0U)!=0x80U) { step=i;break; }
        }
        offset+=step;
        ++count;
    }
    services->release(services->context,value);
    return (int32_t)count;
}
