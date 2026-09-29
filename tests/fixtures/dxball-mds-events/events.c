#include "portable-component-implementation.h"
#include "mds-events-state.h"
#include <string.h>

static uint32_t read_word(const unsigned char *p) {
    return p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}

static void write_word(unsigned char *p,uint32_t value) {
    for (unsigned i=0;i<4;++i) p[i]=(unsigned char)(value>>(8*i));
}

uint32_t lifted_mds_expand(spx_mds_events_context_v5 *context,
                          mds_event_block *input,mds_event_block *output) {
    (void)context;
    uint32_t remaining=input->used, available=output->capacity;
    const unsigned char *source=input->data;
    unsigned char *destination=output->data;
    if (remaining&3) return 0;
    while (remaining) {
        if (available<12) return 0;
        write_word(destination,read_word(source));
        destination+=4; source+=4; remaining-=4;
        if (!remaining) return 0;
        write_word(destination,0);
        destination+=4;
        uint32_t event=read_word(source);
        write_word(destination,event);
        destination+=4; source+=4; remaining-=4; available-=12;
        uint32_t payload=(event&UINT32_C(0x80000000)) ? event&UINT32_C(0x00ffffff) : 0;
        payload=(payload+3)&~UINT32_C(3);
        if (payload>remaining || payload>available) return 0;
        if (payload) memcpy(destination,source,payload);
        destination+=payload; source+=payload;
        remaining-=payload; available-=payload;
    }
    output->used=output->capacity-available;
    return 1;
}
