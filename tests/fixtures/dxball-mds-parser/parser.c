#include "portable-component-implementation.h"
#include "mds-state.h"
#include <string.h>

static uint32_t word(const unsigned char *p) {
    return p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}

uint32_t lifted_mds_parse(spx_mds_parser_context_v5 *context,mds_info *info,
                         mds_file *file,uint32_t length) {
    const spx_mds_parser_services_v5 *services=context->services;
    void *user=services->context;
    const unsigned char *cursor=file->data;
    uint32_t result=3,remaining=length;
    info->buffers=NULL;
    if (remaining<12 || word(cursor)!=UINT32_C(0x46464952) ||
        word(cursor+8)!=UINT32_C(0x5344494d) || remaining-8<word(cursor+4)) goto done;
    cursor+=12; remaining-=12;
    if (remaining<8 || word(cursor)!=UINT32_C(0x20746d66)) goto done;
    uint32_t format_size=word(cursor+4);
    if (format_size>remaining || format_size<12) goto done;
    cursor+=8;
    info->division=word(cursor); info->capacity=word(cursor+4); info->format=word(cursor+8);
    cursor+=format_size; remaining-=format_size+8;
    if (remaining<8 || word(cursor)!=UINT32_C(0x61746164)) goto done;
    uint32_t data_size=word(cursor+4);
    if (data_size>remaining || data_size<4) goto done;
    info->count=word(cursor+8); cursor+=12; remaining-=12;
    mds_memory *allocation=services->allocate(user,0x2002,info->count*(info->capacity+64));
    info->buffers=services->lock(user,info,allocation);
    if (!info->buffers) { result=1; goto done; }
    for (uint32_t i=0;i<info->count;++i) {
        mds_buffer *buffer=&info->buffers->headers[i];
        buffer->event.data=buffer->payload; buffer->event.capacity=info->capacity;
        buffer->flags=0; buffer->owner=info; buffer->next=NULL;
        if (remaining<8) goto done;
        uint32_t bytes=word(cursor+4); cursor+=8; remaining-=8;
        if (bytes>info->capacity || bytes>remaining) goto done;
        if (info->format&1) {
            mds_event_block compact={(unsigned char *)cursor,bytes,bytes};
            if (!services->expand(user,&compact,&buffer->event)) goto done;
        } else {
            buffer->event.used=bytes;
            if (bytes) memcpy(buffer->event.data,cursor,bytes);
        }
        cursor+=bytes; remaining-=bytes;
    }
    result=0;
done:
    if (result && info->buffers) {
        allocation=services->allocation(user,info->buffers);
        (void)services->unlock(user,allocation);
        allocation=services->allocation(user,info->buffers);
        (void)services->free(user,allocation);
    }
    return result;
}
