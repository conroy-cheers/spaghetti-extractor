#include "portable-component-implementation.h"
#include "mds-stream-state.h"

uint32_t lifted_mds_stop(spx_mds_stream_context_v5 *context,mds_info *info) {
    const spx_mds_stream_services_v5 *s=context->services;void *user=s->context;
    if (info->signature!=UINT32_C(0x4953444d)) return 6;
    if (!info->stream) return 7;
    info->flags|=1;
    if (s->reset(user,info)) { info->flags&=~1U; return 5; }
    uint32_t count=info->count;mds_buffers *buffers=info->buffers;
    for (uint32_t i=0;i<count;++i) {
        mds_header header={&buffers->headers[i]};
        (void)s->unprepare(user,info,&header,64);
    }
    (void)s->close(user,info);
    info->stream=0;info->flags=0;
    return 0;
}

uint32_t lifted_mds_start(spx_mds_stream_context_v5 *context,mds_info *info,uint32_t loop) {
    const spx_mds_stream_services_v5 *s=context->services;void *user=s->context;
    if (info->signature!=UINT32_C(0x4953444d)) return 6;
    if (info->stream && !(info->flags&4)) return 7;
    int opening=!info->stream;
    if (opening) {
        if (s->open(user,info,UINT32_MAX,1,0x30000)) goto failed;
        if (s->property(user,info,8,info->division,0x80000001)) goto failed;
        uint32_t count=info->count;mds_buffers *buffers=info->buffers;
        for (uint32_t i=0;i<count;++i) {
            mds_header header={&buffers->headers[i]};
            if (s->prepare(user,info,&header,64) || s->queue(user,info,&header,64)) goto failed;
            ++info->pending;
        }
    }
    info->flags&=~2U;
    if (loop&1) info->flags|=2;
    info->flags&=~4U;
    if (!s->restart(user,info)) return 0;
failed:
    if (opening && info->stream) (void)lifted_mds_stop(context,info);
    return 5;
}

uint32_t lifted_mds_pause(spx_mds_stream_context_v5 *context,mds_info *info) {
    if (info->signature!=UINT32_C(0x4953444d)) return 6;
    if (!info->stream) return 7;
    if (!(info->flags&4)) {
        if (context->services->pause(context->services->context,info)) return 5;
        info->flags|=4;
    }
    return 0;
}

void lifted_mds_complete(spx_mds_stream_context_v5 *context,uint32_t message,mds_header *header) {
    if (message!=0x3c9) return;
    mds_info *info=header->buffer->owner;
    if ((info->flags&2) && !(info->flags&1) &&
        !context->services->queue(context->services->context,info,header,64)) return;
    --info->pending;
}

uint32_t lifted_mds_release(spx_mds_stream_context_v5 *context,mds_info *info) {
    const spx_mds_stream_services_v5 *s=context->services;void *user=s->context;
    if (info->signature!=UINT32_C(0x4953444d)) return 6;
    if (info->stream) (void)lifted_mds_stop(context,info);
    if (info->buffers) {
        mds_memory *allocation=s->allocation(user,info->buffers);
        (void)s->unlock(user,allocation);
        allocation=s->allocation(user,info->buffers);
        (void)s->free_buffers(user,allocation);
    }
    info->signature=UINT32_C(0x61746164);
    (void)s->free_info(user,info);
    return 0;
}
