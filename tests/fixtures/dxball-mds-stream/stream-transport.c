/* Shared object correspondence only; platform execution belongs to the backend. */
#include "mds-stream-runtime.h"
typedef struct { uintptr_t value;uint32_t word,identity; } stream_handle_record;
typedef struct { mds_header view;parser_pool *pool;uint32_t index;spx_wine_midi_header portable; } stream_header_record;
static stream_handle_record stream_handles[32];static unsigned stream_handle_count;
static stream_header_record stream_headers[512];static unsigned stream_header_count;
static loader_record *stream_current;static unsigned stream_depth;
static uintptr_t *stream_open_output;
static spx_wine_midi_callback stream_callback_function;
static uintptr_t stream_value(uint32_t word) {
    for(unsigned i=0;i<stream_handle_count;++i)if(stream_handles[i].word==word)return stream_handles[i].value;
    return word;
}
static uint32_t stream_identity(uint32_t word) {
    for(unsigned i=0;i<stream_handle_count;++i)if(stream_handles[i].word==word)return stream_handles[i].identity;
    return word;
}
static void stream_bind(uintptr_t value,uint32_t identity) {
    if(!value)return;
    REQUIRE(identity);
    for(unsigned i=0;i<stream_handle_count;++i)if(stream_handles[i].value==value) { REQUIRE(stream_handles[i].identity==identity);return; }
    REQUIRE(stream_handle_count<32);stream_handles[stream_handle_count++]=(stream_handle_record){value,(uint32_t)value,identity};
}
static void *stream_raw_header(stream_header_record *h) { return h->pool->raw+h->index*(h->pool->capacity+64); }
static void stream_export_header(stream_header_record *h) {
#ifndef _WIN32
    if(!h->pool->live || !h->pool->locks)return;
    const unsigned char *raw=stream_raw_header(h);mds_buffer *b=h->view.buffer;spx_wine_midi_header *p=&h->portable;
    p->lpData=(char *)b->event.data;p->dwBufferLength=b->event.capacity;p->dwBytesRecorded=b->event.used;
    p->dwUser=b->owner==&h->pool->owner->view ? (uintptr_t)h->pool->owner->raw : (uintptr_t)b->owner;
    p->dwFlags=b->flags;p->lpNext=(spx_wine_midi_header *)b->next;p->reserved=parser_word(raw+24);p->dwOffset=parser_word(raw+28);
    for(unsigned i=0;i<8;++i)p->dwReserved[i]=parser_word(raw+32+4*i);
#else
    (void)h;
#endif
}
static void stream_import_headers(void) {
#ifndef _WIN32
    for(unsigned i=0;i<stream_header_count;++i) {
        stream_header_record *h=&stream_headers[i];if(!h->pool->live || !h->pool->locks)continue;
        unsigned char *raw=stream_raw_header(h);parser_store(raw+16,h->portable.dwFlags);parser_store(raw+28,h->portable.dwOffset);
    }
#endif
}
static spx_wine_midi_header *stream_platform_header(stream_header_record *h) {
#ifdef _WIN32
    return stream_raw_header(h);
#else
    return &h->portable;
#endif
}
static void stream_add_headers(void) {
    for(unsigned i=0;i<parser_pool_count;++i) {
        parser_pool *p=&parser_pools[i];if(!p->live || !p->locks)continue;
        for(unsigned j=0;j<p->count;++j) {
            int found=0;for(unsigned k=0;k<stream_header_count;++k)if(stream_headers[k].pool==p && stream_headers[k].index==j)found=1;
            if(found)continue;
            REQUIRE(stream_header_count<512);stream_header_record *h=&stream_headers[stream_header_count++];
            h->view.buffer=&p->view.headers[j];h->pool=p;h->index=j;stream_export_header(h);
            spx_wine_bind_midi_header_storage(parser_environment,stream_platform_header(h),p->identity,j*(p->capacity+64));
        }
    }
}
static stream_header_record *stream_header_view(mds_header *view) {
    stream_add_headers();for(unsigned i=0;i<stream_header_count;++i)if(stream_headers[i].view.buffer==view->buffer)return &stream_headers[i];
    REQUIRE(0);return NULL;
}
static stream_header_record *stream_header_pointer(uintptr_t value) {
    stream_add_headers();for(unsigned i=0;i<stream_header_count;++i)if((uintptr_t)stream_platform_header(&stream_headers[i])==value)return &stream_headers[i];
    REQUIRE(!value);return NULL;
}
static void stream_pull(void) {
    stream_import_headers();
    if(!stream_current || !stream_current->live)return;
    parser_current=stream_current->info;parser_pull();parser_current->view.stream=stream_value(parser_current->raw[5]);
    memcpy(stream_current->snapshot,parser_current->raw,36);
}
static void stream_push(void) {
    if(!stream_current || !stream_current->live)return;
    parser_current=stream_current->info;parser_push();
    for(unsigned i=0;i<stream_header_count;++i)stream_export_header(&stream_headers[i]);
    memcpy(stream_current->snapshot,parser_current->raw,36);
}
static void stream_before(void *u,const spx_wine_event *event) {
    loader_before(u,event);if(stream_depth)stream_pull();
}
static void stream_after(void *u,const spx_wine_event *event) {
    loader_after(u,event);
    if(event->api==SPX_LOCAL_ALLOC && event->output_object)spx_wine_bind_midi_allocation_user(parser_environment,event->output_object);
    if(event->api==SPX_MIDI_OPEN && stream_current && event->output_object) {
        uintptr_t value=stream_open_output ? *stream_open_output : stream_current->info->raw[5];
        stream_bind(value,event->output_object);stream_current->info->raw[5]=(uint32_t)value;
    }
    if(stream_depth)stream_pull();
}
static void stream_require(mds_info *info) { REQUIRE(stream_current && &stream_current->info->view==info && stream_current->live); }
uint32_t stream_open(void *u,mds_info *info,uint32_t device,uint32_t count,uint32_t flags) {
    (void)u;stream_require(info);stream_push();uintptr_t value=info->stream;stream_open_output=&value;
    uint32_t result=spx_wine_midi_open(parser_environment,&value,&device,count,stream_callback_function,0,flags);
    stream_open_output=NULL;stream_pull();return result;
}
uint32_t stream_property(void *u,mds_info *info,uint32_t size,uint32_t division,uint32_t flags) {
    (void)u;stream_require(info);stream_push();uint32_t property[]={size,division};
    uint32_t result=spx_wine_midi_property(parser_environment,info->stream,property,flags);stream_pull();return result;
}
#define HEADER_SERVICE(name,api) uint32_t stream_##name(void *u,mds_info *info,mds_header *header,uint32_t size) { \
    (void)u;stream_require(info);stream_push();stream_header_record *h=stream_header_view(header); \
    uint32_t result=spx_wine_midi_header_call(parser_environment,api,info->stream,stream_platform_header(h),size);stream_pull();return result; }
HEADER_SERVICE(prepare,SPX_MIDI_PREPARE) HEADER_SERVICE(queue,SPX_MIDI_OUT) HEADER_SERVICE(unprepare,SPX_MIDI_UNPREPARE)
#undef HEADER_SERVICE
#define STREAM_SERVICE(name,api) uint32_t stream_##name(void *u,mds_info *info) { \
    (void)u;stream_require(info);stream_push();uint32_t result=spx_wine_midi_stream_call(parser_environment,api,info->stream);stream_pull();return result; }
STREAM_SERVICE(restart,SPX_MIDI_RESTART) STREAM_SERVICE(pause,SPX_MIDI_PAUSE) STREAM_SERVICE(reset,SPX_MIDI_RESET) STREAM_SERVICE(close,SPX_MIDI_CLOSE)
#undef STREAM_SERVICE
mds_memory *stream_allocation(void *u,mds_buffers *buffers) {
    (void)u;stream_push();uintptr_t h=spx_wine_global_handle(parser_environment,parser_pool_view(buffers)->raw);stream_pull();return parser_memory(h);
}
uint32_t stream_unlock(void *u,mds_memory *memory) {
    (void)u;stream_push();uint32_t result=spx_wine_global_unlock(parser_environment,memory ? memory->handle : 0);stream_pull();return result;
}
mds_memory *stream_free_buffers(void *u,mds_memory *memory) {
    (void)u;stream_push();uintptr_t result=spx_wine_global_free(parser_environment,memory ? memory->handle : 0);stream_pull();return parser_memory(result);
}
mds_info *stream_free_info(void *u,mds_info *info) {
    (void)u;stream_require(info);stream_push();uintptr_t result=spx_wine_local_free(parser_environment,(uintptr_t)stream_current->info->raw);
    stream_pull();return result ? loader_info((uint32_t)result) : NULL;
}
typedef struct { loader_record *stream,*loader;parser_info *parser; } stream_frame;
static stream_frame stream_begin(mds_info *info) {
    stream_frame frame={stream_current,loader_current,parser_current};++stream_depth;
    if(info) { stream_current=loader_record_view(info);loader_current=stream_current;parser_current=stream_current->info; }
    stream_pull();stream_add_headers();return frame;
}
static void stream_end(stream_frame frame) {
    REQUIRE(stream_depth);--stream_depth;stream_current=frame.stream;loader_current=frame.loader;parser_current=frame.parser;
}
