/* Application layouts only. Global storage execution remains in the shared backend. */
#include "mds-parser-runtime.h"
#include "mds-events-runtime.h"
#include "spx-wine-test.h"
#include <stdlib.h>
#include <string.h>
struct spx_opaque_mds_memory_v5 { uintptr_t handle; };
typedef struct { mds_info view;uint32_t *raw;uint32_t identity,shadow[9]; } parser_info;
typedef struct {
    mds_buffers view;unsigned char *raw,*snapshot;uint32_t *shadow;
    uint32_t identity,size,count,capacity,live,locks;parser_info *owner;
} parser_pool;
static spx_wine_env *parser_environment;
static parser_info parser_infos[32],*parser_current;
static parser_pool parser_pools[32];
static mds_memory parser_memories[64];
static unsigned parser_info_count,parser_pool_count,parser_memory_count,parser_active;
static uint32_t parser_do_expand(mds_event_block *,mds_event_block *);
static uint32_t parser_word(const unsigned char *p) {
    return p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static void parser_store(unsigned char *p,uint32_t value) {
    for(unsigned i=0;i<4;++i)p[i]=(unsigned char)(value>>(8*i));
}
static uint32_t parser_bits(const void *p) { return (uint32_t)(uintptr_t)p; }
static parser_pool *parser_pool_at(uint32_t address) {
    for(unsigned i=parser_pool_count;i;--i)if(parser_bits(parser_pools[i-1].raw)==address)return &parser_pools[i-1];
    return NULL;
}
static parser_pool *parser_pool_view(mds_buffers *value) {
    for(unsigned i=0;i<parser_pool_count;++i)if(value==&parser_pools[i].view)return &parser_pools[i];
    REQUIRE(0);return NULL;
}
static mds_buffers *parser_buffers(uint32_t address) {
    if(!address)return NULL;
    parser_pool *p=parser_pool_at(address);return p ? &p->view : (mds_buffers *)(uintptr_t)address;
}
static uint32_t parser_buffer_address(mds_buffers *value) {
    if(!value)return 0;
    for(unsigned i=0;i<parser_pool_count;++i)if(value==&parser_pools[i].view)return parser_bits(parser_pools[i].raw);
    REQUIRE((uintptr_t)value<=UINT32_MAX);return parser_bits(value);
}
static mds_memory *parser_memory(uintptr_t handle) {
    if(!handle)return NULL;
    for(unsigned i=0;i<parser_memory_count;++i)if(parser_memories[i].handle==handle)return &parser_memories[i];
    REQUIRE(parser_memory_count<64);parser_memories[parser_memory_count].handle=handle;return &parser_memories[parser_memory_count++];
}
static void parser_pull_pool(parser_pool *p) {
    if(!p->live || !p->locks)return;
    for(unsigned i=0;i<p->count;++i) {
        unsigned char *raw=p->raw+i*(p->capacity+64);mds_buffer *b=&p->view.headers[i];
        uint32_t observed[6];
        for(unsigned field=0;field<6;++field)observed[field]=parser_word(raw+4*field);
        b->payload=raw+64;uint32_t data=observed[0],owner=observed[3];
        b->event=(mds_event_block){data==parser_bits(b->payload) ? b->payload : (unsigned char *)(uintptr_t)data,
            observed[1],observed[2]};
        b->owner=owner==parser_bits(p->owner->raw) ? &p->owner->view : (mds_info *)(uintptr_t)owner;
        b->flags=observed[4];b->next=(mds_buffer *)(uintptr_t)observed[5];
#ifdef PARSER_HEADER_READ
        PARSER_HEADER_READ(raw);
#endif
        /* The baseline must be the exact read that produced the view. Reading
         * provider-owned memory again could turn its update into an apparent C
         * edit, then overwrite it at the next push. */
        memcpy(p->shadow+6*i,observed,sizeof(observed));
    }
    memcpy(p->snapshot,p->raw,p->size);
}
static void parser_push_pool(parser_pool *p) {
    if(!p->live || !p->locks || p->owner!=parser_current)return;
    for(unsigned i=0;i<p->count;++i) {
        unsigned char *raw=p->raw+i*(p->capacity+64);mds_buffer *b=&p->view.headers[i];
        uint32_t fields[]={parser_bits(b->event.data),b->event.capacity,b->event.used,
            b->owner==&p->owner->view ? parser_bits(p->owner->raw) : parser_bits(b->owner),b->flags,parser_bits(b->next)};
        /* The provider may own other fields while a callback runs. Publish only
         * actual view changes; observation snapshots are not write baselines. */
        for(unsigned field=0;field<6;++field) {
            uint32_t *previous=&p->shadow[6*i+field];
            if(*previous!=fields[field]) { parser_store(raw+4*field,fields[field]);*previous=fields[field]; }
        }
    }
    memcpy(p->snapshot,p->raw,p->size);
}
static void parser_pull(void) {
    REQUIRE(parser_current);uint32_t r[9];mds_info *v=&parser_current->view;
    memcpy(r,parser_current->raw,sizeof(r));
    v->signature=r[0];v->division=r[1];v->capacity=r[2];v->format=r[3];v->buffers=parser_buffers(r[4]);
    v->stream=r[5];v->flags=r[6];v->count=r[7];v->pending=r[8];
    memcpy(parser_current->shadow,r,36);
    for(unsigned i=0;i<parser_pool_count;++i)parser_pull_pool(&parser_pools[i]);
}
static void parser_push(void) {
    REQUIRE(parser_current);uint32_t *r=parser_current->raw;mds_info *v=&parser_current->view;
    uint32_t fields[]={v->signature,v->division,v->capacity,v->format,parser_buffer_address(v->buffers),
        (uint32_t)v->stream,v->flags,v->count,v->pending};
    for(unsigned field=0;field<9;++field)if(parser_current->shadow[field]!=fields[field]) {
        r[field]=fields[field];parser_current->shadow[field]=fields[field];
    }
    for(unsigned i=0;i<parser_pool_count;++i)parser_push_pool(&parser_pools[i]);
}
static void parser_begin(uint32_t *raw,uint32_t identity) {
    REQUIRE(!parser_active);parser_current=NULL;
    for(unsigned i=0;i<parser_info_count;++i)if(parser_infos[i].identity==identity && parser_infos[i].raw==raw)parser_current=&parser_infos[i];
    if(!parser_current) { REQUIRE(parser_info_count<32);parser_current=&parser_infos[parser_info_count++];parser_current->raw=raw;parser_current->identity=identity; }
    parser_active=1;parser_pull();
}
static void parser_before(void *unused,const spx_wine_event *event) {
    (void)unused;
    if(parser_active && event->api>=SPX_LOCAL_ALLOC && event->api<=SPX_GLOBAL_HANDLE)parser_pull();
}
static void parser_after(void *unused,const spx_wine_event *event) {
    (void)unused;
    if(event->api<SPX_LOCAL_ALLOC || event->api>SPX_GLOBAL_HANDLE)return;
    if(parser_active && event->api==SPX_GLOBAL_LOCK && event->output_object) {
        unsigned char *raw=spx_wine_memory_address(parser_environment,event->output_object);
        parser_pool *p=parser_pool_at(parser_bits(raw));
        if(!p || !p->live) {
            REQUIRE(parser_pool_count<32);p=&parser_pools[parser_pool_count++];p->raw=raw;p->identity=event->output_object;
            p->size=event->storage_extent;p->owner=parser_current;p->count=parser_current->view.count;p->capacity=parser_current->view.capacity;
            REQUIRE(p->count<=512 && p->capacity<=16384 && (uint64_t)p->count*(p->capacity+64)==p->size);
            p->view.headers=calloc(p->count ? p->count : 1,sizeof(mds_buffer));p->snapshot=malloc(p->size ? p->size : 1);
            p->shadow=calloc(p->count ? p->count : 1,6*sizeof(uint32_t));REQUIRE(p->view.headers && p->snapshot && p->shadow);
        }
    }
    for(unsigned i=0;i<parser_pool_count;++i) {
        parser_pool *p=&parser_pools[i];if(p->identity==event->storage) { p->live=event->handle_live_after;p->locks=event->locks_after; }
    }
    if(parser_active)parser_pull();
}
mds_memory *parser_allocate(void *unused,uint32_t flags,uint32_t bytes) {
    (void)unused;parser_push();uintptr_t h=spx_wine_global_alloc(parser_environment,flags,bytes);parser_pull();return parser_memory(h);
}
mds_buffers *parser_lock(void *unused,mds_info *info,mds_memory *memory) {
    (void)unused;REQUIRE(info==&parser_current->view);parser_push();
    void *raw=spx_wine_global_lock(parser_environment,memory ? memory->handle : 0);parser_pull();return parser_buffers(parser_bits(raw));
}
mds_memory *parser_allocation(void *unused,mds_buffers *buffers) {
    (void)unused;parser_push();uintptr_t h=spx_wine_global_handle(parser_environment,parser_pool_view(buffers)->raw);parser_pull();return parser_memory(h);
}
uint32_t parser_unlock(void *unused,mds_memory *memory) {
    (void)unused;parser_push();uint32_t r=spx_wine_global_unlock(parser_environment,memory ? memory->handle : 0);parser_pull();return r;
}
mds_memory *parser_free(void *unused,mds_memory *memory) {
    (void)unused;parser_push();uintptr_t h=spx_wine_global_free(parser_environment,memory ? memory->handle : 0);parser_pull();return parser_memory(h);
}
uint32_t parser_expand(void *unused,mds_event_block *input,mds_event_block *output) {
    (void)unused;parser_push();uint32_t result=parser_do_expand(input,output);parser_push();return result;
}
#ifndef MDS_PARSER_NORMAL
static void parser_observe(spx_observer *o,uint32_t result,const unsigned char *file,uint32_t extent) {
    parser_pull();spx_observe_object(o,NULL);spx_observe_u64(o,"result",result);
    uint32_t info[9];memcpy(info,parser_current->raw,sizeof(info));parser_pool *p=parser_pool_at(info[4]);
    if(p)info[4]=p->identity;
    spx_observe_u32s(o,"info",info,9);spx_observe_bytes(o,"file",file,extent);spx_observe_array(o,"buffers");
    for(unsigned i=0;i<parser_pool_count;++i) {
        p=&parser_pools[i];unsigned char *bytes=malloc(p->size ? p->size : 1);REQUIRE(bytes);memcpy(bytes,p->snapshot,p->size);
        for(unsigned j=0;j<p->count;++j) {
            uint32_t offset=j*(p->capacity+64);unsigned char *h=bytes+offset;
            if(parser_word(h)==parser_bits(p->raw+offset+64))parser_store(h,0x10000000U+p->identity*0x100000U+offset+64);
            if(parser_word(h+12)==parser_bits(p->owner->raw))parser_store(h+12,0x90000000U+p->owner->identity);
        }
        spx_observe_object(o,NULL);uint32_t state[]={p->identity,p->size,p->live,p->locks};spx_observe_u32s(o,"state",state,4);
        spx_observe_bytes(o,"bytes",bytes,p->size);spx_observe_end(o);free(bytes);
    }
    spx_observe_end(o);spx_observe_end(o);
}
#endif
static void parser_dispose_views(void) {
    for(unsigned i=0;i<parser_pool_count;++i) { free(parser_pools[i].view.headers);free(parser_pools[i].snapshot);free(parser_pools[i].shadow); }
}
