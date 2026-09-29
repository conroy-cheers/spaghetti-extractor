/* Shared info views; platform effects are executed by the shared Wine backend. */
#include "mds-loader-runtime.h"
typedef struct { parser_info *info;uint32_t identity,live,snapshot[9]; } loader_record;
static loader_record loader_records[32],*loader_current;
static unsigned loader_record_count,loader_active;
static mds_handle loader_handles[64];static unsigned loader_handle_count;
static mds_file loader_views[32];static unsigned loader_view_count;
static uint32_t loader_do_parse(mds_info *,mds_file *,uint32_t);
static loader_record *loader_record_view(mds_info *v) {
    for(unsigned i=0;i<loader_record_count;++i)if(v==&loader_records[i].info->view)return &loader_records[i];
    REQUIRE(0);return NULL;
}
static mds_info *loader_info(uint32_t raw) {
    for(unsigned i=loader_record_count;i;--i)if(parser_bits(loader_records[i-1].info->raw)==raw)return &loader_records[i-1].info->view;
    return (mds_info *)(uintptr_t)raw;
}
static uint32_t loader_address(mds_info *v) {
    for(unsigned i=0;i<loader_record_count;++i)if(v==&loader_records[i].info->view)return parser_bits(loader_records[i].info->raw);
    REQUIRE((uintptr_t)v<=UINT32_MAX);return parser_bits(v);
}
static uint32_t loader_identity(uint32_t raw) {
    for(unsigned i=loader_record_count;i;--i)if(parser_bits(loader_records[i-1].info->raw)==raw)return loader_records[i-1].identity;
    return raw;
}
static void loader_snapshot(void) {
    if(!loader_current || !loader_current->live)return;
    parser_current=loader_current->info;parser_pull();memcpy(loader_current->snapshot,parser_current->raw,36);
}
static void loader_flush(void) {
    if(loader_current && loader_current->live) { parser_current=loader_current->info;parser_push(); }
}
static void loader_before(void *u,const spx_wine_event *event) {
    if(loader_active)loader_snapshot();
    parser_before(u,event);
}
static void loader_after(void *u,const spx_wine_event *event) {
    parser_after(u,event);
    if(loader_active && event->api==SPX_LOCAL_ALLOC && event->output_object) {
        REQUIRE(event->storage_extent==36 && loader_record_count<32 && !parser_active);
        parser_begin(spx_wine_memory_address(parser_environment,event->output_object),event->output_object);parser_active=0;
        loader_current=&loader_records[loader_record_count++];loader_current->info=parser_current;
        loader_current->identity=event->output_object;loader_current->live=event->handle_live_after;
    }
    if(event->api==SPX_LOCAL_FREE)for(unsigned i=0;i<loader_record_count;++i)
        if(loader_records[i].identity==event->storage)loader_records[i].live=event->handle_live_after;
    if(loader_active)loader_snapshot();
}
static mds_handle *loader_handle(uintptr_t value) {
    REQUIRE(loader_handle_count<64);loader_handles[loader_handle_count].value=value;return &loader_handles[loader_handle_count++];
}
mds_info *loader_allocate(void *u,uint32_t flags,uint32_t bytes) {
    (void)u;uintptr_t h=spx_wine_local_alloc(parser_environment,flags,bytes);return h ? loader_info((uint32_t)h) : NULL;
}
mds_info *loader_free(void *u,mds_info *info) {
    (void)u;loader_flush();uintptr_t h=spx_wine_local_free(parser_environment,(uintptr_t)loader_record_view(info)->info->raw);return h ? loader_info((uint32_t)h) : NULL;
}
mds_handle *loader_open(void *u,mds_input *input,uint32_t access,uint32_t share,uint32_t creation,uint32_t attributes) {
    (void)u;loader_flush();uintptr_t h=spx_wine_file_open(parser_environment,(const char *)input->data,access,share,NULL,creation,attributes,0);
    return h==SPX_WINE_INVALID_HANDLE ? NULL : loader_handle(h);
}
uint32_t loader_size(void *u,mds_handle *handle) { (void)u;loader_flush();return spx_wine_file_size(parser_environment,handle->value,NULL); }
mds_handle *loader_mapping(void *u,mds_handle *handle,uint32_t protection) {
    (void)u;loader_flush();uintptr_t h=spx_wine_file_mapping(parser_environment,handle->value,NULL,protection,0,0,NULL);
    return h ? loader_handle(h) : NULL;
}
mds_file *loader_map(void *u,mds_handle *handle,uint32_t access) {
    (void)u;loader_flush();const unsigned char *bytes=spx_wine_file_map(parser_environment,handle->value,access,0,0,0);
    if(!bytes)return NULL;
    REQUIRE(loader_view_count<32);loader_views[loader_view_count].data=bytes;return &loader_views[loader_view_count++];
}
uint32_t loader_unmap(void *u,mds_file *file) { (void)u;loader_flush();return spx_wine_file_unmap(parser_environment,file->data); }
uint32_t loader_close(void *u,mds_handle *handle) { (void)u;loader_flush();return spx_wine_file_close(parser_environment,handle->value); }
uint32_t loader_parse(void *u,mds_info *info,mds_file *file,uint32_t length) {
    (void)u;loader_flush();uint32_t result=loader_do_parse(info,file,length);loader_snapshot();return result;
}
#ifndef MDS_LOADER_NORMAL
static void loader_observe(spx_observer *o) {
    spx_observe_array(o,"infos");
    for(unsigned i=0;i<loader_record_count;++i) {
        loader_record *r=&loader_records[i];uint32_t info[9];memcpy(info,r->snapshot,36);
        parser_pool *p=parser_pool_at(info[4]);if(p)info[4]=p->identity;
        spx_observe_object(o,NULL);spx_observe_u64(o,"identity",r->identity);spx_observe_u64(o,"live",r->live);
        spx_observe_u32s(o,"info",info,9);spx_observe_end(o);
    }
    spx_observe_end(o);spx_observe_array(o,"buffers");
    for(unsigned i=0;i<parser_pool_count;++i) {
        parser_pool *p=&parser_pools[i];unsigned char *bytes=malloc(p->size ? p->size : 1);REQUIRE(bytes);memcpy(bytes,p->snapshot,p->size);
        for(unsigned j=0;j<p->count;++j) {
            uint32_t offset=j*(p->capacity+64);unsigned char *h=bytes+offset;
            if(parser_word(h)==parser_bits(p->raw+offset+64))parser_store(h,0x10000000U+p->identity*0x100000U+offset+64);
            if(parser_word(h+12)==parser_bits(p->owner->raw))parser_store(h+12,0x90000000U+p->owner->identity);
        }
        spx_observe_object(o,NULL);uint32_t state[]={p->identity,p->size,p->live,p->locks};spx_observe_u32s(o,"state",state,4);
        spx_observe_bytes(o,"bytes",bytes,p->size);spx_observe_end(o);free(bytes);
    }
    spx_observe_end(o);
}
#endif
