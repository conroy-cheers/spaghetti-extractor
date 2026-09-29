#define MDS_EVENTS_NORMAL_LIBRARY_ONLY 1
#include "mds-events-normal-runtime.c"
#define MDS_PARSER_NORMAL 1
#include "mds-transport.c"
static uint32_t parser_selected,parser_calls;
static struct { uint32_t result,info[9],count,used[512],flags[512]; } parser_results[32];
void parser_enter(void) { ++parser_selected; }
static uint32_t parser_do_expand(mds_event_block *input,mds_event_block *output) {
    uint32_t raw_input[]={parser_bits(input->data),input->capacity,input->used};void *raw_output=NULL;
    for(unsigned i=0;i<parser_pool_count;++i)for(unsigned j=0;j<parser_pools[i].count;++j)
        if(output==&parser_pools[i].view.headers[j].event)raw_output=parser_pools[i].raw+j*(parser_pools[i].capacity+64);
    REQUIRE(raw_output);uint32_t result=((uint32_t (*)(uint32_t *,void *))0x401d60)(raw_input,raw_output);
    input->data=(unsigned char *)(uintptr_t)raw_input[0];input->capacity=raw_input[1];input->used=raw_input[2];
    parser_pull();return result;
}
static void parser_platform_before(void *u,const spx_wine_event *event) {
    audio_platform_inputs(u,event);parser_before(u,event);
}
static void parser_platform_after(void *u,const spx_wine_event *event) {
    music_platform_outputs(u,event);parser_after(u,event);
}
static uint32_t live_mds_parse(uint32_t *info,const unsigned char *bytes,uint32_t length) {
    parser_begin(info,spx_wine_memory_storage(parser_environment,info).identity);uint32_t result;
    if(source_side) {
        mds_file file={bytes};result=fixture_mds_parse(&parser_current->view,&file,length);parser_push();REQUIRE(install_mds_parse_intact());
    } else {
        REQUIRE(spx_fixture_restore_entry(&install_mds_parse_hook));
        result=((uint32_t (*)(uint32_t *,const unsigned char *,uint32_t))0x401b60)(info,bytes,length);
        install_mds_parse_hook.entry=NULL;REQUIRE(install_mds_parse((void (*)(void))live_mds_parse));
    }
    parser_pull();REQUIRE(parser_calls<32);unsigned index=parser_calls++;
    parser_results[index].result=result;memcpy(parser_results[index].info,info,36);
    parser_pool *pool=parser_pool_at(info[4]);
    if(pool) {
        parser_results[index].info[4]=pool->identity;parser_results[index].count=pool->count;
        for(unsigned i=0;i<pool->count;++i) {
            parser_results[index].used[i]=pool->view.headers[i].event.used;
            parser_results[index].flags[i]=pool->view.headers[i].flags;
        }
    }
    parser_active=0;return result;
}
static void mds_parser_observe(spx_observer *o) {
    mds_events_observe(o);spx_observe_array(o,"mds_parses");
    for(unsigned i=0;i<parser_calls;++i) {
        spx_observe_object(o,NULL);spx_observe_u64(o,"result",parser_results[i].result);
        spx_observe_u32s(o,"info",parser_results[i].info,9);
        spx_observe_u32s(o,"used",parser_results[i].used,parser_results[i].count);
        spx_observe_u32s(o,"flags",parser_results[i].flags,parser_results[i].count);spx_observe_end(o);
    }
    spx_observe_end(o);
}
static void mds_parser_diagnose(spx_observer *o) {
    mds_events_diagnose(o);spx_observe_u64(o,"selected_mds_parser",parser_selected);
}
static void mds_parser_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT");if(!path)return;FILE *out=fopen(path,"wb");REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out);mds_parser_observe(&o);
    REQUIRE(spx_observe_finish(&o));fputs(",\"diagnostics\":",out);o=spx_observe_begin(out);mds_parser_diagnose(&o);
    REQUIRE(spx_observe_finish(&o));fputs("}\n",out);fclose(out);
    if(source_side)REQUIRE(parser_calls && parser_selected==parser_calls);
}
static BOOL mds_parser_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if(!mds_events_main(instance,reason,reserved))return FALSE;
    if(reason==DLL_PROCESS_DETACH) { mds_parser_report();parser_dispose_views();return TRUE; }
    if(reason!=DLL_PROCESS_ATTACH)return TRUE;
    parser_environment=wine_environment;
    spx_wine_set_hooks(parser_environment,(spx_wine_hooks){.before=parser_platform_before,.after=parser_platform_after});
    return install_mds_parse((void (*)(void))live_mds_parse);
}
#ifndef MDS_PARSER_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    return mds_parser_main(instance,reason,reserved);
}
#endif
