#define MDS_LOADER_NORMAL_LIBRARY_ONLY 1
#include "mds-loader-normal-runtime.c"
#include "stream-transport.c"
static uint32_t stream_selected[5],stream_calls[64][13],stream_callbacks[256][5];
static unsigned stream_call_count,stream_callback_count;
void stream_enter(unsigned op) { REQUIRE(op<5);++stream_selected[op]; }
static void stream_record(unsigned op,uint32_t result,mds_info *info) {
    REQUIRE(stream_call_count<64);uint32_t *r=stream_calls[stream_call_count++];loader_record *record=loader_record_view(info);
    r[0]=op;r[1]=result;r[2]=record->identity;r[3]=record->live;memcpy(r+4,record->snapshot,36);
    parser_pool *p=parser_pool_at(r[8]);if(p)r[8]=p->identity;r[9]=stream_identity(r[9]);
}
static void SPX_WINE_CALLBACK live_stream_complete(uintptr_t stream,uint32_t message,uintptr_t instance,uintptr_t first,uintptr_t second) {
    stream_header_record *h=message==0x3c9 ? stream_header_pointer(first) : NULL;
    stream_frame frame=stream_begin(h ? h->view.buffer->owner : NULL);
    REQUIRE(stream_callback_count<256);uint32_t *r=stream_callbacks[stream_callback_count++];
    r[0]=message;r[1]=h ? stream_current->identity : 0;r[2]=h ? h->view.buffer->owner->pending : 0;
    if(source_side) { fixture_mds_complete(message,h ? &h->view : NULL);stream_push();REQUIRE(install_mds_complete_intact()); }
    else {
        REQUIRE(spx_fixture_restore_entry(&install_mds_complete_hook));
        ((spx_wine_midi_callback)0x4020c0)(stream,message,instance,first,second);
        install_mds_complete_hook.entry=NULL;REQUIRE(install_mds_complete((void (*)(void))live_stream_complete));
    }
    stream_pull();r[3]=h ? h->view.buffer->owner->pending : 0;r[4]=h ? h->view.buffer->owner->flags : 0;stream_end(frame);
}
static uint32_t live_stream_start(uint32_t *raw,uint32_t loop) {
    int outer=!stream_depth;mds_info *info=loader_info(parser_bits(raw));stream_frame frame=stream_begin(info);uint32_t result;
    if(source_side) { result=fixture_mds_start(info,loop);stream_push();REQUIRE(install_mds_start_intact()); }
    else { REQUIRE(spx_fixture_restore_entry(&install_mds_start_hook));result=((uint32_t (*)(uint32_t *,uint32_t))0x401ea0)(raw,loop);
        install_mds_start_hook.entry=NULL;REQUIRE(install_mds_start((void (*)(void))live_stream_start)); }
    stream_pull();if(outer)stream_record(0,result,info);stream_end(frame);return result;
}
#define ENTRY(name,op,address) static uint32_t live_stream_##name(uint32_t *raw) { \
    int outer=!stream_depth;mds_info *info=loader_info(parser_bits(raw));stream_frame frame=stream_begin(info);uint32_t result; \
    if(source_side) { result=fixture_mds_##name(info);stream_push();REQUIRE(install_mds_##name##_intact()); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_mds_##name##_hook));result=((uint32_t (*)(uint32_t *))address)(raw); \
        install_mds_##name##_hook.entry=NULL;REQUIRE(install_mds_##name((void (*)(void))live_stream_##name)); } \
    stream_pull();if(outer)stream_record(op,result,info);stream_end(frame);return result; }
ENTRY(pause,1,0x401fe0) ENTRY(stop,2,0x402030) ENTRY(release,4,0x401e40)
#undef ENTRY
static void stream_platform_before(void *u,const spx_wine_event *event) { audio_platform_inputs(u,event);stream_before(u,event); }
static void mds_stream_observe(spx_observer *o) {
    mds_loader_observe(o);spx_observe_object(o,"mds_stream");spx_observe_array(o,"calls");
    for(unsigned i=0;i<stream_call_count;++i)spx_observe_u32s(o,NULL,stream_calls[i],13);
    spx_observe_end(o);spx_observe_array(o,"callbacks");
    for(unsigned i=0;i<stream_callback_count;++i)spx_observe_u32s(o,NULL,stream_callbacks[i],5);
    spx_observe_end(o);spx_observe_end(o);
}
static void mds_stream_diagnose(spx_observer *o) {
    mds_loader_diagnose(o);spx_observe_u32s(o,"selected_mds_stream",stream_selected,5);
}
static void stream_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT");if(!path)return;FILE *out=fopen(path,"wb");REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out);mds_stream_observe(&o);
    REQUIRE(spx_observe_finish(&o));fputs(",\"diagnostics\":",out);o=spx_observe_begin(out);
    mds_stream_diagnose(&o);REQUIRE(spx_observe_finish(&o));fputs("}\n",out);fclose(out);
    if(source_side)REQUIRE(stream_selected[0] && stream_selected[2] && stream_selected[3]==stream_callback_count && stream_selected[4]);
}
static BOOL mds_stream_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if(!mds_loader_main(instance,reason,reserved))return FALSE;
    if(reason==DLL_PROCESS_DETACH) { stream_report();return TRUE; }
    if(reason!=DLL_PROCESS_ATTACH)return TRUE;
    stream_callback_function=(spx_wine_midi_callback)0x4020c0;
    spx_wine_set_hooks(parser_environment,(spx_wine_hooks){.before=stream_platform_before,.after=stream_after});
    REQUIRE(install_mds_start((void (*)(void))live_stream_start));REQUIRE(install_mds_pause((void (*)(void))live_stream_pause));
    REQUIRE(install_mds_stop((void (*)(void))live_stream_stop));REQUIRE(install_mds_release((void (*)(void))live_stream_release));
    return install_mds_complete((void (*)(void))live_stream_complete);
}
#ifndef MDS_STREAM_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    return mds_stream_main(instance,reason,reserved);
}
#endif
