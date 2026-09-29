#define MDS_PARSER_NORMAL_LIBRARY_ONLY 1
#include "mds-parser-normal-runtime.c"
#define MDS_LOADER_NORMAL 1
#include "loader-transport.c"
static unsigned loader_selected,loader_calls;
static uint32_t loader_results[32][5];
void loader_enter(void) { ++loader_selected; }
static uint32_t loader_do_parse(mds_info *info,mds_file *file,uint32_t length) {
    return ((uint32_t (*)(uint32_t *,const unsigned char *,uint32_t))0x401b60)(loader_record_view(info)->info->raw,file->data,length);
}
static void loader_platform_before(void *u,const spx_wine_event *event) {
    audio_platform_inputs(u,event);loader_before(u,event);
}
static void loader_platform_after(void *u,const spx_wine_event *event) {
    music_platform_outputs(u,event);loader_after(u,event);
}
static uint32_t live_mds_load(uint32_t *slot,const unsigned char *bytes,uint32_t length,uint32_t flags) {
    REQUIRE(!loader_active && loader_calls<32);loader_active=1;loader_current=NULL;
    uint32_t *call=loader_results[loader_calls++];call[0]=flags;call[1]=length;call[2]=loader_identity(*slot);
    uint32_t result;
    if(source_side) {
        mds_output output={loader_info(*slot)};mds_input input={bytes};result=fixture_mds_load(&output,&input,length,flags);
        *slot=loader_address(output.value);REQUIRE(install_mds_load_intact());
    } else {
        REQUIRE(spx_fixture_restore_entry(&install_mds_load_hook));
        result=((uint32_t (*)(uint32_t *,const unsigned char *,uint32_t,uint32_t))0x401a20)(slot,bytes,length,flags);
        install_mds_load_hook.entry=NULL;REQUIRE(install_mds_load((void (*)(void))live_mds_load));
    }
    loader_snapshot();call[3]=result;call[4]=loader_identity(*slot);loader_active=0;return result;
}
static void mds_loader_observe(spx_observer *o) {
    mds_parser_observe(o);spx_observe_array(o,"mds_loads");
    for(unsigned i=0;i<loader_calls;++i)spx_observe_u32s(o,NULL,loader_results[i],5);
    spx_observe_end(o);
}
static void mds_loader_diagnose(spx_observer *o) {
    mds_parser_diagnose(o);spx_observe_u64(o,"selected_mds_loader",loader_selected);
}
static void loader_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT");if(!path)return;FILE *out=fopen(path,"wb");REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out);mds_loader_observe(&o);
    REQUIRE(spx_observe_finish(&o));fputs(",\"diagnostics\":",out);o=spx_observe_begin(out);mds_loader_diagnose(&o);
    REQUIRE(spx_observe_finish(&o));fputs("}\n",out);fclose(out);
    if(source_side)REQUIRE(loader_calls && loader_selected==loader_calls);
}
static BOOL mds_loader_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if(!mds_parser_main(instance,reason,reserved))return FALSE;
    if(reason==DLL_PROCESS_DETACH) { loader_report();return TRUE; }
    if(reason!=DLL_PROCESS_ATTACH)return TRUE;
    spx_wine_set_hooks(parser_environment,(spx_wine_hooks){.before=loader_platform_before,.after=loader_platform_after});
    return install_mds_load((void (*)(void))live_mds_load);
}
#ifndef MDS_LOADER_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    return mds_loader_main(instance,reason,reserved);
}
#endif
