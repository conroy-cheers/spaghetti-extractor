/* The actual MDS parser calls the selected event expander. */
#define MUSIC_NORMAL_LIBRARY_ONLY 1
#include "music-normal-runtime.c"
#include "mds-events-runtime.h"
static uint32_t mds_selected,mds_count,mds_calls[256][4];
void mds_events_enter(void) { ++mds_selected; }
static uint32_t live_mds_expand(uint32_t *input,uint32_t *output) {
    REQUIRE(mds_count<256);uint32_t *event=mds_calls[mds_count++];
    event[0]=input[2];event[1]=output[1];uint32_t result;
    if(source_side) {
        mds_event_block in={(unsigned char *)(uintptr_t)input[0],input[1],input[2]};
        mds_event_block out={(unsigned char *)(uintptr_t)output[0],output[1],output[2]};
        result=fixture_mds_expand(&in,&out);
        input[0]=(uint32_t)(uintptr_t)in.data;input[1]=in.capacity;input[2]=in.used;
        output[0]=(uint32_t)(uintptr_t)out.data;output[1]=out.capacity;output[2]=out.used;
        REQUIRE(install_mds_expand_intact());
    } else {
        REQUIRE(spx_fixture_restore_entry(&install_mds_expand_hook));
        result=((uint32_t (*)(uint32_t *,uint32_t *))0x401d60)(input,output);
        install_mds_expand_hook.entry=NULL;REQUIRE(install_mds_expand((void (*)(void))live_mds_expand));
    }
    event[2]=output[2];event[3]=result;return result;
}
static void mds_events_observe(spx_observer *o) {
    music_observe(o);spx_observe_array(o,"mds_events");
    for(unsigned i=0;i<mds_count;++i)spx_observe_u32s(o,NULL,mds_calls[i],4);
    spx_observe_end(o);
}
static void mds_events_diagnose(spx_observer *o) {
    music_diagnose(o);spx_observe_u64(o,"selected_mds_events",mds_selected);
}
static void mds_events_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT");if(!path)return;FILE *out=fopen(path,"wb");REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out);mds_events_observe(&o);
    REQUIRE(spx_observe_finish(&o));fputs(",\"diagnostics\":",out);o=spx_observe_begin(out);mds_events_diagnose(&o);
    REQUIRE(spx_observe_finish(&o));fputs("}\n",out);fclose(out);
    if(source_side)REQUIRE(mds_count && mds_selected==mds_count);
}
static BOOL mds_events_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if(!music_main(instance,reason,reserved))return FALSE;
    if(reason==DLL_PROCESS_DETACH) { mds_events_report();return TRUE; }
    return reason!=DLL_PROCESS_ATTACH || install_mds_expand((void (*)(void))live_mds_expand);
}
#ifndef MDS_EVENTS_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    return mds_events_main(instance,reason,reserved);
}
#endif
