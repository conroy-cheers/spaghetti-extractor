/* Run the same borrowed-table implementation in the actual editor. */
#define DAMAGE_NORMAL_LIBRARY_ONLY 1
#include "damage-normal-runtime.c"
#include "regions-runtime.h"
static region_table regions={&editor.region_count,editor.regions,25};
static uint32_t regions_entries[3],regions_count;
static uint32_t regions_calls[128][8],regions_records[128][125];
void regions_enter(unsigned operation) { REQUIRE(operation<3); ++regions_entries[operation]; }
static void regions_record(unsigned operation,const uint32_t *args,unsigned size,uint32_t result) {
    REQUIRE(regions_count<128); editor_from_native(); uint32_t index=regions_count++,*row=regions_calls[index];
    row[0]=operation; row[1]=result; row[2]=editor.region_count; memcpy(row+3,args,4*size);
    memcpy(regions_records[index],editor.regions,sizeof(editor.regions));
}
static void live_regions_reset(uint32_t requested) {
    uint32_t count=requested+1; REQUIRE(count>=0x80000000 || count<regions.capacity);
    if (source_side) { editor_from_native(); fixture_regions_reset(&regions,requested); editor_to_native(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_regions_reset_hook)); ((void (*)(uint32_t))0x40d520)(requested);
        install_regions_reset_hook.entry=NULL; REQUIRE(install_regions_reset((void (*)(void))live_regions_reset)); }
    regions_record(0,&requested,1,0);
}
static void live_regions_define(uint32_t index,uint32_t left,uint32_t top,uint32_t right,uint32_t bottom) {
    REQUIRE(index<regions.capacity); uint32_t args[]={index,left,top,right,bottom};
    if (source_side) { editor_from_native(); fixture_regions_define(&regions,index,left,top,right,bottom); editor_to_native(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_regions_define_hook));
        ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))0x40d550)(index,left,top,right,bottom);
        install_regions_define_hook.entry=NULL; REQUIRE(install_regions_define((void (*)(void))live_regions_define)); }
    regions_record(1,args,5,0);
}
static uint32_t live_regions_hit(uint32_t x,uint32_t y) {
    editor_from_native(); REQUIRE(editor.region_count>=0x80000000 || editor.region_count<=regions.capacity);
    uint32_t result,args[]={x,y};
    if (source_side) { result=fixture_regions_hit(&regions,x,y); editor_to_native(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_regions_hit_hook)); result=((uint32_t (*)(uint32_t,uint32_t))0x40d590)(x,y);
        install_regions_hit_hook.entry=NULL; REQUIRE(install_regions_hit((void (*)(void))live_regions_hit)); }
    regions_record(2,args,2,result); return result;
}
static void regions_observe(spx_observer *o) {
    damage_observe(o); spx_observe_array(o,"regions");
    for (uint32_t i=0;i<regions_count;++i) {
        spx_observe_object(o,NULL); spx_observe_u32s(o,"call",regions_calls[i],8);
        spx_observe_array(o,"records");
        for (uint32_t j=0;j<25;++j) spx_observe_u32s(o,NULL,regions_records[i]+j*5,5);
        spx_observe_end(o); spx_observe_end(o);
    }
    spx_observe_end(o);
}
static void regions_diagnose(spx_observer *o) {
    damage_diagnose(o); spx_observe_u32s(o,"selected_regions",regions_entries,3);
}
static void regions_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT"); if (!path) return; FILE *out=fopen(path,"wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out); regions_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o=spx_observe_begin(out);
    regions_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL regions_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!damage_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { regions_report(); return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
    REQUIRE(install_regions_reset((void (*)(void))live_regions_reset));
    REQUIRE(install_regions_define((void (*)(void))live_regions_define));
    REQUIRE(install_regions_hit((void (*)(void))live_regions_hit));
    return TRUE;
}
#ifndef REGIONS_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return regions_main(instance,reason,reserved); }
#endif
