#define MDS_STREAM_NORMAL_LIBRARY_ONLY 1
#include "mds-stream-normal-runtime.c"
#include "palette-runtime.h"
static palette_state palette_live={&palettes,&flow};
static uint32_t palette_selected[5],palette_depth,palette_count,palette_calls[2048][12];
void palette_enter(unsigned op) { REQUIRE(op<5);++palette_selected[op]; }
static void palette_pull(void) { pcx_pull();flow.windowed=*word(0x434998); }
static void palette_push(void) { pcx_push();*word(0x434998)=flow.windowed; }
void palette_apply(void *u,palette_state *s,uint32_t first,uint32_t count) {
    (void)u;REQUIRE(s==&palette_live);palette_push();
    uint32_t address=*word(0x4349b8),*table=word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,uint32_t,uint32_t,uint32_t,void *))(uintptr_t)table[6])
        (address,0,first,count,(void *)(uintptr_t)(0x42c148+4*first));palette_pull();
}
void palette_wait(void *u,palette_state *s,uint32_t count) {
    (void)u;REQUIRE(s==&palette_live);palette_push();((void (*)(uint32_t))0x402240)(count);palette_pull();
}
static uint64_t palette_hash(void) { return hash_bytes(UINT64_C(14695981039346656037),(const unsigned char *)0x42c148,2048); }
static void palette_record(unsigned op,const uint32_t *args,unsigned count,uint64_t before,const uint32_t *sequence,uint32_t words) {
    if(--palette_depth)return;
    REQUIRE(palette_count<2048 && count<=5);uint32_t *r=palette_calls[palette_count++];r[0]=op;memcpy(r+1,args,count*4);
    uint64_t after=palette_hash();r[6]=(uint32_t)before;r[7]=(uint32_t)(before>>32);r[8]=(uint32_t)after;r[9]=(uint32_t)(after>>32);
    if(sequence) { uint64_t h=hash_bytes(UINT64_C(14695981039346656037),(const unsigned char *)sequence,words*4);r[10]=(uint32_t)h;r[11]=(uint32_t)(h>>32); }
}
static void live_palette_fade(uint32_t wait,uint32_t step,uint32_t first,uint32_t last,uint32_t direction) {
    ++palette_depth;uint64_t before=palette_hash();
    if(source_side) { palette_pull();fixture_palette_fade(&palette_live,wait,step,first,last,direction);palette_push();REQUIRE(install_palette_fade_intact()); }
    else { REQUIRE(spx_fixture_restore_entry(&install_palette_fade_hook));
        ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))0x402770)(wait,step,first,last,direction);
        install_palette_fade_hook.entry=NULL;REQUIRE(install_palette_fade((void (*)(void))live_palette_fade)); }
    palette_record(0,(uint32_t[]){wait,step,first,last,direction},5,before,NULL,0);
}
#define SHIFT(n,op,address) static void live_palette_##n(uint32_t first,uint32_t last,uint32_t wrap) { \
    ++palette_depth;uint64_t before=palette_hash(); \
    if(source_side) { palette_pull();fixture_palette_##n(&palette_live,first,last,wrap);palette_push();REQUIRE(install_palette_##n##_intact()); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_palette_##n##_hook));((void (*)(uint32_t,uint32_t,uint32_t))address)(first,last,wrap); \
        install_palette_##n##_hook.entry=NULL;REQUIRE(install_palette_##n((void (*)(void))live_palette_##n)); } \
    palette_record(op,(uint32_t[]){first,last,wrap},3,before,NULL,0); }
SHIFT(right,1,0x402a50) SHIFT(left,2,0x402af0)
#undef SHIFT
static void live_palette_rotate(uint32_t index,uint32_t count,uint32_t *values) {
    ++palette_depth;uint64_t before=palette_hash();
    if(source_side) { palette_pull();palette_sequence sequence={values};fixture_palette_rotate(&palette_live,index,count,&sequence);palette_push();REQUIRE(install_palette_rotate_intact()); }
    else { REQUIRE(spx_fixture_restore_entry(&install_palette_rotate_hook));((void (*)(uint32_t,uint32_t,uint32_t *))0x402ba0)(index,count,values);
        install_palette_rotate_hook.entry=NULL;REQUIRE(install_palette_rotate((void (*)(void))live_palette_rotate)); }
    palette_record(3,(uint32_t[]){index,count},2,before,values,count);
}
static void live_palette_set(uint32_t index,uint32_t red,uint32_t green,uint32_t blue) {
    ++palette_depth;uint64_t before=palette_hash();
    if(source_side) { palette_pull();fixture_palette_set(&palette_live,index,red,green,blue);palette_push();REQUIRE(install_palette_set_intact()); }
    else { REQUIRE(spx_fixture_restore_entry(&install_palette_set_hook));((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))0x402c10)(index,red,green,blue);
        install_palette_set_hook.entry=NULL;REQUIRE(install_palette_set((void (*)(void))live_palette_set)); }
    palette_record(4,(uint32_t[]){index,red,green,blue},4,before,NULL,0);
}
static void palette_observe(spx_observer *o) {
    mds_stream_observe(o);spx_observe_array(o,"palette_effects");
    for(unsigned i=0;i<palette_count;++i)spx_observe_u32s(o,NULL,palette_calls[i],12);
    spx_observe_end(o);
}
static void palette_diagnose(spx_observer *o) {
    mds_stream_diagnose(o);spx_observe_u32s(o,"selected_palette",palette_selected,5);
}
static void palette_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT");if(!path)return;FILE *out=fopen(path,"wb");REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out);palette_observe(&o);
    REQUIRE(spx_observe_finish(&o));fputs(",\"diagnostics\":",out);o=spx_observe_begin(out);
    palette_diagnose(&o);REQUIRE(spx_observe_finish(&o));fputs("}\n",out);fclose(out);
    if(source_side)REQUIRE(palette_selected[0] && palette_selected[1] && palette_selected[2] && palette_selected[3]);
}
static BOOL palette_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if(!mds_stream_main(instance,reason,reserved))return FALSE;
    if(reason==DLL_PROCESS_DETACH) { palette_report();return TRUE; }
    if(reason!=DLL_PROCESS_ATTACH)return TRUE;
    REQUIRE(install_palette_fade((void (*)(void))live_palette_fade));REQUIRE(install_palette_right((void (*)(void))live_palette_right));
    REQUIRE(install_palette_left((void (*)(void))live_palette_left));REQUIRE(install_palette_rotate((void (*)(void))live_palette_rotate));
    return install_palette_set((void (*)(void))live_palette_set);
}
#ifndef PALETTE_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    return palette_main(instance,reason,reserved);
}
#endif
