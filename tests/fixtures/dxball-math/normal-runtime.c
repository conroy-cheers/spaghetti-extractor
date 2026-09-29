#define RUNTIME_NORMAL_LIBRARY_ONLY 1
#include "runtime-normal-runtime.c"
#include "math-runtime.h"
static int32_t math_words[851];
static math_tables math_live={math_words,math_words+362};
static uint32_t math_selected[8],math_initialized,math_pan_calls[4096][2],math_pan_count;
void math_enter(unsigned operation) { REQUIRE(operation<8);++math_selected[operation]; }
static void math_pull(void) { memcpy(math_words,(void *)0x4351a8,sizeof(math_words)); }
static void live_math_initialize(void) {
    if(source_side) {
        math_pull();fixture_math_initialize(&math_live);
        memcpy((void *)0x4351a8,math_live.sine,361*4);memcpy((void *)0x435750,math_live.cosine,361*4);
        REQUIRE(install_math_initialize_intact());
    } else {
        REQUIRE(spx_fixture_restore_entry(&install_math_initialize_hook));((void (*)(void))0x40d6b0)();
        install_math_initialize_hook.entry=NULL;REQUIRE(install_math_initialize(live_math_initialize));
    }
    ++math_initialized;memcpy(sine,(void *)0x4351a8,sizeof(sine));memcpy(cosine,(void *)0x435750,sizeof(cosine));
}
#define MATH_READ(name,type,address) static type live_math_##name(uint32_t angle) { \
    if(source_side) { math_pull();type result=fixture_math_##name(&math_live,angle);REQUIRE(install_math_##name##_intact());return result; } \
    REQUIRE(spx_fixture_restore_entry(&install_math_##name##_hook));type result=((type (*)(uint32_t))address)(angle); \
    install_math_##name##_hook.entry=NULL;REQUIRE(install_math_##name((void (*)(void))live_math_##name));return result; }
MATH_READ(sine,uint32_t,0x40d710) MATH_READ(cosine,uint32_t,0x40d740)
MATH_READ(sine_value,double,0x40d770) MATH_READ(cosine_value,double,0x40d7b0)
#undef MATH_READ
#define MATH_PROJECT(name,address) static uint32_t live_math_##name(uint32_t origin,uint32_t angle,uint32_t distance) { \
    if(source_side) { math_pull();uint32_t result=fixture_math_##name(&math_live,origin,angle,distance);REQUIRE(install_math_##name##_intact());return result; } \
    REQUIRE(spx_fixture_restore_entry(&install_math_##name##_hook));uint32_t result=((uint32_t (*)(uint32_t,uint32_t,uint32_t))address)(origin,angle,distance); \
    install_math_##name##_hook.entry=NULL;REQUIRE(install_math_##name((void (*)(void))live_math_##name));return result; }
MATH_PROJECT(project_x,0x40d7f0) MATH_PROJECT(project_y,0x40d820)
#undef MATH_PROJECT
static uint32_t live_math_pan(uint32_t position) {
    uint32_t result;
    if(source_side) { result=fixture_math_pan(position);REQUIRE(install_math_pan_intact()); }
    else { REQUIRE(spx_fixture_restore_entry(&install_math_pan_hook));result=((uint32_t (*)(uint32_t))0x403550)(position);
        install_math_pan_hook.entry=NULL;REQUIRE(install_math_pan((void (*)(void))live_math_pan)); }
    REQUIRE(math_pan_count<4096);math_pan_calls[math_pan_count][0]=position;math_pan_calls[math_pan_count++][1]=result;return result;
}
static void math_observe(spx_observer *o) {
    runtime_observe(o);spx_observe_object(o,"math_policy");spx_observe_u64(o,"initialized",math_initialized);
    spx_observe_u32s(o,"sine",(const uint32_t *)0x4351a8,361);spx_observe_u32s(o,"cosine",(const uint32_t *)0x435750,361);
    spx_observe_array(o,"pan");for(unsigned i=0;i<math_pan_count;++i)spx_observe_u32s(o,NULL,math_pan_calls[i],2);
    spx_observe_end(o);spx_observe_end(o);
}
static void math_diagnose(spx_observer *o) { runtime_diagnose(o);spx_observe_u32s(o,"selected_math",math_selected,8); }
static void math_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT");if(!path)return;FILE *out=fopen(path,"wb");REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out);math_observe(&o);REQUIRE(spx_observe_finish(&o));fputs(",\"diagnostics\":",out);
    o=spx_observe_begin(out);math_diagnose(&o);REQUIRE(spx_observe_finish(&o));fputs("}\n",out);fclose(out);
    if(source_side)REQUIRE(math_selected[0] && math_selected[7]);
}
static BOOL math_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if(!runtime_main(instance,reason,reserved))return FALSE;
    if(reason==DLL_PROCESS_DETACH) { math_report();return TRUE; }
    if(reason!=DLL_PROCESS_ATTACH)return TRUE;
#define MATH_INSTALL(n) REQUIRE(install_math_##n((void (*)(void))live_math_##n));
    MATH_INSTALL(initialize) MATH_INSTALL(sine) MATH_INSTALL(cosine) MATH_INSTALL(sine_value) MATH_INSTALL(cosine_value)
    MATH_INSTALL(project_x) MATH_INSTALL(project_y) MATH_INSTALL(pan)
#undef MATH_INSTALL
    return TRUE;
}
#ifndef MATH_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return math_main(instance,reason,reserved); }
#endif
