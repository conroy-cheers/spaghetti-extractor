/* Preserve existing controlled inputs while replacing their uncontrolled bodies. */
#define BOOTSTRAP_NORMAL_LIBRARY_ONLY 1
#include "bootstrap-normal-runtime.c"
#include "runtime-support.h"
static runtime_state runtime_live={&bootstrap_live,0,0,1};
static uint32_t runtime_selected[8],runtime_depth,runtime_count,runtime_calls[4096][8];
void runtime_enter(unsigned op) { REQUIRE(op<8);++runtime_selected[op]; }
#define RUNTIME_FIELDS(X) X(runtime_live.counter_enabled,0x435cf8) X(runtime_live.counter_divisor,0x435d00) \
    X(runtime_live.random_seed,0x417c74) X(bootstrap_live.last_refresh,0x4349c4) X(scene.refresh_ok,0x4349c0)
static void runtime_push(void) {
#define PUT(field,address) *word(address)=field;
    RUNTIME_FIELDS(PUT)
#undef PUT
    *word(0x4349a8)=shell_device_address(application.graphics);
}
static void runtime_pull(void) {
#define GET(field,address) field=*word(address);
    RUNTIME_FIELDS(GET)
#undef GET
    application.graphics=shell_device_view(*word(0x4349a8));
}
#undef RUNTIME_FIELDS
#define RUNTIME_BEGIN() (void)u;REQUIRE(s==&runtime_live);runtime_push()
#define RUNTIME_END() runtime_pull()
void runtime_version(void *u,runtime_state *s,runtime_version_query *v) {
    RUNTIME_BEGIN();uint32_t native[37]={0};native[0]=v->size;native[4]=v->platform;
    uint32_t result=((uint32_t (WINAPI *)(void *))(uintptr_t)*word(0x415078))(native);
    if(!result) { fprintf(stderr,"runtime version failure requires explicit original-caller history transport\n");ExitProcess(86); }
    v->size=native[0];v->platform=native[4];RUNTIME_END();
}
uint32_t runtime_frequency(void *u,runtime_state *s,runtime_sample *value) {
    RUNTIME_BEGIN();uint32_t result=((uint32_t (WINAPI *)(void *))(uintptr_t)*word(0x415074))(value);RUNTIME_END();return result;
}
void runtime_counter(void *u,runtime_state *s,runtime_sample *value) {
    RUNTIME_BEGIN();uint32_t result=((uint32_t (WINAPI *)(void *))(uintptr_t)*word(0x415070))(value);
    if(!result) { fprintf(stderr,"runtime counter failure requires explicit original-caller history transport\n");ExitProcess(86); }
    RUNTIME_END();
}
uint32_t runtime_ticks(void *u,runtime_state *s) {
    RUNTIME_BEGIN();uint32_t result=((uint32_t (WINAPI *)(void))(uintptr_t)*word(0x415174))();RUNTIME_END();return result;
}
uint32_t runtime_now(void *u,runtime_state *s) {
    RUNTIME_BEGIN();uint32_t result=((uint32_t (*)(void))0x40db20)();RUNTIME_END();return result;
}
void runtime_vertical_blank(void *u,runtime_state *s,shell_device *device,uint32_t flags) {
    RUNTIME_BEGIN();uint32_t address=shell_device_address(device),*table=word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,uint32_t,void *))(uintptr_t)table[22])(address,flags,NULL);RUNTIME_END();
}
void runtime_fault(void *u,runtime_state *s,uint32_t code) { RUNTIME_BEGIN();RaiseException(code,EXCEPTION_NONCONTINUABLE,0,NULL);abort(); }
#undef RUNTIME_BEGIN
#undef RUNTIME_END
static void runtime_record(unsigned op,uint32_t a,uint32_t b,uint32_t result) {
    if(--runtime_depth)return;
    REQUIRE(runtime_count<4096);runtime_pull();uint32_t values[]={op,a,b,result,runtime_live.random_seed,
        runtime_live.counter_enabled,runtime_live.counter_divisor,scene.refresh_ok};
    memcpy(runtime_calls[runtime_count++],values,sizeof(values));
}
static uint32_t live_runtime_now(void) {
    /* These are the same input scopes as the retained paddle/frame consumer.
     * All other reads select the actual original or C clock implementation. */
    if(paddle_input_active())return paddle_input(1,0,paddle_input_tick);
    uint32_t value;
    if(play_clock_input && play_clock_input((uintptr_t)__builtin_return_address(0),&value))return value;
    if(source_side) {
        runtime_pull();runtime_sample overwritten={0,0};uint32_t result=fixture_runtime_now(&runtime_live,&overwritten);runtime_push();
        REQUIRE(install_runtime_now_intact());return result;
    }
    REQUIRE(spx_fixture_restore_entry(&install_runtime_now_hook));uint32_t result=((uint32_t (*)(void))0x40db20)();
    install_runtime_now_hook.entry=NULL;REQUIRE(install_runtime_now((void (*)(void))live_runtime_now));return result;
}
static void live_runtime_clock_init(void) {
    ++runtime_depth;
    if(source_side) { runtime_pull();fixture_runtime_clock_init(&runtime_live,0);runtime_push();REQUIRE(install_runtime_clock_init_intact()); }
    else { REQUIRE(spx_fixture_restore_entry(&install_runtime_clock_init_hook));((void (*)(void))0x40dba0)();
        install_runtime_clock_init_hook.entry=NULL;REQUIRE(install_runtime_clock_init((void (*)(void))live_runtime_clock_init)); }
    runtime_record(0,0,0,0);
}
static uint32_t live_runtime_elapsed(uint32_t previous,uint32_t delay) {
    DWORD thread=frame_clock_thread;uint32_t kind=frame_clock_kind;
    if(frame_clock_caller((uintptr_t)__builtin_return_address(0))) { frame_clock_thread=GetCurrentThreadId();frame_clock_kind=1; }
    uint32_t result;
    if(source_side) { runtime_pull();result=fixture_runtime_elapsed(&runtime_live,previous,delay);runtime_push();REQUIRE(install_runtime_elapsed_intact()); }
    else { REQUIRE(spx_fixture_restore_entry(&install_runtime_elapsed_hook));result=((uint32_t (*)(uint32_t,uint32_t))0x40db80)(previous,delay);
        install_runtime_elapsed_hook.entry=NULL;REQUIRE(install_runtime_elapsed((void (*)(void))live_runtime_elapsed)); }
    frame_clock_thread=thread;frame_clock_kind=kind;return result;
}
static void live_runtime_wait(uint32_t count) {
    ++runtime_depth;
    if(source_side) { runtime_pull();fixture_runtime_wait(&runtime_live,count);runtime_push();REQUIRE(install_runtime_wait_intact()); }
    else { REQUIRE(spx_fixture_restore_entry(&install_runtime_wait_hook));((void (*)(uint32_t))0x402240)(count);
        install_runtime_wait_hook.entry=NULL;REQUIRE(install_runtime_wait((void (*)(void))live_runtime_wait)); }
    runtime_record(3,count,0,0);
}
static void live_runtime_set_seed(uint32_t seed) {
    ++runtime_depth;
    if(source_side) { runtime_pull();fixture_runtime_set_seed(&runtime_live,seed);runtime_push();REQUIRE(install_runtime_set_seed_intact()); }
    else { REQUIRE(spx_fixture_restore_entry(&install_runtime_set_seed_hook));((void (*)(uint32_t))0x40ea60)(seed);
        install_runtime_set_seed_hook.entry=NULL;REQUIRE(install_runtime_set_seed((void (*)(void))live_runtime_set_seed)); }
    runtime_record(4,seed,0,0);
}
static uint32_t live_runtime_next(void) {
    ++runtime_depth;uint32_t result;
    if(source_side) { runtime_pull();result=fixture_runtime_next(&runtime_live);runtime_push();REQUIRE(install_runtime_next_intact()); }
    else { REQUIRE(spx_fixture_restore_entry(&install_runtime_next_hook));result=((uint32_t (*)(void))0x40ea70)();
        install_runtime_next_hook.entry=NULL;REQUIRE(install_runtime_next((void (*)(void))live_runtime_next)); }
    runtime_record(5,0,0,result);return result;
}
static uint32_t live_runtime_random(uint32_t limit) {
    if(paddle_input_active()) { REQUIRE(limit);return paddle_input(2,limit,play_frames%limit); }
    ++runtime_depth;uint32_t result;
    if(source_side) { runtime_pull();result=fixture_runtime_random(&runtime_live,limit);runtime_push();REQUIRE(install_runtime_random_intact()); }
    else { REQUIRE(spx_fixture_restore_entry(&install_runtime_random_hook));result=((uint32_t (*)(uint32_t))0x40ae20)(limit);
        install_runtime_random_hook.entry=NULL;REQUIRE(install_runtime_random((void (*)(void))live_runtime_random)); }
    runtime_record(6,limit,0,result);return result;
}
static void live_runtime_seed(void) {
    REQUIRE(!seed_thread);seed_thread=GetCurrentThreadId();++runtime_depth;
    if(source_side) { runtime_pull();fixture_runtime_seed(&runtime_live);runtime_push();REQUIRE(install_runtime_seed_intact()); }
    else { REQUIRE(spx_fixture_restore_entry(&install_runtime_seed_hook));((void (*)(void))0x40ae30)();
        install_runtime_seed_hook.entry=NULL;REQUIRE(install_runtime_seed((void (*)(void))live_runtime_seed)); }
    runtime_record(7,0,0,0);seed_thread=0;
}
static void runtime_observe(spx_observer *o) {
    bootstrap_observe(o);spx_observe_array(o,"runtime_policy");
    for(unsigned i=0;i<runtime_count;++i)spx_observe_u32s(o,NULL,runtime_calls[i],8);
    spx_observe_end(o);
}
static void runtime_diagnose(spx_observer *o) {
    bootstrap_diagnose(o);spx_observe_u32s(o,"selected_runtime",runtime_selected,8);
}
static void runtime_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT");if(!path)return;FILE *out=fopen(path,"wb");REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out);runtime_observe(&o);REQUIRE(spx_observe_finish(&o));
    fputs(",\"diagnostics\":",out);o=spx_observe_begin(out);runtime_diagnose(&o);
    REQUIRE(spx_observe_finish(&o));fputs("}\n",out);fclose(out);
    if(source_side)REQUIRE(runtime_selected[0] && runtime_selected[1] && runtime_selected[2] && runtime_selected[3] && runtime_selected[6] && runtime_selected[7]);
}
static BOOL runtime_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if(!bootstrap_main(instance,reason,reserved))return FALSE;
    if(reason==DLL_PROCESS_DETACH) { runtime_report();return TRUE; }
    if(reason!=DLL_PROCESS_ATTACH)return TRUE;
    /* Retire four overlapping observation hooks; their input policy is kept in
     * the wrappers above. Body traps now belong to the lifted runtime entries. */
    REQUIRE(spx_fixture_restore_entry(&install_paddle_input_now_hook));install_paddle_input_now_hook.entry=NULL;
    REQUIRE(spx_fixture_restore_entry(&install_paddle_input_random_hook));install_paddle_input_random_hook.entry=NULL;
    REQUIRE(spx_fixture_restore_entry(&install_palette_elapsed_hook));install_palette_elapsed_hook.entry=NULL;
    REQUIRE(spx_fixture_restore_entry(&install_brick_seed_hook));install_brick_seed_hook.entry=NULL;
#define RUNTIME_INSTALL(n) REQUIRE(install_runtime_##n((void (*)(void))live_runtime_##n));
    RUNTIME_INSTALL(clock_init) RUNTIME_INSTALL(now) RUNTIME_INSTALL(elapsed) RUNTIME_INSTALL(wait)
    RUNTIME_INSTALL(set_seed) RUNTIME_INSTALL(next) RUNTIME_INSTALL(random) RUNTIME_INSTALL(seed)
#undef RUNTIME_INSTALL
    return TRUE;
}
#ifndef RUNTIME_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    return runtime_main(instance,reason,reserved);
}
#endif
