/* Native DirectSound backend, sharing the existing application and bank owners. */
#define AUDIO_NORMAL_LIBRARY_ONLY 1
#include "audio-normal-runtime.c"
#include "setup-runtime.h"
static audio_setup_state configuration={.bank=&sound,.application=&application};
static uint32_t setup_entries[2],setup_depth,setup_count;
void setup_enter(unsigned operation) { REQUIRE(operation<2);++setup_entries[operation]; }
static void setup_to_native(void) { audio_to_native();shell_to_native(); }
static void setup_from_native(void) { audio_from_native();shell_from_native(); }
#define SETUP_BEGIN() (void)u;REQUIRE(s==&configuration);setup_to_native()
#define SETUP_END() setup_from_native()
void setup_release_all(void *u,audio_setup_state *s) {
    SETUP_BEGIN();((void (*)(void))0x402f90)();SETUP_END();
}
uint32_t setup_create_device(void *u,audio_setup_state *s) {
    SETUP_BEGIN();uint32_t result=audio_platform(SPX_DS_CREATE,0,0,word(0x42ca10));SETUP_END();return result;
}
uint32_t setup_cooperative(void *u,audio_setup_state *s,audio_device *device,shell_handle *window,uint32_t level) {
    SETUP_BEGIN();spx_wine_call call={0};call.api=SPX_DS_COOPERATIVE;call.receiver=(void *)(uintptr_t)audio_device_address(device);
    call.window=shell_handle_address(window);call.arguments[0]=level;call.argument_count=1;
    uint32_t result=spx_wine_candidate_call(wine_environment,call);SETUP_END();return result;
}
uint32_t setup_create_primary(void *u,audio_setup_state *s,audio_device *device,audio_buffer_spec *spec) {
    SETUP_BEGIN();spx_wine_buffer_spec view={spec->size,spec->flags,spec->bytes,spec->reserved,spec->format};
    spx_wine_call call={0};call.api=SPX_DS_CREATE_BUFFER;call.receiver=(void *)(uintptr_t)audio_device_address(device);
    call.input=&view;call.output=word(0x42ca14);
    uint32_t result=spx_wine_candidate_call(wine_environment,call);SETUP_END();return result;
}
uint32_t setup_play_primary(void *u,audio_setup_state *s,audio_buffer *buffer,uint32_t flags) {
    SETUP_BEGIN();uint32_t result=audio_platform(SPX_DS_PLAY,audio_buffer_address(buffer),flags,NULL);SETUP_END();return result;
}
void setup_release_buffer(void *u,audio_setup_state *s,audio_buffer *buffer) {
    SETUP_BEGIN();audio_release_buffer(NULL,s->bank,buffer);SETUP_END();
}
void setup_release_device(void *u,audio_setup_state *s,audio_device *device) {
    SETUP_BEGIN();audio_release_device(NULL,s->bank,device);SETUP_END();
}
uint32_t setup_message(void *u,audio_setup_state *s,shell_handle *window,audio_name *text,audio_name *caption,uint32_t flags) {
    SETUP_BEGIN();spx_wine_call call={0};call.api=SPX_USER_MESSAGE_A;call.window=shell_handle_address(window);
    call.text=text->text;call.caption=caption->text;call.arguments[0]=flags;call.argument_count=1;
    uint32_t result=spx_wine_candidate_call(wine_environment,call);SETUP_END();return result;
}
void setup_terminate(void *u,audio_setup_state *s,uint32_t code) { SETUP_BEGIN();((void (*)(uint32_t))0x40e3d0)(code);SETUP_END(); }
void setup_load_sample(void *u,audio_setup_state *s,uint32_t slot,audio_name *name) {
    SETUP_BEGIN();((void (*)(uint32_t,const char *))0x403000)(slot,name->text);audio_admit_live_inputs();SETUP_END();
}
#undef SETUP_BEGIN
#undef SETUP_END
static struct { uint32_t operation,graphics_before,graphics_after;audio_snapshot before,after; } setup_records[16];
static void setup_before(unsigned operation) {
    audio_admit_live_inputs();setup_from_native();
    if (++setup_depth!=1) return;
    REQUIRE(setup_count<16);setup_records[setup_count].operation=operation;setup_records[setup_count].graphics_before=application.graphics!=NULL;
    audio_capture(&setup_records[setup_count].before);
}
static void setup_after(void) {
    if (--setup_depth) return;
    setup_from_native();setup_records[setup_count].graphics_after=application.graphics!=NULL;audio_capture(&setup_records[setup_count++].after);
}
#define SETUP_ENTRY(name,operation,address) static void live_setup_##name(uint32_t window) { \
    setup_before(operation); \
    if (source_side) { fixture_setup_##name(&configuration,shell_handle_view(window));setup_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_setup_##name##_hook));((void (*)(uint32_t))address)(window); \
        install_setup_##name##_hook.entry=NULL;REQUIRE(install_setup_##name((void (*)(void))live_setup_##name)); }setup_after(); }
SETUP_ENTRY(initialize,0,0x402c60) SETUP_ENTRY(focus,1,0x402c80)
#undef SETUP_ENTRY
static void setup_observe(spx_observer *o) {
    audio_observe(o);spx_observe_array(o,"audio_setup");
    for (unsigned i=0;i<setup_count;++i) {
        spx_observe_object(o,NULL);spx_observe_u64(o,"operation",setup_records[i].operation);
        spx_observe_u64(o,"graphics_before",setup_records[i].graphics_before);spx_observe_u64(o,"graphics_after",setup_records[i].graphics_after);
        audio_observe_state(o,"before",&setup_records[i].before);audio_observe_state(o,"after",&setup_records[i].after);spx_observe_end(o);
    }
    spx_observe_end(o);
}
static void setup_diagnose(spx_observer *o) {
    audio_diagnose(o);spx_observe_u32s(o,"selected_audio_setup",setup_entries,2);
}
static void setup_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT");if (!path) return;FILE *out=fopen(path,"wb");REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out);setup_observe(&o);REQUIRE(spx_observe_finish(&o));fputs(",\"diagnostics\":",out);
    o=spx_observe_begin(out);setup_diagnose(&o);REQUIRE(spx_observe_finish(&o));fputs("}\n",out);fclose(out);
}
static BOOL setup_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!audio_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { setup_report();return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
    REQUIRE(install_setup_initialize((void (*)(void))live_setup_initialize));REQUIRE(install_setup_focus((void (*)(void))live_setup_focus));return TRUE;
}
#ifndef SETUP_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return setup_main(instance,reason,reserved); }
#endif
