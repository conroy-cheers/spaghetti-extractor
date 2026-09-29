/* Mixed native backend for sound control; sample/device creation remain native. */
#define DISPLAY_NORMAL_LIBRARY_ONLY 1
#include "display-normal-runtime.c"
#include "audio-runtime.h"
#include "spx-wine-test.h"
static spx_wine_env *wine_environment;
static void audio_platform_inputs(void *context,const spx_wine_event *event) {
    (void)context;
    if(event->api==SPX_DS_COOPERATIVE || event->api==SPX_USER_MESSAGE_A) {
        uint32_t main_window=*word(0x434974);
        if(main_window)spx_wine_bind_window(wine_environment,main_window,1);
    }
}
struct spx_opaque_audio_buffer_v5 { uint32_t address; };
struct spx_opaque_audio_device_v5 { uint32_t address; };
static audio_buffer audio_buffers[256];
static audio_device audio_devices[32];
static audio_sample audio_samples[256];
static uint32_t audio_sample_addresses[256],audio_retired[256],audio_buffer_count,audio_device_count,audio_sample_count;
static void (*audio_input_lifetimes)(void);
static audio_state sound;
static uint32_t audio_entries[9],audio_depth,audio_count;
uint32_t audio_entry_restore_history;
void audio_enter(unsigned operation) { REQUIRE(operation<9);++audio_entries[operation]; }
#define AUDIO_MAP(name,type,array,count,limit) \
static type *audio_##name##_view(uint32_t address) { \
    if (!address) return NULL; \
    for (unsigned i=0;i<count;++i) { if (array[i].address==address) return &array[i]; } \
    REQUIRE(count<limit);array[count].address=address;return &array[count++]; } \
static uint32_t audio_##name##_address(type *p) { return p ? p->address : 0; }
AUDIO_MAP(buffer,audio_buffer,audio_buffers,audio_buffer_count,256)
AUDIO_MAP(device,audio_device,audio_devices,audio_device_count,32)
#undef AUDIO_MAP
static unsigned audio_sample_index(audio_sample *sample) {
    for (unsigned i=0;i<audio_sample_count;++i) if (sample==&audio_samples[i]) return i;
    REQUIRE(0);return 0;
}
static uint32_t audio_sample_address(audio_sample *sample) { return sample ? audio_sample_addresses[audio_sample_index(sample)] : 0; }
static audio_sample *audio_sample_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<audio_sample_count;++i) if (audio_sample_addresses[i]==address) return &audio_samples[i];
    REQUIRE(audio_sample_count<256);audio_sample_addresses[audio_sample_count]=address;return &audio_samples[audio_sample_count++];
}
/* The incoming boundary requires live records. Do not infer this premise from
 * pointer equality: a source free keeps its old slot until the caller clears it. */
static void audio_admit_live_inputs(void) {
    if (audio_input_lifetimes) { audio_input_lifetimes();return; }
    for (unsigned i=0;i<50;++i) {
        uint32_t address=*word(0x42c948+4*i);
        if (address) audio_retired[audio_sample_index(audio_sample_view(address))]=0;
    }
}
static void audio_samples_to_native(void) {
    for (unsigned i=0;i<50;++i) if (sound.slots[i]) {
        audio_sample *sample=sound.slots[i];unsigned index=audio_sample_index(sample);
        if (audio_retired[index]) continue;
        uint32_t address=audio_sample_addresses[index];*word(address)=audio_buffer_address(sample->buffer);
        memcpy((void *)(uintptr_t)(address+4),sample->payload,33);
    }
}
static void audio_samples_from_native(void) {
    for (unsigned i=0;i<50;++i) if (sound.slots[i]) {
        audio_sample *sample=sound.slots[i];unsigned index=audio_sample_index(sample);
        if (audio_retired[index]) continue;
        uint32_t address=audio_sample_addresses[index];sample->buffer=audio_buffer_view(*word(address));
        memcpy(sample->payload,(void *)(uintptr_t)(address+4),33);
    }
}
#include "audio-native.h"
#define AUDIO_BEGIN() (void)u;REQUIRE(s==&sound);audio_to_native()
#define AUDIO_END() audio_from_native()
static uint32_t audio_platform(enum spx_wine_api api,uint32_t receiver,uint32_t value,void *out) {
    spx_wine_call call={0};call.api=api;call.receiver=(void *)(uintptr_t)receiver;
    call.arguments[0]=value;call.argument_count=1;call.output=out;
    return spx_wine_candidate_call(wine_environment,call);
}
#define AUDIO_BUFFER_ONE(name,api) void audio_##name(void *u,audio_state *s,audio_buffer *buffer,uint32_t value) { \
    AUDIO_BEGIN();(void)audio_platform(api,audio_buffer_address(buffer),value,NULL);AUDIO_END(); }
AUDIO_BUFFER_ONE(frequency,SPX_DS_FREQUENCY) AUDIO_BUFFER_ONE(pan,SPX_DS_PAN)
AUDIO_BUFFER_ONE(volume,SPX_DS_VOLUME) AUDIO_BUFFER_ONE(position,SPX_DS_POSITION)
#undef AUDIO_BUFFER_ONE
#define AUDIO_BUFFER_ZERO(name,api) void audio_##name(void *u,audio_state *s,audio_buffer *buffer) { \
    AUDIO_BEGIN();(void)audio_platform(api,audio_buffer_address(buffer),0,NULL);AUDIO_END(); }
AUDIO_BUFFER_ZERO(stop,SPX_DS_STOP) AUDIO_BUFFER_ZERO(release_buffer,SPX_COM_RELEASE)
#undef AUDIO_BUFFER_ZERO
uint32_t audio_play(void *u,audio_state *s,audio_buffer *buffer,uint32_t flags) {
    AUDIO_BEGIN();uint32_t result=audio_platform(SPX_DS_PLAY,audio_buffer_address(buffer),flags,NULL);AUDIO_END();return result;
}
void audio_status(void *u,audio_state *s,audio_buffer *buffer,audio_status_word *status) {
    AUDIO_BEGIN();uint32_t result=audio_platform(SPX_DS_STATUS,audio_buffer_address(buffer),0,&status->flags);
    if(result) {
        fprintf(stderr,"audio boundary: failed GetStatus requires original-caller restore history transport\n");fflush(NULL);ExitProcess(86);
    }
    AUDIO_END();
}
uint32_t audio_restore_buffer(void *u,audio_state *s,audio_buffer *buffer) {
    AUDIO_BEGIN();uint32_t result=audio_platform(SPX_DS_RESTORE,audio_buffer_address(buffer),0,NULL);AUDIO_END();return result;
}
void audio_release_device(void *u,audio_state *s,audio_device *device) {
    AUDIO_BEGIN();(void)audio_platform(SPX_COM_RELEASE,audio_device_address(device),0,NULL);AUDIO_END();
}
void audio_free_sample(void *u,audio_state *s,audio_sample *sample) {
    AUDIO_BEGIN();unsigned index=audio_sample_index(sample);
    ((void (*)(uint32_t))0x40e2a0)(audio_sample_address(sample));audio_retired[index]=1;AUDIO_END();
}
void audio_load_sample(void *u,audio_state *s,uint32_t slot,audio_name *name) {
    AUDIO_BEGIN();((void (*)(uint32_t,const char *))0x403000)(slot,name->text);
    audio_admit_live_inputs();AUDIO_END();
}
#undef AUDIO_BEGIN
#undef AUDIO_END
typedef struct { uint32_t device,primary,records[50],buffers[50];unsigned char names[50][33]; } audio_snapshot;
static struct { uint32_t operation,args[4];audio_snapshot before,after; } audio_records[256];
static void audio_capture(audio_snapshot *out) {
    audio_from_native();memset(out,0,sizeof(*out));out->device=sound.device!=NULL;out->primary=sound.primary!=NULL;
    for (unsigned i=0;i<50;++i) if (sound.slots[i]) {
        audio_sample *sample=sound.slots[i];unsigned index=audio_sample_index(sample);
        out->records[i]=index+1;
        if (audio_retired[index]) continue;
        out->buffers[i]=sample->buffer ? (uint32_t)(sample->buffer-audio_buffers)+1 : 0;
        unsigned n=0;while (n<33 && sample->payload[n]) { out->names[i][n]=sample->payload[n];++n; }
        REQUIRE(n<33);
    }
}
static void audio_before(unsigned operation,uint32_t a,uint32_t b,uint32_t c,uint32_t d) {
    audio_admit_live_inputs();
    if (++audio_depth!=1) return;
    REQUIRE(audio_count<256);audio_records[audio_count].operation=operation;
    uint32_t args[]={a,b,c,d};memcpy(audio_records[audio_count].args,args,sizeof(args));audio_capture(&audio_records[audio_count].before);
}
static void audio_after(void) { if (--audio_depth) return;audio_capture(&audio_records[audio_count++].after); }
#define AUDIO_ENTRY0(name,operation,address) static void live_audio_##name(void) { \
    audio_before(operation,0,0,0,0);audio_from_native(); \
    if (source_side) { audio_history overwritten={0};fixture_audio_##name(&sound,&overwritten);audio_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_audio_##name##_hook));((void (*)(void))address)(); \
        install_audio_##name##_hook.entry=NULL;REQUIRE(install_audio_##name(live_audio_##name)); }audio_after(); }
AUDIO_ENTRY0(suspend,0,0x402f20) AUDIO_ENTRY0(release_all,1,0x402f90) AUDIO_ENTRY0(stop_all,5,0x403350) AUDIO_ENTRY0(shutdown,8,0x403460)
#undef AUDIO_ENTRY0
#define AUDIO_ENTRY1(name,operation,address) static void live_audio_##name(uint32_t slot) { \
    audio_before(operation,slot,0,0,0);audio_from_native(); \
    if (source_side) { audio_history overwritten={0};fixture_audio_##name(&sound,&overwritten,slot);audio_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_audio_##name##_hook));((void (*)(uint32_t))address)(slot); \
        install_audio_##name##_hook.entry=NULL;REQUIRE(install_audio_##name((void (*)(void))live_audio_##name)); }audio_after(); }
AUDIO_ENTRY1(release_one,2,0x402fb0) AUDIO_ENTRY1(stop,6,0x403370)
#undef AUDIO_ENTRY1
#define AUDIO_ENTRY4(name,operation,address) static void live_audio_##name(uint32_t slot,uint32_t a,uint32_t b,uint32_t c) { \
    audio_before(operation,slot,a,b,c);audio_from_native(); \
    if (source_side) { audio_history overwritten={0};fixture_audio_##name(&sound,&overwritten,slot,a,b,c);audio_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_audio_##name##_hook));((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))address)(slot,a,b,c); \
        install_audio_##name##_hook.entry=NULL;REQUIRE(install_audio_##name((void (*)(void))live_audio_##name)); }audio_after(); }
AUDIO_ENTRY4(play,3,0x403210) AUDIO_ENTRY4(loop,4,0x4032b0)
#undef AUDIO_ENTRY4
static void __attribute__((naked)) audio_original_restore(void) {
    __asm__ volatile("movl _audio_entry_restore_history, %eax\n\tmovl %eax, -0x104(%esp)\n\tmovl $0x4033d0, %eax\n\tjmp *%eax\n\t");
}
static void live_audio_restore(void);
static void __attribute__((used,noinline)) audio_restore_body(void) {
    audio_before(7,0,0,0,0);audio_from_native();
    if (source_side) { audio_history overwritten={0};fixture_audio_restore(&sound,&overwritten);audio_to_native(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_audio_restore_hook));audio_original_restore();
        install_audio_restore_hook.entry=NULL;REQUIRE(install_audio_restore(live_audio_restore)); }
    audio_after();
}
static void __attribute__((naked)) live_audio_restore(void) {
    __asm__ volatile("movl -0x104(%esp), %eax\n\tmovl %eax, _audio_entry_restore_history\n\tjmp _audio_restore_body\n\t");
}
static void audio_observe_state(spx_observer *o,const char *name,const audio_snapshot *state) {
    spx_observe_object(o,name);spx_observe_u64(o,"device",state->device);spx_observe_u64(o,"primary",state->primary);
    spx_observe_u32s(o,"records",state->records,50);spx_observe_u32s(o,"buffers",state->buffers,50);
    spx_observe_bytes(o,"names",(const unsigned char *)state->names,sizeof(state->names));spx_observe_end(o);
}
static void audio_observe(spx_observer *o) {
    display_observe(o);spx_wine_observe(wine_environment,o,"wine_platform");spx_observe_array(o,"audio_bank");
    for (unsigned i=0;i<audio_count;++i) {
        spx_observe_object(o,NULL);spx_observe_u64(o,"operation",audio_records[i].operation);
        spx_observe_u32s(o,"arguments",audio_records[i].args,4);
        audio_observe_state(o,"before",&audio_records[i].before);audio_observe_state(o,"after",&audio_records[i].after);spx_observe_end(o);
    }
    spx_observe_end(o);
}
static void audio_diagnose(spx_observer *o) { display_diagnose(o);spx_observe_u32s(o,"selected_audio_bank",audio_entries,9); }
static void audio_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT");if (!path) return;FILE *out=fopen(path,"wb");REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out);audio_observe(&o);REQUIRE(spx_observe_finish(&o));fputs(",\"diagnostics\":",out);
    o=spx_observe_begin(out);audio_diagnose(&o);REQUIRE(spx_observe_finish(&o));fputs("}\n",out);fclose(out);
}
static BOOL audio_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!display_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { audio_report();return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
    wine_environment=spx_wine_create(SPX_WINE_NATIVE);REQUIRE(spx_wine_install(wine_environment,NULL,1,1));
    spx_wine_set_hooks(wine_environment,(spx_wine_hooks){.before=audio_platform_inputs});
#define AUDIO_HOOK(name) REQUIRE(install_audio_##name((void (*)(void))live_audio_##name));
    AUDIO_HOOK(suspend) AUDIO_HOOK(release_all) AUDIO_HOOK(release_one) AUDIO_HOOK(play) AUDIO_HOOK(loop)
    AUDIO_HOOK(stop_all) AUDIO_HOOK(stop) AUDIO_HOOK(restore) AUDIO_HOOK(shutdown)
#undef AUDIO_HOOK
    return TRUE;
}
#ifndef AUDIO_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return audio_main(instance,reason,reserved); }
#endif
