/* Independent native/C sound-bank consumer; no sound device or game startup. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "audio-runtime.h"
#include "spx-observation.h"
#include "spx-wine-test.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
static spx_wine_env *wine_environment;
static audio_buffer *buffers[8];
static audio_device *devices[2];
static void (*sync_from)(void),(*sync_to)(void);
static void (*application_callback)(uint32_t);
static audio_sample samples[8];
static audio_state sound;
static audio_history history;
static uint32_t scenario,entries[9],calls,loaded;
static uint32_t sample_live[8],buffer_refs[8],device_refs[2],buffer_status[8];
static uint32_t frequency[8],pan[8],volume[8],position[8];
static int source_side;
static spx_observer *observer;
static void require(int test,const char *expression,unsigned line) {
    if (!test) { fprintf(stderr,"audio-runtime.c:%u: adapter premise failed: %s\n",line,expression);exit(3); }
}
#define REQUIRE(test) require(!!(test),#test,__LINE__)
#define ID(name,type,array,count) static uint32_t name##_id(const type *p) { \
    if (!p) return 0; \
    for (unsigned i=0;i<count;++i) { if (p==&array[i]) return i+1; } \
    REQUIRE(0);return 0; }
ID(sample,audio_sample,samples,8)
static uint32_t buffer_id(const audio_buffer *p) { return spx_wine_object_id(p); }
static uint32_t device_id(const audio_device *p) { return p ? spx_wine_object_id(p)-8 : 0; }
#undef ID
void audio_enter(unsigned operation) { REQUIRE(operation<9);++entries[operation]; }
static void call_release(uint32_t slot);
static void snapshot(const char *name) {
    for(unsigned i=0;i<8;++i) {
        spx_wine_object_state b=spx_wine_state(buffers[i]);
        buffer_refs[i]=b.references;buffer_status[i]=b.status;frequency[i]=b.frequency;pan[i]=b.pan;volume[i]=b.volume;position[i]=b.position;
    }
    for(unsigned i=0;i<2;++i)device_refs[i]=spx_wine_state(devices[i]).references;
    spx_observe_object(observer,name);uint32_t roots[52]={device_id(sound.device),buffer_id(sound.primary)};
    for (unsigned i=0;i<50;++i) roots[i+2]=sample_id(sound.slots[i]);
    spx_observe_u32s(observer,"roots",roots,52);spx_observe_u32s(observer,"samples_live",sample_live,8);
    spx_observe_u32s(observer,"buffer_references",buffer_refs,8);spx_observe_u32s(observer,"device_references",device_refs,2);
    spx_observe_u32s(observer,"buffer_status",buffer_status,8);spx_observe_u32s(observer,"frequency",frequency,8);
    spx_observe_u32s(observer,"pan",pan,8);spx_observe_u32s(observer,"volume",volume,8);spx_observe_u32s(observer,"position",position,8);
    spx_observe_array(observer,"records");
    for (unsigned i=0;i<8;++i) {
        spx_observe_object(observer,NULL);spx_observe_u64(observer,"buffer",buffer_id(samples[i].buffer));
        spx_observe_bytes(observer,"payload",samples[i].payload,33);spx_observe_end(observer);
    }
    spx_observe_end(observer);spx_observe_end(observer);
}
static void begin(audio_state *s,unsigned operation,const uint32_t *args,unsigned count) {
    REQUIRE(s==&sound && calls++<1000);spx_observe_object(observer,NULL);spx_observe_u64(observer,"operation",operation);
    spx_observe_u32s(observer,"arguments",args,count);snapshot("before");
}
static uint32_t end(uint32_t result) {
    snapshot("after");spx_observe_u64(observer,"provider_result",result);spx_observe_end(observer);return result;
}
#define BEGIN(name,...) (void)u;const uint32_t args[]={__VA_ARGS__};begin(s,AUDIO_SERVICE_##name,args,sizeof(args)/sizeof(*args))
static uint32_t platform_call(spx_wine_call call) {
    if(sync_to)sync_to();
    uint32_t result=spx_wine_candidate_call(wine_environment,call);
    if(sync_from)sync_from();
    return result;
}
static uint32_t platform_method(enum spx_wine_api api,void *receiver,uint32_t value,void *output) {
    spx_wine_call call={0};call.api=api;call.receiver=receiver;call.arguments[0]=value;call.argument_count=1;call.output=output;
    return platform_call(call);
}
#define BUFFER_METHOD(name,api) void audio_##name(void *u,audio_state *s,audio_buffer *buffer,uint32_t value) { \
    (void)u;REQUIRE(s==&sound);(void)platform_method(api,buffer,value,NULL); }
BUFFER_METHOD(frequency,SPX_DS_FREQUENCY) BUFFER_METHOD(pan,SPX_DS_PAN)
BUFFER_METHOD(volume,SPX_DS_VOLUME) BUFFER_METHOD(position,SPX_DS_POSITION)
#undef BUFFER_METHOD
uint32_t audio_play(void *u,audio_state *s,audio_buffer *buffer,uint32_t flags) {
    (void)u;REQUIRE(s==&sound);return platform_method(SPX_DS_PLAY,buffer,flags,NULL);
}
void audio_status(void *u,audio_state *s,audio_buffer *buffer,audio_status_word *status) {
    (void)u;REQUIRE(s==&sound);(void)platform_method(SPX_DS_STATUS,buffer,0,&status->flags);
}
uint32_t audio_restore_buffer(void *u,audio_state *s,audio_buffer *buffer) {
    (void)u;REQUIRE(s==&sound);return platform_method(SPX_DS_RESTORE,buffer,0,NULL);
}
void audio_stop(void *u,audio_state *s,audio_buffer *buffer) {
    (void)u;REQUIRE(s==&sound);(void)platform_method(SPX_DS_STOP,buffer,0,NULL);
}
void audio_release_buffer(void *u,audio_state *s,audio_buffer *buffer) {
    (void)u;REQUIRE(s==&sound);(void)platform_method(SPX_COM_RELEASE,buffer,0,NULL);
}
void audio_release_device(void *u,audio_state *s,audio_device *device) {
    (void)u;REQUIRE(s==&sound);(void)platform_method(SPX_COM_RELEASE,device,0,NULL);
}
/* These callbacks describe application state mutations at boundary interactions;
 * all COM effects, outputs, errors and reference counts belong to the backend. */
static void bank_callback(uint32_t action) {
    switch(action) {
    case 1:sound.slots[4]=&samples[1];break;
    case 2:sound.slots[4]=&samples[2];break;
    case 3:sound.slots[4]=&samples[1];sound.slots[17]=NULL;break;
    case 4:sound.slots[4]=&samples[2];sound.slots[49]=NULL;break;
    case 5:sound.primary=buffers[6];break;
    case 6:sound.device=devices[1];break;
    default:REQUIRE(0);
    }
}
static void platform_before(void *context,const spx_wine_event *event) {
    (void)context;if(sync_from)sync_from();
    begin(&sound,1024+event->api,event->arguments,event->argument_count);
    spx_observe_u64(observer,"receiver",event->receiver);
}
static void platform_callback(void *context,uint32_t action) {
    (void)context;if(sync_from)sync_from();application_callback(action);if(sync_to)sync_to();
}
static void platform_after(void *context,const spx_wine_event *event) {
    (void)context;if(sync_from)sync_from();(void)end(event->result);
}
static void rule(enum spx_wine_api api,uint32_t receiver,uint32_t occurrence,uint32_t flags,uint32_t result,uint32_t action) {
    spx_wine_add_rule(wine_environment,(spx_wine_rule){.api=api,.receiver=receiver,.occurrence=occurrence,
        .flags=flags,.result=result,.callback=action});
}
static void bank_schedule(void) {
    if(scenario==3 || scenario==4 || scenario==5 || scenario==30 || scenario==32)
        rule(SPX_DS_PLAY,0,scenario==32 ? 0 : 1,SPX_RULE_RETURN,scenario==4 ? 2 : UINT32_C(0x88780096),0);
    if(scenario==6)rule(SPX_DS_PLAY,0,0,SPX_RULE_RETURN,1,0);
    if(scenario==11 || scenario==14 || scenario==15) {
        unsigned first=scenario==15 ? 2 : 1;
        for(unsigned i=first;i<=50;++i)rule(SPX_DS_STATUS,0,i,SPX_RULE_NO_WRITE|SPX_RULE_RETURN,UINT32_C(0x88780032),0);
    }
    if(scenario==13)rule(SPX_DS_RESTORE,0,0,SPX_RULE_RETURN,UINT32_C(0x8878000a),0);
    if(scenario==20)rule(SPX_COM_RELEASE,1,0,SPX_RULE_CALLBACK,0,1);
    if(scenario==22) { rule(SPX_DS_STATUS,1,0,SPX_RULE_CALLBACK,0,1);rule(SPX_DS_STOP,0,0,SPX_RULE_CALLBACK,0,2); }
    if(scenario==23) { rule(SPX_DS_FREQUENCY,0,0,SPX_RULE_CALLBACK,0,1);rule(SPX_DS_PAN,0,0,SPX_RULE_CALLBACK,0,2); }
    if(scenario==24) { rule(SPX_DS_STATUS,1,0,SPX_RULE_CALLBACK,0,3);rule(SPX_DS_RESTORE,2,0,SPX_RULE_CALLBACK,0,4); }
    if(scenario==33)rule(SPX_COM_RELEASE,8,0,SPX_RULE_CALLBACK,0,5);
    if(scenario==34)rule(SPX_COM_RELEASE,9,0,SPX_RULE_CALLBACK,0,6);
}
void audio_free_sample(void *u,audio_state *s,audio_sample *sample) {
    uint32_t id=sample_id(sample);BEGIN(FREE_SAMPLE,id);REQUIRE(id && sample_live[id-1]);sample_live[id-1]=0;
    /* Allocator-owned storage remains addressable in this fixture, but its
     * contents are changed so a borrowed name cannot masquerade as a copy. */
    memset(sample->payload,0xda,sizeof(sample->payload));
    if (scenario==21) s->slots[4]=&samples[1];
    (void)end(0);
}
void audio_load_sample(void *u,audio_state *s,uint32_t slot,audio_name *name) {
    BEGIN(LOAD_SAMPLE,slot);REQUIRE(name && name->text && slot<50 && loaded<5);
    spx_observe_bytes(observer,"name_before",(const unsigned char *)name->text,strlen(name->text));
    spx_observe_array(observer,"callbacks");call_release(slot);spx_observe_end(observer);
    spx_observe_bytes(observer,"name_after",(const unsigned char *)name->text,strlen(name->text));
    uint32_t index=3+loaded++;REQUIRE(strlen(name->text)<20);memset(samples[index].payload,0x5a,33);
    memcpy(samples[index].payload,name->text,strlen(name->text)+1);samples[index].buffer=buffers[index];
    sample_live[index]=1;spx_wine_object_state state=spx_wine_state(buffers[index]);
    state.references=4;state.status=0;++state.generation;spx_wine_controlled_state((void *)buffers[index],state);s->slots[slot]=&samples[index];(void)end(0);
}
#undef BEGIN

#ifndef DX_STANDALONE
static uint32_t native_samples[8][10];
uint32_t audio_native_restore_history;
static uint32_t *word(uint32_t address) { return (uint32_t *)(uintptr_t)address; }
#define MAP(name,type,views,natives,count) \
static uint32_t audio_##name##_address(type *p) { return p ? (uint32_t)(uintptr_t)natives[name##_id(p)-1] : 0; } \
static type *audio_##name##_view(uint32_t address) { \
    if (!address) return NULL; \
    for (unsigned i=0;i<count;++i) { if (address==(uint32_t)(uintptr_t)natives[i]) return &views[i]; } \
    REQUIRE(0);return NULL; }
MAP(sample,audio_sample,samples,native_samples,8)
static uint32_t audio_buffer_address(audio_buffer *p) { return (uint32_t)(uintptr_t)p; }
static uint32_t audio_device_address(audio_device *p) { return (uint32_t)(uintptr_t)p; }
static audio_buffer *audio_buffer_view(uint32_t address) { return (audio_buffer *)(uintptr_t)address; }
static audio_device *audio_device_view(uint32_t address) { return (audio_device *)(uintptr_t)address; }
#undef MAP
static void audio_samples_to_native(void) {
    for (unsigned i=0;i<8;++i) { native_samples[i][0]=audio_buffer_address(samples[i].buffer);memcpy(&native_samples[i][1],samples[i].payload,33); }
}
static void audio_samples_from_native(void) {
    for (unsigned i=0;i<8;++i) { samples[i].buffer=audio_buffer_view(native_samples[i][0]);memcpy(samples[i].payload,&native_samples[i][1],33); }
}
#include "audio-native.h"
#define NATIVE_BEGIN() audio_from_native()
#define NATIVE_END() audio_to_native()
static void native_free(uint32_t sample) { NATIVE_BEGIN();audio_free_sample(NULL,&sound,audio_sample_view(sample));NATIVE_END(); }
static void native_load(uint32_t slot,const char *text) { NATIVE_BEGIN();audio_name name={text};audio_load_sample(NULL,&sound,slot,&name);NATIVE_END(); }
static void __attribute__((naked)) seeded_restore(void) {
    __asm__ volatile("movl _audio_native_restore_history, %eax\n\tmovl %eax, -0x104(%esp)\n\tmovl $0x4033d0, %eax\n\tjmp *%eax\n\t");
}
static void original_restore(void) {
    REQUIRE(spx_fixture_restore_entry(&install_audio_restore_hook));seeded_restore();
    install_audio_restore_hook.entry=NULL;REQUIRE(install_audio_restore(original_restore));
}
#define ROOT0(name) static void native_root_##name(void) { NATIVE_BEGIN();fixture_audio_##name(&sound,&history);NATIVE_END(); }
ROOT0(suspend) ROOT0(release_all) ROOT0(stop_all) ROOT0(restore) ROOT0(shutdown)
#undef ROOT0
#define ROOT1(name) static void native_root_##name(uint32_t slot) { NATIVE_BEGIN();fixture_audio_##name(&sound,&history,slot);NATIVE_END(); }
ROOT1(release_one) ROOT1(stop)
#undef ROOT1
#define ROOT4(name) static void native_root_##name(uint32_t slot,uint32_t frequency,uint32_t pan,uint32_t volume) { \
    NATIVE_BEGIN();fixture_audio_##name(&sound,&history,slot,frequency,pan,volume);NATIVE_END(); }
ROOT4(play) ROOT4(loop)
#undef ROOT4
static void install(void) {
    sync_from=audio_from_native;sync_to=audio_to_native;
    REQUIRE(install_audio_free((void (*)(void))native_free));REQUIRE(install_audio_load((void (*)(void))native_load));
    if (!source_side) { REQUIRE(install_audio_restore(original_restore));return; }
#define HOOK(name) REQUIRE(install_audio_##name((void (*)(void))native_root_##name));
    HOOK(suspend) HOOK(release_all) HOOK(release_one) HOOK(play) HOOK(loop) HOOK(stop_all) HOOK(stop) HOOK(restore) HOOK(shutdown)
#undef HOOK
}
#endif

static void call_release(uint32_t slot) {
#ifndef DX_STANDALONE
    audio_to_native();((void (*)(uint32_t))0x402fb0)(slot);audio_from_native();
#else
    fixture_audio_release_one(&sound,&history,slot);
#endif
}
static void setup(void) {
    wine_environment=spx_wine_create(SPX_WINE_CONTROLLED);application_callback=bank_callback;
    for(unsigned i=0;i<8;++i)buffers[i]=(void *)spx_wine_seed(wine_environment,i+1,SPX_WINE_DS_BUFFER,(spx_wine_object_state){.references=4});
    for(unsigned i=0;i<2;++i)devices[i]=(void *)spx_wine_seed(wine_environment,i+9,SPX_WINE_DS_DEVICE,(spx_wine_object_state){.references=2});
    spx_wine_set_hooks(wine_environment,(spx_wine_hooks){.before=platform_before,.callback=platform_callback,.after=platform_after});
    sound.device=devices[0];sound.primary=buffers[7];device_refs[0]=2;device_refs[1]=2;
    history.restore_status=scenario==14 ? 2 : UINT32_C(0x80000000);
    for (unsigned i=0;i<8;++i) {
        samples[i].buffer=buffers[i];memset(samples[i].payload,0x70+i,33);snprintf((char *)samples[i].payload,20,"sample-%u.wav",i);
        sample_live[i]=i<3;buffer_refs[i]=4;position[i]=100+i;frequency[i]=22050+i;pan[i]=23+i;volume[i]=42+i;
    }
    sound.slots[4]=&samples[0];sound.slots[17]=&samples[1];sound.slots[49]=&samples[2];
    if (scenario==3 || scenario==4 || scenario==5 || scenario==10 || scenario==12 || scenario==13 || scenario==15 || scenario==24 || scenario==30 || scenario==32) buffer_status[0]=2;
    if (scenario==12 || scenario==13) buffer_status[1]=2;
    if (scenario==7 || scenario==17 || scenario==28 || scenario==31) sound.device=NULL;
    if (scenario==8 || scenario==18) sound.slots[4]=NULL;
    if (scenario==19) samples[0].buffer=NULL;
    if (scenario==11) { sound.slots[2]=sound.slots[4];sound.slots[4]=NULL; }
    for(unsigned i=0;i<8;++i)spx_wine_controlled_state((void *)buffers[i],(spx_wine_object_state){
        .references=buffer_refs[i],.status=buffer_status[i],.frequency=frequency[i],.pan=pan[i],.volume=volume[i],.position=position[i],.generation=1});
    bank_schedule();
#ifndef DX_STANDALONE
    audio_native_restore_history=history.restore_status;
#endif
}
static void run_operation(unsigned operation,uint32_t slot,uint32_t a,uint32_t b,uint32_t c) {
#ifndef DX_STANDALONE
    audio_to_native();
    switch (operation) {
    case 0:((void (*)(void))0x402f20)();break;
    case 1:((void (*)(void))0x402f90)();break;
    case 2:((void (*)(uint32_t))0x402fb0)(slot);break;
    case 3:((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))0x403210)(slot,a,b,c);break;
    case 4:((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))0x4032b0)(slot,a,b,c);break;
    case 5:((void (*)(void))0x403350)();break;
    case 6:((void (*)(uint32_t))0x403370)(slot);break;
    case 7:((void (*)(void))0x4033d0)();break;
    case 8:((void (*)(void))0x403460)();break;
    default:REQUIRE(0);
    }
    audio_from_native();
#else
    switch (operation) {
    case 0:fixture_audio_suspend(&sound,&history);break;
    case 1:fixture_audio_release_all(&sound,&history);break;
    case 2:fixture_audio_release_one(&sound,&history,slot);break;
    case 3:fixture_audio_play(&sound,&history,slot,a,b,c);break;
    case 4:fixture_audio_loop(&sound,&history,slot,a,b,c);break;
    case 5:fixture_audio_stop_all(&sound,&history);break;
    case 6:fixture_audio_stop(&sound,&history,slot);break;
    case 7:fixture_audio_restore(&sound,&history);break;
    case 8:fixture_audio_shutdown(&sound,&history);break;
    default:REQUIRE(0);
    }
#endif
}
int main(int argc,char **argv) {
    REQUIRE(argc==3);scenario=(uint32_t)strtoul(argv[2],NULL,10);REQUIRE(scenario<36);
    source_side=!strcmp(argv[1],"source");REQUIRE(source_side || !strcmp(argv[1],"original"));setup();
#ifndef DX_STANDALONE
    install();audio_to_native();
#else
    REQUIRE(source_side);
#endif
    spx_observer out=spx_observe_begin(stdout);observer=&out;spx_observe_object(observer,"audio");snapshot("initial");
    spx_observe_u64(observer,"restore_history",history.restore_status);spx_observe_array(observer,"calls");
    unsigned op=scenario<=8 || scenario==23 || scenario==32 ? (scenario==2 || scenario==5 ? 4 : 3) :
        scenario<=11 || scenario==22 || scenario==35 ? 6 : scenario<=15 || scenario==24 || scenario==31 ? 7 :
        scenario<=21 ? 2 : scenario==25 ? 5 : scenario==26 ? 1 : scenario==29 ? 8 : 0;
    if (scenario==30) {
        const unsigned sequence[]={3,4,6,2,7,5,0,1,8};
        for (unsigned i=0;i<sizeof(sequence)/sizeof(*sequence);++i) run_operation(sequence[i],4,12000,UINT32_C(0xfffff000),31);
    } else run_operation(op,scenario==11 ? 2 : scenario==35 ? 49 : 4,
        scenario==1 ? 0 : 12000,scenario==1 ? 0 : UINT32_C(0xfffff000),scenario==1 ? 0 : 31);
    spx_observe_end(observer);snapshot("final");spx_wine_observe(wine_environment,observer,"platform");spx_observe_end(observer);REQUIRE(spx_observe_finish(observer));fputc('\n',stdout);return 0;
}
#ifndef DX_STANDALONE
struct native_startupinfo { int newmode; };
int __cdecl __getmainargs(int *,char ***,char ***,int,struct native_startupinfo *);
static LONG WINAPI fault(EXCEPTION_POINTERS *p) {
    fprintf(stderr,"native fault %08lx at %08lx\n",p->ExceptionRecord->ExceptionCode,p->ContextRecord->Eip);fflush(NULL);ExitProcess(86);return EXCEPTION_EXECUTE_HANDLER;
}
static void run_case(void) {
    SetUnhandledExceptionFilter(fault);int argc;char **argv,**environment;struct native_startupinfo startup={0};
    REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&startup));int result=main(argc,argv);fflush(NULL);ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_audio_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reserved;return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
