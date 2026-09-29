/* Application boundary: sample records, file bytes and allocation schedules.
 * Platform execution and observations are owned by the shared Wine backend. */
#include <setjmp.h>
#define main bank_test_main
#define DllMain bank_test_DllMain
#define audio_load_sample bank_scripted_load_sample
#include "bank-runtime.c"
#undef audio_load_sample
#undef DllMain
#undef main
#include "wave-runtime.h"
#ifndef DX_STANDALONE
#include "comparison-services.h"
#endif
static unsigned char file_image[512];
static wave_bytes file_view={file_image};
static wave_history load_history;
static uint32_t wave_case,wave_entries[2],allocated,file_live,terminated,termination_code;
static jmp_buf wave_exit;
void wave_enter(unsigned operation) { REQUIRE(operation<2);++wave_entries[operation]; }
static void file_word(unsigned offset,uint32_t value) {
    REQUIRE(offset+4<=sizeof(file_image));
    for(unsigned i=0;i<4;++i)file_image[offset+i]=(unsigned char)(value>>(8*i));
}
static void make_format(unsigned offset,uint32_t rate) {
    file_word(offset,UINT32_C(0x00010001));file_word(offset+4,rate);
    file_word(offset+8,2*rate);file_word(offset+12,UINT32_C(0x00100002));
}
static unsigned chunk(unsigned at,uint32_t kind,uint32_t length) {
    file_word(at,kind);file_word(at+4,length);
    return at+8+((length+1)&~UINT32_C(1));
}
static void make_file(void) {
    memset(file_image,0x69,sizeof(file_image));
    file_word(0,wave_case==4 ? 0 : UINT32_C(0x46464952));
    file_word(8,wave_case==5 ? 0 : UINT32_C(0x45564157));
    unsigned at=12;
    if(wave_case==11 || wave_case==34)at=chunk(at,UINT32_C(0x4b4e554a),3);
    if(wave_case==34)at=chunk(at,UINT32_C(0x44444150),7);
    if(wave_case==36)at=chunk(at,UINT32_C(0x4b4e554a),UINT32_MAX);
    if(wave_case!=6 && wave_case!=7 && wave_case!=13) {
        unsigned length=wave_case==8 ? 13 : wave_case==9 ? 14 : 16;
        make_format(at+8,22050);at=chunk(at,UINT32_C(0x20746d66),length);
    }
    if(wave_case==10 || wave_case==35) {
        make_format(at+8,16000);at=chunk(at,UINT32_C(0x20746d66),wave_case==35 ? 13 : 16);
    }
    if(wave_case!=7 && wave_case!=12) {
        for(unsigned i=0;i<16;++i)file_image[at+8+i]=(unsigned char)(3*i+11);
        at=chunk(at,UINT32_C(0x61746164),16);
    }
    if(wave_case==13) { make_format(at+8,11025);at=chunk(at,UINT32_C(0x20746d66),16); }
    if(wave_case==33)at=chunk(at,UINT32_C(0x61746164),8);
    file_word(4,at-8);make_format(384,8000);load_history.format=file_image+384;
}
static uint32_t file_offset(const unsigned char *p) {
    if(!p)return UINT32_MAX;
    for(unsigned i=0;i<sizeof(file_image);++i)if(p==file_image+i)return i;
    REQUIRE(0);return 0;
}
static void wave_begin(audio_state *s,unsigned operation,const uint32_t *args,unsigned count) {
    begin(s,200+operation,args,count);
    spx_observe_u64(observer,"file_live_before",file_live);
}
static uint32_t wave_end(uint32_t result) {
    spx_observe_u64(observer,"file_live_after",file_live);return end(result);
}
void wave_release_one(void *u,audio_state *s,uint32_t slot) {
    (void)u;REQUIRE(s==&sound);call_release(slot);
}
audio_sample *wave_allocate(void *u,audio_state *s,uint32_t bytes) {
    (void)u;wave_begin(s,0,&bytes,1);REQUIRE(bytes==37 && allocated<5);
    if(wave_case==2) { (void)wave_end(0);return NULL; }
    unsigned index=3+allocated++;REQUIRE(!sample_live[index]);sample_live[index]=1;
    (void)wave_end(index+1);return &samples[index];
}
wave_bytes *wave_read_file(void *u,audio_state *s,audio_name *name,uint32_t offset,uint32_t owned) {
    (void)u;uint32_t args[]={offset,owned};wave_begin(s,1,args,2);
    spx_observe_bytes(observer,"name",(const unsigned char *)name->text,strlen(name->text));
    REQUIRE(!offset && owned==1 && !file_live);
    if(wave_case==3) { (void)wave_end(0);return NULL; }
    file_live=1;
    if(wave_case==27)sound.slots[4]=&samples[1];
    (void)wave_end(1);return &file_view;
}
void wave_free_sample(void *u,audio_state *s,audio_sample *sample) { audio_free_sample(u,s,sample); }
void wave_free_file(void *u,audio_state *s,wave_bytes *file) {
    (void)u;REQUIRE(file==&file_view && file_live);wave_begin(s,2,NULL,0);file_live=0;
    if(wave_case==26)sound.slots[4]=&samples[1];
    (void)wave_end(0);
}
void wave_terminate(void *u,uint32_t code) {
    (void)u;wave_begin(&sound,3,&code,1);terminated=1;termination_code=code;(void)wave_end(0);longjmp(wave_exit,1);
}
uint32_t wave_create_buffer(void *u,audio_state *s,audio_device *device,audio_sample *sample,wave_buffer_spec *spec) {
    (void)u;REQUIRE(s==&sound);spx_wine_call call={0};call.api=SPX_DS_CREATE_BUFFER;call.receiver=(void *)device;
    spx_wine_buffer_spec view={spec->size,spec->flags,spec->bytes,spec->reserved,spec->format};call.input=&view;
#ifndef DX_STANDALONE
    call.output=word(audio_sample_address(sample));
#else
    call.output=&sample->buffer;
#endif
    return platform_call(call);
}
uint32_t wave_lock(void *u,audio_state *s,audio_buffer *buffer,uint32_t length,wave_locked *locked) {
    (void)u;REQUIRE(s==&sound);spx_wine_call call={0};call.api=SPX_DS_LOCK;call.receiver=(void *)buffer;
    call.arguments[1]=length;call.argument_count=3;spx_wine_locked parts={0};call.output=&parts;
    uint32_t result=platform_call(call);
    if(!result) { locked->first=parts.first;locked->second=parts.second;locked->first_bytes=parts.first_bytes;locked->second_bytes=parts.second_bytes; }
    return result;
}
void wave_unlock(void *u,audio_state *s,audio_buffer *buffer,wave_locked *locked) {
    (void)u;REQUIRE(s==&sound);spx_wine_call call={0};call.api=SPX_DS_UNLOCK;call.receiver=(void *)buffer;
    spx_wine_locked parts={locked->first,locked->second,locked->first_bytes,locked->second_bytes};call.input=&parts;
    (void)platform_call(call);
}
static void wave_query(audio_state *s,audio_buffer *buffer,wave_word *output,enum spx_wine_api api) {
    REQUIRE(s==&sound);
#ifndef DX_STANDALONE
    void *destination=NULL;
    for(unsigned i=0;i<8;++i)for(unsigned j=0;j+4<=33;++j)
        if(output->bytes==samples[i].payload+j)destination=(unsigned char *)&native_samples[i][1]+j;
    REQUIRE(destination);
#else
    void *destination=output->bytes;
#endif
    (void)platform_method(api,buffer,0,destination);
}
void wave_frequency(void *u,audio_state *s,audio_buffer *buffer,wave_word *output) { (void)u;wave_query(s,buffer,output,SPX_DS_GET_FREQUENCY); }
void wave_pan(void *u,audio_state *s,audio_buffer *buffer,wave_word *output) { (void)u;wave_query(s,buffer,output,SPX_DS_GET_PAN); }
void wave_volume(void *u,audio_state *s,audio_buffer *buffer,wave_word *output) { (void)u;wave_query(s,buffer,output,SPX_DS_GET_VOLUME); }
static void wave_call_load(uint32_t,const char *);
void audio_load_sample(void *u,audio_state *s,uint32_t slot,audio_name *name) {
    (void)u;REQUIRE(s==&sound);wave_call_load(slot,name->text);
}
static void wave_callback(uint32_t action) {
    switch(action) {
    case 200:sound.slots[4]=&samples[1];break;
    case 201:sound.slots[4]=&samples[2];break;
    case 202:sound.device=devices[1];break;
    case 203:samples[1].buffer=sound.slots[4]->buffer;sound.slots[4]=&samples[1];break;
    default:bank_callback(action);
    }
}
static void wave_schedule(void) {
    if(wave_case>=14 && wave_case<=16) {
        spx_wine_add_rule(wine_environment,(spx_wine_rule){.api=SPX_DS_CREATE_BUFFER,
            .flags=SPX_RULE_RETURN|(wave_case==16 ? SPX_RULE_OBJECT : SPX_RULE_NO_WRITE),
            .result=wave_case==15 ? 1 : UINT32_C(0x80004005),.object=4});
    }
    if(wave_case==17 || wave_case==18)rule(SPX_DS_LOCK,0,0,SPX_RULE_RETURN,wave_case==18 ? 1 : UINT32_C(0x80004005),0);
    if(wave_case==19)rule(SPX_DS_UNLOCK,0,0,SPX_RULE_RETURN,UINT32_C(0x80004005),0);
    if(wave_case==20)rule(SPX_DS_GET_FREQUENCY,0,0,SPX_RULE_RETURN|SPX_RULE_NO_WRITE,UINT32_C(0x80004005),0);
    if(wave_case==21 || wave_case==22)spx_wine_add_rule(wine_environment,(spx_wine_rule){
        .api=wave_case==21 ? SPX_DS_GET_PAN : SPX_DS_GET_VOLUME,.flags=SPX_RULE_RETURN|SPX_RULE_WORD,
        .result=UINT32_C(0x80004005),.mask=wave_case==21 ? 0xff : UINT32_MAX,.value=UINT32_C(0xaabbcc02)});
    if(wave_case==24)rule(SPX_DS_GET_FREQUENCY,0,0,SPX_RULE_CALLBACK,0,200);
    if(wave_case==25)rule(SPX_DS_GET_PAN,0,0,SPX_RULE_CALLBACK,0,201);
    if(wave_case==28)rule(SPX_DS_CREATE_BUFFER,0,0,SPX_RULE_CALLBACK,0,202);
    if(wave_case==29)rule(SPX_DS_CREATE_BUFFER,0,0,SPX_RULE_CALLBACK,0,203);
    if(wave_case==30)rule(SPX_DS_LOCK,0,0,SPX_RULE_CALLBACK,0,203);
}
#ifndef DX_STANDALONE
uint32_t wave_native_format_history;
static void __attribute__((naked)) original_wave_load(uint32_t slot,const char *name) {
    (void)slot;(void)name;
    __asm__ volatile("movl _wave_native_format_history, %eax\n\tmovl %eax, -4(%esp)\n\tmovl $0x403000, %eax\n\tjmp *%eax\n\t");
}
static uint32_t native_wave_allocate(uint32_t bytes) {
    audio_from_native();audio_sample *sample=wave_allocate(NULL,&sound,bytes);audio_to_native();return audio_sample_address(sample);
}
static unsigned char *native_wave_file(const char *text,uint32_t offset,uint32_t owned) {
    audio_from_native();audio_name name={text};wave_bytes *file=wave_read_file(NULL,&sound,&name,offset,owned);audio_to_native();return file ? file->bytes : NULL;
}
static void native_wave_free(uint32_t address) {
    audio_from_native();
    if(address==(uint32_t)(uintptr_t)file_image)wave_free_file(NULL,&sound,&file_view);
    else wave_free_sample(NULL,&sound,audio_sample_view(address));
    audio_to_native();
}
static void native_wave_terminate(uint32_t code) { audio_from_native();wave_terminate(NULL,code); }
static void wave_install(void) {
    install();REQUIRE(spx_fixture_restore_entry(&install_audio_load_hook));
    REQUIRE(spx_fixture_restore_entry(&install_audio_free_hook));install_audio_free_hook.entry=NULL;
    REQUIRE(install_audio_free((void (*)(void))native_wave_free));
    REQUIRE(install_wave_allocate((void (*)(void))native_wave_allocate));REQUIRE(install_wave_file((void (*)(void))native_wave_file));
    REQUIRE(install_wave_terminate((void (*)(void))native_wave_terminate));
    REQUIRE(spx_wine_install(wine_environment,NULL,1,0));
}
#endif
static void wave_call_load(uint32_t slot,const char *text) {
    audio_name name={text};
#ifndef DX_STANDALONE
    audio_to_native();
    if(source_side)fixture_wave_load(&sound,&load_history,slot,&name);
    else { wave_native_format_history=(uint32_t)(uintptr_t)load_history.format;original_wave_load(slot,text);audio_from_native(); }
#else
    fixture_wave_load(&sound,&load_history,slot,&name);
#endif
}
int main(int argc,char **argv) {
    REQUIRE(argc==3);unsigned selection=(unsigned)strtoul(argv[2],NULL,10);int parser=selection>=100;
    wave_case=parser ? selection-100 : selection;REQUIRE(wave_case<37);
    source_side=!strcmp(argv[1],"source");REQUIRE(source_side || !strcmp(argv[1],"original"));
    scenario=1000;setup();application_callback=wave_callback;wave_schedule();make_file();
    if(wave_case==1)sound.device=NULL;
#ifndef DX_STANDALONE
    wave_install();audio_to_native();
#else
    REQUIRE(source_side);
#endif
    spx_observer out=spx_observe_begin(stdout);observer=&out;spx_observe_object(observer,"wave");snapshot("initial");
    spx_observe_bytes(observer,"file",file_image,sizeof(file_image));spx_observe_array(observer,"calls");
#ifndef DX_STANDALONE
    uint32_t handler=source_side ? spx_service_handler_begin() : 0;
#endif
    if(!setjmp(wave_exit)) {
        if(parser) {
            wave_result result={file_image+384,file_image+480,UINT32_C(0xaabbccdd)};uint32_t answer;
#ifndef DX_STANDALONE
            if(!source_side)answer=((uint32_t (*)(unsigned char *,const unsigned char **,const unsigned char **,uint32_t *))0x403470)(
                file_image,&result.format,&result.data,&result.length);
            else answer=fixture_wave_parse(&file_view,&result);
#else
            answer=fixture_wave_parse(&file_view,&result);
#endif
            spx_observe_object(observer,NULL);uint32_t values[]={answer,file_offset(result.format),file_offset(result.data),result.length};
            spx_observe_u32s(observer,"parse",values,4);spx_observe_end(observer);
        } else {
            const char *name=wave_case==23 ? "a-long-sample-name-123456789.wav" : "sample.wav";
            wave_call_load(4,name);
            if(wave_case==31)wave_call_load(4,"second.wav");
            if(wave_case==32) { run_operation(6,4,0,0,0);run_operation(2,4,0,0,0); }
        }
    } else {
        REQUIRE(terminated);
#ifndef DX_STANDALONE
        if(source_side)spx_service_handler_catch(handler,"process-exit");
#endif
    }
#ifndef DX_STANDALONE
    if(source_side)spx_service_handler_end(handler);
#endif
    spx_observe_end(observer);snapshot("final");spx_observe_u64(observer,"file_live",file_live);
    uint32_t outcome[]={terminated,termination_code};spx_observe_u32s(observer,"outcome",outcome,2);
    spx_wine_observe(wine_environment,observer,"platform");spx_observe_end(observer);REQUIRE(spx_observe_finish(observer));puts("");return 0;
}
#ifndef DX_STANDALONE
static void wave_run_case(void) {
    SetUnhandledExceptionFilter(fault);int argc;char **argv,**environment;struct native_startupinfo startup={0};
    REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&startup));int result=main(argc,argv);fflush(NULL);ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_wave_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reserved;return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(wave_run_case));
}
#endif
