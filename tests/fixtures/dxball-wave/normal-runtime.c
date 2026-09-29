/* Shared owner transport and real lower services for normal program execution. */
#define SETUP_NORMAL_LIBRARY_ONLY 1
#include "setup-normal-runtime.c"
#include "wave-runtime.h"

static uint32_t wave_entries[2],wave_depth,wave_count,wave_pending_record;
uint32_t wave_entry_format_history;
static wave_bytes wave_files[128];
static unsigned wave_file_count;
static struct {
    uint32_t slot,allocations,frees,sample_allocations,sample_frees;
    char name[33];
    audio_snapshot before,after;
    uint32_t live_before[50],live_after[50];
} wave_records[128];
void wave_enter(unsigned operation) { REQUIRE(operation<2);++wave_entries[operation]; }
static void wave_reconcile_lifetimes(void) {
    /* Allocation/free interception owns these flags. Merely seeing the same
     * address in an incoming slot must not turn a retired record live again. */
    for(unsigned i=0;i<50;++i) {
        uint32_t address=*word(0x42c948+4*i);if(!address)continue;
        unsigned found=0;
        for(unsigned j=0;j<audio_sample_count;++j)if(audio_sample_addresses[j]==address)found=1;
        REQUIRE(found);
    }
}
static void wave_lifetimes(uint32_t *live) {
    for(unsigned i=0;i<50;++i)live[i]=sound.slots[i] ? !audio_retired[audio_sample_index(sound.slots[i])] : 0;
}
static uint32_t native_wave_allocate(uint32_t bytes);
static void native_wave_free(uint32_t address);
static uint32_t native_wave_allocate(uint32_t bytes) {
    REQUIRE(spx_fixture_restore_entry(&install_wave_allocate_hook));
    uint32_t address=((uint32_t (*)(uint32_t))0x40e2f0)(bytes);
    install_wave_allocate_hook.entry=NULL;REQUIRE(install_wave_allocate((void (*)(void))native_wave_allocate));
    if(wave_depth) {
        ++wave_records[wave_count].allocations;
        if(wave_pending_record) {
            REQUIRE(bytes==37);wave_pending_record=0;
            if(address) {
                audio_sample *sample=audio_sample_view(address);unsigned index=audio_sample_index(sample);
                audio_retired[index]=0;sample->buffer=audio_buffer_view(*word(address));
                memcpy(sample->payload,(void *)(uintptr_t)(address+4),33);
                ++wave_records[wave_count].sample_allocations;
            }
        }
    }
    return address;
}
static void native_wave_free(uint32_t address) {
    if(wave_depth)++wave_records[wave_count].frees;
    for(unsigned i=0;i<audio_sample_count;++i)if(audio_sample_addresses[i]==address) {
        audio_retired[i]=1;if(wave_depth)++wave_records[wave_count].sample_frees;
    }
    REQUIRE(spx_fixture_restore_entry(&install_wave_free_hook));
    ((void (*)(uint32_t))0x40e2a0)(address);
    install_wave_free_hook.entry=NULL;REQUIRE(install_wave_free((void (*)(void))native_wave_free));
}
#define WAVE_BEGIN() (void)u;REQUIRE(state==&sound);audio_to_native()
#define WAVE_END() audio_from_native()
void wave_release_one(void *u,audio_state *state,uint32_t slot) {
    WAVE_BEGIN();((void (*)(uint32_t))0x402fb0)(slot);WAVE_END();
}
audio_sample *wave_allocate(void *u,audio_state *state,uint32_t bytes) {
    WAVE_BEGIN();uint32_t address=((uint32_t (*)(uint32_t))0x40e2f0)(bytes);WAVE_END();return audio_sample_view(address);
}
wave_bytes *wave_read_file(void *u,audio_state *state,audio_name *name,uint32_t offset,uint32_t owned) {
    WAVE_BEGIN();unsigned char *bytes=((unsigned char *(*)(const char *,uint32_t,uint32_t))0x40d9f0)(name->text,offset,owned);
    WAVE_END();if(!bytes)return NULL;REQUIRE(wave_file_count<128);
    wave_files[wave_file_count].bytes=bytes;return &wave_files[wave_file_count++];
}
void wave_free_sample(void *u,audio_state *state,audio_sample *sample) {
    WAVE_BEGIN();((void (*)(uint32_t))0x40e2a0)(audio_sample_address(sample));WAVE_END();
}
void wave_free_file(void *u,audio_state *state,wave_bytes *file) {
    WAVE_BEGIN();((void (*)(void *))0x40e2a0)(file->bytes);WAVE_END();
}
void wave_terminate(void *u,uint32_t code) { (void)u;((void (*)(uint32_t))0x40e3d0)(code); }
uint32_t wave_create_buffer(void *u,audio_state *state,audio_device *device,audio_sample *sample,wave_buffer_spec *spec) {
    WAVE_BEGIN();spx_wine_call call={0};call.api=SPX_DS_CREATE_BUFFER;call.receiver=(void *)(uintptr_t)audio_device_address(device);
    spx_wine_buffer_spec view={spec->size,spec->flags,spec->bytes,spec->reserved,spec->format};call.input=&view;
    call.output=word(audio_sample_address(sample));uint32_t result=spx_wine_candidate_call(wine_environment,call);WAVE_END();return result;
}
uint32_t wave_lock(void *u,audio_state *state,audio_buffer *buffer,uint32_t length,wave_locked *locked) {
    WAVE_BEGIN();spx_wine_call call={0};call.api=SPX_DS_LOCK;call.receiver=(void *)(uintptr_t)audio_buffer_address(buffer);
    call.arguments[1]=length;call.argument_count=3;spx_wine_locked parts={0};call.output=&parts;
    uint32_t result=spx_wine_candidate_call(wine_environment,call);WAVE_END();
    if(!result) { locked->first=parts.first;locked->second=parts.second;locked->first_bytes=parts.first_bytes;locked->second_bytes=parts.second_bytes; }
    return result;
}
void wave_unlock(void *u,audio_state *state,audio_buffer *buffer,wave_locked *locked) {
    WAVE_BEGIN();spx_wine_call call={0};call.api=SPX_DS_UNLOCK;call.receiver=(void *)(uintptr_t)audio_buffer_address(buffer);
    spx_wine_locked parts={locked->first,locked->second,locked->first_bytes,locked->second_bytes};call.input=&parts;
    (void)spx_wine_candidate_call(wine_environment,call);WAVE_END();
}
static void wave_query(audio_state *state,audio_buffer *buffer,wave_word *output,enum spx_wine_api api) {
    REQUIRE(state==&sound);audio_to_native();void *destination=NULL;
    for(unsigned i=0;i<audio_sample_count;++i)for(unsigned j=0;j+4<=33;++j)
        if(output->bytes==audio_samples[i].payload+j) {
            REQUIRE(!audio_retired[i]);destination=(void *)(uintptr_t)(audio_sample_addresses[i]+4+j);
        }
    REQUIRE(destination);(void)audio_platform(api,audio_buffer_address(buffer),0,destination);audio_from_native();
}
void wave_frequency(void *u,audio_state *state,audio_buffer *buffer,wave_word *output) { (void)u;wave_query(state,buffer,output,SPX_DS_GET_FREQUENCY); }
void wave_pan(void *u,audio_state *state,audio_buffer *buffer,wave_word *output) { (void)u;wave_query(state,buffer,output,SPX_DS_GET_PAN); }
void wave_volume(void *u,audio_state *state,audio_buffer *buffer,wave_word *output) { (void)u;wave_query(state,buffer,output,SPX_DS_GET_VOLUME); }
#undef WAVE_BEGIN
#undef WAVE_END
static void live_wave_load(void);
static void __attribute__((naked)) original_wave_load(uint32_t slot,const char *name) {
    (void)slot;(void)name;
    __asm__ volatile("movl _wave_entry_format_history, %eax\n\tmovl %eax, -4(%esp)\n\tmovl $0x403000, %eax\n\tjmp *%eax\n\t");
}
static void __attribute__((used,noinline)) wave_load_body(uint32_t slot,const char *name) {
    REQUIRE(!wave_depth && wave_count<128 && slot<50 && strlen(name)<33);
    audio_from_native();wave_records[wave_count].slot=slot;strcpy(wave_records[wave_count].name,name);
    audio_capture(&wave_records[wave_count].before);wave_lifetimes(wave_records[wave_count].live_before);
    wave_depth=1;wave_pending_record=1;
    if(source_side) {
        wave_history prior={(const unsigned char *)(uintptr_t)wave_entry_format_history};audio_name path={name};
        fixture_wave_load(&sound,&prior,slot,&path);audio_to_native();
    } else {
        REQUIRE(spx_fixture_restore_entry(&install_wave_load_hook));original_wave_load(slot,name);
        install_wave_load_hook.entry=NULL;REQUIRE(install_wave_load(live_wave_load));
    }
    wave_depth=0;audio_from_native();audio_capture(&wave_records[wave_count].after);
    wave_lifetimes(wave_records[wave_count].live_after);++wave_count;
}
static void __attribute__((naked)) live_wave_load(void) {
    __asm__ volatile("movl -4(%esp), %eax\n\tmovl %eax, _wave_entry_format_history\n\tjmp _wave_load_body\n\t");
}
static uint32_t live_wave_parse(unsigned char *bytes,const unsigned char **format,const unsigned char **data,uint32_t *length) {
    wave_bytes file={bytes};wave_result outputs={*format,*data,*length};
    uint32_t result=fixture_wave_parse(&file,&outputs);*format=outputs.format;*data=outputs.data;*length=outputs.length;return result;
}
static void no_native_descriptor_helper(void) { REQUIRE(0); }
static void wave_observe(spx_observer *o) {
    setup_observe(o);spx_observe_array(o,"wave_loads");
    for(unsigned i=0;i<wave_count;++i) {
        spx_observe_object(o,NULL);spx_observe_u64(o,"slot",wave_records[i].slot);
        spx_observe_bytes(o,"name",(const unsigned char *)wave_records[i].name,strlen(wave_records[i].name));
        uint32_t counts[]={wave_records[i].allocations,wave_records[i].frees,wave_records[i].sample_allocations,wave_records[i].sample_frees};
        spx_observe_u32s(o,"allocation_events",counts,4);
        audio_observe_state(o,"before",&wave_records[i].before);audio_observe_state(o,"after",&wave_records[i].after);
        spx_observe_u32s(o,"live_before",wave_records[i].live_before,50);spx_observe_u32s(o,"live_after",wave_records[i].live_after,50);
        spx_observe_end(o);
    }
    spx_observe_end(o);
}
static void wave_diagnose(spx_observer *o) {
    setup_diagnose(o);spx_observe_u32s(o,"selected_wave",wave_entries,2);
}
static void wave_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT");if(!path)return;FILE *out=fopen(path,"wb");REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out);wave_observe(&o);REQUIRE(spx_observe_finish(&o));fputs(",\"diagnostics\":",out);
    o=spx_observe_begin(out);wave_diagnose(&o);REQUIRE(spx_observe_finish(&o));fputs("}\n",out);fclose(out);
}
static BOOL wave_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if(!setup_main(instance,reason,reserved))return FALSE;
    if(reason==DLL_PROCESS_DETACH) { wave_report();return TRUE; }
    if(reason!=DLL_PROCESS_ATTACH)return TRUE;
    audio_input_lifetimes=wave_reconcile_lifetimes;
    REQUIRE(install_wave_allocate((void (*)(void))native_wave_allocate));REQUIRE(install_wave_free((void (*)(void))native_wave_free));
    REQUIRE(install_wave_load(live_wave_load));
    if(source_side) {
        REQUIRE(install_wave_parse((void (*)(void))live_wave_parse));REQUIRE(install_wave_create(no_native_descriptor_helper));
    }
    return TRUE;
}

#ifndef WAVE_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return wave_main(instance,reason,reserved); }
#endif
