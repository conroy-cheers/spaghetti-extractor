#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define REQUIRE(x) do { if(!(x)) { fprintf(stderr,"MDS stream boundary line %d: %s\n",__LINE__,#x);abort(); } } while(0)
#define MDS_PARSER_NORMAL 1
static void provider_during_read(unsigned char *raw);
#define PARSER_HEADER_READ(raw) provider_during_read(raw)
#include "mds-transport.c"
#include "loader-transport.c"
#include "stream-transport.c"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
static unsigned provider_interleave,provider_changed;
static unsigned provider_read_interleave,provider_read_armed,provider_read_changed;
static void provider_during_read(unsigned char *raw) {
    if(provider_read_armed && parser_pool_count && raw==parser_pools[0].raw) {
        parser_store(raw+20,0x5e010203);provider_read_armed=0;++provider_read_changed;
    }
}
static int source_side;static uint32_t selected[5],loader_selected,parser_selected,events_selected;
static uint32_t steps[32][12];static unsigned step_count,callback_count;
void stream_enter(unsigned op) { REQUIRE(op<5);++selected[op]; }
void loader_enter(void) { ++loader_selected; }
void parser_enter(void) { ++parser_selected; }
void mds_events_enter(void) { ++events_selected; }
static uint32_t parser_do_expand(mds_event_block *input,mds_event_block *output) { return fixture_mds_expand(input,output); }
static uint32_t run_parser(uint32_t *info,const unsigned char *bytes,uint32_t length) {
    parser_begin(info,spx_wine_memory_storage(parser_environment,info).identity);uint32_t result;
#ifndef DX_STANDALONE
    if(!source_side) {
        REQUIRE(spx_fixture_restore_entry(&install_mds_parse_hook));
        result=((uint32_t (*)(uint32_t *,const unsigned char *,uint32_t))0x401b60)(info,bytes,length);
        install_mds_parse_hook.entry=NULL;REQUIRE(install_mds_parse((void (*)(void))run_parser));
    } else
#endif
    { mds_file file={bytes};result=fixture_mds_parse(&parser_current->view,&file,length);parser_push(); }
    parser_active=0;loader_snapshot();return result;
}
static uint32_t loader_do_parse(mds_info *info,mds_file *file,uint32_t length) { return run_parser(loader_record_view(info)->info->raw,file->data,length); }
static void provider_updates_links(uint32_t message) {
    if(provider_interleave && message==0x3c9 && !provider_changed++) {
        REQUIRE(parser_pool_count);parser_store(parser_pools[0].raw+20,0x5e010203);
    }
}
static void SPX_WINE_CALLBACK live_complete(uintptr_t stream,uint32_t message,uintptr_t instance,uintptr_t first,uintptr_t second) {
    stream_header_record *h=message==0x3c9 ? stream_header_pointer(first) : NULL;
    if(provider_read_interleave && message==0x3c9 && !provider_read_changed)provider_read_armed=1;
    stream_frame frame=stream_begin(h ? h->view.buffer->owner : NULL);++callback_count;
#ifndef DX_STANDALONE
    if(!source_side) {
        REQUIRE(spx_fixture_restore_entry(&install_mds_complete_hook));
        ((spx_wine_midi_callback)0x4020c0)(stream,message,instance,first,second);provider_updates_links(message);
        install_mds_complete_hook.entry=NULL;REQUIRE(install_mds_complete((void (*)(void))live_complete));
    } else
#else
    (void)stream;(void)instance;(void)second;
#endif
    { fixture_mds_complete(message,h ? &h->view : NULL);provider_updates_links(message);stream_push(); }
    stream_pull();stream_end(frame);
}
#ifndef DX_STANDALONE
static uint32_t live_start(uint32_t *raw,uint32_t loop) {
    mds_info *info=loader_info(parser_bits(raw));stream_frame frame=stream_begin(info);uint32_t result;
    if(source_side) { result=fixture_mds_start(info,loop);stream_push();REQUIRE(install_mds_start_intact()); }
    else { REQUIRE(spx_fixture_restore_entry(&install_mds_start_hook));result=((uint32_t (*)(uint32_t *,uint32_t))0x401ea0)(raw,loop);
        install_mds_start_hook.entry=NULL;REQUIRE(install_mds_start((void (*)(void))live_start)); }
    stream_pull();stream_end(frame);return result;
}
#define ENTRY(name,address) static uint32_t live_##name(uint32_t *raw) { \
    mds_info *info=loader_info(parser_bits(raw));stream_frame frame=stream_begin(info);uint32_t result; \
    if(source_side) { result=fixture_mds_##name(info);stream_push();REQUIRE(install_mds_##name##_intact()); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_mds_##name##_hook));result=((uint32_t (*)(uint32_t *))address)(raw); \
        install_mds_##name##_hook.entry=NULL;REQUIRE(install_mds_##name((void (*)(void))live_##name)); } \
    stream_pull();stream_end(frame);return result; }
ENTRY(pause,0x401fe0) ENTRY(stop,0x402030) ENTRY(release,0x401e40)
#undef ENTRY
#endif
static void record(unsigned op,uint32_t result,mds_info *info) {
    REQUIRE(step_count<32);uint32_t *s=steps[step_count++];loader_record *r=loader_record_view(info);s[0]=op;s[1]=result;s[2]=r->live;
    memcpy(s+3,r->snapshot,36);parser_pool *p=parser_pool_at(s[7]);if(p)s[7]=p->identity;s[8]=stream_identity(s[8]);
}
static uint32_t invoke(unsigned op,mds_info *info,uint32_t loop) {
    uint32_t result;
#ifndef DX_STANDALONE
    uint32_t *raw=loader_record_view(info)->info->raw;
    if(op==0)result=live_start(raw,loop);
    else if(op==1)result=live_pause(raw);
    else if(op==2)result=live_stop(raw);
    else { REQUIRE(op==4);result=live_release(raw); }
#else
    stream_frame frame=stream_begin(info);
    if(op==0)result=fixture_mds_start(info,loop);
    else if(op==1)result=fixture_mds_pause(info);
    else if(op==2)result=fixture_mds_stop(info);
    else { REQUIRE(op==4);result=fixture_mds_release(info); }
    stream_push();stream_pull();stream_end(frame);
#endif
    record(op,result,info);return result;
}
static void mutate(mds_info *info,unsigned word,uint32_t value) {
    loader_record *r=loader_record_view(info);REQUIRE(r->live && word<9);r->info->raw[word]=value;
    stream_frame f=stream_begin(info);stream_end(f);
}
static void complete(mds_info *info) {
    stream_frame frame=stream_begin(info);mds_header view={&info->buffers->headers[0]};stream_header_record *h=stream_header_view(&view);
    spx_wine_midi_complete(parser_environment,info->stream,spx_wine_midi_header_identity(parser_environment,stream_platform_header(h)));
    stream_pull();stream_end(frame);record(3,0,info);
}
static unsigned char file[1048576];
static mds_info *load(unsigned mode) {
    uint32_t length;
    if(mode>=100) {
        const char *names[]={"12flight.mds","Acker-gs.mds","Brain.mds","Ethno_pa.mds","Freebee.mds","Gmfigaro.mds"};
        REQUIRE(mode<106);FILE *f=fopen(names[mode-100],"rb");REQUIRE(f);size_t n=fread(file,1,sizeof(file),f);REQUIRE(!ferror(f) && feof(f));fclose(f);length=(uint32_t)n;
    } else {
        uint32_t data[]={0x46464952,68,0x5344494d,0x20746d66,12,96,32,1,0x61746164,36,2,0,8,1,0x02000000,0,8,2,0x02000000};
        for(unsigned i=0;i<sizeof(data)/sizeof(*data);++i)parser_store(file+4*i,data[i]);
        length=sizeof(data);
        if(mode==41) { parser_store(file+4,44);parser_store(file+24,0);parser_store(file+36,12);parser_store(file+40,1);parser_store(file+48,0);length=52; }
    }
    uint32_t slot=0,result;loader_active=1;loader_current=NULL;
#ifndef DX_STANDALONE
    if(!source_side)result=((uint32_t (*)(uint32_t *,const unsigned char *,uint32_t,uint32_t))0x401a20)(&slot,file,length,2);
    else
#endif
    { mds_output output={NULL};mds_input input={file};result=fixture_mds_load(&output,&input,length,2);slot=loader_address(output.value); }
    REQUIRE(!result && slot && loader_identity(slot)==loader_current->identity);loader_snapshot();loader_active=0;return loader_info(slot);
}
static void rule(enum spx_wine_api api,uint32_t occurrence,uint32_t result) {
    spx_wine_add_rule(parser_environment,(spx_wine_rule){.api=api,.occurrence=occurrence,.flags=SPX_RULE_RETURN,.result=result});
}
int main(int argc,char **argv) {
    REQUIRE(argc==3);unsigned mode=(unsigned)strtoul(argv[2],NULL,10);source_side=!strcmp(argv[1],"source");REQUIRE(mode<44 || (mode>=100 && mode<106));
    provider_interleave=mode==42;provider_read_interleave=mode==43;
    parser_environment=spx_wine_create(SPX_WINE_CONTROLLED);spx_wine_allocation_history(parser_environment,0x5a);
    if(mode==40)spx_wine_allow_retained_midi_disposal(parser_environment);
    spx_wine_set_hooks(parser_environment,(spx_wine_hooks){.before=stream_before,.after=stream_after});
#ifndef DX_STANDALONE
    REQUIRE(spx_wine_install_memory(parser_environment,NULL,SPX_WINE_MEMORY_ALL));REQUIRE(spx_wine_install_midi(parser_environment,NULL,SPX_WINE_MIDI_ALL));
    REQUIRE(install_mds_parse((void (*)(void))run_parser));REQUIRE(install_mds_start((void (*)(void))live_start));
    REQUIRE(install_mds_pause((void (*)(void))live_pause));REQUIRE(install_mds_stop((void (*)(void))live_stop));
    REQUIRE(install_mds_release((void (*)(void))live_release));REQUIRE(install_mds_complete((void (*)(void))live_complete));
    stream_callback_function=(spx_wine_midi_callback)0x4020c0;SetLastError(0);
#else
    REQUIRE(source_side);stream_callback_function=live_complete;
#endif
    spx_wine_bind_midi_callback(parser_environment,stream_callback_function,0,1);
    mds_info *info=load(mode),*other=mode==39 ? load(0) : NULL;
    if(mode>=6 && mode<=9) { mutate(info,0,0);invoke(mode==6 ? 0 : mode==7 ? 1 : mode==8 ? 2 : 4,info,1); }
    else if(mode==10 || mode==11)invoke(mode==10 ? 1 : 2,info,0);
    else {
        if(mode==12)rule(SPX_MIDI_OPEN,1,2);
        if(mode==13)spx_wine_add_rule(parser_environment,(spx_wine_rule){.api=SPX_MIDI_OPEN,.occurrence=1,.flags=SPX_RULE_RETURN|SPX_RULE_OBJECT,.result=2,.object=SPX_WINE_FAILED_PUBLICATION});
        if(mode==14)rule(SPX_MIDI_PROPERTY,1,1);
        if(mode==15 || mode==16)rule(SPX_MIDI_PREPARE,mode==15 ? 1 : 2,7);
        if(mode==17 || mode==18)rule(SPX_MIDI_OUT,mode==17 ? 1 : 2,1);
        if(mode==19 || mode==35)rule(SPX_MIDI_RESTART,mode==19 ? 1 : 2,1);
        if(mode==20)rule(SPX_MIDI_PAUSE,1,1);
        if(mode==21 || mode==40)rule(SPX_MIDI_RESET,1,1);
        if(mode==22)rule(SPX_MIDI_UNPREPARE,1,1);
        if(mode==23)rule(SPX_MIDI_CLOSE,1,1);
        if(mode==24)rule(SPX_MIDI_OUT,3,1);
        if(mode==26)mutate(info,8,UINT32_MAX);
        if(mode==28)mutate(info,6,0xa5000084);
        if(mode==29)mutate(info,7,0);
        if(mode==30) {
            spx_wine_add_rule(parser_environment,(spx_wine_rule){.api=SPX_MIDI_RESET,.flags=SPX_RULE_DEFER_COMPLETIONS});
            rule(SPX_MIDI_CLOSE,1,0);
        }
        if(mode==32)rule(SPX_GLOBAL_FREE,1,1);
        if(mode==33)spx_wine_add_rule(parser_environment,(spx_wine_rule){.api=SPX_GLOBAL_UNLOCK,.occurrence=1,.flags=SPX_RULE_RETURN|SPX_RULE_ERROR,.result=0,.last_error=8});
        if(mode==34)rule(SPX_LOCAL_FREE,1,1);
        if(mode<31 || mode>34) {
            uint32_t loop=mode==1 || mode==24 || mode==37 || mode==39 ? 1 : mode==38 ? 2 : 0;
            invoke(0,info,loop);
            if(other)invoke(0,other,0);
            if(mode==4)invoke(0,info,1);
            if(mode==3 || mode==5 || mode==20 || mode==35) { invoke(1,info,0);if(mode==5)invoke(1,info,0);else if(mode!=20)invoke(0,info,1); }
            if(mode==25)mutate(info,8,0);
            if(mode==37)mutate(info,6,info->flags|1);
            if(mode==1 || mode==2 || mode==24 || mode==25 || mode==37 || mode==38 || mode==39 || mode==42 || mode==43)complete(info);
            if(mode==27)live_complete(123,0x1234,456,0,789);
            if(mode!=40)invoke(2,info,0);
            if(mode==36) { invoke(0,info,0);invoke(2,info,0); }
            if(other)invoke(2,other,0);
        }
        invoke(4,info,0);if(other)invoke(4,other,0);
    }
    for(unsigned i=0;i<loader_record_count;++i)loader_records[i].snapshot[5]=stream_identity(loader_records[i].snapshot[5]);
    spx_observer o=spx_observe_begin(stdout);spx_observe_object(&o,"mds_stream");spx_observe_array(&o,"steps");
    for(unsigned i=0;i<step_count;++i)spx_observe_u32s(&o,NULL,steps[i],12);
    spx_observe_end(&o);spx_observe_u64(&o,"callbacks",callback_count);loader_observe(&o);spx_wine_observe(parser_environment,&o,"platform");
    spx_observe_end(&o);REQUIRE(spx_observe_finish(&o));puts("");parser_dispose_views();spx_wine_destroy(parser_environment);return 0;
}
#ifndef DX_STANDALONE
struct native_startupinfo { int newmode; };
extern int __cdecl __getmainargs(int *,char ***,char ***,int,struct native_startupinfo *);
static void run_case(void) {
    int argc;char **argv,**environment;struct native_startupinfo startup={0};REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&startup));
    int result=main(argc,argv);fflush(NULL);ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_mds_stream_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reserved;return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
