/* Controlled application services; WinMM is below this component's boundary. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "music-runtime.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
#define REQUIRE(x) do { if(!(x)) { fprintf(stderr,"music boundary line %d: %s\n",__LINE__,#x);exit(3); } } while(0)
struct spx_opaque_music_stream_v5 { uint32_t id; };
static music_stream streams[3];
static music_record records[3];
static music_state state;
static uint32_t live[3],stream_live[3],entries[4],scenario,call_count;
static struct { uint32_t op,arguments[4],result,before[13],after[13];char name[64]; } calls[64];
void music_enter(unsigned op) { REQUIRE(op<4);++entries[op]; }
static uint32_t record_id(music_record *p) {
    if(!p)return 0;
    for(unsigned i=0;i<3;++i)if(p==&records[i])return i+1;
    REQUIRE(0);return 0;
}
static uint32_t stream_id(music_stream *p) {
    if(!p)return 0;
    for(unsigned i=0;i<3;++i)if(p==&streams[i])return i+1;
    REQUIRE(0);return 0;
}
static void capture(uint32_t *out) {
    *out++=record_id(state.current);
    for(unsigned i=0;i<3;++i) { *out++=stream_id(records[i].stream);*out++=records[i].playing;*out++=live[i]; }
    memcpy(out,stream_live,sizeof(stream_live));
}
static unsigned begin(music_state *s,unsigned op,uint32_t a,uint32_t b,uint32_t c) {
    REQUIRE(s==&state && call_count<64);unsigned i=call_count++;calls[i].op=op;
    calls[i].arguments[0]=a;calls[i].arguments[1]=b;calls[i].arguments[2]=c;capture(calls[i].before);return i;
}
static uint32_t finish(unsigned i,uint32_t result) {
    unsigned op=calls[i].op;
    if((scenario==19 && op==MUSIC_SERVICE_LOAD) || ((scenario==20 || scenario==21 || scenario==26) && op==MUSIC_SERVICE_START_STREAM) ||
       ((scenario==22 || scenario==24) && op==MUSIC_SERVICE_RELEASE_STREAM) || (scenario==23 && op==MUSIC_SERVICE_STOP_STREAM) ||
       (scenario==25 && op==MUSIC_SERVICE_FREE_RECORD) || (scenario==27 && op==MUSIC_SERVICE_PAUSE_STREAM) ||
       (scenario==28 && op==MUSIC_SERVICE_ALLOCATE_RECORD))state.current=&records[2];
    calls[i].result=result;capture(calls[i].after);return result;
}
music_record *music_allocate_record(void *u,music_state *s,uint32_t size) {
    (void)u;unsigned i=begin(s,MUSIC_SERVICE_ALLOCATE_RECORD,size,0,0);REQUIRE(size==8 && !live[1]);
    if(scenario==4) { finish(i,0);return NULL; }
    live[1]=1;finish(i,2);return &records[1];
}
void music_free_record(void *u,music_state *s,music_record *record) {
    (void)u;uint32_t id=record_id(record);unsigned i=begin(s,MUSIC_SERVICE_FREE_RECORD,id,0,0);
    if(id) { REQUIRE(live[id-1]);live[id-1]=0; }
    finish(i,0);
}
uint32_t music_load(void *u,music_state *s,music_record *record,music_name *name,uint32_t length,uint32_t flags) {
    (void)u;unsigned i=begin(s,MUSIC_SERVICE_LOAD,record_id(record),length,flags);REQUIRE(strlen(name->text)<64);strcpy(calls[i].name,name->text);
    uint32_t result=scenario==4 || scenario==5 ? 2 : scenario==6 ? UINT32_C(0x80000000) : 0;
    if(!result) { REQUIRE(record && live[record_id(record)-1]);record->stream=&streams[1];stream_live[1]=1; }
    return finish(i,result);
}
uint32_t music_start_stream(void *u,music_state *s,music_stream *stream,uint32_t loop) {
    (void)u;unsigned i=begin(s,MUSIC_SERVICE_START_STREAM,stream_id(stream),loop,0);REQUIRE(stream && stream_live[stream_id(stream)-1]);
    return finish(i,scenario==8 ? UINT32_MAX : scenario==7 || scenario==11 || scenario==21 || scenario==22 ? 5 : 0);
}
uint32_t music_pause_stream(void *u,music_state *s,music_stream *stream) {
    (void)u;unsigned i=begin(s,MUSIC_SERVICE_PAUSE_STREAM,stream_id(stream),0,0);REQUIRE(stream && stream_live[stream_id(stream)-1]);
    return finish(i,scenario==14 ? 5 : 0);
}
uint32_t music_stop_stream(void *u,music_state *s,music_stream *stream) {
    (void)u;unsigned i=begin(s,MUSIC_SERVICE_STOP_STREAM,stream_id(stream),0,0);REQUIRE(stream && stream_live[stream_id(stream)-1]);
    return finish(i,scenario==17 ? 5 : 0);
}
uint32_t music_release_stream(void *u,music_state *s,music_stream *stream) {
    (void)u;unsigned id=stream_id(stream),i=begin(s,MUSIC_SERVICE_RELEASE_STREAM,id,0,0);REQUIRE(id && stream_live[id-1]);
    if(scenario!=18)stream_live[id-1]=0;
    return finish(i,scenario==18 ? 5 : 0);
}
#ifndef DX_STANDALONE
static uint32_t raw_records[3][2];
static music_record *record_view(uint32_t value) {
    if(!value)return NULL;
    for(unsigned i=0;i<3;++i)if(value==(uint32_t)(uintptr_t)raw_records[i])return &records[i];
    REQUIRE(0);return NULL;
}
static uint32_t record_address(music_record *p) { uint32_t id=record_id(p);return id ? (uint32_t)(uintptr_t)raw_records[id-1] : 0; }
static music_stream *stream_view(uint32_t value) {
    if(!value)return NULL;
    for(unsigned i=0;i<3;++i)if(value==(uint32_t)(uintptr_t)&streams[i])return &streams[i];
    REQUIRE(0);return NULL;
}
static void push(void) {
    *(uint32_t *)0x42c144=record_address(state.current);
    for(unsigned i=0;i<3;++i) { raw_records[i][0]=(uint32_t)(uintptr_t)records[i].stream;raw_records[i][1]=records[i].playing; }
}
static void pull(void) {
    state.current=record_view(*(uint32_t *)0x42c144);
    for(unsigned i=0;i<3;++i) { records[i].stream=stream_view(raw_records[i][0]);records[i].playing=raw_records[i][1]; }
}
static uint32_t native_allocate_record(uint32_t n) { pull();music_record *p=music_allocate_record(NULL,&state,n);push();return record_address(p); }
static void native_free_record(uint32_t p) { pull();music_free_record(NULL,&state,record_view(p));push(); }
static uint32_t native_load(uint32_t p,const char *name,uint32_t length,uint32_t flags) {
    pull();music_name path={name};uint32_t result=music_load(NULL,&state,record_view(p),&path,length,flags);push();return result;
}
static uint32_t native_start_stream(uint32_t p,uint32_t loop) { pull();uint32_t r=music_start_stream(NULL,&state,stream_view(p),loop);push();return r; }
#define ONE(name) static uint32_t native_##name(uint32_t p) { pull();uint32_t r=music_##name(NULL,&state,stream_view(p));push();return r; }
ONE(pause_stream) ONE(stop_stream) ONE(release_stream)
#undef ONE
static uint32_t replaced_play(const char *name,uint32_t start) { pull();music_name path={name};uint32_t r=fixture_music_play(&state,&path,start);push();return r; }
#define ROOT(name) static void replaced_##name(void) { pull();fixture_music_##name(&state);push(); }
ROOT(resume) ROOT(pause) ROOT(stop)
#undef ROOT
#endif
static unsigned operation(void) {
    if(scenario==9 || scenario==10 || scenario==11 || scenario==26)return 1;
    if(scenario==12 || scenario==13 || scenario==14 || scenario==27)return 2;
    if((scenario>=15 && scenario<=18) || (scenario>=23 && scenario<=25))return 3;
    return 0;
}
int main(int argc,char **argv) {
    REQUIRE(argc==3);scenario=(uint32_t)strtoul(argv[2],NULL,10);REQUIRE(scenario<30);
    for(unsigned i=0;i<3;++i) { streams[i].id=i+1;records[i].stream=i==1 ? NULL : &streams[i];records[i].playing=17*(i+1);live[i]=stream_live[i]=i!=1; }
    unsigned op=operation();state.current=(op && scenario!=9 && scenario!=12 && scenario!=15) || scenario==3 ? &records[0] : NULL;
    int source=!strcmp(argv[1],"source");uint32_t answers[4]={0},snapshots[4][13];unsigned count=scenario==29 ? 4 : 1;
#ifndef DX_STANDALONE
#define HOOK(name) REQUIRE(install_music_service_##name((void (*)(void))native_##name));
    HOOK(allocate_record) HOOK(free_record) HOOK(load) HOOK(start_stream) HOOK(pause_stream) HOOK(stop_stream) HOOK(release_stream)
#undef HOOK
    if(source) { REQUIRE(install_music_play((void (*)(void))replaced_play));REQUIRE(install_music_resume(replaced_resume));REQUIRE(install_music_pause(replaced_pause));REQUIRE(install_music_stop(replaced_stop)); }
#else
    REQUIRE(source);
#endif
    for(unsigned i=0;i<count;++i) {
        unsigned current=scenario==29 ? (unsigned[]){0,2,1,3}[i] : op;
        uint32_t start=scenario==0 || scenario==19 ? 0 : scenario==2 ? UINT32_MAX : 1;
#ifndef DX_STANDALONE
        push();
        if(!current)answers[i]=((uint32_t (*)(const char *,uint32_t))0x402100)("track.mds",start);
        else ((void (*)(void))(uintptr_t)((uint32_t[]){0,0x4021a0,0x4021d0,0x402200})[current])();
        pull();
        if(source)REQUIRE(install_music_play_intact() && install_music_resume_intact() && install_music_pause_intact() && install_music_stop_intact());
#else
        if(!current) { music_name path={"track.mds"};answers[i]=fixture_music_play(&state,&path,start); }
        else if(current==1)fixture_music_resume(&state);
        else if(current==2)fixture_music_pause(&state);
        else fixture_music_stop(&state);
#endif
        capture(snapshots[i]);
    }
    spx_observer out=spx_observe_begin(stdout);spx_observe_object(&out,"music");spx_observe_u32s(&out,"returned",answers,count);
    spx_observe_array(&out,"states");for(unsigned i=0;i<count;++i)spx_observe_u32s(&out,NULL,snapshots[i],13);spx_observe_end(&out);
    spx_observe_array(&out,"calls");for(unsigned i=0;i<call_count;++i) {
        spx_observe_object(&out,NULL);spx_observe_u64(&out,"operation",calls[i].op);spx_observe_u32s(&out,"arguments",calls[i].arguments,4);
        spx_observe_u64(&out,"result",calls[i].result);spx_observe_u32s(&out,"before",calls[i].before,13);spx_observe_u32s(&out,"after",calls[i].after,13);
        spx_observe_bytes(&out,"name",(const unsigned char *)calls[i].name,strlen(calls[i].name));spx_observe_end(&out);
    }
    spx_observe_end(&out);spx_observe_end(&out);REQUIRE(spx_observe_finish(&out));puts("");return 0;
}
#ifndef DX_STANDALONE
struct native_startupinfo { int newmode; };
extern int __cdecl __getmainargs(int *,char ***,char ***,int,struct native_startupinfo *);
static void run_case(void) {
    int argc;char **argv,**environment;struct native_startupinfo startup={0};REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&startup));
    int result=main(argc,argv);fflush(NULL);ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_music_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reserved;return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
