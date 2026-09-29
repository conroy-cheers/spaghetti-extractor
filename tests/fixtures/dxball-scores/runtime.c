/* Controlled file effects around the actual native table operations. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scores-runtime.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
#define REQUIRE(c) do { if (!(c)) { fprintf(stderr,"scores adapter:%u: %s\n",__LINE__,#c); exit(3); } } while (0)
struct spx_opaque_scores_file_v5 { uint32_t id,open,writing; };
static scores_state table;
static scores_file files[3]={{1,0,0},{2,0,1},{3,0,0}};
static unsigned char disk[660];
static uint32_t mode,disk_size=660,exists=1,entries[3],calls[64][7],call_count;
void scores_enter(unsigned operation) { REQUIRE(operation<3); ++entries[operation]; }
static uint32_t file_id(scores_file *file) {
    if (!file) return 0;
    for (unsigned i=0;i<3;++i) if (file==&files[i]) return files[i].id;
    REQUIRE(0); return 0;
}
static uint32_t table_hash(void) {
    const unsigned char *p=(const unsigned char *)table.entries; uint32_t h=2166136261U;
    for (unsigned i=0;i<sizeof(table.entries);++i) h=(h^p[i])*16777619U;
    return h;
}
static void record(uint32_t operation,uint32_t a,uint32_t b,uint32_t c) {
    REQUIRE(call_count<64); uint32_t values[]={operation,a,b,c,file_id(table.file),table_hash(),exists};
    memcpy(calls[call_count++],values,sizeof(values));
}
scores_file *scores_open(void *unused,scores_state *state,uint32_t writing) {
    (void)unused; REQUIRE(state==&table && writing<=1);
    int failed=writing ? mode==3 || mode==15 : !exists || mode==4;
    scores_file *file=failed ? NULL : &files[writing]; record(0,writing,file_id(file),0);
    if (file) { REQUIRE(!file->open); file->open=1; if (writing) { exists=1; disk_size=0; } }
    return file;
}
void scores_read(void *unused,scores_state *state,scores_file *file,scores_bytes *bytes) {
    (void)unused; REQUIRE(state==&table && file && file->open && !file->writing);
    REQUIRE(bytes->data==(unsigned char *)table.entries && bytes->size==660);
    uint32_t limit=mode==5 ? 0 : mode==6 ? 1 : mode==7 ? 41 : mode==17 ? 657 : 660;
    uint32_t count=disk_size<limit ? disk_size : limit; record(1,file_id(file),bytes->size,count);
    memcpy(bytes->data,disk,count);
}
void scores_write(void *unused,scores_state *state,scores_file *file,scores_bytes *bytes) {
    (void)unused; REQUIRE(state==&table && file && file->open && file->writing);
    REQUIRE(bytes->data==(unsigned char *)table.entries && bytes->size==660);
    disk_size=mode==16 ? 129 : 660; record(2,file_id(file),bytes->size,disk_size);
    memcpy(disk,bytes->data,disk_size);
}
void scores_close(void *unused,scores_state *state,scores_file *file) {
    (void)unused; REQUIRE(state==&table && file && file->open); record(3,file_id(file),0,0); file->open=0;
}
uint32_t scores_access(void *unused,scores_state *state,uint32_t access_mode) {
    (void)unused; REQUIRE(state==&table && (access_mode==0 || access_mode==2));
    uint32_t result=!exists || (access_mode==2 && mode==14) ? UINT32_MAX : mode==2 ? 1 : 0;
    record(4,access_mode,result,0); return result;
}

#ifndef DX_STANDALONE
static void scores_to_native(void) {
    memcpy((void *)0x431cc8,table.entries,660); *(uint32_t *)0x434964=(uint32_t)(uintptr_t)table.file;
}
static void scores_from_native(void) {
    memcpy(table.entries,(void *)0x431cc8,660); table.file=(scores_file *)(uintptr_t)*(uint32_t *)0x434964;
}
static uint32_t native_scores_open(const char *name,const char *access_mode) {
    REQUIRE(!strcmp(name,"score.dat") && (!strcmp(access_mode,"rb") || !strcmp(access_mode,"wb")));
    scores_from_native(); scores_file *file=scores_open(NULL,&table,!strcmp(access_mode,"wb"));
    scores_to_native(); return (uint32_t)(uintptr_t)file;
}
static uint32_t native_scores_read(void *data,uint32_t size,uint32_t count,scores_file *file) {
    REQUIRE(data==(void *)0x431cc8 && size==44 && count==15); scores_from_native();
    scores_bytes bytes={(unsigned char *)table.entries,660}; scores_read(NULL,&table,file,&bytes); scores_to_native(); return 0;
}
static uint32_t native_scores_write(const void *data,uint32_t size,uint32_t count,scores_file *file) {
    REQUIRE(data==(void *)0x431cc8 && size==44 && count==15); scores_from_native();
    scores_bytes bytes={(unsigned char *)table.entries,660}; scores_write(NULL,&table,file,&bytes); scores_to_native(); return 0;
}
static uint32_t native_scores_close(scores_file *file) {
    scores_from_native(); scores_close(NULL,&table,file); scores_to_native(); return UINT32_MAX;
}
static uint32_t native_scores_access(const char *name,uint32_t access_mode) {
    REQUIRE(!strcmp(name,"score.dat")); scores_from_native();
    uint32_t result=scores_access(NULL,&table,access_mode); scores_to_native(); return result;
}
static void native_scores_load(void) { scores_from_native(); fixture_scores_load(&table); scores_to_native(); }
static void native_scores_initialize(void) { scores_from_native(); fixture_scores_initialize(&table); scores_to_native(); }
static uint32_t native_scores_insert(const char *name,uint32_t value) {
    scores_from_native(); scores_name input={name}; uint32_t rank=fixture_scores_insert(&table,&input,value); scores_to_native(); return rank;
}
static void install(int source) {
#define SERVICE(name) REQUIRE(install_scores_service_##name((void (*)(void))native_scores_##name));
    SERVICE(open) SERVICE(read) SERVICE(write) SERVICE(close) SERVICE(access)
    if (!source) return;
    REQUIRE(install_scores_load(native_scores_load)); REQUIRE(install_scores_initialize(native_scores_initialize));
    REQUIRE(install_scores_insert((void (*)(void))native_scores_insert));
}
#endif
static void snapshot(spx_observer *o) {
    spx_observe_object(o,NULL); spx_observe_bytes(o,"records",(const unsigned char *)table.entries,660);
    uint32_t state[]={file_id(table.file),files[0].open,files[1].open,files[2].open};
    spx_observe_u32s(o,"handles",state,4); spx_observe_end(o);
}
int main(int argc,char **argv) {
    REQUIRE(argc==3); mode=(uint32_t)strtoul(argv[2],NULL,10); REQUIRE(mode<20);
    memset(table.entries,0xa5,sizeof(table.entries)); table.file=&files[2];
    for (unsigned i=0;i<15;++i) {
        score_entry record; memset(&record,0x60+i,sizeof(record));
        snprintf(record.name,sizeof(record.name),"A%u",i); score_set_value(&record,150-10*i);
        if (mode==19 && i==10) score_set_value(&record,500);
        memcpy(disk+44*i,&record,44);
    }
    if (mode==18) {
        FILE *input=fopen("score.dat","rb"); REQUIRE(input); disk_size=(uint32_t)fread(disk,1,660,input); REQUIRE(fclose(input)==0);
    }
    if (mode==1 || mode==3) { exists=0; disk_size=0; }
    uint32_t values[]={75,100,0,10,150,75,10,75,100,9,10,90,150,UINT32_MAX,100,100,100,100,100,100};
    scores_name name={mode==13 ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789xy" : mode==12 ? "" : "C sample"};
    REQUIRE(strlen(name.text)<=39);
#ifndef DX_STANDALONE
    int source=!strcmp(argv[1],"source"); install(source); scores_to_native();
#define CALL(name,address) ((void (*)(void))address)(); scores_from_native(); snapshot(&o)
#else
    REQUIRE(!strcmp(argv[1],"source"));
#define CALL(name,address) fixture_scores_##name(&table); snapshot(&o)
#endif
    spx_observer o=spx_observe_begin(stdout); spx_observe_array(&o,"states");
    CALL(initialize,0x409bb0); CALL(load,0x409a30);
#ifndef DX_STANDALONE
    uint32_t rank=((uint32_t (*)(const char *,uint32_t))0x409a70)(name.text,values[mode]); scores_from_native();
#else
    uint32_t rank=fixture_scores_insert(&table,&name,values[mode]);
#endif
    snapshot(&o); spx_observe_end(&o); spx_observe_array(&o,"services");
    for (uint32_t i=0;i<call_count;++i) spx_observe_u32s(&o,NULL,calls[i],7);
    spx_observe_end(&o); spx_observe_bytes(&o,"file",disk,disk_size); spx_observe_u64(&o,"file_size",disk_size);
    spx_observe_u64(&o,"rank",rank); REQUIRE(spx_observe_finish(&o)); REQUIRE(!files[0].open && !files[1].open);
#ifndef DX_STANDALONE
    if (source) REQUIRE(install_scores_load_intact() && install_scores_initialize_intact() && install_scores_insert_intact()
        && entries[0] && entries[1] && entries[2]);
#endif
    return 0;
}
#ifndef DX_STANDALONE
static LONG WINAPI scores_fault(EXCEPTION_POINTERS *p) {
    fprintf(stderr,"native fault %08lx at %08lx\n",p->ExceptionRecord->ExceptionCode,p->ContextRecord->Eip);
    fflush(NULL); ExitProcess(86); return EXCEPTION_EXECUTE_HANDLER;
}
struct native_startupinfo { int newmode; };
__declspec(dllimport) int __cdecl __getmainargs(int *,char ***,char ***,int,struct native_startupinfo *);
static void run_case(void) {
    SetUnhandledExceptionFilter(scores_fault); int count; char **args,**environment; struct native_startupinfo startup={0};
    REQUIRE(__getmainargs(&count,&args,&environment,0,&startup)==0); int result=main(count,args); fflush(NULL); ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_scores_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance; (void)reserved;
    return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
