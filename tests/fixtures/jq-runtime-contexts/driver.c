/* Observe complete process teardown using an OS handle that outlives the CRT. */
#include <windows.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "winpthread-pthread.h"
#include "jq.h"
#include "entries.h"
#include "native-entry.h"
#include "allocation-observer.h"

static HANDLE output;
static unsigned calls[7];
static int trace_releases;
static decContext *main_decimal;
static struct dtoa_context *main_dtoa;
void context_entropy_begin(unsigned);
static void require(int value) { if (!value) ExitProcess(84); }
void spx_observe_context_entry(unsigned index) { require(index<7); ++calls[index]; }
void context_event(const char *text) {
    DWORD length=(DWORD)strlen(text),written;
    require(WriteFile(output,text,length,&written,NULL) && written==length);
    require(WriteFile(output,"\n",1,&written,NULL) && written==1);
}
static LONG WINAPI fault(EXCEPTION_POINTERS *error) {
    fprintf(stderr,"native-fault code=%08lx ip=%08lx image=%p\n",
        (unsigned long)error->ExceptionRecord->ExceptionCode,
        (unsigned long)error->ContextRecord->Eip,(void *)GetModuleHandleA("libjq-1.dll"));
    fflush(stderr);ExitProcess(86);return EXCEPTION_EXECUTE_HANDLER;
}
static void checkpoint(const char *name) {
    allocation_observer_summary state=allocation_observer_snapshot();char text[256];
    snprintf(text,sizeof(text),"{\"checkpoint\":\"%s\",\"live_blocks\":%" PRIu64
        ",\"live_bytes\":%" PRIu64 ",\"invalid_releases\":%" PRIu64 "}",
        name,state.live_blocks,state.live_bytes,state.invalid_releases);
    context_event(text);
}
void context_observer_release(void) { if (trace_releases) checkpoint("cleanup"); }
static void emit_value(const char *name, jv value) {
    allocation_observer_pause(1);
    jv text=jv_dump_string(value,JV_PRINT_SORTED);
    size_t size=strlen(name)+strlen(jv_string_value(text))+32;
    char *line=malloc(size);require(line!=NULL);
    snprintf(line,size,"{\"%s\":%s}",name,jv_string_value(text));
    context_event(line);free(line);jv_free(text);
    allocation_observer_pause(0);
}
static void contexts(const char *name, int worker) {
    decContext *decimal=spx_native_decimal_context();
    struct dtoa_context *dtoa=tsd_dtoa_context_get();
    require(decimal && dtoa);
    char text[512];
    snprintf(text,sizeof(text),"{\"context\":\"%s\",\"decimal_same\":%d,\"dtoa_same\":%d,"
        "\"thread_distinct\":%d,\"digits\":%d,\"emax\":%d,\"emin\":%d,\"round\":%d,"
        "\"traps\":%u,\"status\":%u,\"clamp\":%u}",name,
        decimal==spx_native_decimal_context(),dtoa==tsd_dtoa_context_get(),
        !worker || (decimal!=main_decimal && dtoa!=main_dtoa),
        decimal->digits,decimal->emax,decimal->emin,decimal->round,
        decimal->traps,decimal->status,decimal->clamp);
    context_event(text);
    decimal->status=0x20;
    require(spx_native_decimal_context()->status==0x20);
    if (!worker) { main_decimal=decimal;main_dtoa=dtoa; }
}
static void consumer(void) {
    const char *program="[.[]|{n:.,s:tostring,neg:(-.),sum:(.+0.125)}]";
    jq_state *states[2]={jq_init(),jq_init()};
    for (unsigned i=0;i<2;i++) {
        require(states[i]!=NULL && jq_compile(states[i],program));
        jq_start(states[i],jv_parse("[1.25,1e-300,9007199254740993,-0.0001]"),0);
        jv result=jq_next(states[i]);require(jv_is_valid(result));
        emit_value("numbers",result);
        jv end=jq_next(states[i]);require(!jv_is_valid(end));jv_free(end);
        jq_teardown(&states[i]);
    }
}
static void *worker(void *unused) {
    (void)unused;
    contexts("worker",1);consumer();checkpoint("worker-before-exit");
    trace_releases=1;return NULL;
}
static int child(const char *side, const char *scenario, unsigned mode, const char *file) {
    SetUnhandledExceptionFilter(fault);
    output=CreateFileA(file,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    require(output!=INVALID_HANDLE_VALUE);
    int source=!strcmp(side,"source");require(source || !strcmp(side,"original"));
    context_entropy_begin(mode);
    if (source) require(install_entries());
    allocation_observer_begin();
    if (!strcmp(scenario,"explicit")) { jv_tsd_dec_ctx_init();jv_tsd_dtoa_ctx_init(); }
    uint32_t first=jvp_hash_seed(),second=jvp_hash_seed();char text[128];
    snprintf(text,sizeof(text),"{\"seed\":%u,\"same_seed\":%d}",first,first==second);context_event(text);
    contexts("main",0);consumer();checkpoint("main-live");
    if (!strcmp(scenario,"thread")) {
        pthread_t thread;require(!pthread_create(&thread,NULL,worker,NULL));
        require(!pthread_join(thread,NULL));trace_releases=0;
        checkpoint("worker-joined");
        require(main_decimal==spx_native_decimal_context() && main_dtoa==tsd_dtoa_context_get());
        contexts("main-after-worker",0);
    } else if (!strcmp(scenario,"explicit")) {
        jv_tsd_dtoa_ctx_fini();jv_tsd_dec_ctx_fini();checkpoint("explicit-finalization");
        contexts("recreated",0);consumer();
    } else require(!strcmp(scenario,"contexts"));
    if (source) {
        require(entries_intact());
        for (unsigned i=0;i<7;i++) fprintf(stderr,"context-entry-%u=%u\n",i,calls[i]);
    }
    checkpoint("before-process-exit");trace_releases=1;
    return 0;
}
int main(int argc, char **argv) {
    (void)&jv_is_valid;
    if (argc==6 && !strcmp(argv[1],"child")) return child(argv[2],argv[3],(unsigned)atoi(argv[4]),argv[5]);
    require(argc==4);
    require(!strcmp(argv[1],"source") || !strcmp(argv[1],"original"));
    require(!strcmp(argv[2],"contexts") || !strcmp(argv[2],"thread") || !strcmp(argv[2],"explicit"));
    require(strlen(argv[3])==1 && argv[3][0]>='0' && argv[3][0]<='3');
    char executable[MAX_PATH],command[2*MAX_PATH];
    require(GetModuleFileNameA(NULL,executable,sizeof(executable))>0);
    snprintf(command,sizeof(command),"\"%s\" child %s %s %s context-events.jsonl",executable,argv[1],argv[2],argv[3]);
    STARTUPINFOA startup={.cb=sizeof(startup)};PROCESS_INFORMATION process;
    require(CreateProcessA(executable,command,NULL,NULL,FALSE,0,NULL,NULL,&startup,&process));
    require(WaitForSingleObject(process.hProcess,30000)==WAIT_OBJECT_0);
    DWORD status;require(GetExitCodeProcess(process.hProcess,&status));
    CloseHandle(process.hThread);CloseHandle(process.hProcess);
    if (status) { fprintf(stderr,"context child exit=%lu\n",(unsigned long)status);return 85; }
    FILE *events=fopen("context-events.jsonl","rb");require(events!=NULL);
    char line[4096];unsigned count=0;fputs("{\"events\":[",stdout);
    while (fgets(line,sizeof(line),events)) {
        require(strchr(line,'\n')!=NULL);
        line[strcspn(line,"\r\n")]=0;printf("%s%s",count++?",":"",line);
    }
    require(!ferror(events));fclose(events);require(count>0);puts("]}");return 0;
}
