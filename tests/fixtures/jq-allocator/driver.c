/* Install hooks before creating threads; exercise one thread at a time. The
 * parent reads the child's observation file after complete process teardown,
 * including DLL atexit callbacks. A main-return snapshot would miss those. */
#include <windows.h>
#include <inttypes.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "winpthread-pthread.h"
#include "jq.h"
#include "allocation-observer.h"
#include "allocator-entries.h"
#include "native-entries.h"

static HANDLE output;
static int trace_releases;
static unsigned source_calls[9];

static void require(int condition) { if(!condition) ExitProcess(84); }
void allocator_entry_observation(unsigned index) { require(index<9);++source_calls[index]; }
static void event(const char *text) {
    DWORD size=(DWORD)strlen(text),written;
    require(WriteFile(output,text,size,&written,NULL) && written==size);
    require(WriteFile(output,"\n",1,&written,NULL) && written==1);
}
static void checkpoint(const char *name) {
    allocation_observer_summary state=allocation_observer_snapshot();
    char text[256];
    snprintf(text,sizeof(text),"{\"checkpoint\":\"%s\",\"live_blocks\":%" PRIu64
        ",\"live_bytes\":%" PRIu64 ",\"invalid_releases\":%" PRIu64 "}",
        name,state.live_blocks,state.live_bytes,state.invalid_releases);
    event(text);
}
void allocator_observer_release(void) { if(trace_releases) checkpoint("release"); }

struct handler { jmp_buf escape; const char *name; unsigned calls; };
static struct handler main_a={.name="main-a"},main_b={.name="main-b"},worker_c={.name="worker-c"};
static void exhausted(void *data) {
    struct handler *handler=data;char text[96];
    ++handler->calls;
    snprintf(text,sizeof(text),"{\"handler\":\"%s\",\"calls\":%u}",handler->name,handler->calls);
    event(text);longjmp(handler->escape,1);
}
static void fail_allocation(struct handler *expected) {
    unsigned before=expected->calls;
    if(!setjmp(expected->escape)) {
        allocation_observer_fail_next_malloc();
        (void)jv_mem_alloc(37);
        require(0);
    }
    require(expected->calls==before+1 && allocation_observer_failed_size()==37);
}
static void *worker(void *unused) {
    (void)unused;
    jq_state *jq=jq_init();require(jq!=NULL);
    jq_set_nomem_handler(jq,exhausted,&worker_c);
    fail_allocation(&worker_c);
    jq_teardown(&jq);
    checkpoint("worker-before-exit");trace_releases=1;
    return NULL;
}
static void normal_operations(void) {
    unsigned char *a=jv_mem_alloc(8),*b=jv_mem_alloc_unguarded(8);
    unsigned char *c=jv_mem_calloc(3,4),*d=jv_mem_calloc_unguarded(2,3);
    char *e=jv_mem_strdup("lambda"),*f=jv_mem_strdup_unguarded("");
    require(a && b && c && d && e && f);
    for(unsigned i=0;i<12;++i) require(c[i]==0);
    for(unsigned i=0;i<6;++i) require(d[i]==0);
    require(!strcmp(e,"lambda") && !strcmp(f,""));
    memcpy(a,"retained",8);a=jv_mem_realloc(a,32);require(a && !memcmp(a,"retained",8));
    jv_mem_free(a);jv_mem_free(b);jv_mem_free(c);jv_mem_free(d);jv_mem_free(e);jv_mem_free(f);jv_mem_free(NULL);
    allocation_observer_fail_next_malloc();require(jv_mem_alloc_unguarded(17)==NULL);
    event("{\"allocation_bytes\":\"matched\",\"unguarded_failure\":\"null\"}");
}
static int child(const char *side,const char *scenario,const char *file) {
    output=CreateFileA(file,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    require(output!=INVALID_HANDLE_VALUE);
    int source=!strcmp(side,"source");
    require(source || !strcmp(side,"original"));
    if(source) install_allocator_entries();
    allocation_observer_begin();
    normal_operations();checkpoint("no-registration");
    jq_state *a=jq_init(),*b=jq_init();require(a && b);
    jq_set_nomem_handler(a,exhausted,&main_a);
    jq_set_nomem_handler(b,exhausted,&main_b);
    fail_allocation(&main_b);  /* Two jq contexts share the thread's latest handler. */
    jq_set_nomem_handler(a,exhausted,&main_a);
    fail_allocation(&main_a);
    jq_teardown(&b);jq_teardown(&a);
    checkpoint("main-registered");
    if(!strcmp(scenario,"threads")) {
        pthread_t thread;
        require(!pthread_create(&thread,NULL,worker,NULL));
        require(!pthread_join(thread,NULL));trace_releases=0;
        checkpoint("worker-joined");fail_allocation(&main_a);
    } else require(!strcmp(scenario,"contexts"));
    if(source) {
        require(allocator_entries_intact());
        for(unsigned i=0;i<9;++i) require(source_calls[i]>0);
        fprintf(stderr,"authored-allocator-entry-counts:");
        for(unsigned i=0;i<9;++i) fprintf(stderr," %u",source_calls[i]);
        fputc('\n',stderr);
    }
    checkpoint("before-process-exit");trace_releases=1;
    /* Keep the observer and Win32 handle alive for C/CRT/DLL cleanup. */
    return 0;
}
int main(int argc,char **argv) {
    (void)&jv_is_valid;
    if(argc==5 && !strcmp(argv[1],"child")) return child(argv[2],argv[3],argv[4]);
    require(argc==3);
    char executable[MAX_PATH],command[2*MAX_PATH];
    require(GetModuleFileNameA(NULL,executable,sizeof(executable))>0);
    /* Validated scenarios contain no command-line metacharacters. */
    require(!strcmp(argv[1],"source") || !strcmp(argv[1],"original"));
    require(!strcmp(argv[2],"contexts") || !strcmp(argv[2],"threads"));
    snprintf(command,sizeof(command),"\"%s\" child %s %s allocator-events.jsonl",executable,argv[1],argv[2]);
    STARTUPINFOA startup={.cb=sizeof(startup)};PROCESS_INFORMATION process;
    require(CreateProcessA(executable,command,NULL,NULL,FALSE,0,NULL,NULL,&startup,&process));
    require(WaitForSingleObject(process.hProcess,30000)==WAIT_OBJECT_0);
    DWORD status;require(GetExitCodeProcess(process.hProcess,&status));
    CloseHandle(process.hThread);CloseHandle(process.hProcess);
    if(status) { fprintf(stderr,"allocator child exit=%lu\n",(unsigned long)status);return 85; }
    FILE *events=fopen("allocator-events.jsonl","rb");require(events!=NULL);
    char line[256];unsigned count=0;
    fputs("{\"events\":[",stdout);
    while(fgets(line,sizeof(line),events)) {
        line[strcspn(line,"\r\n")]=0;
        printf("%s%s",count++?",":"",line);
    }
    require(!ferror(events));fclose(events);require(count>0);
    puts("]}");return 0;
}
