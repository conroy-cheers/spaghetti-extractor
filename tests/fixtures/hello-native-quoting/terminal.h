/* Actual fatal diagnostics/exit beneath the selected allocation family. The
 * observer at xalloc_die records the live call-time state, restores its bytes,
 * and runs that original body. It does not intercept error, exit or abort. */
#if HELLO_NATIVE_TERMINAL
#include "pe32-process-observer.h"
#include <wchar.h>
static unsigned terminal_entry;
static unsigned char *terminal_old;

static void terminal_failure(void) {
  unsigned operation=terminal_entry==8?0:terminal_entry==9?4:terminal_entry;
  if(source_side) {
    native_require(checked_calls[operation]==1,"terminal caller executed selected allocation C");
    require_removed_body(&checked_hooks[operation],checked_replacements[operation]);
    for(unsigned i=0x6220;i<0x622d;++i)native_require(image[i]==0xcc,"terminal shared tail remains removed");
  }
  printf("{\"entry\":%u,\"errno\":%u,\"old_prefix\":[",checked_entries[terminal_entry],fixture_load(0,fixture_errno(0)));
  if(terminal_old)for(unsigned i=0;i<8;++i)printf("%s%u",i?",":"",terminal_old[i]);
  printf("],");observe_allocator();printf("}\n");
  /* Leave stdout buffered: the actual native error path must flush it. */
  native_require(spx_fixture_restore_entry(&checked_failure_hook),"restore original fatal body");
  void (*call)(void)=(void *)(image+0x658c);call();
  native_require(0,"original fatal body returned");
}

static int terminal_child(int source,unsigned entry,uint32_t status) {
  SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
  native_initialize(source);terminal_entry=entry;
  native_require(!word(0x30028),"default native error program-name delivery");
  put(0x20000,status); /* Reviewed mutable exit_failure cell, normally 1. */
  unsigned operation=entry==8?0:entry==9?4:entry;
  if(operation>=2 && operation<6) {
    terminal_old=observed_malloc(8);native_require(terminal_old!=NULL,"terminal old allocation");
    memset(terminal_old,0x5a,8);
  }
  fixture_store(0,fixture_errno(0),99);
  force_allocation_failure=force_reallocation_failure=1;terminal_armed=1;
  void *result=invoke_checked_entry(entry,terminal_old,operation<4?7:3,2);
  /* A faulty replacement returning normally is an observable discrepancy. */
  printf("{\"returned\":true,\"result\":%u}\n",allocation_id(result));return 0;
}
static void terminal_bytes(const unsigned char *bytes,DWORD size) {
  putchar('[');for(DWORD i=0;i<size;++i)printf("%s%u",i?",":"",bytes[i]);putchar(']');
}
static void terminal_service_trace(int source,spx_fixture_process_result *result) {
  /* The child has actually terminated. Deliver its interrupted service to the
   * supervising C handler only now. This jump is telemetry transport in the
   * supervisor; it never replaces exit/abort in the child. All trace records are
   * rechecked by the existing catalog/nesting reader in the outer comparison. */
  uint32_t handler=source?spx_service_handler_begin():0;
  DWORD kept=0;
  for(DWORD position=0;position<result->err_size;) {
    DWORD end=position;while(end<result->err_size && result->err[end]!='\n')++end;
    if(end<result->err_size)++end;
    unsigned char *line=result->err+position;DWORD size=end-position;
    int trace=(size>=12 && !memcmp(line,"SPX_SERVICE ",12)) ||
              (size>=18 && !memcmp(line,"SPX_SERVICE_SCOPE ",18));
    if(trace) {
      native_require(source && size && line[size-1]=='\n',"complete source service trace line");
      --size;if(size && line[size-1]=='\r')--size;
      native_require(fwrite(line,1,size,stderr)==size && fputc('\n',stderr)!=EOF,"forward child service trace");
    } else {
      memmove(result->err+kept,line,size);kept+=size;
    }
    position=end;
  }
  result->err_size=kept;
  if(source) {
    /* Only the reviewed boundary observer emits this prefix. A child that
     * returns or fails before that boundary cannot acquire a nomem delivery. */
    jmp_buf delivery;
    if(!setjmp(delivery)) {
      if(result->exit_code && result->out_size>=9 && !memcmp(result->out,"{\"entry\":",9))
        longjmp(delivery,1);
    } else spx_service_handler_catch(handler,"nomem");
    spx_service_handler_end(handler);
  }
}
int native_terminal_run(int source,int child,const char *entry_text,const char *status_text) {
  char *end;unsigned long entry=strtoul(entry_text,&end,10);
  if(!*entry_text || *end || entry>9)return 2;
  unsigned long status=strtoul(status_text,&end,10);
  if(!*status_text || *end || (status!=0 && status!=1 && status!=37))return 2;
  if(child)return terminal_child(source,(unsigned)entry,(uint32_t)status);
  wchar_t executable[32768],command[32768];
  DWORD length=GetModuleFileNameW(NULL,executable,32768);
  native_require(length && length<32768,"terminal supervisor executable path");
  native_require(swprintf(command,32768,L"\"%ls\" %ls terminal-child %lu %lu",executable,
      source?L"source":L"original",entry,status)>0,"terminal child command length");
  spx_fixture_process_result result;
  int observed=spx_fixture_observe_process(executable,command,10000,&result);
  if(!observed)fprintf(stderr,"terminal observer status=%d error=%lu\n",result.status,result.error);
  native_require(observed,"complete terminal process observation");
  terminal_service_trace(source,&result);
  const char failure[]="native Hello fixture:";
  native_require(result.err_size<sizeof(failure)-1 || memcmp(result.err,failure,sizeof(failure)-1),
      "terminal child instrumentation failed");
  printf("{\"terminal\":{\"exit_code\":%lu,\"stdout\":",result.exit_code);
  terminal_bytes(result.out,result.out_size);printf(",\"stderr\":");terminal_bytes(result.err,result.err_size);
  printf("}}\n");return 0;
}
#else
int native_terminal_run(int source,int child,const char *entry,const char *status) {
  (void)source;(void)child;(void)entry;(void)status;return 2;
}
#endif
