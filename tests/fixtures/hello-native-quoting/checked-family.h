/* Reviewed multi-entry family; lower bodies remain ordinary native consumers. */
#if HELLO_NATIVE_CHECKED_ALLOCATION
#include "checked-runtime.h"
#include "comparison-services.h"
#include <setjmp.h>
static spx_fixture_entry_hook checked_hooks[8], checked_failure_hook;
static uint32_t checked_calls[8], checked_probes[20][6], checked_probe_count;
static int checked_failure_armed;
#if HELLO_NATIVE_TERMINAL
static int terminal_armed;
static void terminal_failure(void);
#endif
static jmp_buf checked_escape;
static const uint32_t checked_entries[10]={0x622d,0x6241,0x6257,0x6273,0x628f,0x62b8,0x6462,0x649c,0x6255,0x62b6};
static void require_removed_body(const spx_fixture_entry_hook *,void (*)(void));

static uint32_t checked_lower(void *unused,uint32_t operation,uint32_t block,uint32_t a,uint32_t b) {
  (void)unused;
  const uint32_t entries[]={0x6628,0x6925,0x8db8,0x692a,0x8e10,0x6934,0x65bc,0x692f};
  native_require(operation<8,"lower allocation operation");
  void *address=image+entries[operation], *result;
  if(operation<2){void *(*call)(uint32_t)=address;result=call(a);}
  else if(operation<4){void *(*call)(void *,uint32_t)=address;result=call((void *)(uintptr_t)block,a);}
  else if(operation<6){void *(*call)(void *,uint32_t,uint32_t)=address;result=call((void *)(uintptr_t)block,a,b);}
  else{void *(*call)(uint32_t,uint32_t)=address;result=call(a,b);}
  return (uint32_t)(uintptr_t)result;
}
static void checked_failed(void *unused) {failed(unused,0);}
static void *checked_invoke(uint32_t operation,void *block,uint32_t a,uint32_t b) {
  ++checked_calls[operation];
  const struct checked_adapter adapter={0,checked_lower,checked_failed};
  return (void *)(uintptr_t)fixture_checked_allocation(&adapter,operation,(uint32_t)(uintptr_t)block,a,b);
}
static void *native_checked_allocate(uint32_t a){return checked_invoke(0,0,a,1);}
static void *native_checked_allocate_indexed(uint32_t a){return checked_invoke(1,0,a,1);}
static void *native_checked_resize(void *p,uint32_t a){return checked_invoke(2,p,a,1);}
static void *native_checked_resize_indexed(void *p,uint32_t a){return checked_invoke(3,p,a,1);}
static void *native_checked_resize_array(void *p,uint32_t a,uint32_t b){return checked_invoke(4,p,a,b);}
static void *native_checked_resize_array_indexed(void *p,uint32_t a,uint32_t b){return checked_invoke(5,p,a,b);}
static void *native_checked_allocate_zeroed(uint32_t a,uint32_t b){return checked_invoke(6,0,a,b);}
static void *native_checked_allocate_zeroed_indexed(uint32_t a,uint32_t b){return checked_invoke(7,0,a,b);}
static void (*const checked_replacements[8])(void)={
  (void (*)(void))native_checked_allocate,(void (*)(void))native_checked_allocate_indexed,
  (void (*)(void))native_checked_resize,(void (*)(void))native_checked_resize_indexed,
  (void (*)(void))native_checked_resize_array,(void (*)(void))native_checked_resize_array_indexed,
  (void (*)(void))native_checked_allocate_zeroed,(void (*)(void))native_checked_allocate_zeroed_indexed};
static void observed_checked_failure(void) {
  if(program_mode) {
    native_require(spx_fixture_restore_entry(&checked_failure_hook),"restore program fatal body");
    void (*call)(void)=(void *)(image+0x658c);call();
    native_require(0,"program fatal body returned");
  }
#if HELLO_NATIVE_TERMINAL
  if(terminal_armed){terminal_failure();native_require(0,"terminal failure returned");}
#endif
  native_require(checked_failure_armed,"failure is inside its declared probe handler");
  longjmp(checked_escape,1);
}
static void install_checked_family(void) {
  native_require(spx_fixture_redirect_address_body(&checked_failure_hook,image+0x658c,
      checked_failure_prefix,5,(void (*)(void))observed_checked_failure),"observe declared nonlocal allocation failure");
  if(!source_side)return;
  const uint32_t ends[]={0x6241,0x6255,0x6273,0x628f,0x62b6,0x62df,0x6481,0x64bb};
  const unsigned char *prefixes[]={checked_allocate_prefix,checked_allocate_indexed_prefix,
    checked_resize_prefix,checked_resize_indexed_prefix,checked_resize_array_prefix,
    checked_resize_array_indexed_prefix,checked_allocate_zeroed_prefix,checked_allocate_zeroed_indexed_prefix};
  for(unsigned i=0;i<8;++i)
    native_require(spx_fixture_redirect_address_body(&checked_hooks[i],image+checked_entries[i],prefixes[i],
        ends[i]-checked_entries[i],checked_replacements[i]),"replace complete checked allocation wrapper");
  DWORD protection,ignored;
  native_require(!memcmp(image+0x6220,checked_tail_prefix,5) &&
      VirtualProtect(image+0x6220,13,PAGE_EXECUTE_READWRITE,&protection),"remove shared return/failure tail");
  memset(image+0x6220,0xcc,13);
  native_require(VirtualProtect(image+0x6220,13,protection,&ignored) &&
      FlushInstructionCache(GetCurrentProcess(),image+0x6220,13),"publish removed shared tail");
  /* Both two-byte aliases are ABI entry branches to replaced primary entries.
   * They need no five-byte detour across the next public entry. */
  native_require(image[0x6255]==0xeb && image[0x6256]==0xd6 &&
      image[0x62b6]==0xeb && image[0x62b7]==0xd7,"reviewed short entry aliases");
}
static void *invoke_checked_entry(unsigned entry,void *block,uint32_t a,uint32_t b) {
  unsigned operation=entry==8?0:entry==9?4:entry;void *address=image+checked_entries[entry];
  if(operation<2){void *(*call)(uint32_t)=address;return call(a);}
  if(operation<4){void *(*call)(void *,uint32_t)=address;return call(block,a);}
  if(operation<6){void *(*call)(void *,uint32_t,uint32_t)=address;return call(block,a,b);}
  void *(*call)(uint32_t,uint32_t)=address;return call(a,b);
}
static void probe_checked_family(void) {
  for(unsigned entry=0;entry<10;++entry) {
    unsigned operation=entry==8?0:entry==9?4:entry;
    unsigned resize=operation>=2 && operation<6;
    unsigned char *old=resize?observed_malloc(8):NULL;if(resize){native_require(old!=NULL,"checked probe old block");memset(old,0x5a,8);}
    fixture_store(0,fixture_errno(0),97);
    unsigned char *result=invoke_checked_entry(entry,old,operation<4?7:3,2);
    native_require(result!=NULL,"checked success returned a block");
    uint32_t *row=checked_probes[checked_probe_count++];
    row[0]=checked_entries[entry];row[1]=0;row[2]=allocation_id(result);
    row[3]=fixture_load(0,fixture_errno(0));row[4]=resize || operation>=6?result[0]:0;
    row[5]=allocations[row[2]-1].bytes;observed_free(result);
    old=resize?observed_malloc(8):NULL;if(resize){native_require(old!=NULL,"checked failure old block");memset(old,0x5a,8);}
    fixture_store(0,fixture_errno(0),99);checked_failure_armed=1;
    force_allocation_failure=force_reallocation_failure=1;
    uint32_t handler=source_side?spx_service_handler_begin():0;
    if(!setjmp(checked_escape)) {
      (void)invoke_checked_entry(entry,old,operation<4?7:3,2);
      native_require(0,"allocation failure must not return to caller");
    } else if(source_side)spx_service_handler_catch(handler,"nomem");
    if(source_side)spx_service_handler_end(handler);
    force_allocation_failure=force_reallocation_failure=0;checked_failure_armed=0;
    row=checked_probes[checked_probe_count++];
    row[0]=checked_entries[entry];row[1]=1;row[2]=allocation_id(old);
    row[3]=fixture_load(0,fixture_errno(0));row[4]=resize?old[0]:0;row[5]=resize?allocations[row[2]-1].bytes:0;
    if(old)observed_free(old);
  }
}
static void finish_checked_family(void) {
  if(source_side) {
    for(unsigned i=0;i<8;++i){native_require(checked_calls[i]>=2,"each selected checked operation ran");require_removed_body(&checked_hooks[i],checked_replacements[i]);}
    for(unsigned i=0x6220;i<0x622d;++i)native_require(image[i]==0xcc,"shared tail remains removed");
    native_require(image[0x6255]==0xeb && image[0x6256]==0xd6 && image[0x62b6]==0xeb && image[0x62b7]==0xd7,
        "short entry aliases still reach selected primary entries");
  }
  require_removed_body(&checked_failure_hook,(void (*)(void))observed_checked_failure);
  native_require(checked_probe_count==20,"all entry success/failure probes completed");
  printf(",\"checked_allocation\":[");
  for(unsigned i=0;i<checked_probe_count;++i){printf("%s[",i?",":"");for(unsigned j=0;j<6;++j)printf("%s%u",j?",":"",checked_probes[i][j]);putchar(']');}
  putchar(']');fprintf(stderr,"HELLO_CHECKED_C");for(unsigned i=0;i<8;++i)fprintf(stderr," %u",checked_calls[i]);fputc('\n',stderr);
}
#endif
