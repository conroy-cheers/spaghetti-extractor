#include "portable-component-implementation.h"
#include "quote-objects.h"
#include "native-runtime.h"
#include "runtime.h" /* Existing allocation adapter, unchanged across consumers. */
#include "native-image.h"
#include "comparison-selection.h"
#ifdef SPX_SELECTED_MULTIBYTE_CONVERSION
#include "multibyte-runtime.h"
static uint32_t multibyte_context;
#endif
#if HELLO_NATIVE_CLEANUP
#include "cleanup-runtime.h"
#endif
#if HELLO_NATIVE_REALLOCATE
#include "reallocate-runtime.h"
#endif
#if HELLO_NATIVE_QUOTE_ENGINE
#include "quote-buffer-runtime.h"
#endif
#include "pe32-entry-hook.h"
#include <locale.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const char *image_module="hello-routines.dll";
#include "allocator.h"

typedef struct spx_opaque_quote_table_v5 Slot;
typedef struct spx_opaque_quote_bytes_v5 Buffer;
typedef struct spx_opaque_quote_options_v5 Options;
typedef struct spx_opaque_quote_word_v5 Word;
typedef struct spx_opaque_quote_mask_v5 Mask;
static unsigned char *image;
static int source_side;
#if HELLO_NATIVE_CHECKED_ALLOCATION
static int program_mode;
#endif
static uint32_t source_calls[5];
static struct spx_opaque_quote_state_v5 state;
static spx_fixture_entry_hook quote_hook,growth_hook,release_hook;
#if HELLO_NATIVE_QUOTE_ENGINE
static spx_fixture_entry_hook quote_engine_hook;
static unsigned char quote_engine_saved[0x4eb3-0x36ea];
static uint32_t quote_engine_calls;
static uint32_t __attribute__((regparm(3))) native_quote_engine(void *output,uint32_t capacity,
    void *argument,uint32_t size,uint32_t style,uint32_t flags,const uint32_t *mask,void *left,void *right) {
  ++quote_engine_calls;
  return fixture_quote_buffer(image,output,capacity,argument,size,style,flags,mask,left,right);
}
#endif
#if HELLO_NATIVE_CLEANUP
static spx_fixture_entry_hook cleanup_hook;
#endif
#if HELLO_NATIVE_REALLOCATE
static spx_fixture_entry_hook reallocate_hook;
static uint32_t reallocation_probe[5];
#endif
void fixture_source_release(void *,uint32_t);

void native_require(int condition,const char *message) {
  if(!condition){fprintf(stderr,"native Hello fixture: %s (%lu)\n",message,GetLastError());exit(2);}
}
static uint32_t word(uint32_t rva) {uint32_t value;memcpy(&value,image+rva,4);return value;}
static void put(uint32_t rva,uint32_t value) {memcpy(image+rva,&value,4);}
uint32_t fixture_errno(void *unused) {
  (void)unused;int *(*call)(void)=(void *)(uintptr_t)word(0x321e4);return (uint32_t)(uintptr_t)call();
}
uint32_t fixture_load(void *unused,uint32_t address) {
  (void)unused;uint32_t value;memcpy(&value,(void *)(uintptr_t)address,4);return value;
}
void fixture_store(void *unused,uint32_t address,uint32_t value) {
  (void)unused;memcpy((void *)(uintptr_t)address,&value,4);
}
void fixture_free(void *unused,uint32_t token) {
  (void)unused;void (*call)(void *)=(void *)(uintptr_t)word(0x3222c);call((void *)(uintptr_t)token);
}
static void publish(void) {
  put(0x20050,(uint32_t)(uintptr_t)state.table);put(0x2005c,state.count);
}
static void synchronize(void) {
  state.table=(void *)(uintptr_t)word(0x20050);state.count=word(0x2005c);
  state.initial_table=(void *)(image+0x20054);state.initial_buffer=(void *)(image+0x300c0);
}
static uint32_t resize(void *unused,uint32_t block,uint32_t bytes,uint32_t count) {
  (void)unused;(void)count;void *(*call)(void *,uint32_t)=(void *)(image+0x6257);
  return (uint32_t)(uintptr_t)call((void *)(uintptr_t)block,bytes);
}
static void failed(void *unused,uint32_t count) {
  (void)unused;(void)count;void (*call)(void)=(void *)(image+0x658c);call();
  native_require(0,"xalloc_die returned");
}
static void *native_growth(void *block,uint32_t *count,uint32_t additional,uint32_t maximum,uint32_t width) {
  ++source_calls[1];const struct allocation_adapter adapter={0,resize,failed};
  return (void *)(uintptr_t)fixture_source_growth(&adapter,(uint32_t)(uintptr_t)block,count,additional,maximum,width);
}
static void native_release(void *block) {++source_calls[2];fixture_source_release(0,(uint32_t)(uintptr_t)block);}
#if HELLO_NATIVE_REALLOCATE
static uint32_t raw_resize(void *unused,uint32_t block,uint32_t bytes) {
  (void)unused;return (uint32_t)(uintptr_t)observed_realloc((void *)(uintptr_t)block,bytes);
}
static void *native_reallocate(void *block,uint32_t bytes) {
  ++source_calls[4];
  const struct reallocate_adapter adapter={0,raw_resize,fixture_errno,fixture_load,fixture_store};
  return (void *)(uintptr_t)fixture_source_reallocate(&adapter,(uint32_t)(uintptr_t)block,bytes);
}
#endif
static uint32_t read_errno(void *unused,spx_ref_v5 reference,uint64_t offset,uint32_t width,uint64_t *value) {
  (void)unused;if(offset || width!=4 || !value)return SPX_REF_FAULT;
  *value=fixture_load(0,(uint32_t)reference.object);return SPX_REF_OK;
}
static uint32_t write_errno(void *unused,spx_ref_v5 reference,uint64_t offset,uint32_t width,uint64_t value) {
  (void)unused;if(offset || width!=4)return SPX_REF_FAULT;
  fixture_store(0,(uint32_t)reference.object,(uint32_t)value);return SPX_REF_OK;
}
static spx_view_v5 errno_cell(void *unused) {
  (void)unused;publish();uint32_t address=fixture_errno(0);
  return (spx_view_v5){.base={.object=address,.extent=4,.permissions=3},.extent=4,
      .element_width=1,.read=read_errno,.write=write_errno};
}
static Slot *grow_slots(void *unused,Slot *old,Word *count,uint32_t additional,uint32_t maximum) {
  (void)unused;publish();void *(*call)(void *,uint32_t *,uint32_t,uint32_t,uint32_t)=(void *)(image+0x63ac);
  return call(old,&count->value,additional,maximum,8);
}
static void clear_slots(void *unused,Slot *slots,uint32_t first,uint32_t count) {
  (void)unused;publish();memset(slots+first,0,count*sizeof(*slots));
}
static uint32_t quote_buffer(void *unused,Buffer *output,uint32_t capacity,Buffer *argument,
    uint32_t size,uint32_t style,uint32_t flags,Mask *mask,Buffer *left,Buffer *right) {
  (void)unused;publish();
  uint32_t (__attribute__((regparm(3))) *call)(void *,uint32_t,void *,uint32_t,uint32_t,uint32_t,void *,void *,void *)=
      (void *)(image+0x36ea);
  return call(output,capacity,argument,size,style,flags,mask,left,right);
}
static void release_buffer(void *unused,Buffer *buffer) {
  (void)unused;publish();void (*call)(void *)=(void *)(image+0x1b34);call(buffer);
}
static Buffer *allocate_buffer(void *unused,uint32_t size) {
  (void)unused;publish();void *(*call)(uint32_t)=(void *)(image+0x6255);return call(size);
}
static void invalid_slot(void *unused) {
  (void)unused;publish();void (*call)(void)=(void *)(uintptr_t)word(0x32204);call();
  native_require(0,"abort returned");
}
static Buffer *__attribute__((regparm(3))) native_quote(uint32_t slot,Buffer *argument,uint32_t size,Options *options) {
  ++source_calls[0];synchronize();
  const spx_quote_slots_services_v5 services={.errno_cell=errno_cell,.grow_slots=grow_slots,
      .clear_slots=clear_slots,.quote_buffer=quote_buffer,.release_buffer=release_buffer,
      .allocate_buffer=allocate_buffer,.invalid_slot=invalid_slot};
  spx_quote_slots_context_v5 context={.services=&services,.state={.slots=&state}};
  Buffer *result=quote_slots(&context,slot,argument,size,options);publish();return result;
}
#if HELLO_NATIVE_CLEANUP
static void release_table(void *unused,Slot *table) {
  (void)unused;publish();void (*call)(void *)=(void *)(image+0x1b34);call(table);
}
static uint32_t native_cleanup_source(void) {
  ++source_calls[3];synchronize();
  native_require(state.count<=HELLO_CLEANUP_MAX_SLOTS,"cleanup admitted count");
  const struct cleanup_adapter adapter={0,release_buffer,release_table};
  uint32_t result=fixture_quote_cleanup(&state,&adapter);publish();return result;
}
#endif
#include "checked-family.h"
static void native_install(int source) {
  _Static_assert(sizeof(void *)==4 && sizeof(Slot)==8 && sizeof(Options)==48,"native PE32 relation");
  _Static_assert(offsetof(Slot,buffer)==4 && offsetof(Options,mask)==8 && offsetof(Options,left_quote)==40,"native field relation");
  source_side=source;
  synchronize();native_require(state.count==1 && state.table==state.initial_table &&
      state.table[0].buffer==state.initial_buffer && state.table[0].size==256,"actual initial cache");
  install_allocator();
#if HELLO_NATIVE_CHECKED_ALLOCATION
  install_checked_family();
#endif
  if(source) {
#ifdef SPX_SELECTED_MULTIBYTE_CONVERSION
    fixture_multibyte_install(image);
#endif
#if HELLO_NATIVE_QUOTE_ENGINE
    native_require(spx_fixture_redirect_address_body_with_storage(&quote_engine_hook,image+0x36ea,
        quote_engine_prefix,0x4eb3-0x36ea,(void (*)(void))native_quote_engine,
        quote_engine_saved,sizeof(quote_engine_saved)),"replace complete quote engine body");
    DWORD engine_protection,engine_ignored;
    native_require(VirtualProtect(image+0x14640,5,PAGE_EXECUTE_READWRITE,&engine_protection),"quote engine cold region protection");
    memset(image+0x14640,0xcc,5);
    native_require(VirtualProtect(image+0x14640,5,engine_protection,&engine_ignored) &&
        FlushInstructionCache(GetCurrentProcess(),image+0x14640,5),"remove original quote engine cold region");
#endif
    native_require(spx_fixture_redirect_address_body(&quote_hook,image+0x4eb3,quote_prefix,0x5078-0x4eb3,
        (void (*)(void))native_quote),"replace complete quote body");
    native_require(spx_fixture_redirect_address_body(&growth_hook,image+0x63ac,growth_prefix,0x6462-0x63ac,
        (void (*)(void))native_growth),"replace complete growth body");
    native_require(spx_fixture_redirect_address_body(&release_hook,image+0x1b34,release_prefix,0x1ba0-0x1b34,
        (void (*)(void))native_release),"replace complete free body");
#if HELLO_NATIVE_REALLOCATE
    native_require(spx_fixture_redirect_address_body(&reallocate_hook,image+0x8db8,reallocate_prefix,0x8e10-0x8db8,
        (void (*)(void))native_reallocate),"replace complete realloc body");
#endif
#if HELLO_NATIVE_CLEANUP
    native_require(spx_fixture_redirect_address_body(&cleanup_hook,image+0x52f2,cleanup_prefix,0x5374-0x52f2,
        (void (*)(void))native_cleanup_source),"replace complete cleanup body");
#endif
    /* The invalid-index cold region also belongs to quote. Any original interior
     * entry is unsupported and traps; the C wrapper uses the real abort service. */
    DWORD protection,ignored;
    native_require(VirtualProtect(image+0x14645,5,PAGE_EXECUTE_READWRITE,&protection),"cold region protection");
    memset(image+0x14645,0xcc,5);
    native_require(VirtualProtect(image+0x14645,5,protection,&ignored) &&
        FlushInstructionCache(GetCurrentProcess(),image+0x14645,5),"remove original cold region");
  }
}
void native_initialize(int source) {
  native_require(setlocale(LC_ALL,"C")!=NULL,"C locale initialization");
  image=(void *)LoadLibraryA("hello-routines.dll");native_require(image!=NULL,"load bound original routines");
  IMAGE_DOS_HEADER *dos=(void *)image;IMAGE_NT_HEADERS32 *nt=(void *)(image+dos->e_lfanew);
  native_require(nt->OptionalHeader.SizeOfImage==0x35000 && !nt->OptionalHeader.AddressOfEntryPoint &&
      !nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress,"explicit routine loader boundary");
  native_install(source);
}
void native_environment(uint32_t mode) {
#ifdef SPX_SELECTED_MULTIBYTE_CONVERSION
  multibyte_context=mode;fixture_multibyte_environment(image,mode);
#else
  native_require(!mode,"conversion context needs the selected runtime adapter");
#endif
}
void native_reallocation_probe(void) {
#if HELLO_NATIVE_REALLOCATE
  unsigned char *block=observed_malloc(8);native_require(block!=NULL,"probe allocation");
  memset(block,0x5a,8);
  void *(*checked)(void *,uint32_t)=(void *)(image+0x6257);
  void *(*raw)(void *,uint32_t)=(void *)(image+0x8db8);
  block=checked(block,0);native_require(block!=NULL,"real xrealloc probe returned");
  reallocation_probe[0]=block[0];
  /* Actual native errno behavior around a controlled allocation failure and a
   * high-bit request. The latter must reject before invoking that service. */
  force_reallocation_failure=1;
  fixture_store(0,fixture_errno(0),91);
  reallocation_probe[1]=allocation_id(raw(block,2));
  reallocation_probe[2]=fixture_load(0,fixture_errno(0));
  fixture_store(0,fixture_errno(0),93);
  reallocation_probe[3]=allocation_id(raw(block,UINT32_C(2147483648)));
  reallocation_probe[4]=fixture_load(0,fixture_errno(0));
  force_reallocation_failure=0;
  observed_free(block);
#endif
}
void native_checked_probe(void) {
#if HELLO_NATIVE_CHECKED_ALLOCATION
  probe_checked_family();
#endif
}
char *native_consume(uint32_t slot,uint32_t style,const char *argument,uint32_t size,int kind) {
  if(kind==2) {
    char *(*call)(uint32_t,const char *,const char *,const char *,uint32_t)=(void *)(image+0x55e7);
    return call(slot,"<<",">>",argument,size);
  }
  if(kind==1) {
    char *(*call)(uint32_t,uint32_t,const char *,uint32_t)=(void *)(image+0x5416);
    return call(slot,style,argument,size);
  }
  char *(*call)(uint32_t,uint32_t,const char *)=(void *)(image+0x53e5);return call(slot,style,argument);
}
void native_cleanup(void) {
  uint32_t (*call)(void)=(void *)(image+0x52f2);native_require(call()==0,"cleanup zero return");
}
static void string_hex(const char *text) {
  if(!text){printf("null");return;}
  size_t size=strlen(text);native_require(size<4096,"observed terminated result extent");
  putchar('"');for(size_t i=0;i<size;++i)printf("%02x",(unsigned char)text[i]);putchar('"');
}
void native_observe(const char *result) {
  synchronize();native_require(state.count<=64,"selected finite case count");
  printf("{\"result\":");string_hex(result);
  printf(",\"errno\":%u,\"count\":%u,\"initial_table\":%s,\"slots\":[",
      fixture_load(0,fixture_errno(0)),state.count,state.table==state.initial_table?"true":"false");
  for(uint32_t i=0;i<state.count;++i) {
    Slot *slot=&state.table[i];uint32_t id=slot->buffer==state.initial_buffer?UINT32_MAX:allocation_id(slot->buffer);
    printf("%s{\"capacity\":%u,\"identity\":%u,\"text\":",i?",":"",slot->size,id);
    string_hex((const char *)slot->buffer);putchar('}');
  }
  printf("]}");
}
static void require_removed_body(const spx_fixture_entry_hook *hook,void (*replacement)(void)) {
  uint32_t displacement;memcpy(&displacement,hook->entry+1,4);
  native_require(hook->entry[0]==0xe9 &&
      (uint32_t)(uintptr_t)(hook->entry+5)+displacement==(uint32_t)(uintptr_t)replacement,
      "selected entry still dispatches to authored C");
  for(size_t i=5;i<hook->length;++i)
    native_require(hook->entry[i]==0xcc,"original selected body remains removed");
}
void native_finish(void) {
  if(source_side) {
    native_require(source_calls[0]>=7 && source_calls[1]>=3 && source_calls[2]>=1,
        "all selected C units executed through actual native consumers");
    require_removed_body(&quote_hook,(void (*)(void))native_quote);
    require_removed_body(&growth_hook,(void (*)(void))native_growth);
    require_removed_body(&release_hook,(void (*)(void))native_release);
#if HELLO_NATIVE_QUOTE_ENGINE
    native_require(quote_engine_calls>=7,"selected quote engine runs through actual callers");
    require_removed_body(&quote_engine_hook,(void (*)(void))native_quote_engine);
    for(unsigned i=0x14640;i<0x14645;++i)native_require(image[i]==0xcc,"quote engine cold body remains removed");
#endif
#if HELLO_NATIVE_REALLOCATE
    native_require(source_calls[4]>=6,"selected realloc runs through probes and real growth");
    require_removed_body(&reallocate_hook,(void (*)(void))native_reallocate);
#endif
#if HELLO_NATIVE_CLEANUP
    native_require(source_calls[3]==2,"selected cleanup runs before and after reentry");
    require_removed_body(&cleanup_hook,(void (*)(void))native_cleanup_source);
#endif
    for(uint32_t i=0x14645;i<0x1464a;++i)
      native_require(image[i]==0xcc,"original cold region remains removed");
  }
  observe_allocator();
#ifdef SPX_SELECTED_MULTIBYTE_CONVERSION
  printf(",\"multibyte_context\":%u",multibyte_context);
  fixture_multibyte_finish(image,source_side);
#endif
#if HELLO_NATIVE_CHECKED_ALLOCATION
  finish_checked_family();
  native_require(spx_fixture_restore_import(&calloc_hook),"restore observed calloc import");
#endif
#if HELLO_NATIVE_REALLOCATE
  printf(",\"reallocation_probe\":[");
  for(unsigned i=0;i<5;++i)printf("%s%u",i?",":"",reallocation_probe[i]);
  putchar(']');
  fprintf(stderr,"HELLO_REALLOCATE_C %u\n",source_calls[4]);
#endif
  fprintf(stderr,"HELLO_SELECTED_C %u %u %u\n",source_calls[0],source_calls[1],source_calls[2]);
#if HELLO_NATIVE_QUOTE_ENGINE
  fprintf(stderr,"HELLO_QUOTE_ENGINE_C %u\n",quote_engine_calls);
#endif
#if HELLO_NATIVE_CLEANUP
  fprintf(stderr,"HELLO_CLEANUP_C %u\n",source_calls[3]);
#endif
  native_require(spx_fixture_restore_import(&malloc_hook) && spx_fixture_restore_import(&realloc_hook) &&
      spx_fixture_restore_import(&free_hook),"restore observed CRT imports");
  native_require(FreeLibrary((HMODULE)image),"release native image");
}
#include "terminal.h"
#include "program-runtime.h"
