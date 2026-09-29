/* Complete xpalloc decisions against retained machine-derived C. Large blocks
 * use size metadata and a 64-byte prefix, not an unbounded backing allocation. */
#include "behavioral-c.h"
#include "comparison-services.h"
#include "runtime.h"
#include <errno.h>
#include <inttypes.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { BASE=0x400000, SIZE=0x20000, COUNT=0x401000, OLD=0x410000,
       NEW=0x412000, STACK=0x41f000, RETURN_WORD=0x401234, SAMPLE=64 };
static struct {
  unsigned char memory[SIZE], old_bytes[SAMPLE], new_bytes[SAMPLE];
  uint32_t count, width, old, mode, seed, result, outcome, event[5];
  uint32_t old_alive, new_alive, generations[2];
  uint64_t old_size, new_size;
  jmp_buf terminal;
} world;

static void require(int condition, const char *message) {
  if (!condition) { fprintf(stderr,"allocation fixture: %s\n",message); exit(2); }
}
static uint32_t read_memory(void *unused, uint32_t address, uint32_t width, uint32_t *fault) {
  (void)unused;
  if (address<BASE || !width || width>4 || address-BASE>SIZE-width) { *fault=1; return 0; }
  uint32_t value=0;
  for (uint32_t i=0;i<width;++i) value|=(uint32_t)world.memory[address-BASE+i]<<(i*8U);
  return value;
}
static void write_memory(void *unused, uint32_t address, uint32_t width, uint32_t value, uint32_t *fault) {
  (void)unused;
  if (address<BASE || !width || width>4 || address-BASE>SIZE-width) { *fault=1; return; }
  for (uint32_t i=0;i<width;++i) world.memory[address-BASE+i]=(unsigned char)(value>>(i*8U));
}
static uint32_t load(uint32_t address) {
  uint32_t fault=0, value=read_memory(0,address,4,&fault); require(!fault,"read"); return value;
}
static void store(uint32_t address, uint32_t value) {
  uint32_t fault=0; write_memory(0,address,4,value,&fault); require(!fault,"write");
}
static void failed(void *unused, uint32_t count) {
  (void)unused;
  world.event[0]=2; world.event[3]=count;
  world.outcome=1; longjmp(world.terminal,1);
}
static uint32_t resize(void *unused, uint32_t old, uint32_t bytes, uint32_t count) {
  (void)unused;
  world.event[0]=1; world.event[1]=old; world.event[2]=bytes; world.event[3]=count;
  require(bytes>0 && bytes<=INT32_MAX,"positive target byte extent");
  require(old==world.old,"resize preserves input identity");
  if (world.mode==2) { world.outcome=2; longjmp(world.terminal,1); }
  uint32_t result=old && world.mode==0 ? old : NEW;
  uint64_t retained=world.old_size<bytes ? world.old_size : bytes;
  if (retained>SAMPLE) retained=SAMPLE;
  unsigned char *destination=result==OLD ? world.old_bytes : world.new_bytes;
  if (result!=old) {
    memset(destination,0xac,SAMPLE);
    if (old) memcpy(destination,world.old_bytes,(size_t)retained);
    if (old) { world.old_alive=0; ++world.generations[0]; memset(world.old_bytes,0xdd,SAMPLE); }
    world.new_alive=1; ++world.generations[1]; world.new_size=bytes;
  } else {
    for (uint32_t i=(uint32_t)retained;i<SAMPLE;++i) destination[i]=0xac;
    world.old_size=bytes;
  }
  world.event[4]=result; return result;
}
spx_call_status spx_invoke_call(spx_runtime *runtime, const spx_call_event *call,
    const spx_machine_state *input, spx_machine_state *output) {
  (void)runtime; *output=*input;
  require(world.event[0]==0,"one allocator interaction per invocation");
  if (call->target_rva==0x6257)
    output->eax=resize(0,load(input->esp),load(input->esp+4),load(COUNT));
  else if (call->target_rva==0x658c) failed(0,load(COUNT));
  else require(0,"unexpected supplier");
  return SPX_CALL_OK;
}
static void observe(void) {
  printf("{\"result\":%u,\"outcome\":%u,\"count\":%u,\"event\":[",world.result,world.outcome,world.count);
  for (unsigned i=0;i<5;++i) printf("%s%u",i?",":"",world.event[i]);
  printf("],\"lifetime\":[%u,%u,%u,%u],\"sizes\":[%" PRIu64 ",%" PRIu64 "],\"prefixes\":[\"",
      world.old_alive,world.new_alive,world.generations[0],world.generations[1],world.old_size,world.new_size);
  for (unsigned i=0;i<SAMPLE;++i) printf("%02x",world.old_bytes[i]);
  printf("\",\""); for (unsigned i=0;i<SAMPLE;++i) printf("%02x",world.new_bytes[i]);
  printf("\"]}\n");
}
int main(int argc, char **argv) {
  if (argc!=9 || (strcmp(argv[1],"source") && strcmp(argv[1],"original"))) return 2;
  uint32_t arguments[7];
  for (unsigned i=0;i<7;++i) {
    char *end; errno=0; unsigned long value=strtoul(argv[i+2],&end,10);
    if (errno || !*argv[i+2] || *end || value>UINT32_MAX) return 2;
    arguments[i]=(uint32_t)value;
  }
  uint32_t previous=arguments[0], additional=arguments[1], maximum=arguments[2], width=arguments[3];
  require(previous<=INT32_MAX && additional>0 && additional<=INT32_MAX && width>0 && width<=INT32_MAX,
      "nonnegative count; positive target additional and width");
  require(arguments[4]<=1 && arguments[5]<=2,"block presence and allocator mode");
  require(!arguments[4] || (uint64_t)previous*width<=INT32_MAX,"live target allocation extent");
  world.count=previous; world.width=width; world.old=arguments[4]?OLD:0;
  world.mode=arguments[5]; world.seed=arguments[6]; world.old_alive=arguments[4];
  world.generations[0]=1; world.old_size=arguments[4]?(uint64_t)previous*width:0;
  for (unsigned i=0;i<SAMPLE;++i) world.old_bytes[i]=(unsigned char)(world.seed+i);
  memset(world.new_bytes,0xef,SAMPLE);
  store(COUNT,previous); store(COUNT-4,0x12345678); store(COUNT+4,0x87654321);
  int source=!strcmp(argv[1],"source");
  uint32_t handler=source?spx_service_handler_begin():0;
  if (!setjmp(world.terminal)) {
    if (source) {
      const struct allocation_adapter adapter={0,resize,failed};
      world.result=fixture_source_growth(&adapter,world.old,&world.count,additional,maximum,width);
    } else {
      spx_runtime runtime={.image_base=BASE,.read=read_memory,.write=write_memory};
      spx_machine_state state={.esp=STACK,.ebx=7,.ebp=11,.esi=13,.edi=17};
      store(STACK,RETURN_WORD); store(STACK+4,world.old); store(STACK+8,COUNT);
      store(STACK+12,additional); store(STACK+16,maximum); store(STACK+20,width);
      spx_step_result result=spx_sub_000063ac(&runtime,&state,0x63ac);
      require(result.kind==SPX_RETURN && result.value==RETURN_WORD && state.esp==STACK+4,"complete return/stack");
      require(state.ebx==7 && state.ebp==11 && state.esi==13 && state.edi==17,"preserved registers");
      world.result=state.eax;
    }
  } else if (source) spx_service_handler_catch(handler,"nomem");
  if (source) spx_service_handler_end(handler); else world.count=load(COUNT);
  require(load(COUNT-4)==0x12345678 && load(COUNT+4)==0x87654321,"adjacent count frame");
  observe(); return 0;
}
