/* Standalone boundary for the selected release neighbor. This gives the
 * experimental assembly local evidence instead of a non-executable placeholder. */
#include "behavioral-c.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
enum { BASE=0x400000, SIZE=0x50000, CELL=0x440040, BLOCK=0x444080,
       STACK=0x448000, IAT=0x4321e4, ERRNO_TARGET=0x401111, RETURN_WORD=0x401234 };
static struct {
  unsigned char memory[SIZE];
  uint32_t seed, calls, alive, generation, events[16][5], event_count;
} world;
void fixture_source_release(void *,uint32_t);
spx_step_result spx_sub_00001b34(spx_runtime *,spx_machine_state *,uint32_t);
static void require(int condition) { if (!condition) exit(2); }
static uint32_t read_memory(void *unused,uint32_t address,uint32_t width,uint32_t *fault) {
  (void)unused;
  if(address<BASE || !width || width>4 || address-BASE>SIZE-width) { *fault=1;return 0; }
  uint32_t value=0;for(uint32_t i=0;i<width;++i) value|=(uint32_t)world.memory[address-BASE+i]<<(i*8U);
  return value;
}
static void write_memory(void *unused,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault) {
  (void)unused;
  if(address<BASE || !width || width>4 || address-BASE>SIZE-width) { *fault=1;return; }
  for(uint32_t i=0;i<width;++i) world.memory[address-BASE+i]=(unsigned char)(value>>(i*8U));
}
uint32_t fixture_load(void *unused,uint32_t address) {
  uint32_t fault=0,value=read_memory(unused,address,4,&fault);require(!fault);return value;
}
void fixture_store(void *unused,uint32_t address,uint32_t value) {
  uint32_t fault=0;write_memory(unused,address,4,value,&fault);require(!fault);
}
static void event(uint32_t kind,uint32_t value) {
  require(world.event_count<16);uint32_t *row=world.events[world.event_count++];
  row[0]=kind;row[1]=value;for(unsigned i=0;i<3;++i) row[2+i]=fixture_load(0,CELL+4*i);
}
uint32_t fixture_errno(void *unused) {
  (void)unused;uint32_t result=CELL+4U*(world.seed&1U?world.calls%3U:0U);
  event(1,result);++world.calls;return result;
}
void fixture_free(void *unused,uint32_t token) {
  (void)unused;event(2,token);require(!token || token==BLOCK);
  if(token) { require(world.alive);world.alive=0;++world.generation;memset(world.memory+BLOCK-BASE,0xdd,64); }
  if(world.seed&2U) for(unsigned i=0;i<3;++i) fixture_store(0,CELL+4*i,world.seed&4U?0U:91U+i);
}
spx_call_status spx_invoke_call(spx_runtime *runtime,const spx_call_event *call,
    const spx_machine_state *input,spx_machine_state *output) {
  (void)runtime;*output=*input;
  if(call->kind==SPX_CALL_INDIRECT) { require(call->target_rva==ERRNO_TARGET);output->eax=fixture_errno(0); }
  else if(call->symbol && !strcmp(call->symbol,"free")) fixture_free(0,fixture_load(0,input->esp));
  else require(0);
  return SPX_CALL_OK;
}
int main(int argc,char **argv) {
  if(argc!=3 || (strcmp(argv[1],"source") && strcmp(argv[1],"original"))) return 2;
  char *end;unsigned long seed=strtoul(argv[2],&end,10);if(!*argv[2] || *end || seed>=32) return 2;
  world.seed=(uint32_t)seed;world.alive=1;world.generation=1;
  for(unsigned i=0;i<3;++i) fixture_store(0,CELL+4*i,seed&8U?0:17U+(uint32_t)seed+i);
  for(unsigned i=0;i<64;++i) world.memory[BLOCK-BASE+i]=(unsigned char)(seed+i);
  fixture_store(0,IAT,ERRNO_TARGET);uint32_t token=seed&16U?0:BLOCK;
  if(!strcmp(argv[1],"source")) fixture_source_release(0,token);
  else {
    spx_runtime runtime={.image_base=BASE,.read=read_memory,.write=write_memory};
    spx_machine_state state={.esp=STACK,.ebx=7,.ebp=11,.esi=13,.edi=17};
    fixture_store(0,STACK,RETURN_WORD);fixture_store(0,STACK+4,token);
    spx_step_result result=spx_sub_00001b34(&runtime,&state,0x1b34);
    require(result.kind==SPX_RETURN && result.value==RETURN_WORD && state.esp==STACK+4);
    require(state.ebx==7 && state.ebp==11 && state.esi==13 && state.edi==17);
  }
  printf("{\"errno\":[%u,%u,%u],\"lifetime\":[%u,%u],\"bytes\":\"",
      fixture_load(0,CELL),fixture_load(0,CELL+4),fixture_load(0,CELL+8),world.alive,world.generation);
  for(unsigned i=0;i<64;++i) printf("%02x",world.memory[BLOCK-BASE+i]);
  printf("\",\"events\":[");for(unsigned i=0;i<world.event_count;++i) {
    printf("%s[",i?",":"");for(unsigned j=0;j<5;++j) printf("%s%u",j?",":"",world.events[i][j]);printf("]");
  }
  printf("]}\n");return 0;
}
