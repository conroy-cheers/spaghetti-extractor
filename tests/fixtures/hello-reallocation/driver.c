/* Exact original operation with a controlled allocator, not a libc model proof. */
#include "behavioral-c.h"
#include "reallocate-runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { BASE=0x400000, MEMORY_SIZE=0x50000, CELL=0x440040,
    OLD=0x444000, NEW=0x445000, STACK=0x448000, RETURN_WORD=0x401234, SAMPLE=64 };
static struct {
    unsigned char memory[MEMORY_SIZE], old_bytes[SAMPLE], new_bytes[SAMPLE];
    uint32_t seed, mode, old, old_size, new_size, old_alive, new_alive, generations[2];
    uint32_t events[16][6], event_count, observing;
} world;
static void require(int condition) {
    if(!condition){fputs("invalid realloc fixture state/lifetime\n",stderr);exit(2);}
}
static void event(uint32_t,uint32_t,uint32_t,uint32_t);
static uint32_t read_memory(void *unused,uint32_t address,uint32_t width,uint32_t *fault) {
    (void)unused;
    if(address<BASE || !width || width>4 || address-BASE>MEMORY_SIZE-width){*fault=1;return 0;}
    uint32_t value=0;for(uint32_t i=0;i<width;++i)value|=(uint32_t)world.memory[address-BASE+i]<<(i*8U);
    return value;
}
static void write_memory(void *unused,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault) {
    (void)unused;
    if(address<BASE || !width || width>4 || address-BASE>MEMORY_SIZE-width){*fault=1;return;}
    if(world.observing && (address==CELL || address==CELL+4)) {
        require(width==4);event(3,address,value,0);
    }
    for(uint32_t i=0;i<width;++i)world.memory[address-BASE+i]=(unsigned char)(value>>(i*8U));
}
static uint32_t load(void *unused,uint32_t address) {
    uint32_t fault=0,value=read_memory(unused,address,4,&fault);require(!fault);return value;
}
static void store(void *unused,uint32_t address,uint32_t value) {
    uint32_t fault=0;write_memory(unused,address,4,value,&fault);require(!fault);
}
static void event(uint32_t kind,uint32_t a,uint32_t b,uint32_t c) {
    require(world.event_count<16);uint32_t *row=world.events[world.event_count++];
    row[0]=kind;row[1]=a;row[2]=b;row[3]=c;row[4]=load(0,CELL);row[5]=load(0,CELL+4);
}
static uint32_t errno_address(void *unused) {
    (void)unused;uint32_t address=CELL+4U*(world.seed&1U);event(2,address,0,0);return address;
}
static uint32_t resize(void *unused,uint32_t old,uint32_t bytes) {
    (void)unused;require(old==world.old && bytes>0 && bytes<=INT32_MAX);
    event(1,old,bytes,0);
    /* Observable allocator errno changes must survive success, while the
     * original wrapper overwrites the selected errno cell after failure. */
    store(0,CELL,5U+world.seed);store(0,CELL+4,6U+world.seed);
    if(world.mode==2){event(4,old,bytes,0);return 0;}
    uint32_t result=old && world.mode==0?OLD:NEW;
    uint32_t retained=world.old_size<bytes?world.old_size:bytes;
    if(retained>SAMPLE)retained=SAMPLE;
    if(result==OLD) {
        memset(world.old_bytes+retained,0xac,SAMPLE-retained);world.old_size=bytes;
    } else {
        memset(world.new_bytes,0xac,SAMPLE);
        if(old) {
            memcpy(world.new_bytes,world.old_bytes,retained);
            world.old_alive=0;++world.generations[0];memset(world.old_bytes,0xdd,SAMPLE);
        }
        world.new_alive=1;++world.generations[1];world.new_size=bytes;
    }
    event(4,old,bytes,result);return result;
}
spx_call_status spx_invoke_call(spx_runtime *runtime,const spx_call_event *call,
    const spx_machine_state *input,spx_machine_state *output) {
    (void)runtime;*output=*input;require(call->symbol!=NULL);
    if(!strcmp(call->symbol,"realloc"))output->eax=resize(0,load(0,input->esp),load(0,input->esp+4));
    else if(!strcmp(call->symbol,"_errno"))output->eax=errno_address(0);
    else require(0);
    return SPX_CALL_OK;
}
spx_step_result spx_sub_00008db8(spx_runtime *,spx_machine_state *,uint32_t);
static void hex(const unsigned char *data) {
    putchar('"');for(unsigned i=0;i<SAMPLE;++i)printf("%02x",data[i]);putchar('"');
}
int main(int argc,char **argv) {
    if(argc!=6 || (strcmp(argv[1],"source") && strcmp(argv[1],"original")))return 2;
    uint32_t args[4];
    for(unsigned i=0;i<4;++i) {
        char *end;unsigned long value=strtoul(argv[i+2],&end,10);
        if(!*argv[i+2] || *end || value>UINT32_MAX)return 2;
        args[i]=(uint32_t)value;
    }
    require(args[1]<=1 && args[2]<=2 && (args[3]==0 || args[3]==7 || args[3]==85));
    world.old=args[1]?OLD:0;world.old_alive=args[1];world.generations[0]=args[1];
    world.mode=args[2];world.seed=args[3];
    world.old_size=args[1]?(world.seed==0?0:world.seed==7?64:128):0;
    for(unsigned i=0;i<SAMPLE;++i)world.old_bytes[i]=(unsigned char)(world.seed+i);
    memset(world.new_bytes,0xef,SAMPLE);
    store(0,CELL,71+world.seed);store(0,CELL+4,72+world.seed);
    store(0,CELL-4,0x12345678);store(0,CELL+8,0x87654321);world.observing=1;
    uint32_t result;
    if(!strcmp(argv[1],"source")) {
        const struct reallocate_adapter adapter={0,resize,errno_address,load,store};
        result=fixture_source_reallocate(&adapter,world.old,args[0]);
    } else {
        spx_runtime runtime={.image_base=BASE,.read=read_memory,.write=write_memory};
        spx_machine_state state={.esp=STACK,.ebx=7,.ebp=11,.esi=13,.edi=17,.edx=23};
        store(0,STACK,RETURN_WORD);store(0,STACK+4,world.old);store(0,STACK+8,args[0]);
        spx_step_result step=spx_sub_00008db8(&runtime,&state,0x8db8);
        require(step.kind==SPX_RETURN && step.value==RETURN_WORD && state.esp==STACK+4);
        require(state.ebx==7 && state.ebp==11 && state.esi==13 && state.edi==17 && state.edx==0);
        result=state.eax;
    }
    printf("{\"result\":%u,\"events\":[",result);
    for(uint32_t i=0;i<world.event_count;++i) {
        printf("%s[",i?",":"");for(unsigned j=0;j<6;++j)printf("%s%u",j?",":"",world.events[i][j]);putchar(']');
    }
    printf("],\"errno\":[%u,%u],\"lifetime\":[%u,%u,%u,%u],\"sizes\":[%u,%u],\"prefixes\":[",
        load(0,CELL),load(0,CELL+4),world.old_alive,world.new_alive,world.generations[0],world.generations[1],
        world.old_size,world.new_size);
    hex(world.old_bytes);putchar(',');hex(world.new_bytes);
    printf("],\"frames\":[%u,%u]}\n",load(0,CELL-4),load(0,CELL+8));return 0;
}
