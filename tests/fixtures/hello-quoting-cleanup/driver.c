/* Controlled release observes the cache at every call. The original cleanup
 * runs its complete retained body; no release supplier implementation is linked. */
#include "behavioral-c.h"
#include "cleanup-runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { BASE=0x400000, SIZE=0x50000, TABLE=0x420050, INITIAL=0x420054,
    COUNT=0x42005c, IMMORTAL=0x4300c0, HEAP=0x441000, BUFFERS=0x442000,
    STACK=0x448000, RETURN_WORD=0x401234, SLOTS=HELLO_CLEANUP_MAX_SLOTS };
struct spx_opaque_quote_bytes_v5 { uint32_t address; };
typedef struct spx_opaque_quote_bytes_v5 Buffer;
typedef struct spx_opaque_quote_table_v5 Slot;
static struct {
    unsigned char memory[SIZE];
    Buffer buffers[SLOTS], immortal;
    Slot initial, slots[SLOTS];
    struct spx_opaque_quote_state_v5 state;
    uint32_t alive[SLOTS], table_alive, events[SLOTS+4][5], event_count;
} world;

static void require(int condition) {
    if (!condition) { fputs("invalid cleanup fixture state or lifetime\n",stderr); exit(2); }
}
static uint32_t memory_read(void *unused,uint32_t address,uint32_t width,uint32_t *fault) {
    (void)unused;
    if (address<BASE || !width || width>4 || address-BASE>SIZE-width ||
        (!world.table_alive && address>=HEAP && address<HEAP+SLOTS*8)) { *fault=1;return 0; }
    uint32_t value=0;
    for(uint32_t i=0;i<width;++i)value|=(uint32_t)world.memory[address-BASE+i]<<(i*8U);
    return value;
}
static void memory_write(void *unused,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault) {
    (void)unused;
    if (address<BASE || !width || width>4 || address-BASE>SIZE-width) { *fault=1;return; }
    for(uint32_t i=0;i<width;++i)world.memory[address-BASE+i]=(unsigned char)(value>>(i*8U));
}
static uint32_t get(uint32_t address) {
    uint32_t fault=0,value=memory_read(0,address,4,&fault);require(!fault);return value;
}
static void put(uint32_t address,uint32_t value) {
    uint32_t fault=0;memory_write(0,address,4,value,&fault);require(!fault);
}
static uint32_t buffer_address(Buffer *buffer) { return buffer?buffer->address:0; }
static uint32_t table_address(Slot *table) {
    require(table==&world.initial || table==world.slots);
    return table==&world.initial?INITIAL:HEAP;
}
static void publish(void) {
    put(TABLE,table_address(world.state.table));put(COUNT,world.state.count);
    put(INITIAL,world.initial.size);put(INITIAL+4,buffer_address(world.initial.buffer));
    if(world.table_alive)for(uint32_t i=0;i<SLOTS;++i) {
        put(HEAP+i*8,world.slots[i].size);put(HEAP+i*8+4,buffer_address(world.slots[i].buffer));
    }
}
static void release(uint32_t address) {
    require(world.event_count<SLOTS+4);uint32_t *event=world.events[world.event_count++];
    event[0]=address;event[1]=get(COUNT);event[2]=get(TABLE);
    event[3]=get(INITIAL);event[4]=get(INITIAL+4);
    if(!address)return;
    if(address==HEAP) {
        require(world.table_alive);world.table_alive=0;memset(world.memory+HEAP-BASE,0xdd,SLOTS*8);return;
    }
    require(address>=BUFFERS && address<BUFFERS+SLOTS*64 && (address-BUFFERS)%64==0);
    uint32_t index=(address-BUFFERS)/64;
    require(world.alive[index]);world.alive[index]=0;memset(world.memory+address-BASE,0xdd,64);
}
static void release_buffer(void *unused,Buffer *buffer) {
    (void)unused;publish();release(buffer_address(buffer));
}
static void release_table(void *unused,Slot *table) {
    (void)unused;publish();release(table_address(table));
}
spx_call_status spx_invoke_call(spx_runtime *runtime,const spx_call_event *call,
    const spx_machine_state *input,spx_machine_state *output) {
    (void)runtime;*output=*input;
    require(call->kind==SPX_CALL_INTERNAL_DIRECT && call->target_rva==0x1b34);
    release(get(input->esp));return SPX_CALL_OK;
}
spx_step_result spx_sub_000052f2(spx_runtime *,spx_machine_state *,uint32_t);
static uint32_t original(void) {
    spx_runtime runtime={.image_base=BASE,.read=memory_read,.write=memory_write};
    spx_machine_state state={.esp=STACK,.ebx=7,.ebp=11,.esi=13,.edi=17};
    put(STACK,RETURN_WORD);
    spx_step_result result=spx_sub_000052f2(&runtime,&state,0x52f2);
    require(result.kind==SPX_RETURN && result.value==RETURN_WORD && state.esp==STACK+4);
    require(state.ebx==7 && state.ebp==11 && state.esi==13 && state.edi==17);
    return state.eax;
}
static void setup(uint32_t count,uint32_t mode,uint32_t seed) {
    for(uint32_t i=0;i<SIZE;++i)world.memory[i]=(unsigned char)(seed+i*7U);
    world.immortal.address=IMMORTAL;world.table_alive=count>1 || (mode&1U);
    for(uint32_t i=0;i<SLOTS;++i) {
        world.buffers[i].address=BUFFERS+i*64;
        world.slots[i].size=48+i;
        world.slots[i].buffer=(i<count && !(seed&(1U<<(i%8))))?&world.buffers[i]:NULL;
        world.alive[i]=world.slots[i].buffer!=NULL;
    }
    uint32_t kind=mode>>1;
    world.slots[0].buffer=kind==0?&world.immortal:kind==2?NULL:&world.buffers[0];
    world.alive[0]=world.slots[0].buffer==&world.buffers[0];
    world.slots[0].size=kind==0?256:48;
    world.initial=world.slots[0];
    if(world.table_alive && kind==3)world.initial.size=31; /* Earlier record shares the live buffer. */
    world.state=(struct spx_opaque_quote_state_v5){.table=world.table_alive?world.slots:&world.initial,
        .count=count,.initial_table=&world.initial,.initial_buffer=&world.immortal};
    publish();
}
static void hex(uint32_t address,uint32_t size) {
    putchar('"');for(uint32_t i=0;i<size;++i)printf("%02x",world.memory[address-BASE+i]);putchar('"');
}
int main(int argc,char **argv) {
    if(argc!=5 || (strcmp(argv[1],"original") && strcmp(argv[1],"source")))return 2;
    uint32_t arguments[3];
    for(unsigned i=0;i<3;++i) {
        char *end;unsigned long value=strtoul(argv[i+2],&end,10);
        if(!*argv[i+2] || *end || value>UINT32_MAX)return 2;
        arguments[i]=(uint32_t)value;
    }
    if(arguments[0]>SLOTS || arguments[1]>7 || arguments[2]>255)return 2;
    setup(arguments[0],arguments[1],arguments[2]);uint32_t results[2];
    const struct cleanup_adapter adapter={0,release_buffer,release_table};
    for(unsigned i=0;i<2;++i) {
        if(!strcmp(argv[1],"source")) {results[i]=fixture_quote_cleanup(&world.state,&adapter);publish();}
        else results[i]=original();
    }
    printf("{\"returns\":[%u,%u],\"cache\":[%u,%u],\"initial\":[%u,%u],\"events\":[",
        results[0],results[1],get(TABLE),get(COUNT),get(INITIAL),get(INITIAL+4));
    for(uint32_t i=0;i<world.event_count;++i) {
        printf("%s[",i?",":"");for(unsigned j=0;j<5;++j)printf("%s%u",j?",":"",world.events[i][j]);putchar(']');
    }
    printf("],\"alive\":[%u",world.table_alive);
    for(unsigned i=0;i<SLOTS;++i)printf(",%u",world.alive[i]);
    printf("],\"contents\":[");hex(IMMORTAL,256);putchar(',');hex(BUFFERS,SLOTS*64);
    printf("],\"frames\":[%u,%u,%u,%u,%u]}\n",get(TABLE-4),get(COUNT+4),get(IMMORTAL+256),get(HEAP-4),get(HEAP+SLOTS*8));
    return 0;
}
