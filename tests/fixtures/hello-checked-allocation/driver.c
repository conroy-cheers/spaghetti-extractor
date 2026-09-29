/* One family oracle with controlled lower calls and nonreturning failure. */
#include "behavioral-c.h"
#include "comparison-services.h"
#include "checked-runtime.h"
#include "spx-observation.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "checked-original.h"

enum { BASE=0x400000, MEMORY_SIZE=0x50000, CELL=0x440040, OLD=0x444000,
    NEW=0x445000, STACK=0x448000, RETURN_WORD=0x401234, SAMPLE=64 };
static struct {
    unsigned char memory[MEMORY_SIZE], old_bytes[SAMPLE], new_bytes[SAMPLE];
    uint32_t operation, old, mode, seed, result, outcome, old_alive, new_alive, generation[2];
    uint64_t old_size, new_size;
    uint32_t events[8][6], event_count;
    jmp_buf terminal;
} world;
static void require(int condition) {
    if(!condition){fputs("invalid checked-allocation fixture state\n",stderr);exit(2);}
}
static uint32_t read_memory(void *unused,uint32_t address,uint32_t width,uint32_t *fault) {
    (void)unused;
    if(address<BASE || !width || width>4 || address-BASE>MEMORY_SIZE-width){*fault=1;return 0;}
    uint32_t value=0;for(uint32_t i=0;i<width;++i)value|=(uint32_t)world.memory[address-BASE+i]<<(i*8U);
    return value;
}
static void write_memory(void *unused,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault) {
    (void)unused;
    if(address<BASE || !width || width>4 || address-BASE>MEMORY_SIZE-width){*fault=1;return;}
    for(uint32_t i=0;i<width;++i)world.memory[address-BASE+i]=(unsigned char)(value>>(i*8U));
}
static uint32_t load(uint32_t address) {
    uint32_t fault=0,value=read_memory(0,address,4,&fault);require(!fault);return value;
}
static void store(uint32_t address,uint32_t value) {
    uint32_t fault=0;write_memory(0,address,4,value,&fault);require(!fault);
}
static void event(uint32_t kind,uint32_t old,uint32_t a,uint32_t b,uint32_t result) {
    require(world.event_count<8);uint32_t *row=world.events[world.event_count++];
    row[0]=kind;row[1]=old;row[2]=a;row[3]=b;row[4]=result;row[5]=load(CELL);
}
static uint32_t lower(void *unused,uint32_t operation,uint32_t old,uint32_t a,uint32_t b) {
    (void)unused;require(operation==world.operation && old==world.old);
    event(operation+1,old,a,b,0);store(CELL,5+world.seed);
    if(world.mode==2){event(20,old,a,b,0);return 0;}
    uint64_t bytes=(uint64_t)a*b, retained=world.old_size<bytes?world.old_size:bytes;
    if(retained>SAMPLE)retained=SAMPLE;
    uint32_t result=old && !world.mode?OLD:NEW;
    if(result==OLD){memset(world.old_bytes+retained,0xac,SAMPLE-(size_t)retained);world.old_size=bytes;}
    else {
        memset(world.new_bytes,operation>=CHECKED_ZEROED?0:0xac,SAMPLE);
        if(old){memcpy(world.new_bytes,world.old_bytes,(size_t)retained);world.old_alive=0;++world.generation[0];memset(world.old_bytes,0xdd,SAMPLE);}
        world.new_alive=1;++world.generation[1];world.new_size=bytes;
    }
    event(20,old,a,b,result);return result;
}
static void failed(void *unused) {
    (void)unused;event(21,0,0,0,0);world.outcome=1;longjmp(world.terminal,1);
}
spx_call_status spx_invoke_call(spx_runtime *runtime,const spx_call_event *call,
    const spx_machine_state *input,spx_machine_state *output) {
    (void)runtime;*output=*input;
    const uint32_t suppliers[]={0x6628,0x6925,0x8db8,0x692a,0x8e10,0x6934,0x65bc,0x692f};
    if(call->target_rva==0x658c)failed(0);
    else {
        require(call->target_rva==suppliers[world.operation]);
        uint32_t resize=world.operation>=2 && world.operation<=5;
        uint32_t old=resize?load(input->esp):0, a=load(input->esp+4*resize);
        uint32_t b=world.operation>=4?load(input->esp+4*(resize+1)):1;
        output->eax=lower(0,world.operation,old,a,b);
    }
    return SPX_CALL_OK;
}
int main(int argc,char **argv) {
    if(argc!=9 || (strcmp(argv[1],"source") && strcmp(argv[1],"original")))return 2;
    uint32_t args[7];
    for(unsigned i=0;i<7;++i){char *end;unsigned long v=strtoul(argv[i+2],&end,10);if(!*argv[i+2] || *end || v>UINT32_MAX)return 2;args[i]=(uint32_t)v;}
    require(args[0]<8 && args[4]<2 && args[5]<3);
    world.operation=args[0];world.old=args[4]?OLD:0;world.old_alive=args[4];world.generation[0]=args[4];
    world.mode=args[5];world.seed=args[6];world.old_size=args[4]?64:0;
    for(unsigned i=0;i<SAMPLE;++i)world.old_bytes[i]=(unsigned char)(world.seed+i);
    memset(world.new_bytes,0xef,SAMPLE);store(CELL,71+world.seed);store(CELL-4,0x12345678);store(CELL+4,0x87654321);
    int source=!strcmp(argv[1],"source");uint32_t handler=source?spx_service_handler_begin():0;
    if(!setjmp(world.terminal)) {
        if(source) {
            const struct checked_adapter adapter={0,lower,failed};
            world.result=fixture_checked_allocation(&adapter,world.operation,world.old,args[2],args[3]);
        } else {
            spx_runtime runtime={.image_base=BASE,.read=read_memory,.write=write_memory};
            spx_machine_state state={.esp=STACK,.ebx=7,.ebp=11,.esi=13,.edi=17};
            uint32_t resize=world.operation>=2 && world.operation<=5;
            store(STACK,RETURN_WORD);if(resize)store(STACK+4,world.old);
            store(STACK+4+4*resize,args[2]);store(STACK+8+4*resize,args[3]);
            uint32_t entry=args[1];spx_step_result step={SPX_UNIMPLEMENTED,0,0};
            for(unsigned i=0;i<64;++i) {
                step=original_step(&runtime,&state,entry);
                if(step.kind==SPX_RETURN)break;
                require(step.kind==SPX_JUMP || step.kind==SPX_FALLTHROUGH || step.kind==SPX_BRANCH);
                entry=step.target_rva;
            }
            require(step.kind==SPX_RETURN && step.value==RETURN_WORD && state.esp==STACK+4);
            require(state.ebx==7 && state.ebp==11 && state.esi==13 && state.edi==17);world.result=state.eax;
        }
    } else if(source)spx_service_handler_catch(handler,"nomem");
    if(source)spx_service_handler_end(handler);
    spx_observer out=spx_observe_begin(stdout);
    spx_observe_u64(&out,"result",world.result);spx_observe_u64(&out,"outcome",world.outcome);
    spx_observe_array(&out,"events");
    for(uint32_t i=0;i<world.event_count;++i)spx_observe_u32s(&out,NULL,world.events[i],6);
    spx_observe_end(&out);
    spx_observe_u64(&out,"errno",load(CELL));
    const uint32_t lifetime[]={world.old_alive,world.new_alive,world.generation[0],world.generation[1]};
    spx_observe_u32s(&out,"lifetime",lifetime,4);
    spx_observe_array(&out,"sizes");
    spx_observe_u64(&out,NULL,world.old_size);spx_observe_u64(&out,NULL,world.new_size);spx_observe_end(&out);
    spx_observe_array(&out,"prefixes");
    spx_observe_bytes(&out,NULL,world.old_bytes,SAMPLE);spx_observe_bytes(&out,NULL,world.new_bytes,SAMPLE);spx_observe_end(&out);
    const uint32_t frames[]={load(CELL-4),load(CELL+4)};
    spx_observe_u32s(&out,"frames",frames,2);
    require(spx_observe_finish(&out));return 0;
}
