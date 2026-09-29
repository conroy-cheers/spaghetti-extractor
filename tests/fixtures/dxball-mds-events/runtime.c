/* Exact byte regions and PE32 descriptor transport for the event boundary. */
#include "mds-events-runtime.h"
#include "spx-observation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr,"MDS event boundary line %d\n",__LINE__);abort(); } } while (0)
enum { REGION=16384, GUARD=16 };
static unsigned char input_region[REGION+2*GUARD+4],output_region[REGION+2*GUARD+4];
static uint32_t selected,block_count,last_used;
static int source_side;
void mds_events_enter(void) { ++selected; }
static uint32_t load_word(const unsigned char *p) {
    return p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static void store_word(unsigned char *p,uint32_t word) {
    for(unsigned i=0;i<4;++i)p[i]=(unsigned char)(word>>(8*i));
}
#ifndef DX_STANDALONE
static uint32_t replaced_expand(uint32_t *in,uint32_t *out) {
    mds_event_block input={(unsigned char *)(uintptr_t)in[0],in[1],in[2]};
    mds_event_block output={(unsigned char *)(uintptr_t)out[0],out[1],out[2]};
    uint32_t result=fixture_mds_expand(&input,&output);
    in[0]=(uint32_t)(uintptr_t)input.data;in[1]=input.capacity;in[2]=input.used;
    out[0]=(uint32_t)(uintptr_t)output.data;out[1]=output.capacity;out[2]=output.used;
    return result;
}
#endif
static void block(spx_observer *o,const unsigned char *bytes,uint32_t size,uint32_t input_capacity,
                  uint32_t capacity,unsigned input_alignment,unsigned output_alignment,int retain) {
    REQUIRE(size<=REGION && capacity<=REGION && input_alignment<4 && output_alignment<4);
    memset(input_region,0x6b,sizeof(input_region));
    if(!retain)memset(output_region,0xa7,sizeof(output_region));
    unsigned char *input_data=size ? input_region+GUARD+input_alignment : NULL;
    unsigned char *output_data=capacity ? output_region+GUARD+output_alignment : NULL;
    if(size)memcpy(input_data,bytes,size);
    mds_event_block input={input_data,input_capacity,size},output={output_data,capacity,retain ? last_used : UINT32_C(0xdec0adde)};
    uint32_t input_extra[13],output_extra[13];
    for(unsigned i=0;i<13;++i) { input_extra[i]=0x12600000U+i;output_extra[i]=0x74900000U+i; }
    uint32_t result;
#ifndef DX_STANDALONE
    uint32_t native_input[16]={(uint32_t)(uintptr_t)input.data,input.capacity,input.used};
    uint32_t native_output[16]={(uint32_t)(uintptr_t)output.data,output.capacity,output.used};
    memcpy(native_input+3,input_extra,sizeof(input_extra));memcpy(native_output+3,output_extra,sizeof(output_extra));
    result=((uint32_t (*)(uint32_t *,uint32_t *))0x401d60)(native_input,native_output);
    input=(mds_event_block){(unsigned char *)(uintptr_t)native_input[0],native_input[1],native_input[2]};
    output=(mds_event_block){(unsigned char *)(uintptr_t)native_output[0],native_output[1],native_output[2]};
    memcpy(input_extra,native_input+3,sizeof(input_extra));memcpy(output_extra,native_output+3,sizeof(output_extra));
    if(source_side)REQUIRE(install_mds_expand_intact());
#else
    result=fixture_mds_expand(&input,&output);
#endif
    last_used=output.used;++block_count;
    spx_observe_object(o,NULL);spx_observe_u64(o,"result",result);
    uint32_t metadata[]={input.capacity,input.used,input.data==input_data,output.capacity,output.used,output.data==output_data};
    spx_observe_u32s(o,"descriptors",metadata,6);
    spx_observe_u32s(o,"input_header_tail",input_extra,13);spx_observe_u32s(o,"output_header_tail",output_extra,13);
    spx_observe_bytes(o,"input",input_region,size+2*GUARD+input_alignment);
    spx_observe_bytes(o,"output",output_region,capacity+2*GUARD+output_alignment);spx_observe_end(o);
}
static void asset(spx_observer *o,unsigned number) {
    const char *names[]={"12flight.mds","Acker-gs.mds","Brain.mds","Ethno_pa.mds","Freebee.mds","Gmfigaro.mds"};
    REQUIRE(number<6);FILE *file=fopen(names[number],"rb");REQUIRE(file);
    REQUIRE(!fseek(file,0,SEEK_END));long length=ftell(file);REQUIRE(length>=44 && length<1048576);rewind(file);
    unsigned char *data=malloc((size_t)length);REQUIRE(data && fread(data,1,(size_t)length,file)==(size_t)length);fclose(file);
    REQUIRE(load_word(data)==0x46464952 && load_word(data+8)==0x5344494d && load_word(data+12)==0x20746d66);
    uint32_t capacity=load_word(data+24),offset=20+load_word(data+16);
    REQUIRE((load_word(data+28)&1) && offset+12<=(uint32_t)length && load_word(data+offset)==0x61746164);
    uint32_t count=load_word(data+offset+8);offset+=12;
    for(unsigned i=0;i<count;++i) {
        REQUIRE(offset+8<=(uint32_t)length);uint32_t size=load_word(data+offset+4);offset+=8;
        REQUIRE(size<=(uint32_t)length-offset);block(o,data+offset,size,size,capacity,0,0,0);offset+=size;
    }
    free(data);
}
int main(int argc,char **argv) {
    REQUIRE(argc==3);unsigned mode=(unsigned)strtoul(argv[2],NULL,10);source_side=!strcmp(argv[1],"source");
#ifndef DX_STANDALONE
    if(source_side)REQUIRE(install_mds_expand((void (*)(void))replaced_expand));
#else
    REQUIRE(source_side);
#endif
    spx_observer o=spx_observe_begin(stdout);spx_observe_object(&o,"mds_events");spx_observe_array(&o,"blocks");
    if(mode>=100)asset(&o,mode-100);
    else {
        REQUIRE(mode<28);unsigned char data[REGION]={0};uint32_t size=8,capacity=64;
        store_word(data,7);store_word(data+4,0x02000000);
        if(mode==0 || mode==23)size=0;
        if(mode==2 || mode==5) { size=16;store_word(data+8,19);store_word(data+12,0x01010203); }
        if(mode==3 || mode==4 || mode==14 || mode==15 || mode==19 || mode==22) {
            size=12;store_word(data+4,mode==4 ? 0x80000003 : mode==19 ? 0x80ffffff : 0x80000004);store_word(data+8,0xcc030201);
        }
        if(mode==5) { store_word(data+12,0x80000003);store_word(data+16,0xaa070605);store_word(data+20,3);store_word(data+24,0x03040201);size=28; }
        if(mode>=6 && mode<=8)size=mode-5;
        if(mode==9)size=4;
        if(mode==10 || mode==23)capacity=0;
        if(mode==11)capacity=11;
        if(mode==12)capacity=12;
        if(mode==13)capacity=13;
        if(mode==14 || mode==22)size=8;
        if(mode==15)capacity=15;
        if(mode==16) { size=12;store_word(data+8,31); }
        if(mode==17)store_word(data+4,0x7fffffff);
        if(mode==18)store_word(data+4,0x80000000);
        if(mode==26 || mode==27) {
            size=0;capacity=4096;uint32_t random=0x12489abc;
            for(unsigned i=0;i<64;++i) {
                random=random*1664525U+1013904223U;store_word(data+size,random);size+=4;
                uint32_t payload=mode==27 && !(i%3) ? i%13 : 0;
                store_word(data+size,payload ? 0x80000000U|payload : random&0x7fffffffU);size+=4;
                for(unsigned j=0;j<((payload+3)&~3U);++j)data[size++]=(unsigned char)(random+j);
            }
        }
        block(&o,data,size,mode==24 ? 0 : size,capacity,mode==20,mode==21,0);
        if(mode==25) { store_word(data,99);block(&o,data,4,64,capacity,0,0,1); }
    }
    spx_observe_end(&o);spx_observe_end(&o);REQUIRE(spx_observe_finish(&o));puts("");
    if(source_side)REQUIRE(selected==block_count);
    return 0;
}
#ifndef DX_STANDALONE
struct native_startupinfo { int newmode; };
extern int __cdecl __getmainargs(int *,char ***,char ***,int,struct native_startupinfo *);
static void run_case(void) {
    int argc;char **argv,**environment;struct native_startupinfo startup={0};REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&startup));
    int result=main(argc,argv);fflush(NULL);ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_mds_events_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reserved;return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
