#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "math-runtime.h"
#include "spx-observation.h"
#define REQUIRE(x) do { if(!(x)) { fprintf(stderr,"math boundary line %d: %s\n",__LINE__,#x);abort(); } } while(0)
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
static int source_side;
static uint32_t selected[8],rows[10000][6],row_count;
static int32_t words[851];
static math_tables tables={words,words+362};
void math_enter(unsigned operation) { REQUIRE(operation<8);++selected[operation]; }
static void initialize(void) {
#ifndef DX_STANDALONE
    if(!source_side)((void (*)(void))0x40d6b0)();
    else
#endif
    fixture_math_initialize(&tables);
}
static uint32_t word_read(unsigned cosine,uint32_t angle) {
#ifndef DX_STANDALONE
    if(!source_side)return ((uint32_t (*)(uint32_t))(cosine ? 0x40d740 : 0x40d710))(angle);
#endif
    return cosine ? fixture_math_cosine(&tables,angle) : fixture_math_sine(&tables,angle);
}
static double value_read(unsigned cosine,uint32_t angle) {
#ifndef DX_STANDALONE
    if(!source_side)return ((double (*)(uint32_t))(cosine ? 0x40d7b0 : 0x40d770))(angle);
#endif
    return cosine ? fixture_math_cosine_value(&tables,angle) : fixture_math_sine_value(&tables,angle);
}
static uint32_t project(unsigned x,uint32_t origin,uint32_t angle,uint32_t distance) {
#ifndef DX_STANDALONE
    if(!source_side)return ((uint32_t (*)(uint32_t,uint32_t,uint32_t))(x ? 0x40d7f0 : 0x40d820))(origin,angle,distance);
#endif
    return x ? fixture_math_project_x(&tables,origin,angle,distance) : fixture_math_project_y(&tables,origin,angle,distance);
}
static uint32_t pan(uint32_t position) {
#ifndef DX_STANDALONE
    if(!source_side)return ((uint32_t (*)(uint32_t))0x403550)(position);
#endif
    return fixture_math_pan(position);
}
static void record(uint32_t op,uint32_t a,uint32_t b,uint32_t c,uint64_t value) {
    REQUIRE(row_count<10000);uint32_t row[]={op,a,b,c,(uint32_t)value,(uint32_t)(value>>32)};
    memcpy(rows[row_count++],row,sizeof(row));
}
static void readers(uint32_t angle) {
    for(unsigned k=0;k<2;++k) {
        record(k+1,angle,0,0,word_read(k,angle));double value=value_read(k,angle);uint64_t bits;memcpy(&bits,&value,8);
        record(k+3,angle,0,0,bits);
    }
}
static const uint32_t edges[]={0,1,15,16,17,30,45,90,180,320,359,360,361,719,720,1024,
    UINT32_MAX,UINT32_MAX-1,0u-16,0u-320,0u-359,0u-360,0u-361,0u-720,0x7fffffff,0x80000000,0x80000001,0xffff0001};
#ifndef DX_STANDALONE
static void native_fallback(void) { REQUIRE(0); }
#endif
int main(int argc,char **argv) {
    REQUIRE(argc==3);source_side=!strcmp(argv[1],"source");unsigned mode=(unsigned)strtoul(argv[2],NULL,10);REQUIRE(mode<9);
    uint32_t seed=0xa654ef23;
    for(unsigned i=0;i<851;++i) { seed=seed*1664525+1013904223;memcpy(&words[i],&seed,4); }
#ifndef DX_STANDALONE
    memcpy((void *)0x4351a8,words,sizeof(words));
    if(source_side) {
#define TRAP(n) REQUIRE(install_math_##n(native_fallback));
        TRAP(initialize) TRAP(sine) TRAP(cosine) TRAP(sine_value) TRAP(cosine_value) TRAP(project_x) TRAP(project_y) TRAP(pan)
#undef TRAP
    }
#endif
    if(mode<2) { initialize();if(mode)initialize(); }
    else if(mode==2) { for(unsigned i=0;i<sizeof(edges)/sizeof(*edges);++i)readers(edges[i]); }
    else if(mode==3) { for(int i=-720;i<=720;++i)readers((uint32_t)i); }
    else if(mode==4) { for(unsigned i=0;i<sizeof(edges)/sizeof(*edges);++i)record(7,edges[i],0,0,pan(edges[i])); }
    else if(mode==5) { for(int i=-1024;i<=1024;++i)record(7,(uint32_t)i,0,0,pan((uint32_t)i)); }
    else if(mode==6) {
        for(unsigned i=0;i<2048;++i) { seed=seed*1664525+1013904223;record(7,seed,0,0,pan(seed)); }
    } else {
        if(mode==7)initialize();
        for(unsigned i=0;i<sizeof(edges)/sizeof(*edges);++i)for(unsigned j=0;j<sizeof(edges)/sizeof(*edges);++j) {
            uint32_t origin=edges[(i+j)%28],angle=edges[i],distance=edges[j];
            record(5,origin,angle,distance,project(1,origin,angle,distance));
            record(6,origin,angle,distance,project(0,origin,angle,distance));
        }
    }
#ifndef DX_STANDALONE
    if(!source_side)memcpy(words,(void *)0x4351a8,sizeof(words));
#endif
    if(source_side) { unsigned count=0;for(unsigned i=0;i<8;++i)count+=selected[i];REQUIRE(count); }
    spx_observer out=spx_observe_begin(stdout);spx_observe_object(&out,"math");spx_observe_u32s(&out,"storage",(const uint32_t *)words,851);
    spx_observe_array(&out,"results");for(unsigned i=0;i<row_count;++i)spx_observe_u32s(&out,NULL,rows[i],6);
    spx_observe_end(&out);spx_observe_end(&out);REQUIRE(spx_observe_finish(&out));puts("");return 0;
}
#ifndef DX_STANDALONE
struct native_startupinfo { int newmode; };
extern int __cdecl __getmainargs(int *,char ***,char ***,int,struct native_startupinfo *);
static void run_case(void) {
    int argc;char **argv,**environment;struct native_startupinfo startup={0};REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&startup));
    int result=main(argc,argv);fflush(NULL);ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_math_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reserved;return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
