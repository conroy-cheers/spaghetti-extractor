/* Machine-call adapters around the declared palette and wait boundaries. */
#include "palette-runtime.h"
#include "spx-observation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
#define REQUIRE(x) do { if(!(x)) { fprintf(stderr,"palette boundary %s:%d: %s\n",__func__,__LINE__,#x);abort(); } } while(0)
static pcx_state colors;
static flow_state flow;
static palette_state state={&colors,&flow};
static uint32_t sequence_storage[70],selected[5],mode,event_count,apply_count,wait_count;
static palette_sequence sequence={sequence_storage+2};
static int source_side;
static spx_observer *observer;
void palette_enter(unsigned operation) { REQUIRE(operation<5);++selected[operation]; }
static void snapshot(const char *name) {
    spx_observe_object(observer,name);spx_observe_u64(observer,"windowed",flow.windowed);
    spx_observe_bytes(observer,"colors",(const unsigned char *)&colors,sizeof(colors));
    spx_observe_u32s(observer,"sequence",sequence_storage,70);spx_observe_end(observer);
}
static void call(unsigned op,uint32_t first,uint32_t count) {
    REQUIRE(++event_count<200);uint32_t args[]={op,first,count};
    spx_observe_object(observer,NULL);spx_observe_u32s(observer,"arguments",args,3);snapshot("before");
    if(op==0) {
        REQUIRE(first<=256 && count<=256-first);++apply_count;
        if(mode==13 && apply_count==1)flow.windowed=1;
        if(mode==14 && apply_count==1)colors.staged[9][1]=241;
        if(mode==29)sequence.values[0]^=0x98765432;
    } else {
        ++wait_count;
        if((mode==11 || mode==12) && wait_count==1)
            for(unsigned i=0;i<256;++i)for(unsigned c=0;c<3;++c)colors.current[i][c]=colors.staged[i][c]=0;
    }
    snapshot("after");spx_observe_end(observer);
}
void palette_apply(void *u,palette_state *s,uint32_t first,uint32_t count) { (void)u;REQUIRE(s==&state);call(0,first,count); }
void palette_wait(void *u,palette_state *s,uint32_t count) { (void)u;REQUIRE(s==&state);call(1,0,count); }
#ifndef DX_STANDALONE
static uint32_t vtable[7],object;
static void pull(void) { memcpy(&colors,(void *)0x42c148,sizeof(colors));flow.windowed=*(uint32_t *)0x434998; }
static void push(void) { memcpy((void *)0x42c148,&colors,sizeof(colors));*(uint32_t *)0x434998=flow.windowed; }
static uint32_t WINAPI native_apply(uint32_t handle,uint32_t flags,uint32_t first,uint32_t count,void *entries) {
    REQUIRE(handle==(uint32_t)(uintptr_t)&object && !flags && entries==(void *)(uintptr_t)(0x42c148+4*first));
    pull();palette_apply(NULL,&state,first,count);push();return 0x80004005;
}
static void native_wait(uint32_t count) { pull();palette_wait(NULL,&state,count);push(); }
static void live_fade(uint32_t wait,uint32_t step,uint32_t first,uint32_t last,uint32_t direction) {
    pull();fixture_palette_fade(&state,wait,step,first,last,direction);push();
}
#define SHIFT(n) static void live_##n(uint32_t first,uint32_t last,uint32_t wrap) { pull();fixture_palette_##n(&state,first,last,wrap);push(); }
SHIFT(right) SHIFT(left)
static void live_set(uint32_t i,uint32_t r,uint32_t g,uint32_t b) { pull();fixture_palette_set(&state,i,r,g,b);push(); }
static void live_rotate(uint32_t i,uint32_t count,uint32_t *values) { pull();palette_sequence s={values};fixture_palette_rotate(&state,i,count,&s);push(); }
#endif
static void invoke(unsigned op,const uint32_t *a) {
#ifndef DX_STANDALONE
    push();
    switch(op) {
    case 0: ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))0x402770)(a[0],a[1],a[2],a[3],a[4]);break;
    case 1: ((void (*)(uint32_t,uint32_t,uint32_t))0x402a50)(a[0],a[1],a[2]);break;
    case 2: ((void (*)(uint32_t,uint32_t,uint32_t))0x402af0)(a[0],a[1],a[2]);break;
    case 3: ((void (*)(uint32_t,uint32_t,uint32_t *))0x402ba0)(a[0],a[1],sequence.values);break;
    default: ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))0x402c10)(a[0],a[1],a[2],a[3]);break;
    }
    pull();
#else
    switch(op) {
    case 0: fixture_palette_fade(&state,a[0],a[1],a[2],a[3],a[4]);break;
    case 1: fixture_palette_right(&state,a[0],a[1],a[2]);break;
    case 2: fixture_palette_left(&state,a[0],a[1],a[2]);break;
    case 3: fixture_palette_rotate(&state,a[0],a[1],&sequence);break;
    default: fixture_palette_set(&state,a[0],a[1],a[2],a[3]);break;
    }
#endif
}
int main(int argc,char **argv) {
    REQUIRE(argc==3);mode=(uint32_t)strtoul(argv[2],NULL,10);REQUIRE(mode<31);source_side=!strcmp(argv[1],"source");
    for(unsigned i=0;i<sizeof(colors);++i)((unsigned char *)&colors)[i]=(unsigned char)(i*13+i/4+3);
    for(unsigned i=0;i<70;++i)sequence_storage[i]=0x12300000U+i*1397;
    uint32_t op=0,args[5]={2,6,7,12,0};
    if(mode==1 || mode==3 || mode==14)args[4]=1;
    if(mode==2 || mode==10)memset(colors.current,0,sizeof(colors.current));
    if(mode==3)memcpy(colors.current,colors.staged,sizeof(colors.current));
    if(mode==4) { args[2]=256;args[3]=255; }
    if(mode==5 || mode==22 || mode==24 || mode==28)flow.windowed=1;
    if(mode==6)flow.windowed=2;
    if(mode==7)args[4]=2;
    if(mode==8)args[1]=512;
    if(mode==9) { memset(colors.current,12,sizeof(colors.current));args[1]=12; }
    if(mode==10 || mode==11)args[1]=0;
    if(mode==12)args[1]=0xffffffff;
    if(mode>=15 && mode<=22) { op=mode==16 || mode==18 ? 2 : 1;args[0]=3;args[1]=11;args[2]=1;
        if(mode==17 || mode==18)args[2]=0;
        if(mode==19)args[2]=2;
        if(mode==20)args[1]=3;
        if(mode==21) { args[0]=0;args[1]=255; }
    }
    if(mode==23 || mode==24) { op=4;args[0]=255;args[1]=0xffff0123;args[2]=0xdeadbeef;args[3]=0x80000142; }
    if(mode>=25 && mode<=29) { op=3;args[0]=189;args[1]=mode==25 ? 3 : mode==26 ? 4 : 66; }
#ifndef DX_STANDALONE
    vtable[6]=(uint32_t)(uintptr_t)native_apply;object=(uint32_t)(uintptr_t)vtable;*(uint32_t *)0x4349b8=(uint32_t)(uintptr_t)&object;
    REQUIRE(install_palette_wait((void (*)(void))native_wait));
    if(source_side) {
        REQUIRE(install_palette_fade((void (*)(void))live_fade));REQUIRE(install_palette_right((void (*)(void))live_right));
        REQUIRE(install_palette_left((void (*)(void))live_left));REQUIRE(install_palette_rotate((void (*)(void))live_rotate));
        REQUIRE(install_palette_set((void (*)(void))live_set));
    }
#else
    REQUIRE(source_side);
#endif
    spx_observer out=spx_observe_begin(stdout);observer=&out;spx_observe_object(observer,"palette");snapshot("initial");
    spx_observe_array(observer,"calls");invoke(op,args);
    if(mode==30) { invoke(1,(uint32_t[]){7,12,1});invoke(2,(uint32_t[]){7,12,0});invoke(3,(uint32_t[]){189,66});invoke(4,(uint32_t[]){19,5,9,11});invoke(0,(uint32_t[]){0,32,7,12,1}); }
    spx_observe_end(observer);snapshot("final");spx_observe_end(observer);REQUIRE(spx_observe_finish(observer));puts("");
    if(source_side) { uint32_t count=0;for(unsigned i=0;i<5;++i)count+=selected[i];REQUIRE(count); }
    return 0;
}
#ifndef DX_STANDALONE
struct native_startupinfo { int newmode; };
extern int __cdecl __getmainargs(int *,char ***,char ***,int,struct native_startupinfo *);
static void run_case(void) {
    int argc;char **argv,**environment;struct native_startupinfo s={0};REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&s));
    int result=main(argc,argv);fflush(NULL);ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_palette_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reserved;return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
