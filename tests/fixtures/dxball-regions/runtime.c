/* Exercise the real native entries with complete borrowed-table observations. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "regions-runtime.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif

static struct { uint32_t before; editor_region records[25]; uint32_t after; } storage;
static uint32_t count, count_guards[2], entered[3];
static region_table table = {&count, storage.records, 25};
static void require(int condition, const char *expression, unsigned line) {
    if (!condition) { fprintf(stderr,"regions.c:%u: adapter premise failed: %s\n",line,expression); exit(3); }
}
#define REQUIRE(test) require(!!(test),#test,__LINE__)
void regions_enter(unsigned operation) { REQUIRE(operation<3); ++entered[operation]; }

#ifndef DX_STANDALONE
static void push(void) {
    memcpy((void *)0x4349d4,&storage,sizeof(storage));
    *(uint32_t *)0x435cf0=count_guards[0]; *(uint32_t *)0x435cf4=count; *(uint32_t *)0x435cf8=count_guards[1];
}
static void pull(void) {
    memcpy(&storage,(void *)0x4349d4,sizeof(storage));
    count_guards[0]=*(uint32_t *)0x435cf0; count=*(uint32_t *)0x435cf4; count_guards[1]=*(uint32_t *)0x435cf8;
}
static void native_reset(uint32_t requested) { pull(); fixture_regions_reset(&table,requested); push(); }
static void native_define(uint32_t index,uint32_t left,uint32_t top,uint32_t right,uint32_t bottom) {
    pull(); fixture_regions_define(&table,index,left,top,right,bottom); push();
}
static uint32_t native_hit(uint32_t x,uint32_t y) { pull(); uint32_t hit=fixture_regions_hit(&table,x,y); push(); return hit; }
#endif

static void snapshot(spx_observer *o,unsigned operation,const uint32_t *args,size_t size,uint32_t result) {
    spx_observe_object(o,NULL); spx_observe_u64(o,"operation",operation); spx_observe_u32s(o,"arguments",args,size);
    spx_observe_u64(o,"result",result); spx_observe_u64(o,"count",count); spx_observe_array(o,"records");
    for (unsigned i=0;i<25;++i) {
        editor_region *r=&storage.records[i]; uint32_t words[]={r->left,r->top,r->right,r->bottom,r->enabled};
        spx_observe_u32s(o,NULL,words,5);
    }
    spx_observe_end(o); uint32_t guards[]={storage.before,storage.after,count_guards[0],count_guards[1]};
    spx_observe_u32s(o,"guards",guards,4); spx_observe_end(o);
}
static void reset(spx_observer *o,uint32_t requested) {
    uint32_t n=requested+1; REQUIRE(n>=0x80000000 || n<table.capacity);
#ifndef DX_STANDALONE
    push(); ((void (*)(uint32_t))0x40d520)(requested); pull();
#else
    fixture_regions_reset(&table,requested);
#endif
    snapshot(o,0,&requested,1,0);
}
static void define(spx_observer *o,uint32_t index,uint32_t left,uint32_t top,uint32_t right,uint32_t bottom) {
    REQUIRE(index<table.capacity);
#ifndef DX_STANDALONE
    push(); ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))0x40d550)(index,left,top,right,bottom); pull();
#else
    fixture_regions_define(&table,index,left,top,right,bottom);
#endif
    const uint32_t args[]={index,left,top,right,bottom}; snapshot(o,1,args,5,0);
}
static void hit(spx_observer *o,uint32_t x,uint32_t y) {
    REQUIRE(count>=0x80000000 || count<=table.capacity); uint32_t result;
#ifndef DX_STANDALONE
    push(); result=((uint32_t (*)(uint32_t,uint32_t))0x40d590)(x,y); pull();
#else
    result=fixture_regions_hit(&table,x,y);
#endif
    const uint32_t args[]={x,y}; snapshot(o,2,args,2,result);
}
static uint32_t next_word(uint32_t *seed) { *seed=*seed*1664525+1013904223; return *seed; }
int main(int argc,char **argv) {
    REQUIRE(argc==3); unsigned mode=(unsigned)strtoul(argv[2],NULL,10); REQUIRE(mode<9);
    int source=!strcmp(argv[1],"source"); REQUIRE(source || !strcmp(argv[1],"original"));
    uint32_t seed=0x19a2e791+mode;
    for (unsigned i=0;i<25;++i) storage.records[i]=(editor_region){next_word(&seed),next_word(&seed),next_word(&seed),next_word(&seed),next_word(&seed)};
    storage.before=0x1a2b3c4d; storage.after=0x98765432; count_guards[0]=0x51525354; count_guards[1]=0x898a8b8c; count=24;
#ifndef DX_STANDALONE
    if (source) { REQUIRE(install_regions_reset((void (*)(void))native_reset));
        REQUIRE(install_regions_define((void (*)(void))native_define)); REQUIRE(install_regions_hit((void (*)(void))native_hit)); }
#else
    REQUIRE(source);
#endif
    spx_observer o=spx_observe_begin(stdout); spx_observe_array(&o,"regions");
    if (mode==0) {
        reset(&o,23);
        for (uint32_t i=1;i<=23;++i) define(&o,i,20+25*(i-1),420,44+25*(i-1),444);
        hit(&o,20,420); hit(&o,44,444); hit(&o,45,444); hit(&o,594,444); hit(&o,595,444);
    } else if (mode==1) {
        reset(&o,3); reset(&o,0); reset(&o,UINT32_MAX); hit(&o,0,0);
    } else if (mode==2) {
        reset(&o,0x7fffffff); hit(&o,0,0); reset(&o,0x80000000); hit(&o,UINT32_MAX,UINT32_MAX);
    } else if (mode==3) {
        reset(&o,3); define(&o,0,10,20,30,40); define(&o,1,10,20,30,40); define(&o,2,20,30,30,40);
        define(&o,3,30,40,30,40); define(&o,4,10,20,30,40);
        hit(&o,30,40); hit(&o,20,30); hit(&o,10,20); hit(&o,9,20); hit(&o,31,40); hit(&o,30,41);
    } else if (mode==4) {
        reset(&o,3); define(&o,1,0x80000000,0x80000000,0x7fffffff,0x7fffffff);
        define(&o,2,0xfffffff0,0xffffffe0,UINT32_MAX,UINT32_MAX); define(&o,3,0,0,0,0);
        hit(&o,0x80000000,0x80000000); hit(&o,UINT32_MAX,UINT32_MAX); hit(&o,0,0); hit(&o,0x7fffffff,0x7fffffff);
    } else if (mode==5) {
        reset(&o,3); define(&o,1,0,0,10,10); define(&o,2,0,0,10,10); define(&o,3,10,10,0,0);
        storage.records[1].enabled=0x80000000; storage.records[2].enabled=0; hit(&o,5,5);
        storage.records[2].enabled=0x12345678; hit(&o,5,5); hit(&o,11,11);
    } else if (mode==6) {
        reset(&o,23); define(&o,0,0,0,10,10); define(&o,1,0,0,10,10); define(&o,24,0,0,10,10);
        const uint32_t counts[]={0,1,2,24,25,0x80000000,UINT32_MAX};
        for (unsigned i=0;i<sizeof(counts)/sizeof(counts[0]);++i) { count=counts[i]; hit(&o,5,5); }
    } else {
        reset(&o,23);
        for (unsigned i=0;i<25;++i) {
            uint32_t a=next_word(&seed),b=next_word(&seed),c=next_word(&seed),d=next_word(&seed);
            define(&o,i,a,b,c,d); storage.records[i].enabled=next_word(&seed);
        }
        count=25;
        for (unsigned i=0;i<25;++i) { editor_region *r=&storage.records[i]; hit(&o,r->left,r->top); hit(&o,r->right,r->bottom); }
    }
    spx_observe_end(&o); REQUIRE(spx_observe_finish(&o)); fputc('\n',stdout);
#ifndef DX_STANDALONE
    if (source) REQUIRE(install_regions_reset_intact() && install_regions_define_intact() && install_regions_hit_intact());
#endif
    return 0;
}
#ifndef DX_STANDALONE
struct native_startupinfo { int newmode; };
int __cdecl __getmainargs(int *,char ***,char ***,int,struct native_startupinfo *);
static LONG WINAPI fault(EXCEPTION_POINTERS *p) {
    fprintf(stderr,"native fault %08lx at %08lx\n",p->ExceptionRecord->ExceptionCode,p->ContextRecord->Eip);
    fflush(NULL); ExitProcess(86); return EXCEPTION_EXECUTE_HANDLER;
}
static void run_case(void) {
    SetUnhandledExceptionFilter(fault); int argc; char **argv,**environment; struct native_startupinfo startup={0};
    REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&startup)); int result=main(argc,argv); fflush(NULL); ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_regions_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance; (void)reserved;
    return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
