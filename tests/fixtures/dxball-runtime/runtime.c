/* Concrete input schedules and per-target native state/stack transport. */
#include "runtime-support.h"
#include "spx-observation.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#include "pe32-import-hook.h"
#include "comparison-services.h"
#endif
#define REQUIRE(x) do { if(!(x)) { fprintf(stderr,"runtime boundary %s:%d: %s\n",__func__,__LINE__,#x);abort(); } } while(0)
struct spx_opaque_shell_device_v5 { uint32_t identity; };
static shell_device devices[2]={{1},{2}};
static scene_state scene;
static shell_state application={.scene=&scene,.graphics=&devices[0]};
static bootstrap_state bootstrap={&application,100};
static runtime_state state={&bootstrap,1,1000,1};
static runtime_sample history={8000,0x13579bdf};
static uint32_t mode,selected[8],event_count,now_count,blank_count,counter_count,fault_code;
static uint32_t now_values[16],now_length,platform_history=1;
static int source_side;
static jmp_buf fault_landing;
static spx_observer *observer;
void runtime_enter(unsigned op) { REQUIRE(op<8);++selected[op]; }
static uint32_t device_id(shell_device *p) { REQUIRE(p==&devices[0] || p==&devices[1]);return p==&devices[0] ? 1 : 2; }
static void snapshot(const char *name) {
    uint32_t fields[]={state.counter_enabled,state.counter_divisor,state.random_seed,bootstrap.last_refresh,
        scene.refresh_ok,device_id(application.graphics),history.low,history.high};
    spx_observe_u32s(observer,name,fields,8);
}
static void begin(runtime_state *s,unsigned op,const uint32_t *args,unsigned count) {
    REQUIRE(s==&state && ++event_count<200);spx_observe_object(observer,NULL);spx_observe_u64(observer,"service",op);
    spx_observe_u32s(observer,"arguments",args,count);snapshot("before");
}
static uint32_t end(uint32_t result) { snapshot("after");spx_observe_u64(observer,"result",result);spx_observe_end(observer);return result; }
#define BEGIN0(n) (void)u;begin(s,RUNTIME_SERVICE_##n,NULL,0)
#define BEGIN(n,...) (void)u;const uint32_t args[]={__VA_ARGS__};begin(s,RUNTIME_SERVICE_##n,args,sizeof(args)/4)
void runtime_version(void *u,runtime_state *s,runtime_version_query *v) {
    REQUIRE(v);BEGIN(VERSION,v->size,v->platform);
    if(mode!=17)v->platform=mode==15 ? 1 : mode==16 ? 3 : 2;
    uint32_t after[]={v->size,v->platform};spx_observe_u32s(observer,"output",after,2);(void)end(0);
}
uint32_t runtime_frequency(void *u,runtime_state *s,runtime_sample *value) {
    REQUIRE(value);BEGIN(FREQUENCY,value->low,value->high);
    if(mode!=8)value->low=mode==13 ? 999 : mode==4 ? 1000 : mode==7 ? 4000 : 1000003;
    value->high=0x12345678;
    if(mode==10) { state.counter_divisor=77;state.counter_enabled=0; }
    uint32_t output[]={value->low,value->high};spx_observe_u32s(observer,"output",output,2);
    return end(mode==3 ? 0 : mode==45 ? 2 : 1);
}
void runtime_counter(void *u,runtime_state *s,runtime_sample *value) {
    REQUIRE(value);BEGIN(COUNTER,value->low,value->high);++counter_count;
    if(mode!=6 && mode!=7 && mode!=9) { value->low=1234567+counter_count;value->high=0x87654321; }
    if(mode==9)value->high=0;
    if(mode==11)state.counter_divisor=7;
    if(mode==12)state.counter_divisor=0;
    uint32_t output[]={value->low,value->high};spx_observe_u32s(observer,"output",output,2);(void)end(0);
}
uint32_t runtime_ticks(void *u,runtime_state *s) {
    BEGIN0(TICKS);if(mode==37)state.random_seed=0xabcddcba;return end(mode==36 ? UINT32_MAX : 599);
}
uint32_t runtime_now(void *u,runtime_state *s) {
    BEGIN0(NOW);REQUIRE(now_count<now_length);uint32_t result=now_values[now_count++];
    if(mode==33) { bootstrap.last_refresh=now_count==1 ? 400 : 0x98765432;scene.refresh_ok=1; }
    return end(result);
}
void runtime_vertical_blank(void *u,runtime_state *s,shell_device *device,uint32_t flags) {
    BEGIN(VERTICAL_BLANK,device_id(device),flags);++blank_count;
    if(mode==28 && blank_count==1) { application.graphics=&devices[1];scene.refresh_ok=0; }
    (void)end(0);
}
void runtime_fault(void *u,runtime_state *s,uint32_t code) {
    BEGIN(FAULT,code);fault_code=code;(void)end(0);longjmp(fault_landing,1);
}
#undef BEGIN
#undef BEGIN0

#ifndef DX_STANDALONE
uint32_t runtime_native_history[3] __attribute__((used));
static uint32_t native_devices[2],draw_vtable[23];
static uint32_t *word(uint32_t address) { return (uint32_t *)(uintptr_t)address; }
static uint32_t device_address(shell_device *p) { return (uint32_t)(uintptr_t)&native_devices[device_id(p)-1]; }
static shell_device *device_view(uint32_t address) {
    for(unsigned i=0;i<2;++i)if(address==device_address(&devices[i]))return &devices[i];
    REQUIRE(0);return NULL;
}
#define FIELDS(X) X(state.counter_enabled,0x435cf8) X(state.counter_divisor,0x435d00) X(state.random_seed,0x417c74) \
    X(bootstrap.last_refresh,0x4349c4) X(scene.refresh_ok,0x4349c0)
static void push(void) {
#define PUT(field,address) *word(address)=field;
    FIELDS(PUT)
#undef PUT
    *word(0x4349a8)=device_address(application.graphics);
}
static void pull(void) {
#define GET(field,address) field=*word(address);
    FIELDS(GET)
#undef GET
    application.graphics=device_view(*word(0x4349a8));
}
#undef FIELDS
static uint32_t WINAPI native_version(uint32_t *v) {
    REQUIRE(v);pull();runtime_version_query view={v[0],v[4]};runtime_version(NULL,&state,&view);v[0]=view.size;v[4]=view.platform;push();return mode==18 ? 0 : 1;
}
static uint32_t WINAPI native_frequency(runtime_sample *value) { pull();uint32_t result=runtime_frequency(NULL,&state,value);push();return result; }
static uint32_t WINAPI native_counter(runtime_sample *value) { pull();runtime_counter(NULL,&state,value);push();return mode==6 || mode==7 ? 0 : 1; }
static uint32_t WINAPI native_ticks(void) { pull();uint32_t result=runtime_ticks(NULL,&state);push();return result; }
static uint32_t native_now(void) { pull();uint32_t result=runtime_now(NULL,&state);push();return result; }
static uint32_t WINAPI native_blank(uint32_t device,uint32_t flags,void *event) {
    REQUIRE(!event);pull();runtime_vertical_blank(NULL,&state,device_view(device),flags);push();return UINT32_MAX;
}
static LONG CALLBACK native_fault(EXCEPTION_POINTERS *e) {
    uintptr_t address=(uintptr_t)e->ExceptionRecord->ExceptionAddress;
    if(e->ExceptionRecord->ExceptionCode!=EXCEPTION_INT_DIVIDE_BY_ZERO || (address!=0x40db67 && address!=0x40ae26))return EXCEPTION_CONTINUE_SEARCH;
    pull();runtime_fault(NULL,&state,e->ExceptionRecord->ExceptionCode);return EXCEPTION_CONTINUE_SEARCH;
}
static uint32_t live_now(void) { pull();uint32_t result=fixture_runtime_now(&state,&history);push();return result; }
static void live_clock_init(void) { pull();fixture_runtime_clock_init(&state,platform_history);push(); }
static uint32_t live_elapsed(uint32_t previous,uint32_t delay) { pull();uint32_t result=fixture_runtime_elapsed(&state,previous,delay);push();return result; }
static void live_wait(uint32_t count) { pull();fixture_runtime_wait(&state,count);push(); }
static void live_set_seed(uint32_t seed) { pull();fixture_runtime_set_seed(&state,seed);push(); }
static uint32_t live_next(void) { pull();uint32_t result=fixture_runtime_next(&state);push();return result; }
static uint32_t live_random(uint32_t limit) { pull();uint32_t result=fixture_runtime_random(&state,limit);push();return result; }
static void live_seed(void) { pull();fixture_runtime_seed(&state);push(); }
/* The machine now frame is 8 bytes; version.platform is entry SP - 0x84. */
static uint32_t __attribute__((naked)) seeded_now(void) {
    __asm__ volatile("movl _runtime_native_history, %eax\n\tmovl %eax,-8(%esp)\n\t"
        "movl _runtime_native_history+4, %eax\n\tmovl %eax,-4(%esp)\n\tmovl $0x40db20,%eax\n\tjmp *%eax\n\t");
}
static void __attribute__((naked)) seeded_initialize(void) {
    __asm__ volatile("movl _runtime_native_history+8, %eax\n\tmovl %eax,-0x84(%esp)\n\tmovl $0x40dba0,%eax\n\tjmp *%eax\n\t");
}
#endif
static void invoke(unsigned op,uint32_t a,uint32_t b) {
    spx_observe_object(observer,NULL);uint32_t arguments[]={op,a,b};spx_observe_u32s(observer,"operation",arguments,3);snapshot("before");
    spx_observe_array(observer,"calls");uint32_t result=0;
#ifndef DX_STANDALONE
    uint32_t handler=source_side ? spx_service_handler_begin() : 0;push();
#endif
    if(!setjmp(fault_landing)) {
#ifndef DX_STANDALONE
        runtime_native_history[0]=history.low;runtime_native_history[1]=history.high;runtime_native_history[2]=platform_history;
        switch(op) {
        case 0:seeded_initialize();break;
        case 1:result=seeded_now();break;
        case 2:result=((uint32_t (*)(uint32_t,uint32_t))0x40db80)(a,b);break;
        case 3:((void (*)(uint32_t))0x402240)(a);break;
        case 4:((void (*)(uint32_t))0x40ea60)(a);break;
        case 5:result=((uint32_t (*)(void))0x40ea70)();break;
        case 6:result=((uint32_t (*)(uint32_t))0x40ae20)(a);break;
        default:((void (*)(void))0x40ae30)();break;
        }
        pull();
#else
        switch(op) {
        case 0:fixture_runtime_clock_init(&state,platform_history);break;
        case 1:result=fixture_runtime_now(&state,&history);break;
        case 2:result=fixture_runtime_elapsed(&state,a,b);break;
        case 3:fixture_runtime_wait(&state,a);break;
        case 4:fixture_runtime_set_seed(&state,a);break;
        case 5:result=fixture_runtime_next(&state);break;
        case 6:result=fixture_runtime_random(&state,a);break;
        default:fixture_runtime_seed(&state);break;
        }
#endif
    } else {
        REQUIRE(fault_code);
#ifndef DX_STANDALONE
        if(source_side)spx_service_handler_catch(handler,"arithmetic-fault");
#endif
    }
#ifndef DX_STANDALONE
    if(source_side)spx_service_handler_end(handler);
#endif
    spx_observe_end(observer);snapshot("after");spx_observe_u64(observer,"result",result);spx_observe_u64(observer,"fault",fault_code);spx_observe_end(observer);
}
int main(int argc,char **argv) {
    REQUIRE(argc==3);source_side=!strcmp(argv[1],"source");mode=(uint32_t)strtoul(argv[2],NULL,10);REQUIRE(mode<46);
    if(!mode)state.counter_enabled=0;
    if(mode==2 || mode==3 || mode==4 || mode==7 || mode==8 || mode==10 || mode==13 || mode==44 || mode==45)state.counter_divisor=0;
    unsigned op=mode<14 || mode>=44 ? 1 : mode<=18 ? 0 : mode<=24 ? 2 : mode<=33 ? 3 : mode==34 ? 5 : mode<=37 || mode==43 ? 7 : 6;
    uint32_t a=0,b=0;
    if(op==2) {
        a=100;b=17;now_values[0]=mode==19 ? 116 : mode==20 ? 117 : mode==21 ? 118 : mode==22 ? 99 : mode==23 ? 0xfffffff9 : 100;
        if(mode==23) { a=0xfffffff0;b=32; }
        if(mode==24)b=0;
        now_length=1;
    }
    if(op==3) {
        a=mode==26 ? 0 : mode==27 ? UINT32_MAX : mode<=28 ? 3 : mode==30 ? 2 : 1;scene.refresh_ok=mode<=28 ? 2 : 0;
        uint32_t values[]={100,116,117,120,120,137,141};memcpy(now_values,values,sizeof(values));now_length=7;
        if(mode==31) { now_values[0]=99;now_values[1]=7;now_length=2; }
        if(mode==32) { bootstrap.last_refresh=0xfffffff8;now_values[0]=0xfffffff9;now_values[1]=5;now_length=2; }
        if(mode==33) { now_values[0]=110;now_values[1]=401;now_length=2; }
    }
    if(op==6)a=mode==39 ? (uint32_t)-100 : mode==40 ? 0x80000000 : mode==41 ? 1 : mode==42 ? 0 : 100;
#ifndef DX_STANDALONE
    REQUIRE(AddVectoredExceptionHandler(1,native_fault));draw_vtable[22]=(uint32_t)(uintptr_t)native_blank;
    native_devices[0]=native_devices[1]=(uint32_t)(uintptr_t)draw_vtable;
#define IMPORT(n,dll,symbol) { static spx_fixture_import_hook hook;REQUIRE(spx_fixture_redirect_import(&hook,NULL,dll,symbol,(void (*)(void))native_##n)); }
    IMPORT(version,"KERNEL32.dll","GetVersionExA") IMPORT(frequency,"KERNEL32.dll","QueryPerformanceFrequency")
    IMPORT(counter,"KERNEL32.dll","QueryPerformanceCounter") IMPORT(ticks,"WINMM.dll","timeGetTime")
#undef IMPORT
    if(op==2 || op==3)REQUIRE(install_runtime_now((void (*)(void))native_now));
    if(source_side) {
#define INSTALL(n) REQUIRE(install_runtime_##n((void (*)(void))live_##n));
        INSTALL(clock_init) INSTALL(elapsed) INSTALL(wait) INSTALL(set_seed) INSTALL(next) INSTALL(random) INSTALL(seed)
        if(op!=2 && op!=3) { INSTALL(now) }
#undef INSTALL
    }
#else
    REQUIRE(source_side);
#endif
    spx_observer out=spx_observe_begin(stdout);observer=&out;spx_observe_array(observer,"runtime");
    if(mode==34) {
        uint32_t seeds[]={0,1,0xdeadbeef,UINT32_MAX};
        for(unsigned i=0;i<4;++i) { invoke(4,seeds[i],0);for(unsigned j=0;j<8;++j)invoke(5,0,0); }
    } else {
        invoke(op,a,b);
        if(mode==43)for(unsigned i=0;i<8;++i)invoke(6,37+i,0);
        if(mode==44)for(unsigned i=0;i<3;++i)invoke(1,0,0);
    }
    spx_observe_end(observer);REQUIRE(spx_observe_finish(observer));puts("");
    if(source_side) { unsigned count=0;for(unsigned i=0;i<8;++i)count+=selected[i];REQUIRE(count); }
    return 0;
}
#ifndef DX_STANDALONE
struct native_startupinfo { int newmode; };
extern int __cdecl __getmainargs(int *,char ***,char ***,int,struct native_startupinfo *);
static void run_case(void) {
    int argc;char **argv,**environment;struct native_startupinfo s={0};REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&s));
    int result=main(argc,argv);fflush(NULL);ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_runtime_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reserved;return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
