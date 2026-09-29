/* Native entry bodies, controlled services, exact memory and interaction observations. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "particle-runtime.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
enum { NODES=32,PITCH=648,HEIGHT=480,GUARD=16,IMAGE=PITCH*HEIGHT };
static particle items[NODES];
static uint32_t live[NODES],scenario,entered[3],calls,callback_done,lock_attempts,lease;
static font_surface surfaces[2]={{1},{2}};
static unsigned char pixels[2][IMAGE+2*GUARD];
static font_surface *destination;
static particle_state particles={.destination=&destination};
static spx_observer *observer;
static void require(int test,const char *expression,unsigned line) {
    if (!test) { fprintf(stderr,"particle-runtime.c:%u: adapter premise failed: %s\n",line,expression); exit(3); }
}
#define REQUIRE(test) require(!!(test),#test,__LINE__)
void particle_enter(unsigned operation) { REQUIRE(operation<3); ++entered[operation]; }
static uint32_t particle_id(const particle *p) {
    if (!p) return 0;
    for (unsigned i=0;i<NODES;++i) if (p==&items[i]) return i+1;
    REQUIRE(0); return 0;
}
static uint32_t surface_id(const font_surface *p) {
    for (unsigned i=0;i<2;++i) if (p==&surfaces[i]) return i+1;
    REQUIRE(0); return 0;
}
static void snapshot(const char *name) {
    spx_observe_object(observer,name);
    uint32_t roots[]={particle_id(particles.current),particle_id(particles.first),particle_id(particles.last),surface_id(destination),lease};
    spx_observe_u32s(observer,"roots",roots,5); spx_observe_array(observer,"objects");
    for (unsigned i=0;i<NODES;++i) {
        uint32_t row[12]={live[i]};
        if (live[i]) { memcpy(row+1,&items[i],36); row[10]=particle_id(items[i].next); row[11]=particle_id(items[i].previous); }
        spx_observe_u32s(observer,NULL,row,12);
    }
    spx_observe_end(observer); spx_observe_end(observer);
}
static void observe_pixels(void) {
    /* Exact sparse encoding against the known initial bytes, including guards. */
    spx_observe_array(observer,"pixels");
    for (unsigned s=0;s<2;++s) for (unsigned i=0;i<sizeof(pixels[s]);++i) {
        unsigned char expected=i<GUARD || i>=IMAGE+GUARD ? 0xa5 : 0x37;
        if (pixels[s][i]!=expected) { uint32_t row[]={s+1,i,pixels[s][i]}; spx_observe_u32s(observer,NULL,row,3); }
    }
    spx_observe_end(observer);
}
static void begin(particle_state *s,unsigned operation,const uint32_t *args,unsigned count) {
    REQUIRE(s==&particles && calls++<10000); spx_observe_object(observer,NULL);
    spx_observe_u64(observer,"operation",operation); spx_observe_u32s(observer,"arguments",args,count); snapshot("before");
}
static uint32_t end(uint32_t result) {
    snapshot("after"); spx_observe_u64(observer,"result",result); spx_observe_end(observer); return result;
}
#define BEGIN0(op) (void)unused; begin(s,op,NULL,0)
#define BEGIN(op,...) (void)unused; const uint32_t args[]={__VA_ARGS__}; begin(s,op,args,sizeof(args)/sizeof(*args))
particle *particle_allocate(void *unused,particle_state *s) {
    BEGIN0(PARTICLE_ALLOCATE);
    if (scenario==4) { (void)end(0); return NULL; }
    for (unsigned i=0;i<NODES;++i) if (!live[i]) {
        live[i]=1; memset(&items[i],0,sizeof(items[i])); memset(&items[i],0xa5,36);
        if (scenario==3) { particles.last=&items[0]; items[0].next=NULL; }
        (void)end(i+1); return &items[i];
    }
    REQUIRE(0); return NULL;
}
void particle_free(void *unused,particle_state *s,particle *item) {
    uint32_t id=particle_id(item); BEGIN(PARTICLE_FREE,id); REQUIRE(id && live[id-1]); live[id-1]=0;
    if (scenario==11 && !callback_done++) particles.current=&items[2];
    (void)end(0);
}
void particle_terminate(void *unused,particle_state *s,uint32_t status) {
    BEGIN(PARTICLE_TERMINATE,status); REQUIRE(scenario==4 && status==1); particles.current=&items[0]; (void)end(0);
}
static void image_view(font_surface *surface,pcx_view *view) {
    view->width=640; view->height=HEIGHT; view->image=(asset_view){pixels[surface_id(surface)-1]+GUARD,PITCH};
}
void particle_describe(void *unused,particle_state *s,font_surface *surface,pcx_view *view) {
    BEGIN(PARTICLE_DESCRIBE,surface_id(surface)); image_view(surface,view);
    if (scenario==14) { particles.current=&items[1]; destination=&surfaces[1]; }
    (void)end(0);
}
uint32_t particle_lock(void *unused,particle_state *s,font_surface *surface,pcx_view *view) {
    BEGIN(PARTICLE_LOCK,surface_id(surface)); REQUIRE(!lease); uint32_t result=scenario==13 && lock_attempts++<2;
    if (!result) { lease=surface_id(surface); image_view(surface,view); }
    if (scenario==15) { particles.current=&items[1]; items[1].color=0x101; }
    return end(result);
}
void particle_unlock(void *unused,particle_state *s,font_surface *surface) {
    BEGIN(PARTICLE_UNLOCK,surface_id(surface)); REQUIRE(lease); observe_pixels(); lease=0; (void)end(0);
}
void particle_damage(void *unused,particle_state *s,font_rect *bounds) {
    BEGIN(PARTICLE_DAMAGE,bounds->left,bounds->top,bounds->right,bounds->bottom); observe_pixels();
    if (scenario==16 && !callback_done++) { particles.current=&items[1]; items[2].color=42; }
    if (scenario==17) destination=&surfaces[1];
    (void)end(0);
}

#ifndef DX_STANDALONE
static uint32_t native_items[NODES][11],native_surfaces[2],vtable[33];
static uint32_t *word(uint32_t address) { return (uint32_t *)(uintptr_t)address; }
static uint32_t particle_address(particle *p) { uint32_t id=particle_id(p); return id ? (uint32_t)(uintptr_t)&native_items[id-1] : 0; }
static particle *particle_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)&native_items[i]) { REQUIRE(live[i]); return &items[i]; }
    REQUIRE(0); return NULL;
}
static uint32_t surface_address(font_surface *p) { return (uint32_t)(uintptr_t)&native_surfaces[surface_id(p)-1]; }
static font_surface *surface_view(uint32_t address) {
    for (unsigned i=0;i<2;++i) if (address==(uint32_t)(uintptr_t)&native_surfaces[i]) return &surfaces[i];
    REQUIRE(0); return NULL;
}
static void particle_to_native(void) {
    *word(0x42ca28)=particle_address(particles.current); *word(0x42ca2c)=particle_address(particles.first); *word(0x42ca30)=particle_address(particles.last);
    *word(0x41c728)=surface_address(destination);
    for (unsigned i=0;i<NODES;++i) if (live[i]) {
        memcpy(native_items[i],&items[i],36); native_items[i][9]=particle_address(items[i].next); native_items[i][10]=particle_address(items[i].previous);
    }
}
static void particle_from_native(void) {
    particles.current=particle_view(*word(0x42ca28)); particles.first=particle_view(*word(0x42ca2c)); particles.last=particle_view(*word(0x42ca30));
    destination=surface_view(*word(0x41c728));
    for (unsigned i=0;i<NODES;++i) if (live[i]) {
        memcpy(&items[i],native_items[i],36); items[i].next=particle_view(native_items[i][9]); items[i].previous=particle_view(native_items[i][10]);
    }
}
static uint32_t native_allocate(uint32_t size) { REQUIRE(size==44); particle_from_native(); uint32_t result=particle_address(particle_allocate(NULL,&particles)); particle_to_native(); return result; }
static void native_free(uint32_t address) { particle_from_native(); particle_free(NULL,&particles,particle_view(address)); particle_to_native(); }
static void native_terminate(uint32_t status) { particle_from_native(); particle_terminate(NULL,&particles,status); particle_to_native(); }
static void native_damage(font_rect bounds) { particle_from_native(); particle_damage(NULL,&particles,&bounds); particle_to_native(); }
static void descriptor(uint32_t *desc,pcx_view *view) {
    desc[2]=view->height; desc[3]=view->width; desc[4]=view->image.pitch; desc[9]=(uint32_t)(uintptr_t)view->image.pixels;
}
static uint32_t WINAPI native_describe(uint32_t surface,uint32_t *desc) {
    REQUIRE(desc[0]==108 && desc[1]==14); particle_from_native(); pcx_view view={0};
    particle_describe(NULL,&particles,surface_view(surface),&view); descriptor(desc,&view); particle_to_native(); return 0;
}
static uint32_t WINAPI native_lock(uint32_t surface,void *rect,uint32_t *desc,uint32_t flags,void *event) {
    REQUIRE(!rect && !flags && !event && desc[0]==108); particle_from_native(); pcx_view view={0};
    uint32_t result=particle_lock(NULL,&particles,surface_view(surface),&view);
    if (!result) descriptor(desc,&view);
    particle_to_native(); return result;
}
static uint32_t WINAPI native_unlock(uint32_t surface,void *data) {
    REQUIRE(!data); particle_from_native(); particle_unlock(NULL,&particles,surface_view(surface)); particle_to_native(); return 0;
}
static void native_root_create(uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f) {
    particle_from_native(); fixture_particle_create(&particles,a,b,c,d,e,f); particle_to_native();
}
static void native_root_update(void) { particle_from_native(); fixture_particle_update(&particles); particle_to_native(); }
static void native_root_draw(void) { particle_from_native(); fixture_particle_draw(&particles); particle_to_native(); }
static void install(int source) {
    vtable[22]=(uint32_t)(uintptr_t)native_describe; vtable[25]=(uint32_t)(uintptr_t)native_lock; vtable[32]=(uint32_t)(uintptr_t)native_unlock;
    for (unsigned i=0;i<2;++i) native_surfaces[i]=(uint32_t)(uintptr_t)vtable;
#define HOOK(name) REQUIRE(install_particle_service_##name((void (*)(void))native_##name));
    HOOK(allocate) HOOK(free) HOOK(terminate) HOOK(damage)
#undef HOOK
    if (!source) return;
#define ROOT(name) REQUIRE(install_particle_##name((void (*)(void))native_root_##name));
    ROOT(create) ROOT(update) ROOT(draw)
#undef ROOT
}
#define SYNC() particle_to_native()
#define CREATE(a,b,c,d,e,f) do { ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))0x407b00)(a,b,c,d,e,f); particle_from_native(); } while (0)
#define CALL(name,address) do { ((void (*)(void))address)(); particle_from_native(); } while (0)
#else
#define SYNC() ((void)0)
#define CREATE(a,b,c,d,e,f) fixture_particle_create(&particles,a,b,c,d,e,f)
#define CALL(name,address) fixture_particle_##name(&particles)
#endif
static void setup(void) {
    memset(items,0,sizeof(items)); memset(live,0,sizeof(live)); destination=&surfaces[0];
    particles=(particle_state){.destination=&destination}; callback_done=lock_attempts=lease=0;
    for (unsigned i=0;i<2;++i) { memset(pixels[i],0xa5,sizeof(pixels[i])); memset(pixels[i]+GUARD,0x37,IMAGE); }
}
static void list(unsigned count) {
    particles.current=particles.first=count ? &items[0] : NULL; particles.last=count ? &items[count-1] : NULL;
    for (unsigned i=0;i<count;++i) {
        live[i]=1; items[i]=(particle){.x=100+i*20,.y=100,.dx=1,.dy=2,.gravity=1,.color=16+i,
            .next=i+1<count ? &items[i+1] : NULL,.previous=i ? &items[i-1] : NULL};
    }
}
static void run_scenario(void) {
    switch (scenario) {
    case 0: SYNC(); CALL(update,0x407bf0); CALL(draw,0x407db0); break;
    case 1: {
        const uint32_t xs[]={0,20,21,618,619,0x7fffffff,0x80000000,UINT32_MAX};
        for (unsigned i=0;i<8;++i) { SYNC(); CREATE(xs[i],1,0,0,16,1); }
        const uint32_t ys[]={0,1,478,479,UINT32_MAX};
        for (unsigned i=0;i<5;++i) { SYNC(); CREATE(21,ys[i],0,0,17,0); } break;
    }
    case 2: case 3: case 4: list(1); SYNC(); CREATE(201,202,UINT32_MAX,2,0xabcdef01,7); break;
    case 5: list(3); SYNC(); CALL(update,0x407bf0); break;
    case 6:
        list(4); for (unsigned i=0;i<4;++i) { items[i].gravity=i; items[i].gravity_tick=5; }
        SYNC(); CALL(update,0x407bf0); break;
    case 7:
        for (unsigned i=0;i<4;++i) {
            const uint32_t ticks[]={4,5,0x7fffffff,UINT32_MAX}; setup(); list(1);
            items[0].gravity_tick=items[0].color_tick=items[0].age=ticks[i]; items[0].color=UINT32_MAX;
            SYNC(); CALL(update,0x407bf0); snapshot(NULL);
        } break;
    case 8: {
        const uint32_t x[]={19,20,618,619,0x80000000,UINT32_MAX,100,100,100,100};
        const uint32_t y[]={100,100,100,100,100,100,UINT32_MAX,0,478,479};
        for (unsigned i=0;i<10;++i) { setup(); list(1); items[0].x=x[i]; items[0].y=y[i]; items[0].dx=items[0].dy=0; SYNC(); CALL(update,0x407bf0); snapshot(NULL); } break;
    }
    case 9:
        list(3); for (unsigned i=0;i<3;++i) { items[i].color_tick=4; items[i].age=5+i; }
        SYNC(); CALL(update,0x407bf0); break;
    case 10: case 11:
        list(4); items[0].x=619; items[1].x=620; SYNC(); CALL(update,0x407bf0); break;
    case 12: case 13: case 14: case 15: case 16: case 17:
        list(3); SYNC(); CALL(draw,0x407db0); break;
    case 18:
        list(4); items[0].color=0; items[1].color=255; items[2].color=256; items[3].color=UINT32_MAX;
        items[3].x=618; items[3].y=478; SYNC(); CALL(draw,0x407db0); break;
    case 19:
        SYNC(); CREATE(250,100,1,0,16,1); CREATE(21,100,UINT32_MAX,0,255,0); CREATE(400,200,0,0,100,0);
        for (unsigned i=0;i<40;++i) { CALL(update,0x407bf0); CALL(draw,0x407db0); snapshot(NULL); } break;
    default: REQUIRE(0);
    }
}
#ifdef PARTICLE_CONNECTED
#include "frame-particles.h"
#endif
int main(int argc,char **argv) {
    REQUIRE(argc==3); scenario=(uint32_t)strtoul(argv[2],NULL,10); setup();
#ifdef PARTICLE_CONNECTED
    REQUIRE(scenario>=20 && scenario<24); frame_setup();
#else
    REQUIRE(scenario<20);
#endif
    int source=!strcmp(argv[1],"source"); REQUIRE(source || !strcmp(argv[1],"original"));
#ifndef DX_STANDALONE
    install(source);
#ifdef PARTICLE_CONNECTED
    frame_install(source);
#endif
    SYNC();
#else
    REQUIRE(source);
#endif
    spx_observer out=spx_observe_begin(stdout); observer=&out; spx_observe_object(observer,"particles"); snapshot("initial");
    spx_observe_array(observer,"calls");
#ifdef PARTICLE_CONNECTED
    if (scenario>=20) frame_run(); else run_scenario();
#else
    run_scenario();
#endif
    spx_observe_end(observer); snapshot("final"); observe_pixels();
    spx_observe_end(observer); REQUIRE(spx_observe_finish(observer)); fputc('\n',stdout); return 0;
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
__declspec(dllexport) void dx_particles_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance; (void)reserved;
    return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
