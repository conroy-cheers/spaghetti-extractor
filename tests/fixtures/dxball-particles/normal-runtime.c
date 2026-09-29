/* Actual allocation and shared software-surface services in normal gameplay. */
#define PICKUP_NORMAL_LIBRARY_ONLY 1
#include "pickup-normal-runtime.c"
#include "particle-runtime.h"
enum { PARTICLE_OBJECTS=256,PARTICLE_RECORDS=512 };
static particle_state particles={.destination=&title.software};
static uint32_t particle_entries[3],particle_depth,particle_count,particle_objects;
static struct { uint32_t address,seen; particle value; } particle_pool[PARTICLE_OBJECTS];
void particle_enter(unsigned operation) { REQUIRE(operation<3); ++particle_entries[operation]; }
static uint32_t particle_id(const particle *p) {
    if (!p) return 0;
    for (uint32_t i=0;i<particle_objects;++i) if (p==&particle_pool[i].value) return i+1;
    REQUIRE(0); return 0;
}
static uint32_t particle_address(particle *p) { uint32_t id=particle_id(p); return id ? particle_pool[id-1].address : 0; }
static particle *particle_view(uint32_t address) {
    if (!address) return NULL;
    uint32_t i;
    for (i=0;i<particle_objects && particle_pool[i].address!=address;++i) {}
    if (i==particle_objects) { REQUIRE(particle_objects<PARTICLE_OBJECTS); ++particle_objects; particle_pool[i].address=address; }
    particle *view=&particle_pool[i].value;
    if (!particle_pool[i].seen) {
        particle_pool[i].seen=1; const uint32_t *p=word(address); memcpy(view,p,36);
        view->next=particle_view(p[9]); view->previous=particle_view(p[10]);
    }
    return view;
}
static void particle_to_native(void) {
    pickup_to_native();
    *word(0x42ca28)=particle_address(particles.current); *word(0x42ca2c)=particle_address(particles.first); *word(0x42ca30)=particle_address(particles.last);
    for (uint32_t i=0;i<particle_objects;++i) if (particle_pool[i].seen) {
        uint32_t *p=word(particle_pool[i].address); memcpy(p,&particle_pool[i].value,36);
        p[9]=particle_address(particle_pool[i].value.next); p[10]=particle_address(particle_pool[i].value.previous);
    }
}
static void particle_from_native(void) {
    pickup_from_native();
    for (uint32_t i=0;i<particle_objects;++i) particle_pool[i].seen=0;
    particles.current=particle_view(*word(0x42ca28)); particles.first=particle_view(*word(0x42ca2c)); particles.last=particle_view(*word(0x42ca30));
}
particle *particle_allocate(void *unused,particle_state *s) {
    (void)unused; REQUIRE(s==&particles); particle_to_native();
    uint32_t address=((uint32_t (*)(uint32_t))0x40df40)(44); particle_from_native(); if (!address) return NULL;
    uint32_t i;
    for (i=0;i<particle_objects && particle_pool[i].address!=address;++i) {}
    if (i==particle_objects) { REQUIRE(particle_objects<PARTICLE_OBJECTS); ++particle_objects; particle_pool[i].address=address; }
    REQUIRE(!particle_pool[i].seen); particle_pool[i].seen=1;
    memcpy(&particle_pool[i].value,(void *)(uintptr_t)address,36);
    particle_pool[i].value.next=particle_pool[i].value.previous=NULL; return &particle_pool[i].value;
}
void particle_free(void *unused,particle_state *s,particle *item) {
    (void)unused; REQUIRE(s==&particles); uint32_t address=particle_address(item); particle_to_native();
    ((void (*)(uint32_t))0x40df30)(address); particle_from_native();
}
void particle_terminate(void *unused,particle_state *s,uint32_t status) {
    (void)unused; REQUIRE(s==&particles); particle_to_native(); ((void (*)(uint32_t))0x40e3d0)(status); particle_from_native();
}
void particle_describe(void *u,particle_state *s,font_surface *surface,pcx_view *view) {
    REQUIRE(s==&particles); particle_to_native(); pcx_describe(u,surface,view); particle_from_native();
}
uint32_t particle_lock(void *u,particle_state *s,font_surface *surface,pcx_view *view) {
    REQUIRE(s==&particles); particle_to_native(); uint32_t result=pcx_lock(u,surface,view); particle_from_native(); return result;
}
void particle_unlock(void *u,particle_state *s,font_surface *surface) {
    REQUIRE(s==&particles); particle_to_native(); pcx_unlock(u,surface); particle_from_native();
}
void particle_damage(void *unused,particle_state *s,font_rect *bounds) {
    (void)unused; REQUIRE(s==&particles); particle_to_native(); ((void (*)(font_rect))0x401200)(*bounds); particle_from_native();
}
typedef struct {
    uint32_t operation,args[6],roots[4],objects[PARTICLE_OBJECTS][12],size;
    uint64_t pixels;
} particle_snapshot;
static particle_snapshot particle_records[PARTICLE_RECORDS];
static void particle_record(uint32_t operation,const uint32_t *args) {
    if (--particle_depth) return;
    REQUIRE(particle_count<PARTICLE_RECORDS); particle_from_native(); particle_snapshot *r=&particle_records[particle_count++];
    r->operation=operation; if (args) memcpy(r->args,args,sizeof(r->args));
    uint32_t roots[]={particle_id(particles.current),particle_id(particles.first),particle_id(particles.last),observed_surface(surface_address(*particles.destination))};
    memcpy(r->roots,roots,sizeof(roots));
    for (uint32_t i=0;i<particle_objects;++i) if (particle_pool[i].seen) {
        uint32_t *row=r->objects[r->size++]; row[0]=i+1; memcpy(row+1,&particle_pool[i].value,36);
        row[10]=particle_id(particle_pool[i].value.next); row[11]=particle_id(particle_pool[i].value.previous);
    }
    if (operation==2) r->pixels=title_surface_hash(surface_address(*particles.destination));
}
#define PARTICLE_LIVE0(name,op,address) static void live_particle_##name(void) { \
    ++particle_depth; particle_from_native(); \
    if (source_side) { fixture_particle_##name(&particles); particle_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_particle_##name##_hook)); ((void (*)(void))address)(); \
        install_particle_##name##_hook.entry=NULL; REQUIRE(install_particle_##name(live_particle_##name)); } \
    particle_record(op,NULL); }
PARTICLE_LIVE0(update,1,0x407bf0) PARTICLE_LIVE0(draw,2,0x407db0)
#undef PARTICLE_LIVE0
static void live_particle_create(uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f) {
    ++particle_depth; particle_from_native();
    if (source_side) { fixture_particle_create(&particles,a,b,c,d,e,f); particle_to_native(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_particle_create_hook)); ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))0x407b00)(a,b,c,d,e,f);
        install_particle_create_hook.entry=NULL; REQUIRE(install_particle_create((void (*)(void))live_particle_create)); }
    const uint32_t args[]={a,b,c,d,e,f}; particle_record(0,args);
}
static void particle_observe(spx_observer *observer) {
    spx_observer o=*observer; pickup_observe(&o); spx_observe_array(&o,"particles");
    for (uint32_t i=0;i<particle_count;++i) {
        particle_snapshot *r=&particle_records[i]; spx_observe_object(&o,NULL);
        spx_observe_u64(&o,"operation",r->operation); spx_observe_u32s(&o,"arguments",r->args,6);
        spx_observe_u32s(&o,"roots",r->roots,4); spx_observe_u64(&o,"pixels",r->pixels); spx_observe_array(&o,"objects");
        for (uint32_t j=0;j<r->size;++j) spx_observe_u32s(&o,NULL,r->objects[j],12);
        spx_observe_end(&o); spx_observe_end(&o);
    }
    spx_observe_end(&o); *observer=o;
}
static void particle_diagnose(spx_observer *observer) {
    pickup_diagnose(observer); spx_observe_u32s(observer,"selected_particles",particle_entries,3);
}
static void particle_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT"); if (!path) return; FILE *out=fopen(path,"wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out); particle_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o=spx_observe_begin(out); particle_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL particle_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!pickup_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { particle_report(); return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
#define PARTICLE_ROOT(name) REQUIRE(install_particle_##name((void (*)(void))live_particle_##name));
    PARTICLE_ROOT(create) PARTICLE_ROOT(update) PARTICLE_ROOT(draw)
#undef PARTICLE_ROOT
    return TRUE;
}
#ifndef PARTICLE_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return particle_main(instance,reason,reserved); }
#endif
