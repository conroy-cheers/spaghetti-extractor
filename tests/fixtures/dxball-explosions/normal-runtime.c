/* Concrete explosion views preserve the parent's opaque effect identities. */
#define SHOT_NORMAL_LIBRARY_ONLY 1
#include "shot-normal-runtime.c"
#include "explosion-runtime.h"
enum { EXPLOSION_OBJECTS=64,EXPLOSION_RECORDS=512 };
static play_effects explosion_roots;
static explosion_state explosions={.roots=&explosion_roots};
static uint32_t explosion_entries[3],explosion_depth,explosion_count,explosion_objects;
static struct { uint32_t address,seen; explosion value; } explosion_pool[EXPLOSION_OBJECTS];
void explosion_enter(unsigned operation) { REQUIRE(operation<3); ++explosion_entries[operation]; }
static uint32_t explosion_id(const explosion *p) {
    if (!p) return 0;
    for (uint32_t i=0;i<explosion_objects;++i) if (p==&explosion_pool[i].value) return i+1;
    REQUIRE(0); return 0;
}
static uint32_t explosion_address(explosion *p) { uint32_t id=explosion_id(p); return id ? explosion_pool[id-1].address : 0; }
static explosion *explosion_view(uint32_t address) {
    if (!address) return NULL;
    uint32_t i;
    for (i=0;i<explosion_objects && explosion_pool[i].address!=address;++i) {}
    if (i==explosion_objects) { REQUIRE(explosion_objects<EXPLOSION_OBJECTS); ++explosion_objects; explosion_pool[i].address=address; }
    explosion *view=&explosion_pool[i].value;
    if (!explosion_pool[i].seen) {
        explosion_pool[i].seen=1; const uint32_t *p=word(address); memcpy(view,p,12);
        view->next=explosion_view(p[3]); view->previous=explosion_view(p[4]);
    }
    return view;
}
static void explosion_to_native(void) {
    play.explosions.current=effect_view(explosion_address(explosion_current(&explosions)));
    play.explosions.first=effect_view(explosion_address(explosion_first(&explosions)));
    paddle_to_native(); *word(0x42cdc0)=explosion_address(explosions.last); *word(0x42cdc4)=explosions.retained;
    for (uint32_t i=0;i<explosion_objects;++i) if (explosion_pool[i].seen) {
        uint32_t *p=word(explosion_pool[i].address); memcpy(p,&explosion_pool[i].value,12);
        p[3]=explosion_address(explosion_pool[i].value.next); p[4]=explosion_address(explosion_pool[i].value.previous);
    }
}
static void explosion_from_native(void) {
    paddle_from_native();
    for (uint32_t i=0;i<explosion_objects;++i) explosion_pool[i].seen=0;
    explosion_roots.current=(void *)explosion_view(*word(0x42cdb8)); explosion_roots.first=(void *)explosion_view(*word(0x42cdbc));
    explosions.last=explosion_view(*word(0x42cdc0)); explosions.retained=*word(0x42cdc4);
}
explosion *explosion_allocate(void *unused,explosion_state *s) {
    (void)unused; REQUIRE(s==&explosions); explosion_to_native();
    uint32_t address=((uint32_t (*)(uint32_t))0x40df40)(20); explosion_from_native(); if (!address) return NULL;
    uint32_t i;
    for (i=0;i<explosion_objects && explosion_pool[i].address!=address;++i) {}
    if (i==explosion_objects) { REQUIRE(explosion_objects<EXPLOSION_OBJECTS); ++explosion_objects; explosion_pool[i].address=address; }
    REQUIRE(!explosion_pool[i].seen); explosion_pool[i].seen=1;
    memcpy(&explosion_pool[i].value,(void *)(uintptr_t)address,12);
    explosion_pool[i].value.next=explosion_pool[i].value.previous=NULL; return &explosion_pool[i].value;
}
void explosion_free(void *unused,explosion_state *s,explosion *item) {
    (void)unused; REQUIRE(s==&explosions); uint32_t address=explosion_address(item); explosion_to_native();
    ((void (*)(uint32_t))0x40df30)(address); explosion_from_native();
}
void explosion_terminate(void *unused,explosion_state *s,uint32_t status) {
    (void)unused; REQUIRE(s==&explosions); explosion_to_native(); ((void (*)(uint32_t))0x40e3d0)(status); explosion_from_native();
}
void explosion_sprite(void *unused,explosion_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    (void)unused; REQUIRE(s==&explosions); explosion_to_native(); ((void (*)(uint32_t,uint32_t,uint32_t))0x401080)(slot,x,y); explosion_from_native();
}
typedef struct { uint32_t operation,args[2],roots[4],objects[EXPLOSION_OBJECTS][6],size; } explosion_snapshot;
static explosion_snapshot explosion_records[EXPLOSION_RECORDS];
static void explosion_record(uint32_t operation,const uint32_t *args) {
    if (--explosion_depth) return;
    REQUIRE(explosion_count<EXPLOSION_RECORDS); explosion_from_native(); explosion_snapshot *r=&explosion_records[explosion_count++]; r->operation=operation;
    if (args) memcpy(r->args,args,sizeof(r->args));
    uint32_t roots[]={explosion_id(explosion_current(&explosions)),explosion_id(explosion_first(&explosions)),explosion_id(explosions.last),explosions.retained};
    memcpy(r->roots,roots,sizeof(roots));
    for (uint32_t i=0;i<explosion_objects;++i) if (explosion_pool[i].seen) {
        uint32_t *row=r->objects[r->size++]; row[0]=i+1; memcpy(row+1,&explosion_pool[i].value,12);
        row[4]=explosion_id(explosion_pool[i].value.next); row[5]=explosion_id(explosion_pool[i].value.previous);
    }
}
#define EXPLOSION_LIVE(name,operation,address) static void live_explosion_##name(void) { \
    ++explosion_depth; explosion_from_native(); \
    if (source_side) { fixture_explosion_##name(&explosions); explosion_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_explosion_##name##_hook)); ((void (*)(void))address)(); \
        install_explosion_##name##_hook.entry=NULL; REQUIRE(install_explosion_##name(live_explosion_##name)); } \
    explosion_record(operation,NULL); }
EXPLOSION_LIVE(reset,0,0x404100) EXPLOSION_LIVE(draw,2,0x406e10)
#undef EXPLOSION_LIVE
static void live_explosion_create(uint32_t x,uint32_t y) {
    ++explosion_depth; explosion_from_native();
    if (source_side) { fixture_explosion_create(&explosions,x,y); explosion_to_native(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_explosion_create_hook)); ((void (*)(uint32_t,uint32_t))0x406d30)(x,y);
        install_explosion_create_hook.entry=NULL; REQUIRE(install_explosion_create((void (*)(void))live_explosion_create)); }
    const uint32_t args[]={x,y}; explosion_record(1,args);
}
static void explosion_observe(spx_observer *observer) {
    spx_observer o=*observer; shot_observe(&o); spx_observe_array(&o,"explosions");
    for (uint32_t i=0;i<explosion_count;++i) {
        explosion_snapshot *r=&explosion_records[i]; spx_observe_object(&o,NULL); spx_observe_u64(&o,"operation",r->operation);
        spx_observe_u32s(&o,"arguments",r->args,2); spx_observe_u32s(&o,"roots",r->roots,4); spx_observe_array(&o,"objects");
        for (uint32_t j=0;j<r->size;++j) spx_observe_u32s(&o,NULL,r->objects[j],6);
        spx_observe_end(&o); spx_observe_end(&o);
    }
    spx_observe_end(&o); *observer=o;
}
static void explosion_diagnose(spx_observer *observer) {
    shot_diagnose(observer); spx_observe_u32s(observer,"selected_explosions",explosion_entries,3);
}
static void explosion_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT"); if (!path) return; FILE *out=fopen(path,"wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out); explosion_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o=spx_observe_begin(out); explosion_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL explosion_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!shot_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { explosion_report(); return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
    REQUIRE(install_explosion_reset(live_explosion_reset)); REQUIRE(install_explosion_create((void (*)(void))live_explosion_create)); REQUIRE(install_explosion_draw(live_explosion_draw));
    return TRUE;
}
#ifndef EXPLOSION_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return explosion_main(instance,reason,reserved); }
#endif
