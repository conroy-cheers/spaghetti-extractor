/* Actual game objects and services around the locally compared C operations. */
#define RENDER_NORMAL_LIBRARY_ONLY 1
#include "render-normal-runtime.c"
#include "damage-runtime.h"
static damage_state damage={.scene=&scene};
static uint32_t damage_entries[13],damage_depth,damage_count,damage_dropped;
static uint32_t damage_records[2048][34],damage_ticks[2048];
void damage_enter(unsigned operation) { REQUIRE(operation<13); ++damage_entries[operation]; }
#include "damage-native.h"
static void damage_push(void) { editor_to_native(); damage_to_native(); }
static void damage_pull(void) { editor_from_native(); damage_from_native(); }
static uint64_t damage_live_pixels(font_surface *surface) { return title_surface_hash(surface_address(surface)); }
static font_rect *damage_rectangle_address(font_rect *rectangle) {
    uintptr_t p=(uintptr_t)rectangle,history=(uintptr_t)damage.history,pending=(uintptr_t)damage.pending;
    if (p>=history && p<history+sizeof(damage.history)) return (font_rect *)(uintptr_t)(0x424438+p-history);
    if (p>=pending && p<pending+sizeof(damage.pending)) return (font_rect *)(uintptr_t)(0x41c730+p-pending);
    return rectangle;
}
void damage_sprite_blit(void *unused,damage_state *s,font_surface *destination,font_sprite *sprite,
                         uint32_t x,uint32_t y,uint32_t flags) {
    (void)unused; REQUIRE(s==&damage); damage_push();
    uint32_t address=surface_address(destination),object=sprite_address(sprite),*table=word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,uint32_t,uint32_t,uint32_t,font_rect *,uint32_t))(uintptr_t)table[7])
        (address,x,y,*word(object),(font_rect *)(uintptr_t)(object+20),flags); damage_pull();
}
void damage_blit_fast(void *unused,damage_state *s,font_surface *destination,uint32_t x,uint32_t y,
                      font_surface *source,font_rect *rectangle,uint32_t flags) {
    (void)unused; REQUIRE(s==&damage); damage_push();
    uint32_t address=surface_address(destination),*table=word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,uint32_t,uint32_t,uint32_t,font_rect *,uint32_t))(uintptr_t)table[7])
        (address,x,y,surface_address(source),damage_rectangle_address(rectangle),flags); damage_pull();
}
void damage_blit(void *unused,damage_state *s,font_surface *destination,font_rect *dr,
                 font_surface *source,font_rect *sr,uint32_t flags) {
    (void)unused; REQUIRE(s==&damage); damage_push();
    uint32_t address=surface_address(destination),*table=word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,font_rect *,uint32_t,font_rect *,uint32_t,void *))(uintptr_t)table[5])
        (address,damage_rectangle_address(dr),surface_address(source),damage_rectangle_address(sr),flags,NULL); damage_pull();
}
uint32_t damage_now(void *unused,damage_state *s) {
    (void)unused; REQUIRE(s==&damage); damage_push(); uint32_t result=((uint32_t (*)(void))0x40db20)(); damage_pull(); return result;
}
uint32_t damage_elapsed(void *unused,damage_state *s,uint32_t previous,uint32_t delay) {
    (void)unused; REQUIRE(s==&damage); damage_push();
    uint32_t result=((uint32_t (*)(uint32_t,uint32_t))0x40db80)(previous,delay); damage_pull(); return result;
}
void damage_wait(void *unused,damage_state *s,uint32_t count) {
    (void)unused; REQUIRE(s==&damage); damage_push(); ((void (*)(uint32_t))0x402240)(count); damage_pull();
}
uint32_t damage_flip(void *unused,damage_state *s,font_surface *surface) {
    (void)unused; REQUIRE(s==&damage); damage_push(); uint32_t address=surface_address(surface),*table=word(*word(address));
    uint32_t result=((uint32_t (WINAPI *)(uint32_t,void *,uint32_t))(uintptr_t)table[11])(address,NULL,0);
    damage_pull(); return result;
}
void damage_recover(void *unused,damage_state *s) {
    (void)unused; REQUIRE(s==&damage); damage_push(); ((void (*)(void))0x40aaa0)(); damage_pull();
}
static void damage_record(uint32_t operation,const uint32_t *arguments,unsigned count,uint32_t result) {
    if (--damage_depth) return;
    if (damage_count==2048) { ++damage_dropped; return; }
    damage_pull(); uint32_t index=damage_count++,*record=damage_records[index]; record[0]=operation;
    REQUIRE(count<=8); if (count) memcpy(record+1,arguments,count*sizeof(*arguments)); record[9]=result;
    uint32_t values[]={damage.page,damage.count[0],damage.count[1],damage.pending_count,damage.clipped,damage.capability,
        title.fast,scene.presentation_mode,scene.refresh_ok,0,
        observed_surface(surface_address(damage.background)),observed_surface(surface_address(title.software)),
        observed_surface(surface_address(title.primary)),observed_surface(surface_address(scene.flip))};
    memcpy(record+10,values,sizeof(values)); damage_ticks[index]=damage.last_tick;
    uint64_t hashes[]={hash_bytes(UINT64_C(14695981039346656037),(const unsigned char *)damage.history,sizeof(damage.history)),
        hash_bytes(UINT64_C(14695981039346656037),(const unsigned char *)damage.pending,sizeof(damage.pending)),
        hash_bytes(UINT64_C(14695981039346656037),(const unsigned char *)damage.keys,sizeof(damage.keys)),0,0};
    if (operation==0 || operation==6 || operation==9 || operation==10) {
        hashes[3]=damage_observe_surface(title.primary,damage_live_pixels);
        hashes[4]=damage_observe_surface(title.software,damage_live_pixels);
    }
    for (unsigned i=0;i<5;++i) { record[24+2*i]=(uint32_t)hashes[i]; record[25+2*i]=(uint32_t)(hashes[i]>>32); }
}
#define LIVE0(name,operation,address) \
static void live_damage_##name(void) { \
    ++damage_depth; \
    if (source_side) { damage_pull(); fixture_damage_##name(&damage); damage_push(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_damage_##name##_hook)); ((void (*)(void))address)(); \
        install_damage_##name##_hook.entry=NULL; REQUIRE(install_damage_##name((void (*)(void))live_damage_##name)); } \
    damage_record(operation,NULL,0,0); \
}
LIVE0(reset,0,0x401000) LIVE0(restore,6,0x401430) LIVE0(present,9,0x401650) LIVE0(flush,10,0x401700)
#define LIVE_SPRITE(name,operation,address) \
static void live_damage_##name(uint32_t slot,uint32_t x,uint32_t y) { \
    ++damage_depth; const uint32_t args[]={slot,x,y}; \
    if (source_side) { damage_pull(); fixture_damage_##name(&damage,slot,x,y); damage_push(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_damage_##name##_hook)); ((void (*)(uint32_t,uint32_t,uint32_t))address)(slot,x,y); \
        install_damage_##name##_hook.entry=NULL; REQUIRE(install_damage_##name((void (*)(void))live_damage_##name)); } \
    damage_record(operation,args,3,0); \
}
LIVE_SPRITE(transparent,1,0x401080) LIVE_SPRITE(opaque,2,0x401140)
#define LIVE_RECT(name,operation,address) \
static void live_damage_##name(font_rect rectangle) { \
    ++damage_depth; const uint32_t args[]={rectangle.left,rectangle.top,rectangle.right,rectangle.bottom}; \
    if (source_side) { damage_pull(); fixture_damage_##name(&damage,&rectangle); damage_push(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_damage_##name##_hook)); ((void (*)(font_rect))address)(rectangle); \
        install_damage_##name##_hook.entry=NULL; REQUIRE(install_damage_##name((void (*)(void))live_damage_##name)); } \
    damage_record(operation,args,4,0); \
}
LIVE_RECT(mark,3,0x401200) LIVE_RECT(erase,4,0x401280) LIVE_RECT(damage,5,0x401350)
#define LIVE_SURFACE(name,operation,address) \
static void live_damage_##name(uint32_t surface) { \
    ++damage_depth; uint32_t identity=observed_surface(surface); \
    if (source_side) { damage_pull(); fixture_damage_##name(&damage,surface_view(surface)); damage_push(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_damage_##name##_hook)); ((void (*)(uint32_t))address)(surface); \
        install_damage_##name##_hook.entry=NULL; REQUIRE(install_damage_##name((void (*)(void))live_damage_##name)); } \
    damage_record(operation,&identity,1,0); \
}
LIVE_SURFACE(background,7,0x401630) LIVE_SURFACE(destination,8,0x401640)
static void live_damage_sort(uint32_t first,uint32_t last) {
    ++damage_depth; uint32_t args[]={first,last};
    if (source_side) { damage_pull(); fixture_damage_sort(&damage,first,last); damage_push(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_damage_sort_hook)); ((void (*)(uint32_t,uint32_t))0x401930)(first,last);
        install_damage_sort_hook.entry=NULL; REQUIRE(install_damage_sort((void (*)(void))live_damage_sort)); }
    damage_record(11,args,2,0);
}
static uint32_t live_damage_overlap(font_rect a,font_rect b) {
    ++damage_depth; uint32_t args[]={a.left,a.top,a.right,a.bottom,b.left,b.top,b.right,b.bottom},result;
    if (source_side) { damage_pull(); result=fixture_damage_overlap(&damage,&a,&b); damage_push(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_damage_overlap_hook)); result=((uint32_t (*)(font_rect,font_rect))0x40d5e0)(a,b);
        install_damage_overlap_hook.entry=NULL; REQUIRE(install_damage_overlap((void (*)(void))live_damage_overlap)); }
    damage_record(12,args,8,result); return result;
}
static void damage_observe(spx_observer *o) {
    render_observe(o); spx_observe_array(o,"damage");
    for (uint32_t i=0;i<damage_count;++i) spx_observe_u32s(o,NULL,damage_records[i],34);
    spx_observe_end(o);
}
static void damage_diagnose(spx_observer *o) {
    render_diagnose(o); spx_observe_u32s(o,"selected_damage",damage_entries,13);
    spx_observe_u32s(o,"damage_ticks",damage_ticks,damage_count); spx_observe_u64(o,"damage_records_dropped",damage_dropped);
}
static void damage_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT"); if (!path) return; FILE *out=fopen(path,"wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out); damage_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o=spx_observe_begin(out);
    damage_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL damage_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!render_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { damage_report(); return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
#define DAMAGE_ENTRY(name) REQUIRE(install_damage_##name((void (*)(void))live_damage_##name));
    DAMAGE_ENTRY(reset) DAMAGE_ENTRY(transparent) DAMAGE_ENTRY(opaque) DAMAGE_ENTRY(mark) DAMAGE_ENTRY(erase)
    DAMAGE_ENTRY(damage) DAMAGE_ENTRY(restore) DAMAGE_ENTRY(background) DAMAGE_ENTRY(destination)
    DAMAGE_ENTRY(present) DAMAGE_ENTRY(flush) DAMAGE_ENTRY(sort) DAMAGE_ENTRY(overlap)
#undef DAMAGE_ENTRY
    return TRUE;
}
#ifndef DAMAGE_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return damage_main(instance,reason,reserved); }
#endif
