/* Use native allocation/sound and existing lifted shared-state consumers. */
#define PADDLE_NORMAL_LIBRARY_ONLY 1
#include "paddle-normal-runtime.c"
#include "shot-runtime.h"
enum { SHOT_RECORDS=512 };
static uint32_t shot_entries[3],shot_depth,shot_records_count;
void shot_enter(unsigned operation) { REQUIRE(operation<3); ++shot_entries[operation]; }
struct spx_opaque_allocation_v5 *shot_allocate(void *unused,motion_state *s) {
    (void)unused; REQUIRE(s==&motion); paddle_to_native();
    uint32_t address=((uint32_t (*)(uint32_t))0x40df40)(24); paddle_from_native(); if (!address) return NULL;
    uint32_t i;
    for (i=0;i<shot_count && shot_pool[i].address!=address;++i) {}
    if (i==shot_count) { REQUIRE(shot_count<PLAY_OBJECTS); ++shot_count; shot_pool[i].address=address; }
    REQUIRE(!shot_pool[i].seen); shot_pool[i].seen=1;
    memcpy(&shot_pool[i].value,(void *)(uintptr_t)address,16);
    shot_pool[i].value.next=shot_pool[i].value.previous=NULL; return (void *)&shot_pool[i].value;
}
void shot_free(void *unused,motion_state *s,struct spx_opaque_allocation_v5 *storage) {
    (void)unused; REQUIRE(s==&motion); uint32_t address=shot_address((void *)storage); paddle_to_native();
    ((void (*)(uint32_t))0x40df30)(address); paddle_from_native();
}
void shot_terminate(void *unused,motion_state *s,uint32_t status) {
    (void)unused; REQUIRE(s==&motion); paddle_to_native(); ((void (*)(uint32_t))0x40e3d0)(status); paddle_from_native();
}
uint32_t shot_random(void *unused,motion_state *s,uint32_t limit) {
    (void)unused; REQUIRE(s==&motion); paddle_to_native();
    uint32_t result=((uint32_t (*)(uint32_t))0x40ae20)(limit); paddle_from_native(); return result;
}
uint32_t shot_hit(void *unused,motion_state *s,uint32_t column,uint32_t row) {
    (void)unused; REQUIRE(s==&motion); paddle_to_native();
    uint32_t result=((uint32_t (*)(uint32_t,uint32_t))0x405c80)(column,row); paddle_from_native(); return result;
}
void shot_stop_sound(void *unused,motion_state *s,uint32_t sound) {
    (void)unused; REQUIRE(s==&motion); paddle_to_native(); ((void (*)(uint32_t))0x403370)(sound); paddle_from_native();
}
uint32_t shot_pan(void *unused,motion_state *s,uint32_t x) {
    (void)unused; REQUIRE(s==&motion); paddle_to_native();
    uint32_t result=((uint32_t (*)(uint32_t))0x403550)(x); paddle_from_native(); return result;
}
void shot_play_sound(void *unused,motion_state *s,uint32_t sound,uint32_t repeat,uint32_t pan,uint32_t flags) {
    (void)unused; REQUIRE(s==&motion); paddle_to_native();
    ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))0x403210)(sound,repeat,pan,flags); paddle_from_native();
}
typedef struct { uint32_t operation,fields[12],roots[4],objects[PLAY_OBJECTS][7],size; } shot_snapshot;
static shot_snapshot shot_records[SHOT_RECORDS];
static void shot_record(uint32_t operation) {
    if (--shot_depth) return;
    REQUIRE(shot_records_count<SHOT_RECORDS); paddle_from_native(); shot_snapshot *r=&shot_records[shot_records_count++]; r->operation=operation;
    uint32_t fields[]={play.shot_count,motion.paddle_width,play.paddle_x,play.paddle_y,motion.pierce,motion.impact_dx,
        motion.impact_dy,menu.score,state.current_bank,play.gun,play.launch_pressed,play.remaining_bricks};
    memcpy(r->fields,fields,sizeof(fields));
    uint32_t roots[]={shot_id(play.shots.current),shot_id(play.shots.first),shot_id(play.shots.last),play.shots.retained};
    memcpy(r->roots,roots,sizeof(roots));
    for (uint32_t i=0;i<shot_count;++i) if (shot_pool[i].seen) {
        uint32_t *row=r->objects[r->size++]; row[0]=i+1; memcpy(row+1,&shot_pool[i].value,16);
        row[5]=shot_id(shot_pool[i].value.next); row[6]=shot_id(shot_pool[i].value.previous);
    }
}
#define SHOT_LIVE(name,operation,address) static void live_shot_##name(void) { \
    ++shot_depth; paddle_from_native(); \
    if (source_side) { fixture_shot_##name(&motion); paddle_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_shot_##name##_hook)); ((void (*)(void))address)(); \
        install_shot_##name##_hook.entry=NULL; REQUIRE(install_shot_##name(live_shot_##name)); } \
    shot_record(operation); }
SHOT_LIVE(update,0,0x4069c0) SHOT_LIVE(fire,1,0x406af0) SHOT_LIVE(remove,2,0x406cc0)
#undef SHOT_LIVE
static void shot_observe(spx_observer *observer) {
    spx_observer o=*observer; paddle_observe(&o); spx_observe_array(&o,"shots");
    for (uint32_t i=0;i<shot_records_count;++i) {
        shot_snapshot *r=&shot_records[i]; spx_observe_object(&o,NULL); spx_observe_u64(&o,"operation",r->operation);
        spx_observe_u32s(&o,"fields",r->fields,12); spx_observe_u32s(&o,"roots",r->roots,4); spx_observe_array(&o,"objects");
        for (uint32_t j=0;j<r->size;++j) spx_observe_u32s(&o,NULL,r->objects[j],7);
        spx_observe_end(&o); spx_observe_end(&o);
    }
    spx_observe_end(&o); *observer=o;
}
static void shot_diagnose(spx_observer *observer) {
    paddle_diagnose(observer); spx_observe_u32s(observer,"selected_shots",shot_entries,3);
}
static void shot_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT"); if (!path) return; FILE *out=fopen(path,"wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out); shot_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o=spx_observe_begin(out); shot_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL shot_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!paddle_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { shot_report(); return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
    REQUIRE(install_shot_update(live_shot_update)); REQUIRE(install_shot_fire(live_shot_fire)); REQUIRE(install_shot_remove(live_shot_remove));
    return TRUE;
}
#ifndef SHOT_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return shot_main(instance,reason,reserved); }
#endif
