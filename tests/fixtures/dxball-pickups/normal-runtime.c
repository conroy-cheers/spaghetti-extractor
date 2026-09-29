/* Select pickups in the existing normal game and shared object network. */
#define BRICK_NORMAL_LIBRARY_ONLY 1
#include "brick-normal-runtime.c"
#include "pickup-runtime.h"
static pickup_state pickups={.motion=&motion};
static uint32_t pickup_entries[4],pickup_depth,pickup_count,pickup_objects;
static struct { uint32_t address,seen; pickup value; } pickup_pool[PLAY_OBJECTS];
void pickup_enter(unsigned operation) { REQUIRE(operation<4); ++pickup_entries[operation]; }
static uint32_t pickup_id(const pickup *p) {
    if (!p) return 0;
    for (uint32_t i=0;i<pickup_objects;++i) if (p==&pickup_pool[i].value) return i+1;
    REQUIRE(0); return 0;
}
static uint32_t pickup_address(pickup *p) { uint32_t id=pickup_id(p); return id ? pickup_pool[id-1].address : 0; }
static pickup *pickup_view(uint32_t address) {
    if (!address) return NULL;
    uint32_t i;
    for (i=0;i<pickup_objects && pickup_pool[i].address!=address;++i) {}
    if (i==pickup_objects) { REQUIRE(pickup_objects<PLAY_OBJECTS); ++pickup_objects; pickup_pool[i].address=address; }
    pickup *view=&pickup_pool[i].value;
    if (!pickup_pool[i].seen) {
        pickup_pool[i].seen=1; const uint32_t *p=word(address); memcpy(view,p,28);
        view->next=pickup_view(p[7]); view->previous=pickup_view(p[8]);
    }
    return view;
}
#define PICKUP_WORDS(X) X(count,0x431cb8) X(lives,0x431ca8) X(next_life,0x431c7c) X(paddle_sprite,0x431c84)
static void pickup_to_native(void) {
    brick_to_native();
#define PUT(name,address) *word(address)=pickups.name;
    PICKUP_WORDS(PUT)
#undef PUT
    *word(0x431c50)=pickup_address(pickups.current); *word(0x431c54)=pickup_address(pickups.first); *word(0x431c58)=pickup_address(pickups.last);
    for (uint32_t i=0;i<pickup_objects;++i) if (pickup_pool[i].seen) {
        uint32_t *p=word(pickup_pool[i].address); memcpy(p,&pickup_pool[i].value,28);
        p[7]=pickup_address(pickup_pool[i].value.next); p[8]=pickup_address(pickup_pool[i].value.previous);
    }
}
static void pickup_from_native(void) {
    brick_from_native();
#define GET(name,address) pickups.name=*word(address);
    PICKUP_WORDS(GET)
#undef GET
    for (uint32_t i=0;i<pickup_objects;++i) pickup_pool[i].seen=0;
    pickups.current=pickup_view(*word(0x431c50)); pickups.first=pickup_view(*word(0x431c54)); pickups.last=pickup_view(*word(0x431c58));
}
pickup *pickup_allocate(void *unused,pickup_state *s) {
    (void)unused; REQUIRE(s==&pickups); pickup_to_native();
    uint32_t address=((uint32_t (*)(uint32_t))0x40df40)(36); pickup_from_native(); if (!address) return NULL;
    uint32_t i;
    for (i=0;i<pickup_objects && pickup_pool[i].address!=address;++i) {}
    if (i==pickup_objects) { REQUIRE(pickup_objects<PLAY_OBJECTS); ++pickup_objects; pickup_pool[i].address=address; }
    REQUIRE(!pickup_pool[i].seen); pickup_pool[i].seen=1;
    memcpy(&pickup_pool[i].value,(void *)(uintptr_t)address,28);
    pickup_pool[i].value.next=pickup_pool[i].value.previous=NULL; return &pickup_pool[i].value;
}
void pickup_free(void *unused,pickup_state *s,pickup *item) {
    (void)unused; REQUIRE(s==&pickups); uint32_t address=pickup_address(item); pickup_to_native();
    ((void (*)(uint32_t))0x40df30)(address); pickup_from_native();
}
#define PICKUP_SERVICE0(name,address) void pickup_##name(void *u,pickup_state *s) { \
    (void)u; REQUIRE(s==&pickups); pickup_to_native(); ((void (*)(void))address)(); pickup_from_native(); }
PICKUP_SERVICE0(next_board,0x408930) PICKUP_SERVICE0(unstick,0x4084b0) PICKUP_SERVICE0(queue_explosive_bricks,0x408260)
PICKUP_SERVICE0(detonate_bricks,0x408540) PICKUP_SERVICE0(release_attached,0x4086e0) PICKUP_SERVICE0(move_paddle,0x406730) PICKUP_SERVICE0(lose_life,0x408990)
#undef PICKUP_SERVICE0
#define PICKUP_RESULT1(name,address) uint32_t pickup_##name(void *u,pickup_state *s,uint32_t value) { \
    (void)u; REQUIRE(s==&pickups); pickup_to_native(); uint32_t result=((uint32_t (*)(uint32_t))address)(value); pickup_from_native(); return result; }
PICKUP_RESULT1(random,0x40ae20) PICKUP_RESULT1(pan,0x403550)
#undef PICKUP_RESULT1
void pickup_stop_sound(void *u,pickup_state *s,uint32_t id) {
    (void)u; REQUIRE(s==&pickups); pickup_to_native(); ((void (*)(uint32_t))0x403370)(id); pickup_from_native();
}
void pickup_play_sound(void *u,pickup_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d) {
    (void)u; REQUIRE(s==&pickups); pickup_to_native(); ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))0x403210)(a,b,c,d); pickup_from_native();
}
void pickup_particle(void *u,pickup_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f) {
    (void)u; REQUIRE(s==&pickups); pickup_to_native(); ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))0x407b00)(a,b,c,d,e,f); pickup_from_native();
}
uint32_t pickup_overlap(void *u,pickup_state *s,font_rect *a,font_rect *b) {
    (void)u; REQUIRE(s==&pickups); pickup_to_native(); uint32_t result=((uint32_t (*)(font_rect,font_rect))0x40d5e0)(*a,*b); pickup_from_native(); return result;
}
void pickup_sprite(void *u,pickup_state *s,uint32_t a,uint32_t b,uint32_t c) {
    (void)u; REQUIRE(s==&pickups); pickup_to_native(); ((void (*)(uint32_t,uint32_t,uint32_t))0x401140)(a,b,c); pickup_from_native();
}
typedef struct {
    uint32_t operation,args[4],fields[21],roots[3],objects[PLAY_OBJECTS][10],size;
} pickup_snapshot;
static pickup_snapshot pickup_records[256];
static void pickup_record(uint32_t operation,uint32_t a,uint32_t b,uint32_t c,uint32_t d) {
    if (--pickup_depth) return;
    REQUIRE(pickup_count<256); pickup_from_native(); pickup_snapshot *r=&pickup_records[pickup_count++];
    r->operation=operation; r->args[0]=a; r->args[1]=b; r->args[2]=c; r->args[3]=d;
    uint32_t fields[]={pickups.count,pickups.lives,pickups.next_life,pickups.paddle_sprite,menu.score,title.fast,
        motion.paddle_width,motion.gravity,motion.paddle_power,motion.sticky,motion.pierce,play.gun,
        play.slow_balls,play.speedup_balls,play.fire_balls,play.split_balls,play.power_balls,
        play.old_paddle_x,play.old_paddle_y,state.current_bank,play.changed};
    memcpy(r->fields,fields,sizeof(fields));
    uint32_t roots[]={pickup_id(pickups.current),pickup_id(pickups.first),pickup_id(pickups.last)}; memcpy(r->roots,roots,sizeof(roots));
    for (uint32_t i=0;i<pickup_objects;++i) if (pickup_pool[i].seen) {
        uint32_t *row=r->objects[r->size++]; row[0]=i+1; memcpy(row+1,&pickup_pool[i].value,28);
        row[8]=pickup_id(pickup_pool[i].value.next); row[9]=pickup_id(pickup_pool[i].value.previous);
    }
}
#define PICKUP_LIVE0(name,op,address) static void live_pickup_##name(void) { \
    ++pickup_depth; pickup_from_native(); \
    if (source_side) { fixture_pickup_##name(&pickups); pickup_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_pickup_##name##_hook)); ((void (*)(void))address)(); \
        install_pickup_##name##_hook.entry=NULL; REQUIRE(install_pickup_##name(live_pickup_##name)); } \
    pickup_record(op,0,0,0,0); }
PICKUP_LIVE0(update,1,0x407420) PICKUP_LIVE0(draw,2,0x407a40) PICKUP_LIVE0(remove,3,0x407a90)
#undef PICKUP_LIVE0
static void live_pickup_create(uint32_t a,uint32_t b,uint32_t c,uint32_t d) {
    ++pickup_depth; pickup_from_native();
    if (source_side) { fixture_pickup_create(&pickups,a,b,c,d); pickup_to_native(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_pickup_create_hook)); ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))0x406ef0)(a,b,c,d);
        install_pickup_create_hook.entry=NULL; REQUIRE(install_pickup_create((void (*)(void))live_pickup_create)); }
    pickup_record(0,a,b,c,d);
}
static void pickup_observe(spx_observer *observer) {
    spx_observer o=*observer; brick_observe(&o); spx_observe_array(&o,"pickups");
    for (uint32_t i=0;i<pickup_count;++i) {
        pickup_snapshot *r=&pickup_records[i]; spx_observe_object(&o,NULL);
        spx_observe_u64(&o,"operation",r->operation); spx_observe_u32s(&o,"arguments",r->args,4);
        spx_observe_u32s(&o,"fields",r->fields,21); spx_observe_u32s(&o,"roots",r->roots,3); spx_observe_array(&o,"objects");
        for (uint32_t j=0;j<r->size;++j) spx_observe_u32s(&o,NULL,r->objects[j],10);
        spx_observe_end(&o); spx_observe_end(&o);
    }
    spx_observe_end(&o); *observer=o;
}
static void pickup_diagnose(spx_observer *observer) {
    brick_diagnose(observer); spx_observe_u32s(observer,"selected_pickups",pickup_entries,4);
}
static void pickup_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT"); if (!path) return; FILE *out=fopen(path,"wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out); pickup_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o=spx_observe_begin(out); pickup_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL pickup_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!brick_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { pickup_report(); return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
#define PICKUP_ROOT(name) REQUIRE(install_pickup_##name((void (*)(void))live_pickup_##name));
    PICKUP_ROOT(create) PICKUP_ROOT(update) PICKUP_ROOT(draw) PICKUP_ROOT(remove)
#undef PICKUP_ROOT
    return TRUE;
}
#ifndef PICKUP_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return pickup_main(instance,reason,reserved); }
#endif
