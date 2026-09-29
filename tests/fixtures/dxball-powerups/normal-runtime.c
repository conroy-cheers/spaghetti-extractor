/* Temporary and live lists share the existing ball/event identity maps. */
#define EXPLOSION_NORMAL_LIBRARY_ONLY 1
#include "explosion-normal-runtime.c"
#include "power-runtime.h"
static powerup_state powers={.motion=&motion};
static uint32_t power_entries[7],power_depth,power_operation=UINT32_MAX,power_count;
void power_enter(unsigned operation) { REQUIRE(operation<7); ++power_entries[operation]; }
static void power_to_native(void) {
    explosion_to_native();
#define LIST(name,address,singular) do { uint32_t *p=word(address); p[0]=singular##_address(powers.name.current); \
    p[1]=singular##_address(powers.name.first); p[2]=singular##_address(powers.name.last); p[3]=powers.name.retained; } while (0)
    LIST(staged_balls,0x431c98,ball); LIST(queued_cells,0x42ca40,event);
#undef LIST
}
static void power_from_native(void) {
    explosion_from_native();
#define LIST(name,address,singular) do { const uint32_t *p=word(address); powers.name.current=singular##_view(p[0]); \
    powers.name.first=singular##_view(p[1]); powers.name.last=singular##_view(p[2]); powers.name.retained=p[3]; } while (0)
    LIST(staged_balls,0x431c98,ball); LIST(queued_cells,0x42ca40,event);
#undef LIST
}
/* Register transient allocations on both sides so temporary records do not shift
 * the source side's later surviving object identities. Do not follow fresh links. */
static void (*normal_allocation_observer)(uint32_t size,uint32_t address);
static uint32_t power_observed_allocate(uint32_t size) {
    REQUIRE(spx_fixture_restore_entry(&install_power_allocation_observer_hook));
    uint32_t address=((uint32_t (*)(uint32_t))0x40df40)(size);
    install_power_allocation_observer_hook.entry=NULL;
    REQUIRE(install_power_allocation_observer((void (*)(void))power_observed_allocate));
    if (normal_allocation_observer) normal_allocation_observer(size,address);
    if (!address || !power_depth) return address;
#define REGISTER(name) do { uint32_t i; \
    for (i=0;i<name##_count && name##_pool[i].address!=address;++i) {} \
    if (i==name##_count) { REQUIRE(name##_count<PLAY_OBJECTS); ++name##_count; name##_pool[i].address=address; } } while (0)
    if (power_operation==0 && size==60) REGISTER(ball);
    if (power_operation==1 && size==20) REGISTER(event);
#undef REGISTER
    return address;
}
#define ALLOCATE(name,type,method,size,payload) \
type *power_allocate_##method(void *u,powerup_state *s) { \
    (void)u; REQUIRE(s==&powers); power_to_native(); \
    uint32_t address=((uint32_t (*)(uint32_t))0x40df40)(size); power_from_native(); if (!address) return NULL; \
    uint32_t i; for (i=0;i<name##_count && name##_pool[i].address!=address;++i) {} \
    if (i==name##_count) { REQUIRE(name##_count<PLAY_OBJECTS); ++name##_count; name##_pool[i].address=address; } \
    REQUIRE(!name##_pool[i].seen); name##_pool[i].seen=1; memcpy(&name##_pool[i].value,(void *)(uintptr_t)address,payload); \
    name##_pool[i].value.next=name##_pool[i].value.previous=NULL; return &name##_pool[i].value; }
ALLOCATE(ball,play_ball,ball,60,52) ALLOCATE(event,play_event,cell,20,12)
#undef ALLOCATE
#define FREE(name,type,method) void power_free_##method(void *u,powerup_state *s,type *p) { \
    (void)u; REQUIRE(s==&powers); uint32_t address=name##_address(p); power_to_native(); \
    ((void (*)(uint32_t))0x40df30)(address); power_from_native(); }
FREE(ball,play_ball,ball) FREE(event,play_event,cell)
#undef FREE
void power_terminate(void *u,powerup_state *s,uint32_t status) {
    (void)u; REQUIRE(s==&powers); power_to_native(); ((void (*)(uint32_t))0x40e3d0)(status); power_from_native();
}
void power_destination(void *u,powerup_state *s,font_surface *surface) {
    (void)u; REQUIRE(s==&powers); uint32_t address=surface_address(surface); power_to_native(); ((void (*)(uint32_t))0x40bd60)(address); power_from_native();
}
void power_cell(void *u,powerup_state *s,uint32_t a,uint32_t b,uint32_t c) {
    (void)u; REQUIRE(s==&powers); power_to_native(); ((void (*)(uint32_t,uint32_t,uint32_t))0x405ad0)(a,b,c); power_from_native();
}
uint32_t power_hit(void *u,powerup_state *s,uint32_t a,uint32_t b) {
    (void)u; REQUIRE(s==&powers); power_to_native(); uint32_t result=((uint32_t (*)(uint32_t,uint32_t))0x405c80)(a,b); power_from_native(); return result;
}
void power_rebound(void *u,powerup_state *s) {
    (void)u; REQUIRE(s==&powers); power_to_native(); ((void (*)(void))0x405710)(); power_from_native();
}
void power_stop_sound(void *u,powerup_state *s,uint32_t sound) {
    (void)u; REQUIRE(s==&powers); power_to_native(); ((void (*)(uint32_t))0x403370)(sound); power_from_native();
}
void power_play_sound(void *u,powerup_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d) {
    (void)u; REQUIRE(s==&powers); power_to_native(); ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))0x403210)(a,b,c,d); power_from_native();
}
void power_blit(void *u,powerup_state *s,font_surface *destination,font_rect *a,font_surface *source,font_rect *b,uint32_t flags) {
    (void)u; REQUIRE(s==&powers); uint32_t dst=surface_address(destination),src=surface_address(source); power_to_native();
    uint32_t *vtable=(uint32_t *)(uintptr_t)*(uint32_t *)(uintptr_t)dst;
    ((uint32_t (WINAPI *)(uint32_t,font_rect *,uint32_t,font_rect *,uint32_t,void *))(uintptr_t)vtable[5])(dst,a,src,b,flags,NULL);
    power_from_native();
}
void power_damage(void *u,powerup_state *s,font_rect *bounds) {
    (void)u; REQUIRE(s==&powers); power_to_native(); ((void (*)(font_rect))0x401350)(*bounds); power_from_native();
}
typedef struct {
    uint32_t operation,fields[9],roots[12],balls[PLAY_OBJECTS][16],cells[PLAY_OBJECTS][6],ball_size,cell_size;
    unsigned char board[400];
} power_snapshot;
static power_snapshot power_records[512];
static void power_record(uint32_t operation) {
    if (--power_depth) return;
    REQUIRE(power_count<512); power_from_native(); power_snapshot *r=&power_records[power_count++]; r->operation=operation;
    uint32_t fields[]={motion.ball_count,motion.paddle_power,play.remaining_bricks,menu.score,
        observed_surface(surface_address(title.back)),observed_surface(surface_address(flow.overlay)),
        observed_surface(surface_address(font.destination)),play.split_balls,play.power_balls};
    memcpy(r->fields,fields,sizeof(fields)); memcpy(r->board,&board_live.current,400);
    uint32_t roots[]={ball_id(play.balls.current),ball_id(play.balls.first),ball_id(play.balls.last),play.balls.retained,
        ball_id(powers.staged_balls.current),ball_id(powers.staged_balls.first),ball_id(powers.staged_balls.last),powers.staged_balls.retained,
        event_id(powers.queued_cells.current),event_id(powers.queued_cells.first),event_id(powers.queued_cells.last),powers.queued_cells.retained};
    memcpy(r->roots,roots,sizeof(roots));
    for (uint32_t i=0;i<ball_count;++i) if (ball_pool[i].seen) {
        uint32_t *row=r->balls[r->ball_size++]; row[0]=i+1; memcpy(row+1,&ball_pool[i].value,52);
        row[14]=ball_id(ball_pool[i].value.next); row[15]=ball_id(ball_pool[i].value.previous);
    }
    for (uint32_t i=0;i<event_count;++i) if (event_pool[i].seen) {
        uint32_t *row=r->cells[r->cell_size++]; row[0]=i+1; memcpy(row+1,&event_pool[i].value,12);
        row[4]=event_id(event_pool[i].value.next); row[5]=event_id(event_pool[i].value.previous);
    }
}
#define ENTRY(name,operation,address) static void live_power_##name(void) { \
    uint32_t previous=power_operation; power_operation=operation; ++power_depth; power_from_native(); \
    if (source_side) { fixture_power_##name(&powers); power_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_power_##name##_hook)); ((void (*)(void))address)(); \
        install_power_##name##_hook.entry=NULL; REQUIRE(install_power_##name(live_power_##name)); } \
    power_record(operation); power_operation=previous; }
ENTRY(split,0,0x407eb0) ENTRY(expand,1,0x408260) ENTRY(soften,2,0x4084b0) ENTRY(detonate,3,0x408540)
ENTRY(super,4,0x408580) ENTRY(drop,5,0x4085d0) ENTRY(release,6,0x4086e0)
#undef ENTRY
static void power_observe(spx_observer *observer) {
    spx_observer o=*observer; explosion_observe(&o); spx_observe_array(&o,"powerups");
    for (uint32_t i=0;i<power_count;++i) {
        power_snapshot *r=&power_records[i]; spx_observe_object(&o,NULL); spx_observe_u64(&o,"operation",r->operation);
        spx_observe_u32s(&o,"fields",r->fields,9); spx_observe_u32s(&o,"roots",r->roots,12); spx_observe_bytes(&o,"board",r->board,400);
        spx_observe_array(&o,"balls"); for (uint32_t j=0;j<r->ball_size;++j) spx_observe_u32s(&o,NULL,r->balls[j],16); spx_observe_end(&o);
        spx_observe_array(&o,"cells"); for (uint32_t j=0;j<r->cell_size;++j) spx_observe_u32s(&o,NULL,r->cells[j],6); spx_observe_end(&o); spx_observe_end(&o);
    }
    spx_observe_end(&o); *observer=o;
}
static void power_diagnose(spx_observer *observer) {
    explosion_diagnose(observer); spx_observe_u32s(observer,"selected_powerups",power_entries,7);
}
static void power_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT"); if (!path) return; FILE *out=fopen(path,"wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out); power_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o=spx_observe_begin(out); power_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL power_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!explosion_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { power_report(); return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
#define ENTRY(name) REQUIRE(install_power_##name(live_power_##name));
    ENTRY(split) ENTRY(expand) ENTRY(soften) ENTRY(detonate) ENTRY(super) ENTRY(drop) ENTRY(release)
#undef ENTRY
    REQUIRE(install_power_allocation_observer((void (*)(void))power_observed_allocate)); return TRUE;
}
#ifndef POWER_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return power_main(instance,reason,reserved); }
#endif
