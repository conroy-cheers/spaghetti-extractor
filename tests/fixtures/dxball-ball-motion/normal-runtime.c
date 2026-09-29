/* Use actual allocation/audio/brick services and the existing live C network. */
#define PLAY_NORMAL_LIBRARY_ONLY 1
#include "play-normal-runtime.c"
#include "motion-runtime.h"
static motion_state motion={.play=&play,.board=&board_live.current};
static uint32_t motion_entries[5],motion_depth,motion_count;
void motion_enter(unsigned operation) { REQUIRE(operation<5); ++motion_entries[operation]; }
#include "motion-native.h"

play_ball *motion_allocate(void *unused,motion_state *s) {
    (void)unused; REQUIRE(s==&motion); motion_to_native();
    uint32_t address=((uint32_t (*)(uint32_t))0x40df40)(60); motion_from_native();
    if (!address) return NULL;
    uint32_t i;
    for (i=0;i<ball_count && ball_pool[i].address!=address;++i) {}
    if (i==ball_count) { REQUIRE(ball_count<PLAY_OBJECTS); ++ball_count; ball_pool[i].address=address; }
    /* Fresh raw storage has no readable links. Register its identity without
     * following uninitialized memory; create initializes the complete record. */
    REQUIRE(!ball_pool[i].seen); ball_pool[i].seen=1;
    memset(&ball_pool[i].value,0,sizeof(ball_pool[i].value)); return &ball_pool[i].value;
}
void motion_free(void *unused,motion_state *s,play_ball *ball) {
    (void)unused; REQUIRE(s==&motion); uint32_t address=ball_address(ball); motion_to_native();
    ((void (*)(uint32_t))0x40df30)(address); motion_from_native();
}
#define MOTION_SERVICE0(name,address) \
void motion_##name(void *unused,motion_state *s) { (void)unused; REQUIRE(s==&motion); motion_to_native(); \
    ((void (*)(void))address)(); motion_from_native(); }
MOTION_SERVICE0(paddle_power,0x4085d0) MOTION_SERVICE0(unstick,0x4084b0) MOTION_SERVICE0(lose_life,0x408990)
#undef MOTION_SERVICE0
#define MOTION_RESULT1(name,address) \
uint32_t motion_##name(void *unused,motion_state *s,uint32_t value) { (void)unused; REQUIRE(s==&motion); motion_to_native(); \
    uint32_t result=((uint32_t (*)(uint32_t))address)(value); motion_from_native(); return result; }
MOTION_RESULT1(random,0x40ae20) MOTION_RESULT1(pan,0x403550)
#undef MOTION_RESULT1
void motion_stop_sound(void *unused,motion_state *s,uint32_t sound) {
    (void)unused; REQUIRE(s==&motion); motion_to_native(); ((void (*)(uint32_t))0x403370)(sound); motion_from_native();
}
void motion_play_sound(void *unused,motion_state *s,uint32_t sound,uint32_t repeat,uint32_t volume,uint32_t pan) {
    (void)unused; REQUIRE(s==&motion); motion_to_native();
    ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))0x403210)(sound,repeat,volume,pan); motion_from_native();
}
uint32_t motion_overlap(void *unused,motion_state *s,font_rect *a,font_rect *b) {
    (void)unused; REQUIRE(s==&motion); motion_to_native();
    uint32_t result=((uint32_t (*)(font_rect,font_rect))0x40d5e0)(*a,*b); motion_from_native(); return result;
}
void motion_particle(void *unused,motion_state *s,uint32_t x,uint32_t y,uint32_t dx,uint32_t dy,uint32_t color,uint32_t gravity) {
    (void)unused; REQUIRE(s==&motion); motion_to_native();
    ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))0x407b00)(x,y,dx,dy,color,gravity); motion_from_native();
}
void motion_explosion(void *unused,motion_state *s,uint32_t x,uint32_t y) {
    (void)unused; REQUIRE(s==&motion); motion_to_native(); ((void (*)(uint32_t,uint32_t))0x406d30)(x,y); motion_from_native();
}
uint32_t motion_hit(void *unused,motion_state *s,uint32_t column,uint32_t row) {
    (void)unused; REQUIRE(s==&motion); motion_to_native();
    uint32_t result=((uint32_t (*)(uint32_t,uint32_t))0x405c80)(column,row); motion_from_native(); return result;
}
typedef struct {
    uint32_t operation,arguments[2],result,fields[19],list[4],balls[PLAY_OBJECTS][16],ball_size;
    unsigned char board[400];
} motion_snapshot;
static motion_snapshot motion_records[128];
static void motion_record(uint32_t operation,uint32_t x,uint32_t y,uint32_t result) {
    if (--motion_depth) return;
    REQUIRE(motion_count<128); motion_from_native(); motion_snapshot *r=&motion_records[motion_count++];
    r->operation=operation; r->arguments[0]=x; r->arguments[1]=y; r->result=result;
    uint32_t fields[]={motion.ball_count,motion.gravity,motion.paddle_width,motion.paddle_power,motion.sticky,motion.pierce,
        motion.impact_dx,motion.impact_dy,play.paddle_x,play.paddle_y,play.old_paddle_x,play.old_paddle_y,play.changed,
        play.launch_pressed,play.remaining_bricks,menu.score,title.fast,state.current_bank,flow.scene};
    memcpy(r->fields,fields,sizeof(fields));
    uint32_t list[]={ball_id(play.balls.current),ball_id(play.balls.first),ball_id(play.balls.last),play.balls.retained};
    memcpy(r->list,list,sizeof(list));
    for (uint32_t i=0;i<ball_count;++i) if (ball_pool[i].seen) {
        uint32_t *row=r->balls[r->ball_size++]; row[0]=i+1; memcpy(row+1,&ball_pool[i].value,52);
        row[14]=ball_id(ball_pool[i].value.next); row[15]=ball_id(ball_pool[i].value.previous);
    }
    memcpy(r->board,motion.board,400);
}
#define MOTION_LIVE0(name,operation,address) \
static void live_motion_##name(void) { \
    ++motion_depth; motion_from_native(); \
    unsigned short control; __asm__ volatile("fnstcw %0":"=m"(control)); REQUIRE((control&0x0f00)==0x0200); \
    if (source_side) { fixture_motion_##name(&motion); motion_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_motion_##name##_hook)); ((void (*)(void))address)(); \
        install_motion_##name##_hook.entry=NULL; REQUIRE(install_motion_##name(live_motion_##name)); } \
    motion_record(operation,0,0,0); }
MOTION_LIVE0(create,0,0x404d70) MOTION_LIVE0(update,1,0x404e80) MOTION_LIVE0(rebound,2,0x405710) MOTION_LIVE0(remove,4,0x405a00)
#undef MOTION_LIVE0
static uint32_t live_motion_contact(uint32_t x,uint32_t y) {
    ++motion_depth; uint32_t result; motion_from_native();
    if (source_side) { result=fixture_motion_contact(&motion,x,y); motion_to_native(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_motion_contact_hook)); result=((uint32_t (*)(uint32_t,uint32_t))0x405910)(x,y);
        install_motion_contact_hook.entry=NULL; REQUIRE(install_motion_contact((void (*)(void))live_motion_contact)); }
    motion_record(3,x,y,result); return result;
}
static void motion_observe(spx_observer *o) {
    play_observe(o); spx_observe_array(o,"motion");
    for (uint32_t i=0;i<motion_count;++i) {
        motion_snapshot *r=&motion_records[i]; spx_observe_object(o,NULL);
        spx_observe_u64(o,"operation",r->operation); spx_observe_u32s(o,"arguments",r->arguments,2); spx_observe_u64(o,"result",r->result);
        spx_observe_u32s(o,"fields",r->fields,19); spx_observe_u32s(o,"list",r->list,4); spx_observe_array(o,"balls");
        for (uint32_t j=0;j<r->ball_size;++j) spx_observe_u32s(o,NULL,r->balls[j],16);
        spx_observe_end(o); spx_observe_bytes(o,"board",r->board,400); spx_observe_end(o);
    }
    spx_observe_end(o);
}
static void motion_diagnose(spx_observer *o) {
    play_diagnose(o); spx_observe_u32s(o,"selected_motion",motion_entries,5);
}
static void motion_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT"); if (!path) return; FILE *out=fopen(path,"wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out); motion_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o=spx_observe_begin(out); motion_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL motion_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!play_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { motion_report(); return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
#define MOTION_ENTRY(name) REQUIRE(install_motion_##name((void (*)(void))live_motion_##name));
    MOTION_ENTRY(create) MOTION_ENTRY(update) MOTION_ENTRY(rebound) MOTION_ENTRY(contact) MOTION_ENTRY(remove)
#undef MOTION_ENTRY
    return TRUE;
}
#ifndef MOTION_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return motion_main(instance,reason,reserved); }
#endif
