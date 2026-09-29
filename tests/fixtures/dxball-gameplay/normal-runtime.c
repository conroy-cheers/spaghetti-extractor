/* Borrow complete live gameplay records around each synchronous native service. */
#define REGIONS_NORMAL_LIBRARY_ONLY 1
#include "regions-normal-runtime.c"
#include "play-runtime.h"
#ifndef PLAY_FRAME_CAPACITY
#define PLAY_FRAME_CAPACITY 32
#endif
enum { PLAY_OBJECTS=64,PLAY_FRAMES=PLAY_FRAME_CAPACITY };
struct play_effect { uint32_t address; };
static int32_t sine[361],cosine[361];
static play_state play={.menu=&menu,.sine=sine,.cosine=cosine};
static uint32_t play_entered,play_depth,play_frames;
void play_enter(void) { ++play_entered; }

#define POOL(name,type) \
static struct { uint32_t address,seen; type value; } name##_pool[PLAY_OBJECTS]; \
static uint32_t name##_count; \
static uint32_t name##_id(const type *p) { \
    if (!p) return 0; \
    for (uint32_t i=0;i<name##_count;++i) if (p==&name##_pool[i].value) return i+1; \
    REQUIRE(0); return 0; } \
static uint32_t name##_address(type *p) { uint32_t id=name##_id(p); return id ? name##_pool[id-1].address : 0; }
POOL(ball,play_ball) POOL(shot,play_shot) POOL(event,play_event)

#define VIEW(name,type,payload) \
static type *name##_view(uint32_t address) { \
    if (!address) return NULL; \
    uint32_t i; \
    for (i=0;i<name##_count && name##_pool[i].address!=address;++i) {} \
    if (i==name##_count) { REQUIRE(name##_count<PLAY_OBJECTS); ++name##_count; name##_pool[i].address=address; } \
    type *view=&name##_pool[i].value; \
    if (!name##_pool[i].seen) { \
        name##_pool[i].seen=1; const uint32_t *p=(const uint32_t *)(uintptr_t)address; \
        memcpy(view,p,payload*4); view->next=name##_view(p[payload]); view->previous=name##_view(p[payload+1]); \
    } \
    return view; }
VIEW(ball,play_ball,13) VIEW(shot,play_shot,4) VIEW(event,play_event,3)
static play_effect effect_pool[PLAY_OBJECTS];
static uint32_t effect_count;
static play_effect *effect_view(uint32_t address) {
    if (!address) return NULL;
    for (uint32_t i=0;i<effect_count;++i) if (effect_pool[i].address==address) return &effect_pool[i];
    REQUIRE(effect_count<PLAY_OBJECTS); effect_pool[effect_count].address=address; return &effect_pool[effect_count++];
}
static uint32_t effect_address(play_effect *p) { return p ? p->address : 0; }
static uint32_t effect_id(play_effect *p) {
    if (!p) return 0;
    for (uint32_t i=0;i<effect_count;++i) if (p==&effect_pool[i]) return i+1;
    REQUIRE(0); return 0;
}
static void play_parent_to_native(void) { editor_to_native(); }
static void play_parent_from_native(void) { editor_from_native(); }
static void play_objects_to_native(void) {
#define PUSH(name,payload) \
    for (uint32_t i=0;i<name##_count;++i) if (name##_pool[i].seen) { \
        uint32_t *p=(uint32_t *)(uintptr_t)name##_pool[i].address; \
        memcpy(p,&name##_pool[i].value,payload*4); p[payload]=name##_address(name##_pool[i].value.next); \
        p[payload+1]=name##_address(name##_pool[i].value.previous); }
    PUSH(ball,13) PUSH(shot,4) PUSH(event,3)
#undef PUSH
}
static void play_objects_from_native(void) {
    for (uint32_t i=0;i<ball_count;++i) ball_pool[i].seen=0;
    for (uint32_t i=0;i<shot_count;++i) shot_pool[i].seen=0;
    for (uint32_t i=0;i<event_count;++i) event_pool[i].seen=0;
    /* Only follow live roots after a helper returns. Removed objects are never
     * read merely because an earlier call borrowed them. */
}
#include "play-native.h"
#include "paddle-inputs.h"

#define SERVICE0(name,address) \
void play_##name(void *unused,play_state *s) { (void)unused; REQUIRE(s==&play); play_to_native(); \
    ((void (*)(void))address)(); play_from_native(); }
SERVICE0(refresh_score,0x408740) SERVICE0(move_paddle,0x406730) SERVICE0(move_balls,0x404e80)
SERVICE0(move_shots,0x4069c0) SERVICE0(move_pickups,0x407420) SERVICE0(move_trails,0x407bf0)
SERVICE0(restore_damage,0x401430) SERVICE0(advance_brick_effects,0x406020)
SERVICE0(draw_explosions,0x406e10) SERVICE0(draw_paddle,0x4067b0) SERVICE0(draw_pickups,0x407a40)
SERVICE0(draw_trails,0x407db0) SERVICE0(prepare_last_brick,0x408c20) SERVICE0(draw_last_brick,0x408ed0)
SERVICE0(present,0x401650) SERVICE0(split,0x407eb0) SERVICE0(power,0x408580)
SERVICE0(next_board,0x408930) SERVICE0(advance_stage,0x408b40) SERVICE0(fire,0x406af0)
#define SERVICE1(name,address) \
void play_##name(void *unused,play_state *s,uint32_t value) { (void)unused; REQUIRE(s==&play); play_to_native(); \
    ((void (*)(uint32_t))address)(value); play_from_native(); }
SERVICE1(wait,0x402240) SERVICE1(stop_sound,0x403370)
void play_sprite(void *unused,play_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    (void)unused; REQUIRE(s==&play); play_to_native(); ((void (*)(uint32_t,uint32_t,uint32_t))0x401080)(slot,x,y); play_from_native();
}
uint32_t play_elapsed(void *unused,play_state *s,uint32_t previous,uint32_t delay) {
    (void)unused; REQUIRE(s==&play); play_to_native(); uint32_t result=((uint32_t (*)(uint32_t,uint32_t))0x40db80)(previous,delay); play_from_native(); return result;
}
void play_cycle(void *unused,play_state *s,uint32_t first,uint32_t last,uint32_t amount) {
    (void)unused; REQUIRE(s==&play); play_to_native(); ((void (*)(uint32_t,uint32_t,uint32_t))0x402af0)(first,last,amount); play_from_native();
}
uint32_t play_now(void *unused,play_state *s) {
    (void)unused; REQUIRE(s==&play); play_to_native(); uint32_t result=((uint32_t (*)(void))0x40db20)(); play_from_native(); return result;
}
void play_hit_tile(void *unused,play_state *s,uint32_t column,uint32_t row) {
    (void)unused; REQUIRE(s==&play); play_to_native(); ((void (*)(uint32_t,uint32_t))0x406070)(column,row); play_from_native();
}
uint32_t play_read_pending(void *unused,play_state *s,uint32_t column,uint32_t row) {
    (void)unused;REQUIRE(s==&play);play_to_native();
    uint32_t address=UINT32_C(0x42cc10)+row*20+column;
    return *(const volatile unsigned char *)(uintptr_t)address;
}
uint32_t play_random(void *unused,play_state *s,uint32_t limit) {
    (void)unused; REQUIRE(s==&play); play_to_native(); uint32_t result=((uint32_t (*)(uint32_t))0x40ae20)(limit); play_from_native(); return result;
}
void play_spawn_debris(void *unused,play_state *s,uint32_t column,uint32_t row,uint32_t dx,uint32_t dy) {
    (void)unused; REQUIRE(s==&play); play_to_native(); ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))0x406ef0)(column,row,dx,dy); play_from_native();
}
void play_free_event(void *unused,play_state *s,play_event *event) {
    (void)unused; REQUIRE(s==&play); uint32_t address=event_address(event); play_to_native();
    ((void (*)(uint32_t))0x40df30)(address); play_from_native();
}
void play_play_sound(void *unused,play_state *s,uint32_t sound,uint32_t repeat,uint32_t volume,uint32_t pan) {
    (void)unused; REQUIRE(s==&play); play_to_native(); ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))0x403210)(sound,repeat,volume,pan); play_from_native();
}

typedef struct {
    uint32_t fields[21],lists[16],balls[PLAY_OBJECTS][16],shots[PLAY_OBJECTS][7],events[PLAY_OBJECTS][6];
    uint32_t balls_size,shots_size,events_size,last_tick,control;
    unsigned char pending[400];
    uint64_t primary_pixels,back_pixels;
} play_snapshot;
static play_snapshot play_records[PLAY_FRAMES];
static void play_record(void) {
    REQUIRE(play_frames<PLAY_FRAMES); play_from_native(); play_snapshot *record=&play_records[play_frames++];
    uint32_t fields[]={play.paused,play.changed,play.paddle_x,play.paddle_y,play.old_paddle_x,play.old_paddle_y,
        play.remaining_bricks,play.warning_sound,play.voice_pending,play.slow_balls,play.speedup_balls,play.fire_balls,
        play.split_balls,play.power_balls,play.launch_pressed,play.gun,play.shot_count,menu.score,scene.presentation_mode,scene.mouse_buttons,flow.scene};
    memcpy(record->fields,fields,sizeof(fields)); record->last_tick=play.last_tick;
    uint32_t lists[]={ball_id(play.balls.current),ball_id(play.balls.first),ball_id(play.balls.last),play.balls.retained,
        shot_id(play.shots.current),shot_id(play.shots.first),shot_id(play.shots.last),play.shots.retained,
        event_id(play.events.current),event_id(play.events.first),event_id(play.events.last),play.events.retained,
        effect_id(play.brick_effects.current),effect_id(play.brick_effects.first),effect_id(play.explosions.current),effect_id(play.explosions.first)};
    memcpy(record->lists,lists,sizeof(lists));
#define SNAP(name,plural,payload) \
    for (uint32_t i=0;i<name##_count;++i) if (name##_pool[i].seen) { \
        uint32_t *row=record->plural[record->plural##_size++]; row[0]=i+1; \
        memcpy(row+1,&name##_pool[i].value,payload*4); row[payload+1]=name##_id(name##_pool[i].value.next); \
        row[payload+2]=name##_id(name##_pool[i].value.previous); }
    SNAP(ball,balls,13) SNAP(shot,shots,4) SNAP(event,events,3)
#undef SNAP
    memcpy(record->pending,play.pending_cells,400);
    unsigned short control; __asm__ volatile("fnstcw %0":"=m"(control)); record->control=control;
    record->primary_pixels=title_surface_hash(surface_address(title.primary));
    record->back_pixels=title_surface_hash(surface_address(title.back));
}
static void live_play_update(void) {
    unsigned outer=!play_depth++; play_from_native();
    unsigned short control; __asm__ volatile("fnstcw %0":"=m"(control)); REQUIRE((control&0x0f00)==0x0200);
    if (source_side) { fixture_play_update(&play); play_to_native(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_play_update_hook)); ((void (*)(void))0x4044d0)();
        install_play_update_hook.entry=NULL; REQUIRE(install_play_update(live_play_update)); }
    --play_depth; if (outer) play_record();
}
static void play_observe(spx_observer *o) {
    regions_observe(o); spx_observe_array(o,"gameplay");
    for (uint32_t i=0;i<play_frames;++i) {
        play_snapshot *r=&play_records[i]; spx_observe_object(o,NULL); spx_observe_u32s(o,"fields",r->fields,21);
        spx_observe_u32s(o,"lists",r->lists,16);
#define OBSERVE(name,width) spx_observe_array(o,#name); for (uint32_t j=0;j<r->name##_size;++j) spx_observe_u32s(o,NULL,r->name[j],width); spx_observe_end(o)
        OBSERVE(balls,16); OBSERVE(shots,7); OBSERVE(events,6);
#undef OBSERVE
        spx_observe_bytes(o,"pending_cells",r->pending,400); spx_observe_u64(o,"primary_pixels",r->primary_pixels);
        spx_observe_u64(o,"back_pixels",r->back_pixels); spx_observe_u64(o,"floating_control",r->control); spx_observe_end(o);
    }
    spx_observe_end(o); spx_observe_array(o,"gameplay_environment");
    for (uint32_t i=0;i<paddle_input_count;++i) spx_observe_u32s(o,NULL,paddle_inputs[i],4);
    spx_observe_end(o);
}
static void play_diagnose(spx_observer *o) {
    regions_diagnose(o); spx_observe_u64(o,"selected_gameplay_frames",play_entered); spx_observe_array(o,"gameplay_clocks");
    for (uint32_t i=0;i<play_frames;++i) spx_observe_u64(o,NULL,play_records[i].last_tick);
    spx_observe_end(o);
}
static void play_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT"); if (!path) return; FILE *out=fopen(path,"wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out); play_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o=spx_observe_begin(out); play_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL play_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!regions_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { play_report(); return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
    REQUIRE(install_play_update(live_play_update)); paddle_inputs_install(); return TRUE;
}
#ifndef PLAY_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return play_main(instance,reason,reserved); }
#endif
