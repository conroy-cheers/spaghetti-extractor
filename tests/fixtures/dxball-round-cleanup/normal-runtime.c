/* Existing live object maps supply typed allocation transport and real free. */
#define PROGRESS_NORMAL_LIBRARY_ONLY 1
#include "progress-normal-runtime.c"
#include "round-runtime.h"
static round_state rounds={.progression=&progress,.powers=&powers,.particles=&particles,.explosions=&explosions};
static uint32_t round_entries[2],round_frees[7],round_depth,round_count;
void round_enter(unsigned operation) { REQUIRE(operation<2); ++round_entries[operation]; }
void round_exit(round_state *s) { REQUIRE(s==&rounds); progress_to_native(); progress_from_native(); }
void round_free(void *u,round_state *s,round_storage *storage) {
    (void)u; REQUIRE(s==&rounds); uint32_t address=0,kind=0;
#define STORAGE(name,count,index) for (uint32_t i=0;i<count;++i) if ((void *)storage==&name##_pool[i].value) { address=name##_pool[i].address; kind=index; }
    STORAGE(ball,ball_count,1) STORAGE(shot,shot_count,2) STORAGE(brick,brick_objects,3)
    STORAGE(event,event_count,4) STORAGE(pickup,pickup_objects,5) STORAGE(particle,particle_objects,6) STORAGE(explosion,explosion_objects,7)
#undef STORAGE
    REQUIRE(address && kind); ++round_frees[kind-1]; progress_to_native(); ((void (*)(uint32_t))0x40df30)(address); progress_from_native();
}
void round_fade(void *u,round_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e) {
    (void)u; REQUIRE(s==&rounds); progress_to_native(); ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))0x402770)(a,b,c,d,e); progress_from_native();
}
void round_clear_surface(void *u,round_state *s,font_surface *surface,uint32_t color) {
    (void)u; REQUIRE(s==&rounds); uint32_t address=surface_address(surface); progress_to_native(); ((void (*)(uint32_t,uint32_t))0x402710)(address,color); progress_from_native();
}
#define ROUND_SERVICE(name,address) void round_##name(void *u,round_state *s) { \
    (void)u; REQUIRE(s==&rounds); progress_to_native(); ((void (*)(void))address)(); progress_from_native(); }
ROUND_SERVICE(release_sounds,0x402f90) ROUND_SERVICE(clear_sprites,0x40bcc0) ROUND_SERVICE(stop_music,0x402200)
#undef ROUND_SERVICE
enum { ROUND_NODES=6*PLAY_OBJECTS+PARTICLE_OBJECTS,ROUND_RECORDS=32 };
typedef struct {
    uint32_t fields[24],roots[36],nodes[ROUND_NODES][17],size;
    unsigned char board[400],pending[400],current[1024],staged[1024];
} round_snapshot;
static struct { uint32_t operation,full; round_snapshot before,after; } round_records[ROUND_RECORDS];
static void round_capture(round_snapshot *r) {
    progress_from_native();
    uint32_t fields[]={progress.pending,progress.board_changed,progress.warning_y,progress.warning_frames,
        pickups.count,pickups.lives,pickups.next_life,pickups.paddle_sprite,motion.ball_count,motion.paddle_width,
        play.shot_count,play.remaining_bricks,play.paddle_x,play.paddle_y,play.last_tick,play.paused,menu.score,
        bricks.board_index,flow.next_scene,flow.transition_pending,
        observed_surface(surface_address(title.back)),observed_surface(surface_address(flow.primary)),
        observed_surface(surface_address(flow.overlay)),observed_surface(surface_address(font.destination))};
    _Static_assert(sizeof(fields)==sizeof(r->fields),"round fields"); memcpy(r->fields,fields,sizeof(fields));
    uint32_t roots[]={shot_id(play.shots.current),shot_id(play.shots.first),shot_id(play.shots.last),play.shots.retained,
        ball_id(play.balls.current),ball_id(play.balls.first),ball_id(play.balls.last),play.balls.retained,
        brick_id(bricks.current),brick_id(bricks.first),brick_id(bricks.last),0,
        event_id(play.events.current),event_id(play.events.first),event_id(play.events.last),play.events.retained,
        pickup_id(pickups.current),pickup_id(pickups.first),pickup_id(pickups.last),0,
        particle_id(particles.current),particle_id(particles.first),particle_id(particles.last),0,
        ball_id(powers.staged_balls.current),ball_id(powers.staged_balls.first),ball_id(powers.staged_balls.last),powers.staged_balls.retained,
        event_id(powers.queued_cells.current),event_id(powers.queued_cells.first),event_id(powers.queued_cells.last),powers.queued_cells.retained,
        explosion_id(explosion_current(&explosions)),explosion_id(explosion_first(&explosions)),explosion_id(explosions.last),explosions.retained};
    _Static_assert(sizeof(roots)==sizeof(r->roots),"round roots"); memcpy(r->roots,roots,sizeof(roots));
#define CAPTURE(name,count,kind,words) for (uint32_t i=0;i<count;++i) if (name##_pool[i].seen) { \
    REQUIRE(r->size<ROUND_NODES); uint32_t *row=r->nodes[r->size++]; row[0]=kind; row[1]=i+1; memcpy(row+2,&name##_pool[i].value,words*4); \
    row[words+2]=name##_id(name##_pool[i].value.next); row[words+3]=name##_id(name##_pool[i].value.previous); }
    CAPTURE(ball,ball_count,1,13) CAPTURE(shot,shot_count,2,4) CAPTURE(brick,brick_objects,3,8)
    CAPTURE(event,event_count,4,3) CAPTURE(pickup,pickup_objects,5,7) CAPTURE(particle,particle_objects,6,9) CAPTURE(explosion,explosion_objects,7,3)
#undef CAPTURE
    memcpy(r->board,&board_live.current,400); memcpy(r->pending,play.pending_cells,400);
    memcpy(r->current,palettes.current,1024); memcpy(r->staged,palettes.staged,1024);
}
static void round_before(uint32_t operation,uint32_t full) {
    if (++round_depth!=1) return;
    REQUIRE(round_count<ROUND_RECORDS); round_records[round_count].operation=operation; round_records[round_count].full=full;
    round_capture(&round_records[round_count].before);
}
static void round_after(void) { if (--round_depth) return; round_capture(&round_records[round_count++].after); }
static void live_round_clear(void) {
    round_before(0,0); progress_from_native();
    if (source_side) { fixture_round_clear(&rounds); progress_to_native(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_round_clear_hook)); ((void (*)(void))0x408fd0)();
        install_round_clear_hook.entry=NULL; REQUIRE(install_round_clear(live_round_clear)); }
    round_after();
}
static void live_round_leave(uint32_t full) {
    round_before(1,full); progress_from_native();
    if (source_side) { fixture_round_leave(&rounds,full); progress_to_native(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_round_leave_hook)); ((void (*)(uint32_t))0x408f70)(full);
        install_round_leave_hook.entry=NULL; REQUIRE(install_round_leave((void (*)(void))live_round_leave)); }
    round_after();
}
static void round_observe_state(spx_observer *o,const char *name,const round_snapshot *r) {
    spx_observe_object(o,name); spx_observe_u32s(o,"fields",r->fields,24); spx_observe_u32s(o,"roots",r->roots,36);
    spx_observe_array(o,"nodes"); for (uint32_t i=0;i<r->size;++i) spx_observe_u32s(o,NULL,r->nodes[i],17); spx_observe_end(o);
    spx_observe_bytes(o,"board",r->board,400); spx_observe_bytes(o,"pending_cells",r->pending,400);
    spx_observe_bytes(o,"current_palette",r->current,1024); spx_observe_bytes(o,"staged_palette",r->staged,1024); spx_observe_end(o);
}
static void round_observe(spx_observer *observer) {
    spx_observer o=*observer; progress_observe(&o); spx_observe_array(&o,"round_cleanup");
    for (uint32_t i=0;i<round_count;++i) {
        spx_observe_object(&o,NULL); spx_observe_u64(&o,"operation",round_records[i].operation); spx_observe_u64(&o,"full",round_records[i].full);
        round_observe_state(&o,"before",&round_records[i].before); round_observe_state(&o,"after",&round_records[i].after); spx_observe_end(&o);
    }
    spx_observe_end(&o); *observer=o;
}
static void round_diagnose(spx_observer *observer) {
    progress_diagnose(observer); spx_observe_u32s(observer,"selected_round_cleanup",round_entries,2); spx_observe_u32s(observer,"selected_round_frees",round_frees,7);
}
static void round_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT"); if (!path) return; FILE *out=fopen(path,"wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out); round_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o=spx_observe_begin(out);
    round_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL round_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!progress_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { round_report(); return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
    REQUIRE(install_round_clear(live_round_clear)); REQUIRE(install_round_leave((void (*)(void))live_round_leave)); return TRUE;
}

#ifndef ROUND_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return round_main(instance,reason,reserved); }
#endif
