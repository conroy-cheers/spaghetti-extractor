/* Select progression over the preceding shared native object maps. */
#define POWER_NORMAL_LIBRARY_ONLY 1
#include "power-normal-runtime.c"
#include "progress-runtime.h"
static progression_state progress={.paddle=&paddle,.bricks=&bricks};
static uint32_t progress_entries[8],progress_depth,progress_count;
void progress_enter(unsigned operation) { REQUIRE(operation<8); ++progress_entries[operation]; }
#define PROGRESS_WORDS(X) X(pending,0x42ca5c) X(board_changed,0x431cc0) X(warning_y,0x42cdc8) X(warning_frames,0x431cb0)
static void progress_to_native(void) {
    power_to_native();
#define PUT(name,address) *word(address)=progress.name;
    PROGRESS_WORDS(PUT)
#undef PUT
}
static void progress_from_native(void) {
    power_from_native();
#define GET(name,address) progress.name=*word(address);
    PROGRESS_WORDS(GET)
#undef GET
}
#define PROGRESS_SERVICE0(name,address) void progress_##name(void *u,progression_state *s) { \
    (void)u; REQUIRE(s==&progress); progress_to_native(); ((void (*)(void))address)(); progress_from_native(); }
PROGRESS_SERVICE0(load_board,0x405a70) PROGRESS_SERVICE0(redraw,0x40aad0) PROGRESS_SERVICE0(create_ball,0x404d70)
PROGRESS_SERVICE0(clear_objects,0x408fd0) PROGRESS_SERVICE0(reset_damage,0x401000)
#undef PROGRESS_SERVICE0
#define PROGRESS_SERVICE1(name,address) void progress_##name(void *u,progression_state *s,uint32_t n) { \
    (void)u; REQUIRE(s==&progress); progress_to_native(); ((void (*)(uint32_t))address)(n); progress_from_native(); }
PROGRESS_SERVICE1(stop_sound,0x403370) PROGRESS_SERVICE1(wait,0x402240)
#undef PROGRESS_SERVICE1
uint32_t progress_pan(void *u,progression_state *s,uint32_t x) {
    (void)u; REQUIRE(s==&progress); progress_to_native(); uint32_t result=((uint32_t (*)(uint32_t))0x403550)(x); progress_from_native(); return result;
}
void progress_play_sound(void *u,progression_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d) {
    (void)u; REQUIRE(s==&progress); progress_to_native(); ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))0x403210)(a,b,c,d); progress_from_native();
}
void progress_fade(void *u,progression_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e) {
    (void)u; REQUIRE(s==&progress); progress_to_native(); ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))0x402770)(a,b,c,d,e); progress_from_native();
}
void progress_destination(void *u,progression_state *s,font_surface *surface) {
    (void)u; REQUIRE(s==&progress); uint32_t address=surface_address(surface); progress_to_native(); ((void (*)(uint32_t))0x40bd60)(address); progress_from_native();
}
void progress_clear(void *u,progression_state *s,font_surface *surface,uint32_t color) {
    (void)u; REQUIRE(s==&progress); uint32_t address=surface_address(surface); progress_to_native(); ((void (*)(uint32_t,uint32_t))0x402710)(address,color); progress_from_native();
}
void progress_palette(void *u,progression_state *s,asset_name *name) {
    (void)u; REQUIRE(s==&progress); progress_to_native(); ((void (*)(const char *))0x4023e0)(name->text); progress_from_native();
}
void progress_text(void *u,progression_state *s,uint32_t x,uint32_t y,uint32_t length,font_bytes *bytes) {
    (void)u; REQUIRE(s==&progress); progress_to_native(); ((void (*)(uint32_t,uint32_t,uint32_t,const unsigned char *))0x40c6b0)(x,y,length,bytes->data); progress_from_native();
}
void progress_sprite(void *u,progression_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    (void)u; REQUIRE(s==&progress); progress_to_native(); ((void (*)(uint32_t,uint32_t,uint32_t))0x40bd90)(slot,x,y); progress_from_native();
}
void progress_damage(void *u,progression_state *s,font_rect *bounds) {
    (void)u; REQUIRE(s==&progress); progress_to_native(); ((void (*)(font_rect))0x401350)(*bounds); progress_from_native();
}
void progress_blit_fast(void *u,progression_state *s,font_surface *destination,uint32_t x,uint32_t y,font_surface *source,font_rect *bounds,uint32_t flags) {
    (void)u; REQUIRE(s==&progress); uint32_t dst=surface_address(destination),src=surface_address(source); progress_to_native();
    ((uint32_t (WINAPI *)(uint32_t,uint32_t,uint32_t,uint32_t,font_rect *,uint32_t))(uintptr_t)word(*word(dst))[7])(dst,x,y,src,bounds,flags);
    progress_from_native();
}
typedef struct {
    uint32_t operation,result,fields[48],roots[4],balls[PLAY_OBJECTS][16],size;
    uint64_t pixels[2];
    unsigned char board[400],pending[400],current[1024],staged[1024];
} progress_snapshot;
static progress_snapshot progress_records[512];
static void progress_record(uint32_t operation,uint32_t result) {
    if (--progress_depth) return;
    REQUIRE(progress_count<512); progress_from_native(); progress_snapshot *r=&progress_records[progress_count++]; r->operation=operation; r->result=result;
    uint32_t fields[]={progress.pending,progress.board_changed,progress.warning_y,progress.warning_frames,
        menu.score,pickups.next_life,pickups.lives,pickups.count,pickups.paddle_sprite,bricks.board_index,
        flow.transition_pending,flow.next_scene,scene.mouse_x,scene.mouse_y,scene.mouse_buttons,scene.presentation_mode,
        play.paused,play.last_tick,play.changed,play.paddle_x,play.paddle_y,play.old_paddle_x,play.old_paddle_y,
        play.remaining_bricks,play.warning_sound,play.voice_pending,play.slow_balls,play.speedup_balls,play.fire_balls,
        play.split_balls,play.power_balls,play.launch_pressed,play.gun,play.shot_count,
        motion.ball_count,motion.gravity,motion.paddle_width,motion.paddle_power,motion.sticky,motion.pierce,
        paddle.phase,paddle.last_tick,paddle.spark_deadline,paddle.spark_width,paddle.spark_sprite,font.objects->current_bank,
        observed_surface(surface_address(title.back)),observed_surface(surface_address(flow.primary))};
    _Static_assert(sizeof(fields)==sizeof(r->fields),"progress fields"); memcpy(r->fields,fields,sizeof(fields));
    uint32_t roots[]={ball_id(play.balls.current),ball_id(play.balls.first),ball_id(play.balls.last),play.balls.retained}; memcpy(r->roots,roots,sizeof(roots));
    for (uint32_t i=0;i<ball_count;++i) if (ball_pool[i].seen) {
        uint32_t *row=r->balls[r->size++]; row[0]=i+1; memcpy(row+1,&ball_pool[i].value,52);
        row[14]=ball_id(ball_pool[i].value.next); row[15]=ball_id(ball_pool[i].value.previous);
    }
    memcpy(r->board,&board_live.current,400); memcpy(r->pending,play.pending_cells,400);
    memcpy(r->current,palettes.current,1024); memcpy(r->staged,palettes.staged,1024);
    r->pixels[0]=damage_observe_surface(title.back,damage_live_pixels);
    r->pixels[1]=damage_observe_surface(flow.primary,damage_live_pixels);
}
#define ENTRY(name,operation,address) static void live_progress_##name(void) { \
    ++progress_depth; progress_from_native(); \
    if (source_side) { fixture_progress_##name(&progress); progress_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_progress_##name##_hook)); ((void (*)(void))address)(); \
        install_progress_##name##_hook.entry=NULL; REQUIRE(install_progress_##name(live_progress_##name)); } \
    progress_record(operation,0); }
ENTRY(refresh,0,0x408740) ENTRY(draw,1,0x408770) ENTRY(next,3,0x408930) ENTRY(lose,4,0x408990)
ENTRY(over,5,0x4089e0) ENTRY(restart,6,0x408a00) ENTRY(advance,7,0x408b40)
#undef ENTRY
static uint32_t live_progress_count(void) {
    ++progress_depth; progress_from_native(); uint32_t result;
    if (source_side) { result=fixture_progress_count(&progress); progress_to_native(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_progress_count_hook)); result=((uint32_t (*)(void))0x408900)();
        install_progress_count_hook.entry=NULL; REQUIRE(install_progress_count((void (*)(void))live_progress_count)); }
    progress_record(2,result); return result;
}
static void progress_observe(spx_observer *observer) {
    spx_observer o=*observer; power_observe(&o); spx_observe_array(&o,"progression");
    for (uint32_t i=0;i<progress_count;++i) {
        progress_snapshot *r=&progress_records[i]; spx_observe_object(&o,NULL); spx_observe_u64(&o,"operation",r->operation); spx_observe_u64(&o,"returned",r->result);
        spx_observe_u32s(&o,"fields",r->fields,48); spx_observe_u32s(&o,"roots",r->roots,4);
        spx_observe_u64(&o,"back_pixels",r->pixels[0]); spx_observe_u64(&o,"primary_pixels",r->pixels[1]);
        spx_observe_bytes(&o,"board",r->board,400); spx_observe_bytes(&o,"pending_cells",r->pending,400);
        spx_observe_bytes(&o,"current_palette",r->current,1024); spx_observe_bytes(&o,"staged_palette",r->staged,1024);
        spx_observe_array(&o,"balls"); for (uint32_t j=0;j<r->size;++j) spx_observe_u32s(&o,NULL,r->balls[j],16); spx_observe_end(&o); spx_observe_end(&o);
    }
    spx_observe_end(&o); *observer=o;
}
static void progress_diagnose(spx_observer *observer) {
    power_diagnose(observer); spx_observe_u32s(observer,"selected_progression",progress_entries,8);
}
static void progress_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT"); if (!path) return; FILE *out=fopen(path,"wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out); progress_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o=spx_observe_begin(out); progress_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL progress_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!power_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { progress_report(); return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
#define ENTRY(name) REQUIRE(install_progress_##name((void (*)(void))live_progress_##name));
    ENTRY(refresh) ENTRY(draw) ENTRY(count) ENTRY(next) ENTRY(lose) ENTRY(over) ENTRY(restart) ENTRY(advance)
#undef ENTRY
    return TRUE;
}
#ifndef PROGRESS_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return progress_main(instance,reason,reserved); }
#endif
