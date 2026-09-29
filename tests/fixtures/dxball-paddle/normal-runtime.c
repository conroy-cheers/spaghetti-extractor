/* Select the paddle body while retaining the established clock/random schedule. */
#define PARTICLE_NORMAL_LIBRARY_ONLY 1
#include "particle-normal-runtime.c"
#include "paddle-runtime.h"
static paddle_state paddle={.pickups=&pickups};
static uint32_t paddle_entries[2],paddle_depth,paddle_count;
void paddle_enter(unsigned operation) { REQUIRE(operation<2); ++paddle_entries[operation]; }
#define PADDLE_WORDS(X) X(phase,0x431c64) X(last_tick,0x42ca50) X(spark_deadline,0x431c70) X(spark_width,0x431c18) X(spark_sprite,0x42cc08)
static void paddle_to_native(void) {
    particle_to_native();
#define PUT(name,address) *word(address)=paddle.name;
    PADDLE_WORDS(PUT)
#undef PUT
}
static void paddle_from_native(void) {
    particle_from_native();
#define GET(name,address) paddle.name=*word(address);
    PADDLE_WORDS(GET)
#undef GET
}
void paddle_cursor(void *unused,paddle_state *s,uint32_t x,uint32_t y) {
    (void)unused; REQUIRE(s==&paddle); paddle_to_native();
    ((int (WINAPI *)(uint32_t,uint32_t))(uintptr_t)*word(0x415114))(x,y); paddle_from_native();
}
uint32_t paddle_clock(void *unused,paddle_state *s) {
    (void)unused; REQUIRE(s==&paddle); paddle_to_native();
    uint32_t result=((uint32_t (WINAPI *)(void))(uintptr_t)*word(0x415174))(); paddle_from_native(); return result;
}
uint32_t paddle_elapsed(void *unused,paddle_state *s,uint32_t a,uint32_t b) {
    (void)unused; REQUIRE(s==&paddle); paddle_to_native();
    uint32_t result=((uint32_t (*)(uint32_t,uint32_t))0x40db80)(a,b); paddle_from_native(); return result;
}
uint32_t paddle_now(void *unused,paddle_state *s) {
    (void)unused; REQUIRE(s==&paddle); paddle_to_native();
    uint32_t result=((uint32_t (*)(void))0x40db20)(); paddle_from_native(); return result;
}
uint32_t paddle_random(void *unused,paddle_state *s,uint32_t limit) {
    (void)unused; REQUIRE(s==&paddle); paddle_to_native();
    uint32_t result=((uint32_t (*)(uint32_t))0x40ae20)(limit); paddle_from_native(); return result;
}
void paddle_blit_fast(void *unused,paddle_state *s,font_surface *destination,uint32_t x,uint32_t y,font_surface *source,font_rect *bounds,uint32_t flags) {
    (void)unused; REQUIRE(s==&paddle); paddle_to_native(); uint32_t address=surface_address(destination),*table=word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,uint32_t,uint32_t,uint32_t,font_rect *,uint32_t))(uintptr_t)table[7])
        (address,x,y,surface_address(source),bounds,flags); paddle_from_native();
}
void paddle_damage(void *unused,paddle_state *s,font_rect *bounds) {
    (void)unused; REQUIRE(s==&paddle); paddle_to_native(); ((void (*)(font_rect))0x401200)(*bounds); paddle_from_native();
}
void paddle_sprite(void *unused,paddle_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    (void)unused; REQUIRE(s==&paddle); paddle_to_native(); ((void (*)(uint32_t,uint32_t,uint32_t))0x401080)(slot,x,y); paddle_from_native();
}
typedef struct { uint32_t operation,fields[19]; uint64_t pixels; } paddle_snapshot;
static paddle_snapshot paddle_records[256];
static void paddle_record(unsigned operation) {
    if (--paddle_depth) return;
    REQUIRE(paddle_count<256); paddle_from_native(); paddle_snapshot *r=&paddle_records[paddle_count++]; r->operation=operation;
    uint32_t fields[]={paddle.phase,paddle.last_tick,paddle.spark_deadline,paddle.spark_width,paddle.spark_sprite,
        motion.paddle_width,play.paddle_x,play.paddle_y,play.old_paddle_x,play.old_paddle_y,play.changed,play.gun,
        scene.mouse_x,scene.mouse_y,flow.windowed,pickups.paddle_sprite,state.current_bank,
        observed_surface(surface_address(title.software)),observed_surface(surface_address(font.destination))};
    memcpy(r->fields,fields,sizeof(fields));
    if (operation==1) r->pixels=title_surface_hash(surface_address(title.software));
}
static void live_paddle_move(void) {
    ++paddle_depth; paddle_from_native();
    if (source_side) { fixture_paddle_move(&paddle); paddle_to_native(); }
    else {
        REQUIRE(spx_fixture_restore_entry(&install_paddle_move_hook)); ((void (*)(void))0x406730)();
        install_paddle_move_hook.entry=NULL; REQUIRE(install_paddle_move(live_paddle_move));
    }
    paddle_record(0);
}
static void live_paddle_draw(void) {
    ++paddle_depth; paddle_from_native(); REQUIRE(!paddle_input_thread);
    paddle_input_tick=UINT32_C(0xf0000000)+play_frames*64;
    REQUIRE(*word(0x431c70)<paddle_input_tick && *word(0x42ca50)<paddle_input_tick);
    paddle_input_thread=GetCurrentThreadId();
    if (source_side) { fixture_paddle_draw(&paddle); paddle_to_native(); }
    else {
        REQUIRE(spx_fixture_restore_entry(&install_paddle_draw_hook)); ((void (*)(void))0x4067b0)();
        install_paddle_draw_hook.entry=NULL; REQUIRE(install_paddle_draw(live_paddle_draw));
    }
    paddle_input_thread=0; paddle_record(1);
}
static void paddle_observe(spx_observer *observer) {
    spx_observer o=*observer; particle_observe(&o); spx_observe_array(&o,"paddle");
    for (uint32_t i=0;i<paddle_count;++i) {
        paddle_snapshot *r=&paddle_records[i]; spx_observe_object(&o,NULL);
        spx_observe_u64(&o,"operation",r->operation); spx_observe_u32s(&o,"fields",r->fields,19); spx_observe_u64(&o,"pixels",r->pixels); spx_observe_end(&o);
    }
    spx_observe_end(&o); *observer=o;
}
static void paddle_diagnose(spx_observer *observer) {
    particle_diagnose(observer); spx_observe_u32s(observer,"selected_paddle",paddle_entries,2);
}
static void paddle_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT"); if (!path) return; FILE *out=fopen(path,"wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out); paddle_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o=spx_observe_begin(out); paddle_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL paddle_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!particle_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { paddle_report(); return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
    /* The parent scopes environment inputs around this same entry. Transfer
     * that scope to the selection wrapper while retaining all input observers. */
    REQUIRE(spx_fixture_restore_entry(&install_paddle_input_draw_hook)); install_paddle_input_draw_hook.entry=NULL;
    REQUIRE(install_paddle_move(live_paddle_move)); REQUIRE(install_paddle_draw(live_paddle_draw));
    return TRUE;
}
#ifndef PADDLE_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return paddle_main(instance,reason,reserved); }
#endif
