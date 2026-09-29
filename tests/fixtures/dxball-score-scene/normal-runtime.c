/* Keep the real scene dispatcher, CRT and graphics consumers in the game. */
#define SCORES_NORMAL_LIBRARY_ONLY 1
#include "scores-normal-runtime.c"
#include "screen-runtime.h"
static score_screen screen={.menu=&menu,.scores=&scores_live};
static uint32_t screen_entries[6],screen_depth,screen_count,screen_calls[64][25],screen_ticks[64];
static unsigned char screen_names[64][40],screen_records[64][660];
void screen_enter(unsigned operation) { REQUIRE(operation<6); ++screen_entries[operation]; }
#include "screen-native.h"
#define SCREEN_PUSH() screen_to_native()
#define SCREEN_PULL() screen_from_native()
#include "screen-common.h"
uint32_t screen_measure(void *unused,font_state *s,uint32_t length,font_bytes *bytes) {
    (void)unused; REQUIRE(s==&font); SCREEN_PUSH(); uint32_t result=native_font_measure(length,bytes->data); SCREEN_PULL(); return result;
}
void screen_load_scores(void *unused,scores_state *s) {
    (void)unused; REQUIRE(s==&scores_live); SCREEN_PUSH(); live_scores_load(); SCREEN_PULL();
}
uint32_t screen_insert_score(void *unused,scores_state *s,scores_name *name,uint32_t value) {
    (void)unused; REQUIRE(s==&scores_live); SCREEN_PUSH(); uint32_t result=live_scores_insert(name->text,value); SCREEN_PULL(); return result;
}
void screen_damage(void *unused,score_screen *s,font_rect *rectangle) {
    (void)unused; REQUIRE(s==&screen); SCREEN_PUSH(); ((void (*)(font_rect))0x401200)(*rectangle); SCREEN_PULL();
}
static void screen_record(unsigned operation,uint32_t argument) {
    if (screen_count==64) return;
    screen_from_native(); uint32_t index=screen_count++,*row=screen_calls[index];
    uint32_t values[]={operation,argument,menu.score,screen.length,screen.blink,screen.entering,screen.show_table,screen.highlight,screen.shift,
        scene.presentation_mode,scene.mouse_x,scene.mouse_y,scene.cursor_x,scene.cursor_y,scene.mouse_buttons,
        flow.scene,flow.transition_pending,flow.next_scene,!!scores_live.file};
    memcpy(row,values,sizeof(values)); screen_ticks[index]=screen.last_tick;
    uint64_t hashes[]={title_surface_hash(surface_address(title.primary)),title_surface_hash(surface_address(title.back)),
        hash_bytes(UINT64_C(14695981039346656037),(const unsigned char *)0x42c148,2048)};
    for (unsigned i=0;i<3;++i) { row[19+2*i]=(uint32_t)hashes[i]; row[20+2*i]=(uint32_t)(hashes[i]>>32); }
    memcpy(screen_names[index],screen.name,40); memcpy(screen_records[index],scores_live.entries,660);
}
#define LIVE_SCREEN(name,operation,address,parameters,arguments,call,argument) \
static void live_screen_##name parameters { \
    unsigned outer=!screen_depth++; \
    if (source_side) { screen_from_native(); fixture_screen_##name call; screen_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_screen_##name##_hook)); \
        ((void (*) parameters)(uintptr_t)address) arguments; \
        install_screen_##name##_hook.entry=NULL; REQUIRE(install_screen_##name((void (*)(void))live_screen_##name)); } \
    --screen_depth; if (outer) screen_record(operation,argument); \
}
LIVE_SCREEN(enter,0,0x409410,(void),(),(&screen),0)
LIVE_SCREEN(redraw,1,0x409510,(void),(),(&screen),0)
LIVE_SCREEN(update,2,0x4096a0,(void),(),(&screen),0)
LIVE_SCREEN(key,3,0x4098e0,(uint32_t key),(key),(&screen,key),key)
LIVE_SCREEN(draw_table,4,0x409900,(void),(),(&screen),0)
LIVE_SCREEN(edit,5,0x409f80,(uint32_t key),(key),(&screen,key),key)
static void screen_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT"); if (!path) return;
    FILE *out=fopen(path,"wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out); scores_observe(&o); spx_observe_array(&o,"score_screen");
    for (uint32_t i=0;i<screen_count;++i) {
        spx_observe_object(&o,NULL); spx_observe_u32s(&o,"call",screen_calls[i],25);
        spx_observe_bytes(&o,"name",screen_names[i],40); spx_observe_bytes(&o,"records",screen_records[i],660); spx_observe_end(&o);
    }
    spx_observe_end(&o); REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o=spx_observe_begin(out);
    scores_diagnose(&o); spx_observe_u32s(&o,"selected_score_screen",screen_entries,6);
    spx_observe_u32s(&o,"score_screen_clock",screen_ticks,screen_count);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL screen_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!scores_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { screen_report(); return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
#define SCREEN_INSTALL(name) REQUIRE(install_screen_##name((void (*)(void))live_screen_##name));
    SCREEN_INSTALL(enter) SCREEN_INSTALL(redraw) SCREEN_INSTALL(update) SCREEN_INSTALL(key) SCREEN_INSTALL(draw_table) SCREEN_INSTALL(edit)
    return TRUE;
}
#ifndef SCREEN_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    return screen_main(instance,reason,reserved);
}
#endif
