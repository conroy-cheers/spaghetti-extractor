/* Scene orchestration over the preceding shared live object maps. */
#define ROUND_NORMAL_LIBRARY_ONLY 1
#include "round-normal-runtime.c"
#include "game-runtime.h"
static game_scene_state game={.progression=&progress,.damage=&damage};
static uint32_t game_entries[3],game_depth,game_count;
void game_enter(unsigned operation) { REQUIRE(operation<3); ++game_entries[operation]; }
static void game_to_native(void) { progress_to_native(); memcpy((void *)0x416068,&game.stereo_direction,8); }
static void game_from_native(void) { progress_from_native(); memcpy(&game.stereo_direction,(void *)0x416068,8); }
void game_exit(game_scene_state *s) { REQUIRE(s==&game); game_to_native(); game_from_native(); }
#define GAME_BEGIN() (void)unused; REQUIRE(s==&game); game_to_native()
#define GAME_END() game_from_native()
#define GAME_ZERO(name,address) void game_##name(void *unused,game_scene_state *s) { GAME_BEGIN(); ((void (*)(void))address)(); GAME_END(); }
GAME_ZERO(load_board,0x405a70) GAME_ZERO(restart,0x408a00) GAME_ZERO(reset_damage,0x401000)
GAME_ZERO(draw_score,0x408770) GAME_ZERO(redraw_scene,0x40aad0) GAME_ZERO(stop_music,0x402200)
#undef GAME_ZERO
#define GAME_ONE(name,address) void game_##name(void *unused,game_scene_state *s,uint32_t n) { GAME_BEGIN(); ((void (*)(uint32_t))address)(n); GAME_END(); }
GAME_ONE(select_bank,0x40bd70) GAME_ONE(select_font,0x40bd80) GAME_ONE(draw_board,0x405a90)
#undef GAME_ONE
#define GAME_SURFACE(name,address) void game_##name(void *unused,game_scene_state *s,font_surface *surface) { GAME_BEGIN(); ((void (*)(uint32_t))address)(surface_address(surface)); GAME_END(); }
GAME_SURFACE(damage_background,0x401630) GAME_SURFACE(damage_destination,0x401640)
#undef GAME_SURFACE
void game_clear(void *unused,game_scene_state *s,font_surface *surface,uint32_t color) { GAME_BEGIN(); ((void (*)(uint32_t,uint32_t))0x402710)(surface_address(surface),color); GAME_END(); }
void game_image(void *unused,game_scene_state *s,font_surface *surface,asset_name *name,uint32_t palette,uint32_t x,uint32_t y) {
    GAME_BEGIN(); ((void (*)(uint32_t,const char *,uint32_t,uint32_t,uint32_t))0x402490)(surface_address(surface),name->text,palette,x,y); GAME_END();
}
void game_load_bank(void *unused,game_scene_state *s,uint32_t bank,uint32_t mode,asset_name *name) { GAME_BEGIN(); ((void (*)(uint32_t,uint32_t,const char *))0x40c080)(bank,mode,name->text); GAME_END(); }
void game_load_sound(void *unused,game_scene_state *s,uint32_t slot,asset_name *name) { GAME_BEGIN(); ((void (*)(uint32_t,const char *))0x403000)(slot,name->text); GAME_END(); }
void game_play_music(void *unused,game_scene_state *s,asset_name *name,uint32_t loop) { GAME_BEGIN(); ((void (*)(const char *,uint32_t))0x402100)(name->text,loop); GAME_END(); }
void game_create_sprite(void *unused,game_scene_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e) { GAME_BEGIN(); ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))0x40be10)(a,b,c,d,e); GAME_END(); }
void game_fade(void *unused,game_scene_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e) { GAME_BEGIN(); ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))0x402770)(a,b,c,d,e); GAME_END(); }
void game_center(void *unused,game_scene_state *s,uint32_t x,uint32_t y,uint32_t length,font_bytes *bytes) { GAME_BEGIN(); ((void (*)(uint32_t,uint32_t,uint32_t,const unsigned char *))0x40c720)(x,y,length,bytes->data); GAME_END(); }
uint32_t game_random(void *unused,game_scene_state *s,uint32_t limit) { GAME_BEGIN(); uint32_t result=((uint32_t (*)(uint32_t))0x40ae20)(limit); GAME_END(); return result; }
void game_blit(void *unused,game_scene_state *s,font_surface *destination,font_rect *dr,font_surface *source,font_rect *sr,uint32_t flags) {
    GAME_BEGIN(); uint32_t address=surface_address(destination),*table=word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,font_rect *,uint32_t,font_rect *,uint32_t,void *))(uintptr_t)table[5])(address,dr,surface_address(source),sr,flags,NULL); GAME_END();
}
#undef GAME_BEGIN
#undef GAME_END
typedef struct { round_snapshot shared; uint32_t fields[12],banks[21]; uint64_t stereo_bits; } game_snapshot;
static struct { uint32_t operation,key; game_snapshot before,after; } game_records[32];
static void game_capture(game_snapshot *r) {
    game_from_native(); round_capture(&r->shared);
    uint32_t fields[]={play.paused,paddle.phase,paddle.last_tick,menu.input_ready,damage.capability,scene.presentation_mode,
        observed_surface(surface_address(scene.flip)),font.bank,title.font->objects->current_bank,motion.sticky,play.gun,motion.paddle_width};
    _Static_assert(sizeof(fields)==sizeof(r->fields),"game fields"); memcpy(r->fields,fields,sizeof(fields));
    for (unsigned i=0;i<3;++i) { r->banks[i*7]=title.font->objects->banks[i].count; memcpy(r->banks+i*7+1,title.font->objects->banks[i].retained,24); }
    memcpy(&r->stereo_bits,&game.stereo_direction,8);
}
static void game_before(uint32_t operation,uint32_t key) {
    if (++game_depth!=1) return;
    REQUIRE(game_count<32); game_records[game_count].operation=operation; game_records[game_count].key=key; game_capture(&game_records[game_count].before);
}
static void game_after(void) { if (--game_depth) return; game_capture(&game_records[game_count++].after); }
#define GAME_ENTRY(name,operation,address) static void live_game_##name(void) { \
    game_before(operation,0); game_from_native(); \
    if (source_side) { fixture_game_##name(&game); game_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_game_##name##_hook)); ((void (*)(void))address)(); \
        install_game_##name##_hook.entry=NULL; REQUIRE(install_game_##name(live_game_##name)); } game_after(); }
GAME_ENTRY(enter,0,0x404120) GAME_ENTRY(redraw,1,0x4043d0)
#undef GAME_ENTRY
static void live_game_key(uint32_t key) {
    game_before(2,key); game_from_native();
    if (source_side) { fixture_game_key(&game,key); game_to_native(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_game_key_hook)); ((void (*)(uint32_t))0x404ad0)(key);
        install_game_key_hook.entry=NULL; REQUIRE(install_game_key((void (*)(void))live_game_key)); }
    game_after();
}
static void game_observe_state(spx_observer *o,const char *name,const game_snapshot *r) {
    spx_observe_object(o,name); round_observe_state(o,"shared",&r->shared); spx_observe_u32s(o,"fields",r->fields,12);
    spx_observe_u32s(o,"banks",r->banks,21); spx_observe_u64(o,"stereo_bits",r->stereo_bits); spx_observe_end(o);
}
static void game_observe(spx_observer *o) {
    round_observe(o); spx_observe_array(o,"game_scene");
    for (uint32_t i=0;i<game_count;++i) {
        spx_observe_object(o,NULL); spx_observe_u64(o,"operation",game_records[i].operation); spx_observe_u64(o,"key",game_records[i].key);
        game_observe_state(o,"before",&game_records[i].before); game_observe_state(o,"after",&game_records[i].after); spx_observe_end(o);
    }
    spx_observe_end(o);
}
static void game_diagnose(spx_observer *o) {
    round_diagnose(o); spx_observe_u32s(o,"selected_game_scene",game_entries,3);
}
static void game_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT"); if (!path) return; FILE *out=fopen(path,"wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out); game_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o=spx_observe_begin(out); game_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL game_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!round_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { game_report(); return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
    REQUIRE(install_game_enter(live_game_enter)); REQUIRE(install_game_redraw(live_game_redraw)); REQUIRE(install_game_key((void (*)(void))live_game_key)); return TRUE;
}

#ifndef GAME_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return game_main(instance,reason,reserved); }
#endif
