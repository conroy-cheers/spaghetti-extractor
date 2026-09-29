/* Reuse the live board/scene objects, CRT and actual rendering/input services. */
#define BOARD_NORMAL_LIBRARY_ONLY 1
#include "board-normal-runtime.c"
#include "editor-runtime.h"
static board_editor editor={.menu=&menu,.boards=&board_live};
static uint32_t editor_entries[7],editor_depth,editor_count,editor_calls[32][22],editor_regions[32][125];
static unsigned char editor_bytes_after[32][20400];
void editor_enter(unsigned operation) { REQUIRE(operation<7); ++editor_entries[operation]; }
#define editor_boards board_live
static uint32_t editor_file_address(board_file *file) { return file ? file->address : 0; }
static board_file *editor_file_view(uint32_t address) { return board_file_view(address); }
#include "editor-native.h"
#define EDITOR_PUSH() editor_to_native()
#define EDITOR_PULL() editor_from_native()
#include "editor-common.h"
#define EDITOR_BEGIN() (void)unused; REQUIRE(s==&editor); EDITOR_PUSH()
#define EDITOR_END() EDITOR_PULL()
#define EDITOR_BOARD_COPY(name) \
void editor_##name##_board(void *unused,board_set *s,uint32_t index) { \
    (void)unused; REQUIRE(s==&board_live); EDITOR_PUSH(); live_board_##name(index); EDITOR_PULL(); \
}
EDITOR_BOARD_COPY(select) EDITOR_BOARD_COPY(store)
#define EDITOR_BOARD_IO(name) \
void editor_##name##_boards(void *unused,board_set *s,board_name *name) { \
    (void)unused; REQUIRE(s==&board_live); EDITOR_PUSH(); live_board_##name(name->text); EDITOR_PULL(); \
}
EDITOR_BOARD_IO(load) EDITOR_BOARD_IO(save)
uint32_t editor_sprite_id(void *unused,uint32_t kind) {
    (void)unused; EDITOR_PUSH(); uint32_t result=live_board_sprite(kind); EDITOR_PULL(); return result;
}
void editor_sprite(void *unused,menu_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    (void)unused; REQUIRE(s==&menu); EDITOR_PUSH(); (void)live_opaque(slot,x,y); EDITOR_PULL();
}
void editor_reset_regions(void *unused,board_editor *s,uint32_t count) {
    EDITOR_BEGIN(); ((void (*)(uint32_t))0x40d520)(count); EDITOR_END();
}
void editor_define_region(void *unused,board_editor *s,uint32_t index,font_rect *rectangle) {
    EDITOR_BEGIN(); ((void (*)(uint32_t,font_rect))0x40d550)(index,*rectangle); EDITOR_END();
}
uint32_t editor_hit_region(void *unused,board_editor *s,uint32_t x,uint32_t y) {
    EDITOR_BEGIN(); uint32_t result=((uint32_t (*)(uint32_t,uint32_t))0x40d590)(x,y); EDITOR_END(); return result;
}
void editor_cursor(void *unused,board_editor *s,uint32_t slot,uint32_t x,uint32_t y) {
    EDITOR_BEGIN(); ((void (*)(uint32_t,uint32_t,uint32_t))0x401080)(slot,x,y); EDITOR_END();
}
void editor_draw_board(void *unused,board_editor *s,uint32_t mode) {
    EDITOR_BEGIN(); ((void (*)(uint32_t))0x405a90)(mode); EDITOR_END();
}
void editor_draw_cell(void *unused,board_editor *s,uint32_t column,uint32_t row,uint32_t mode) {
    EDITOR_BEGIN(); ((void (*)(uint32_t,uint32_t,uint32_t))0x405ad0)(column,row,mode); EDITOR_END();
}
static void editor_record(unsigned operation,uint32_t argument) {
    REQUIRE(editor_count<32); editor_from_native(); uint32_t index=editor_count++,*row=editor_calls[index];
    uint32_t values[]={operation,argument,editor.selected_tile,editor.index,editor.region_count,!!board_live.file,
        menu.input_ready,scene.presentation_mode,scene.mouse_x,scene.mouse_y,scene.cursor_x,scene.cursor_y,
        scene.mouse_buttons,flow.scene,flow.transition_pending,flow.next_scene};
    memcpy(row,values,sizeof(values));
    uint64_t hashes[]={title_surface_hash(surface_address(title.primary)),title_surface_hash(surface_address(title.back)),
        hash_bytes(UINT64_C(14695981039346656037),(const unsigned char *)0x42c148,2048)};
    for (unsigned i=0;i<3;++i) { row[16+2*i]=(uint32_t)hashes[i]; row[17+2*i]=(uint32_t)(hashes[i]>>32); }
    memcpy(editor_regions[index],editor.regions,sizeof(editor.regions));
    memcpy(editor_bytes_after[index],&board_live.current,400); memcpy(editor_bytes_after[index]+400,board_live.saved,20000);
}
/* Nested palette/status calls may be direct C calls. Compare complete outer
 * operations on both sides, with unchanged lower-level board/pixel observations. */
#define LIVE_EDITOR(name,operation,address,parameters,arguments,call,argument) \
static void live_editor_##name parameters { \
    unsigned outer=!editor_depth++; \
    if (source_side) { editor_from_native(); fixture_editor_##name call; editor_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_editor_##name##_hook)); \
        ((void (*) parameters)(uintptr_t)address) arguments; \
        install_editor_##name##_hook.entry=NULL; REQUIRE(install_editor_##name((void (*)(void))live_editor_##name)); } \
    --editor_depth; if (outer) editor_record(operation,argument); \
}
LIVE_EDITOR(enter,0,0x403570,(void),(),(&editor),0)
LIVE_EDITOR(redraw,1,0x403660,(void),(),(&editor),0)
LIVE_EDITOR(update,2,0x403750,(void),(),(&editor),0)
LIVE_EDITOR(key,3,0x403a00,(uint32_t key),(key),(&editor,key),key)
LIVE_EDITOR(draw_palette,4,0x403b60,(void),(),(&editor),0)
LIVE_EDITOR(draw_status,5,0x403bd0,(void),(),(&editor),0)
LIVE_EDITOR(leave,6,0x403f30,(uint32_t reason),(reason),(&editor,reason),reason)
static void editor_observe(spx_observer *o) {
    board_observe(o); spx_observe_array(o,"editor");
    for (uint32_t i=0;i<editor_count;++i) {
        spx_observe_object(o,NULL); spx_observe_u32s(o,"call",editor_calls[i],22);
        spx_observe_u32s(o,"regions",editor_regions[i],125); spx_observe_bytes(o,"boards",editor_bytes_after[i],20400);
        spx_observe_end(o);
    }
    spx_observe_end(o);
}
static void editor_diagnose(spx_observer *o) {
    board_diagnose(o); spx_observe_u32s(o,"selected_editor",editor_entries,7);
}
static void editor_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT"); if (!path) return;
    FILE *out=fopen(path,"wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out); editor_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o=spx_observe_begin(out); editor_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL editor_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!board_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { editor_report(); return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
#define EDITOR_INSTALL(name) REQUIRE(install_editor_##name((void (*)(void))live_editor_##name));
    EDITOR_INSTALL(enter) EDITOR_INSTALL(redraw) EDITOR_INSTALL(update) EDITOR_INSTALL(key)
    EDITOR_INSTALL(draw_palette) EDITOR_INSTALL(draw_status) EDITOR_INSTALL(leave)
    return TRUE;
}
#ifndef EDITOR_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    return editor_main(instance,reason,reserved);
}
#endif
