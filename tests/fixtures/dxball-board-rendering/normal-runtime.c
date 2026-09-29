/* Use the editor's actual shared objects and native platform services. */
#define EDITOR_NORMAL_LIBRARY_ONLY 1
#include "editor-normal-runtime.c"
#include "render-runtime.h"
static board_renderer renderer={.menu=&menu,.boards=&board_live};
static uint32_t render_entries[2],render_depth,render_count,render_calls[64][11];
static unsigned char render_boards_after[64][400];
void render_enter(unsigned operation) { REQUIRE(operation<2); ++render_entries[operation]; }
void render_sprite_destination(void *unused,scene_state *s,font_surface *surface) {
    EDITOR_PUSH(); scene_sprite_destination(unused,s,surface); EDITOR_PULL();
}
void render_sprite(void *unused,menu_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    editor_sprite(unused,s,slot,x,y);
}
void render_blit_fast(void *unused,menu_state *s,font_surface *destination,uint32_t x,uint32_t y,
                      font_surface *source,font_rect *rectangle,uint32_t flags) {
    EDITOR_PUSH(); menu_blit_fast(unused,s,destination,x,y,source,rectangle,flags); EDITOR_PULL();
}
void render_damage(void *unused,menu_state *s,font_rect *rectangle) {
    EDITOR_PUSH(); menu_damage(unused,s,rectangle); EDITOR_PULL();
}
static void render_record(uint32_t operation,uint32_t column,uint32_t row,uint32_t mode) {
    REQUIRE(render_count<64); editor_from_native(); uint32_t index=render_count++,*record=render_calls[index];
    uint32_t values[]={operation,column,row,mode,flow.scene}; memcpy(record,values,sizeof(values));
    uint64_t hashes[]={title_surface_hash(surface_address(font.destination)),title_surface_hash(surface_address(title.back)),
        hash_bytes(UINT64_C(14695981039346656037),(const unsigned char *)0x42c148,2048)};
    for (unsigned i=0;i<3;++i) { record[5+2*i]=(uint32_t)hashes[i]; record[6+2*i]=(uint32_t)(hashes[i]>>32); }
    memcpy(render_boards_after[index],&board_live.current,400);
}
static void live_render_draw(uint32_t mode) {
    unsigned outer=!render_depth++;
    if (source_side) { editor_from_native(); fixture_render_draw(&renderer,mode); editor_to_native(); }
    else {
        REQUIRE(spx_fixture_restore_entry(&install_render_draw_hook)); ((void (*)(uint32_t))0x405a90)(mode);
        install_render_draw_hook.entry=NULL; REQUIRE(install_render_draw((void (*)(void))live_render_draw));
    }
    --render_depth; if (outer) render_record(0,0,0,mode);
}
static void live_render_cell(uint32_t column,uint32_t row,uint32_t mode) {
    REQUIRE(column<20 && row<20); unsigned outer=!render_depth++;
    if (source_side) { editor_from_native(); fixture_render_cell(&renderer,column,row,mode); editor_to_native(); }
    else {
        REQUIRE(spx_fixture_restore_entry(&install_render_cell_hook)); ((void (*)(uint32_t,uint32_t,uint32_t))0x405ad0)(column,row,mode);
        install_render_cell_hook.entry=NULL; REQUIRE(install_render_cell((void (*)(void))live_render_cell));
    }
    --render_depth; if (outer) render_record(1,column,row,mode);
}
static void render_observe(spx_observer *o) {
    editor_observe(o); spx_observe_array(o,"rendering");
    for (uint32_t i=0;i<render_count;++i) {
        spx_observe_object(o,NULL); spx_observe_u32s(o,"call",render_calls[i],11);
        spx_observe_bytes(o,"board",render_boards_after[i],400); spx_observe_end(o);
    }
    spx_observe_end(o);
}
static void render_diagnose(spx_observer *o) {
    editor_diagnose(o); spx_observe_u32s(o,"selected_rendering",render_entries,2);
}
static void render_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT"); if (!path) return;
    FILE *out=fopen(path,"wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out); render_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o=spx_observe_begin(out);
    render_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL render_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!editor_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { render_report(); return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
    REQUIRE(install_render_draw((void (*)(void))live_render_draw));
    REQUIRE(install_render_cell((void (*)(void))live_render_cell));
    return TRUE;
}
#ifndef RENDER_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return render_main(instance,reason,reserved); }
#endif
