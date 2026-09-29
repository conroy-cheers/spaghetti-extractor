/* Actual game objects/services, extending the established live metric adapter. */
#define DllMain metrics_DllMain
#define report metrics_report
#include "metrics-normal-runtime.c"
#undef report
#undef DllMain
#include "drawing-runtime.h"

static uint32_t drawing_entries[3], graphics_entries[6], graphics[128][6], graphics_count, graphics_depth;
/* Observation identities follow externally observed selections. Transport can
 * inspect extra temporary objects while implementing a different C call graph. */
static uint32_t observed_surfaces[CAPACITY], observed_surface_count;
static uint32_t observed_surface(uint32_t address) {
    if (!address) return 0;
    for (uint32_t i=0;i<observed_surface_count;++i) if (observed_surfaces[i]==address) return i+1;
    REQUIRE(observed_surface_count<CAPACITY);
    observed_surfaces[observed_surface_count++]=address; return observed_surface_count;
}
void drawing_enter(unsigned operation) { REQUIRE(operation < 3); ++drawing_entries[operation]; }
uint32_t font_service_find(void *unused,font_state *s,uint32_t character) {
    (void)unused; REQUIRE(s==&font); push(); uint32_t result=native_font_find(character); pull(); return result;
}
uint32_t font_service_measure(void *unused,font_state *s,uint32_t length,font_bytes *text) {
    (void)unused; REQUIRE(s==&font); push(); uint32_t result=native_font_measure(length,text->data); pull(); return result;
}
void font_service_blit(void *unused,font_state *s,font_rect *destination,font_surface *surface,font_rect *rectangle) {
    (void)unused; REQUIRE(s==&font); push(); uint32_t address=surface_address(s->destination);
    uint32_t *table=word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,font_rect *,uint32_t,font_rect *,uint32_t,void *))(uintptr_t)table[5])
        (address,destination,surface_address(surface),rectangle,0x01008000,NULL);
    pull();
}
uint32_t drawing_blit_fast(void *unused,font_state *s,font_sprite *sprite,uint32_t x,uint32_t y,uint32_t flags) {
    (void)unused; REQUIRE(s==&font); push();
    uint32_t destination=surface_address(s->destination), object=sprite_address(sprite);
    uint32_t *table=word(*word(destination));
    uint32_t result=((uint32_t (WINAPI *)(uint32_t,uint32_t,uint32_t,uint32_t,font_rect *,uint32_t))(uintptr_t)table[7])
        (destination,x,y,*word(object),(font_rect *)(uintptr_t)(object+20),flags);
    pull(); return result;
}
static void graphics_record(uint32_t operation,uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t result) {
    REQUIRE(graphics_depth); --graphics_depth; ++graphics_entries[operation];
    if (graphics_depth || graphics_count>=128) return;
    uint32_t *row=graphics[graphics_count++];row[0]=operation;row[1]=a;row[2]=b;row[3]=c;row[4]=d;row[5]=result;
}
static void live_destination(uint32_t address) {
    ++graphics_depth; pull(); uint32_t id=observed_surface(address);
    if (source_side) { fixture_sprite_destination(&font,surface_view(address)); push(); }
    else {
        REQUIRE(spx_fixture_restore_entry(&install_sprite_destination_hook));
        ((void (*)(uint32_t))(uintptr_t)0x40bd60)(address);
        install_sprite_destination_hook.entry=NULL;REQUIRE(install_sprite_destination((void (*)(void))live_destination));
    }
    graphics_record(0,id,0,0,0,0);
}
#define DRAW_WRAPPER(name,operation,address) \
static uint32_t live_##name(uint32_t slot,uint32_t x,uint32_t y) { \
    ++graphics_depth;uint32_t result; \
    if (source_side) { pull(); result=fixture_sprite_##name(&font,slot,x,y);push(); } \
    else { \
        REQUIRE(spx_fixture_restore_entry(&install_sprite_##name##_hook)); \
        result=((uint32_t (*)(uint32_t,uint32_t,uint32_t))(uintptr_t)address)(slot,x,y); \
        install_sprite_##name##_hook.entry=NULL;REQUIRE(install_sprite_##name((void (*)(void))live_##name)); \
    } \
    graphics_record(operation,slot,x,y,0,result);return result; \
}
DRAW_WRAPPER(transparent,1,0x40bd90)
DRAW_WRAPPER(opaque,2,0x40bdd0)
static uint32_t live_glyph(uint32_t character,uint32_t x,uint32_t y) {
    ++graphics_depth;uint32_t result;
    if (source_side) { pull();result=fixture_font_glyph(&font,character,x,y);push(); }
    else {
        REQUIRE(spx_fixture_restore_entry(&install_font_glyph_hook));
        result=((uint32_t (*)(uint32_t,uint32_t,uint32_t))(uintptr_t)0x40c5a0)(character,x,y);
        install_font_glyph_hook.entry=NULL;REQUIRE(install_font_glyph((void (*)(void))live_glyph));
    }
    graphics_record(3,character,x,y,0,result);return result;
}
#define TEXT_WRAPPER(name,operation,address) \
static uint32_t live_##name(uint32_t x,uint32_t y,uint32_t length,const unsigned char *text) { \
    ++graphics_depth;uint32_t result; \
    if (source_side) { font_bytes bytes={text};pull();result=fixture_font_##name(&font,x,y,length,&bytes);push(); } \
    else { \
        REQUIRE(spx_fixture_restore_entry(&install_font_##name##_hook)); \
        result=((uint32_t (*)(uint32_t,uint32_t,uint32_t,const unsigned char *))(uintptr_t)address)(x,y,length,text); \
        install_font_##name##_hook.entry=NULL;REQUIRE(install_font_##name((void (*)(void))live_##name)); \
    } \
    graphics_record(operation,x,y,length,0,result);return result; \
}
TEXT_WRAPPER(line,4,0x40c6b0)
TEXT_WRAPPER(center,5,0x40c720)

static void graphics_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT");if (!path)return;
    FILE *out=fopen(path,"wb");REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side?"source":"original");
    spx_observer o=spx_observe_begin(out);spx_observe_array(&o,"metrics");
    for(uint32_t i=0;i<call_count;++i) {
        spx_observe_object(&o,NULL);spx_observe_u32s(&o,"values",calls[i],5);
        spx_observe_bytes(&o,"text_prefix",texts[i],text_lengths[i]);spx_observe_end(&o);
    }
    spx_observe_end(&o);spx_observe_array(&o,"graphics");
    for(uint32_t i=0;i<graphics_count;++i)spx_observe_u32s(&o,NULL,graphics[i],6);
    spx_observe_end(&o);REQUIRE(spx_observe_finish(&o));fputs(",\"diagnostics\":",out);o=spx_observe_begin(out);
    spx_observe_u32s(&o,"selected_drawing",drawing_entries,3);spx_observe_u32s(&o,"selected_font",selected,6);
    spx_observe_u32s(&o,"selected_cleanup",cleanup_entries,3);spx_observe_u32s(&o,"native_graphics_calls",graphics_entries,6);
    REQUIRE(spx_observe_finish(&o));fputs("}\n",out);fclose(out);
}
static BOOL drawing_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!metrics_DllMain(instance,reason,reserved))return FALSE;
    if (reason==DLL_PROCESS_DETACH) { graphics_report();return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH)return TRUE;
    REQUIRE(install_sprite_destination((void (*)(void))live_destination));
    REQUIRE(install_sprite_transparent((void (*)(void))live_transparent));
    REQUIRE(install_sprite_opaque((void (*)(void))live_opaque));
    REQUIRE(install_font_glyph((void (*)(void))live_glyph));
    REQUIRE(install_font_line((void (*)(void))live_line));
    REQUIRE(install_font_center((void (*)(void))live_center));return TRUE;
}
#ifndef DRAWING_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    return drawing_main(instance,reason,reserved);
}
#endif
