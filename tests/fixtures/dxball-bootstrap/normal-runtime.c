/* Boundary adapters use the retained real callers and DirectDraw resources. */
#define PALETTE_NORMAL_LIBRARY_ONLY 1
#include "palette-normal-runtime.c"
#include "bootstrap-runtime.h"
static bootstrap_state bootstrap_live={&application,0};
static uint32_t bootstrap_selected[3],bootstrap_depth,bootstrap_count,bootstrap_calls[128][17],bootstrap_ticks[128];
void bootstrap_enter(unsigned op) { REQUIRE(op<3);++bootstrap_selected[op]; }
#define BOOTSTRAP_FIELDS(X) X(flow.first_frame,0x417a00) X(flow.scene,0x431fd0) X(flow.next_scene,0x431fc4) \
    X(flow.transition_pending,0x431fc8) X(flow.windowed,0x434998) X(flow.refresh_needed,0x4349a4) \
    X(title.fast,0x4349c8) X(scene.no_hardware,0x417a08) X(scene.refresh_ok,0x4349c0) X(bootstrap_live.last_refresh,0x4349c4)
static void bootstrap_push(void) {
#define PUT(field,address) *word(address)=field;
    BOOTSTRAP_FIELDS(PUT)
#undef PUT
    *word(0x4349a8)=shell_device_address(application.graphics);*word(0x4349b8)=shell_palette_address(application.palette);
    *word(0x4349ac)=surface_address(title.primary);*word(0x4349b4)=surface_address(title.back);*word(0x431fcc)=surface_address(flow.overlay);pcx_push();
}
static void bootstrap_pull(void) {
#define GET(field,address) field=*word(address);
    BOOTSTRAP_FIELDS(GET)
#undef GET
    application.graphics=shell_device_view(*word(0x4349a8));application.palette=shell_palette_view(*word(0x4349b8));
    title.primary=flow.primary=surface_view(*word(0x4349ac));title.back=flow.back=surface_view(*word(0x4349b4));flow.overlay=surface_view(*word(0x431fcc));pcx_pull();
}
#undef BOOTSTRAP_FIELDS
#define BOOTSTRAP_BEGIN() (void)u;REQUIRE(s==&bootstrap_live);bootstrap_push()
#define BOOTSTRAP_END() bootstrap_pull()
#define BOOTSTRAP_SERVICE0(n,address) void bootstrap_##n(void *u,bootstrap_state *s) { BOOTSTRAP_BEGIN();((void (*)(void))address)();BOOTSTRAP_END(); }
BOOTSTRAP_SERVICE0(scores_initialize,0x409bb0) BOOTSTRAP_SERVICE0(scores_load,0x409a30) BOOTSTRAP_SERVICE0(seed_random,0x40ae30)
#undef BOOTSTRAP_SERVICE0
void bootstrap_boards_load(void *u,bootstrap_state *s,asset_name *name) {
    BOOTSTRAP_BEGIN();((void (*)(const char *))0x403d50)(name->text);BOOTSTRAP_END();
}
void bootstrap_terminate(void *u,bootstrap_state *s,uint32_t code) {
    BOOTSTRAP_BEGIN();((void (*)(uint32_t))0x40e3d0)(code);abort();
}
uint32_t bootstrap_now(void *u,bootstrap_state *s) {
    BOOTSTRAP_BEGIN();uint32_t result=((uint32_t (*)(void))0x40db20)();BOOTSTRAP_END();return result;
}
uint32_t bootstrap_create_overlay(void *u,bootstrap_state *s,shell_device *device,display_surface *d) {
    BOOTSTRAP_BEGIN();uint32_t native[27]={0};native[0]=d->size;native[1]=d->flags;native[2]=d->height;native[3]=d->width;native[26]=d->caps;
    uint32_t address=shell_device_address(device),*table=word(*word(address));
    uint32_t result=((uint32_t (WINAPI *)(uint32_t,void *,uint32_t *,void *))(uintptr_t)table[6])(address,native,word(0x431fcc),NULL);
    BOOTSTRAP_END();return result;
}
uint32_t bootstrap_create_palette(void *u,bootstrap_state *s,shell_device *device,uint32_t flags) {
    BOOTSTRAP_BEGIN();uint32_t address=shell_device_address(device),*table=word(*word(address));
    uint32_t result=((uint32_t (WINAPI *)(uint32_t,uint32_t,void *,uint32_t *,void *))(uintptr_t)table[5])
        (address,flags,(void *)0x42c148,word(0x4349b8),NULL);BOOTSTRAP_END();return result;
}
void bootstrap_attach_palette(void *u,bootstrap_state *s,font_surface *surface,shell_palette *palette) {
    BOOTSTRAP_BEGIN();uint32_t address=surface_address(surface),*table=word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,uint32_t))(uintptr_t)table[31])(address,shell_palette_address(palette));BOOTSTRAP_END();
}
void bootstrap_vertical_blank(void *u,bootstrap_state *s,shell_device *device,uint32_t flags) {
    BOOTSTRAP_BEGIN();uint32_t address=shell_device_address(device),*table=word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,uint32_t,void *))(uintptr_t)table[22])(address,flags,NULL);BOOTSTRAP_END();
}
void bootstrap_fill(void *u,bootstrap_state *s,font_surface *surface,font_rect *rectangle,uint32_t size,uint32_t flags,uint32_t color) {
    BOOTSTRAP_BEGIN();uint32_t effects[25]={0};effects[0]=size;effects[20]=color;
    uint32_t address=surface_address(surface),*table=word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,font_rect *,uint32_t,void *,uint32_t,void *))(uintptr_t)table[5])
        (address,rectangle,0,NULL,flags,effects);BOOTSTRAP_END();
}
#undef BOOTSTRAP_BEGIN
#undef BOOTSTRAP_END
static void bootstrap_record(unsigned op,uint32_t surface,uint32_t color) {
    if(--bootstrap_depth)return;
    REQUIRE(bootstrap_count<128);bootstrap_pull();unsigned index=bootstrap_count++;
    uint64_t palette=palette_hash(),pixels=surface ? title_surface_hash(surface) : title_surface_hash(surface_address(title.primary));
    uint32_t values[]={op,color,flow.scene,flow.next_scene,flow.transition_pending,scene.refresh_ok,title.fast,scene.no_hardware,
        !!flow.overlay,!!application.palette,!!application.graphics,surface==surface_address(title.primary),surface==surface_address(title.back),
        (uint32_t)palette,(uint32_t)(palette>>32),(uint32_t)pixels,(uint32_t)(pixels>>32)};
    memcpy(bootstrap_calls[index],values,sizeof(values));bootstrap_ticks[index]=bootstrap_live.last_refresh;
}
#define BOOTSTRAP_LIVE0(n,op,address) static void live_bootstrap_##n(void) { \
    ++bootstrap_depth; \
    if(source_side) { bootstrap_pull();fixture_bootstrap_##n(&bootstrap_live);bootstrap_push();REQUIRE(install_bootstrap_##n##_intact()); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_bootstrap_##n##_hook));((void (*)(void))address)(); \
        install_bootstrap_##n##_hook.entry=NULL;REQUIRE(install_bootstrap_##n((void (*)(void))live_bootstrap_##n)); } \
    bootstrap_record(op,0,0); }
BOOTSTRAP_LIVE0(initialize,0,0x40ad10) BOOTSTRAP_LIVE0(palette,1,0x4022b0)
#undef BOOTSTRAP_LIVE0
static void live_bootstrap_clear(uint32_t surface,uint32_t color) {
    ++bootstrap_depth;
    if(source_side) { bootstrap_pull();fixture_bootstrap_clear(&bootstrap_live,surface_view(surface),color);bootstrap_push();REQUIRE(install_bootstrap_clear_intact()); }
    else { REQUIRE(spx_fixture_restore_entry(&install_bootstrap_clear_hook));((void (*)(uint32_t,uint32_t))0x402710)(surface,color);
        install_bootstrap_clear_hook.entry=NULL;REQUIRE(install_bootstrap_clear((void (*)(void))live_bootstrap_clear)); }
    bootstrap_record(2,surface,color);
}
static void bootstrap_observe(spx_observer *o) {
    palette_observe(o);spx_observe_array(o,"bootstrap");
    for(unsigned i=0;i<bootstrap_count;++i)spx_observe_u32s(o,NULL,bootstrap_calls[i],17);
    spx_observe_end(o);
}
static void bootstrap_diagnose(spx_observer *o) {
    palette_diagnose(o);spx_observe_u32s(o,"selected_bootstrap",bootstrap_selected,3);spx_observe_u32s(o,"bootstrap_clock",bootstrap_ticks,bootstrap_count);
}
static void bootstrap_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT");if(!path)return;FILE *out=fopen(path,"wb");REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out);bootstrap_observe(&o);
    REQUIRE(spx_observe_finish(&o));fputs(",\"diagnostics\":",out);o=spx_observe_begin(out);
    bootstrap_diagnose(&o);
    REQUIRE(spx_observe_finish(&o));fputs("}\n",out);fclose(out);if(source_side)REQUIRE(bootstrap_selected[0] && bootstrap_selected[2]);
}
static BOOL bootstrap_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if(!palette_main(instance,reason,reserved))return FALSE;
    if(reason==DLL_PROCESS_DETACH) { bootstrap_report();return TRUE; }
    if(reason!=DLL_PROCESS_ATTACH)return TRUE;
    REQUIRE(install_bootstrap_initialize((void (*)(void))live_bootstrap_initialize));
    REQUIRE(install_bootstrap_palette((void (*)(void))live_bootstrap_palette));
    return install_bootstrap_clear((void (*)(void))live_bootstrap_clear);
}
#ifndef BOOTSTRAP_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    return bootstrap_main(instance,reason,reserved);
}
#endif
