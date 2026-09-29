#define MATH_NORMAL_LIBRARY_ONLY 1
#include "math-normal-runtime.c"
#include "raster-runtime.h"
static uint32_t raster_selected[2],raster_calls[4096][7],raster_count;
static spx_wine_surface_desc raster_descriptor;
void raster_enter(unsigned operation) {
    REQUIRE(operation<2);++raster_selected[operation];memset(&raster_descriptor,0,sizeof(raster_descriptor));
    raster_descriptor.words[0]=108;raster_descriptor.words[1]=14;
}
static uint32_t raster_identity(uint32_t raw) {
    /* Boundary identities come from named program roots. The existing view
     * cache's encounter order is allowed to differ between implementations. */
    static const uint32_t roots[]={0x4349ac,0x4349b4,0x4349b0,0x41c728};
    REQUIRE(raw);
    for(unsigned i=0;i<4;++i)if(*word(roots[i])==raw)return i+1;
    fprintf(stderr,"raster boundary: surface needs an explicit caller input binding\n");fflush(NULL);ExitProcess(86);return 0;
}
static spx_wine_object *raster_surface(font_surface *s) {
    REQUIRE(s);uint32_t raw=surface_address(s);
    return spx_wine_bind_surface(wine_environment,(void *)(uintptr_t)raw,raster_identity(raw));
}
static void raster_view(pcx_view *view) {
    view->width=raster_descriptor.words[3];view->height=raster_descriptor.words[2];
    view->image.pitch=raster_descriptor.words[4];view->image.pixels=raster_descriptor.pixels;
}
uint32_t raster_describe(void *unused,font_surface *s,pcx_view *view) {
    (void)unused;spx_wine_call c={0};c.api=SPX_DD_DESCRIBE;c.receiver=raster_surface(s);c.output=&raster_descriptor;
    uint32_t result=spx_wine_candidate_call(wine_environment,c);raster_view(view);return result;
}
uint32_t raster_lock(void *unused,font_surface *s,pcx_view *view) {
    (void)unused;spx_wine_call c={0};c.api=SPX_DD_LOCK;c.receiver=raster_surface(s);c.output=&raster_descriptor;
    uint32_t result=spx_wine_candidate_call(wine_environment,c);raster_view(view);return result;
}
uint32_t raster_unlock(void *unused,font_surface *s) {
    (void)unused;spx_wine_call c={0};c.api=SPX_DD_UNLOCK;c.receiver=raster_surface(s);return spx_wine_candidate_call(wine_environment,c);
}
uint32_t raster_fill(void *unused,font_surface *s,font_rect *rect,uint32_t size,uint32_t flags,uint32_t color) {
    (void)unused;spx_wine_rect r={(int32_t)font_signed(rect->left),(int32_t)font_signed(rect->top),
        (int32_t)font_signed(rect->right),(int32_t)font_signed(rect->bottom)};
    spx_wine_blt b={.destination=&r,.flags=flags,.effects_size=size,.fill_color=color};
    spx_wine_call c={0};c.api=SPX_DD_BLT;c.receiver=raster_surface(s);c.input=&b;return spx_wine_candidate_call(wine_environment,c);
}
#define RASTER_BODY(n,op,address) static void live_raster_##n(uint32_t raw,uint32_t x1,uint32_t y1,uint32_t x2,uint32_t y2,uint32_t color) { \
    font_surface *s=surface_view(raw);REQUIRE(raster_count<4096);uint32_t row[]={op,raster_identity(raw),x1,y1,x2,y2,color};memcpy(raster_calls[raster_count++],row,sizeof(row)); \
    if(source_side) { fixture_raster_##n(s,x1,y1,x2,y2,color);REQUIRE(install_raster_##n##_intact()); } \
    else { spx_wine_object *proxy=raster_surface(s);REQUIRE(spx_fixture_restore_entry(&install_raster_##n##_hook)); \
        ((void (*)(void *,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))address)(proxy,x1,y1,x2,y2,color); \
        install_raster_##n##_hook.entry=NULL;REQUIRE(install_raster_##n((void (*)(void))live_raster_##n)); } }
RASTER_BODY(line,0,0x40d850) RASTER_BODY(fill,1,0x40d990)
#undef RASTER_BODY
static void raster_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT");if(!path)return;FILE *out=fopen(path,"wb");REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out);math_observe(&o);spx_observe_array(&o,"raster_policy");
    for(unsigned i=0;i<raster_count;++i)spx_observe_u32s(&o,NULL,raster_calls[i],7);
    spx_observe_end(&o);REQUIRE(spx_observe_finish(&o));fputs(",\"diagnostics\":",out);
    o=spx_observe_begin(out);math_diagnose(&o);spx_observe_u32s(&o,"selected_raster",raster_selected,2);
    REQUIRE(spx_observe_finish(&o));fputs("}\n",out);fclose(out);
    if(source_side)REQUIRE(raster_selected[0] && raster_selected[1]);
}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    if(!math_main(instance,reason,reserved))return FALSE;
    if(reason==DLL_PROCESS_DETACH) { raster_report();return TRUE; }
    if(reason!=DLL_PROCESS_ATTACH)return TRUE;
    REQUIRE(install_raster_line((void (*)(void))live_raster_line));REQUIRE(install_raster_fill((void (*)(void))live_raster_fill));return TRUE;
}
