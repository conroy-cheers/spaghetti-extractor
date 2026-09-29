#ifndef DX_STANDALONE
#define PROGRESS_NATIVE0(name) static void native_connected_##name(void) { round_from_native(); progress_##name(NULL,&progress); round_to_native(); }
PROGRESS_NATIVE0(load_board) PROGRESS_NATIVE0(redraw) PROGRESS_NATIVE0(create_ball) PROGRESS_NATIVE0(reset_damage)
#undef PROGRESS_NATIVE0
#define PROGRESS_NATIVE(name,params,...) static void native_connected_##name params { round_from_native(); progress_##name(NULL,&progress,__VA_ARGS__); round_to_native(); }
PROGRESS_NATIVE(stop_sound,(uint32_t n),n) PROGRESS_NATIVE(play_sound,(uint32_t a,uint32_t b,uint32_t c,uint32_t d),a,b,c,d)
PROGRESS_NATIVE(sprite,(uint32_t a,uint32_t b,uint32_t c),a,b,c) PROGRESS_NATIVE(wait,(uint32_t n),n)
PROGRESS_NATIVE(damage,(font_rect bounds),&bounds)
#undef PROGRESS_NATIVE
static uint32_t native_connected_pan(uint32_t x) { round_from_native(); uint32_t result=progress_pan(NULL,&progress,x); round_to_native(); return result; }
static void native_connected_destination(uint32_t surface) { round_from_native(); progress_destination(NULL,&progress,surface_view(surface)); round_to_native(); }
static void native_connected_text(uint32_t x,uint32_t y,uint32_t length,const unsigned char *bytes) { round_from_native(); font_bytes view={bytes}; progress_text(NULL,&progress,x,y,length,&view); round_to_native(); }
static void native_connected_palette(const char *name) { round_from_native(); asset_name view={name}; progress_palette(NULL,&progress,&view); round_to_native(); }
static uint32_t WINAPI native_connected_blit_fast(uint32_t destination,uint32_t x,uint32_t y,uint32_t source,font_rect *bounds,uint32_t flags) {
    round_from_native(); progress_blit_fast(NULL,&progress,surface_view(destination),x,y,surface_view(source),bounds,flags); round_to_native(); return 0x88760001;
}
#define PROGRESS_ENTRY(name) static void native_connected_progress_##name(void) { round_from_native(); fixture_progress_##name(&progress); round_to_native(); }
PROGRESS_ENTRY(refresh) PROGRESS_ENTRY(draw) PROGRESS_ENTRY(next) PROGRESS_ENTRY(lose) PROGRESS_ENTRY(over) PROGRESS_ENTRY(restart) PROGRESS_ENTRY(advance)
#undef PROGRESS_ENTRY
static uint32_t native_connected_progress_count(void) { round_from_native(); uint32_t r=fixture_progress_count(&progress); round_to_native(); return r; }
static void connected_install(int source) {
    vtable[7]=(uint32_t)(uintptr_t)native_connected_blit_fast;
#define HOOK(name) REQUIRE(install_connected_service_##name((void (*)(void))native_connected_##name));
    HOOK(destination) HOOK(text) HOOK(damage) HOOK(sprite) HOOK(load_board) HOOK(stop_sound) HOOK(pan) HOOK(play_sound)
    HOOK(wait) HOOK(redraw) HOOK(palette) HOOK(create_ball) HOOK(reset_damage)
#undef HOOK
    if (source) {
#define ENTRY(name) REQUIRE(install_connected_progress_##name((void (*)(void))native_connected_progress_##name));
        ENTRY(refresh) ENTRY(draw) ENTRY(count) ENTRY(next) ENTRY(lose) ENTRY(over) ENTRY(restart) ENTRY(advance)
#undef ENTRY
    }
}
#endif
static void connected_setup(void) {
    progress.pending=1; if (scenario==29) flow.next_scene=3;
    if (scenario==30) pickups.lives=0;
}
static void connected_run(void) {
#ifndef DX_STANDALONE
    ((void (*)(void))0x408b40)(); round_from_native();
#else
    fixture_progress_advance(&progress);
#endif
    snapshot(NULL);
    if (scenario==28) {
#ifndef DX_STANDALONE
        ((void (*)(void))0x408990)(); ((void (*)(void))0x408b40)(); round_from_native();
#else
        fixture_progress_lose(&progress); fixture_progress_advance(&progress);
#endif
        snapshot(NULL);
    }
}
