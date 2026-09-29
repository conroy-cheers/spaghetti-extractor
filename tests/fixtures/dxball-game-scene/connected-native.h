#ifndef DX_STANDALONE
#define PROGRESS_NATIVE0(name) static void native_following_##name(void) { game_from_native(); progress_##name(NULL,&progress); game_to_native(); }
PROGRESS_NATIVE0(create_ball)
#undef PROGRESS_NATIVE0
#define PROGRESS_NATIVE(name,params,...) static void native_following_##name params { game_from_native(); progress_##name(NULL,&progress,__VA_ARGS__); game_to_native(); }
PROGRESS_NATIVE(stop_sound,(uint32_t n),n) PROGRESS_NATIVE(play_sound,(uint32_t a,uint32_t b,uint32_t c,uint32_t d),a,b,c,d)
PROGRESS_NATIVE(sprite,(uint32_t a,uint32_t b,uint32_t c),a,b,c) PROGRESS_NATIVE(wait,(uint32_t n),n)
PROGRESS_NATIVE(damage,(font_rect bounds),&bounds)
#undef PROGRESS_NATIVE
static uint32_t native_following_pan(uint32_t x) { game_from_native(); uint32_t result=progress_pan(NULL,&progress,x); game_to_native(); return result; }
static void native_following_destination(uint32_t surface) { game_from_native(); progress_destination(NULL,&progress,surface_view(surface)); game_to_native(); }
static void native_following_text(uint32_t x,uint32_t y,uint32_t length,const unsigned char *bytes) { game_from_native(); font_bytes view={bytes}; progress_text(NULL,&progress,x,y,length,&view); game_to_native(); }
static void native_following_palette(const char *name) { game_from_native(); asset_name view={name}; progress_palette(NULL,&progress,&view); game_to_native(); }
static uint32_t WINAPI native_following_blit_fast(uint32_t destination,uint32_t x,uint32_t y,uint32_t source,font_rect *bounds,uint32_t flags) {
    game_from_native(); progress_blit_fast(NULL,&progress,surface_view(destination),x,y,surface_view(source),bounds,flags); game_to_native(); return 0x88760001;
}
static void native_following_draw(void) { game_from_native(); fixture_progress_draw(&progress); game_to_native(); }
static void native_following_restart(void) { game_from_native(); fixture_progress_restart(&progress); game_to_native(); }
static void connected_install(int source) {
    vtable[7]=(uint32_t)(uintptr_t)native_following_blit_fast;
#define HOOK(name) REQUIRE(install_following_service_##name((void (*)(void))native_following_##name));
    HOOK(destination) HOOK(text) HOOK(damage) HOOK(sprite) HOOK(stop_sound) HOOK(pan) HOOK(play_sound)
    HOOK(wait) HOOK(palette) HOOK(create_ball)
#undef HOOK
    if (source) { REQUIRE(install_following_draw(native_following_draw)); REQUIRE(install_following_restart(native_following_restart)); }
}
#endif
