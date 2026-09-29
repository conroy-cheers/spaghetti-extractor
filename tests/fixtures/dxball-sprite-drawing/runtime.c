/* Reuse the established object transport and neighboring font/cleanup consumer. */
#define FONT_LIBRARY_ONLY 1
#include "font-runtime.c"
#include "drawing-runtime.h"

static uint32_t drawing_entries[3], fast_calls[16][11], fast_count, drawing_mode;
void drawing_enter(unsigned operation) { REQUIRE(operation < 3); ++drawing_entries[operation]; }
uint32_t drawing_blit_fast(void *unused, font_state *s, font_sprite *sprite,
                           uint32_t x, uint32_t y, uint32_t flags) {
    (void)unused; REQUIRE(s == &font && fast_count < 16);
    uint32_t *row = fast_calls[fast_count++];
    row[0] = surface_id(s->destination); row[1] = surface_id(sprite->surface);
    row[2] = x; row[3] = y; row[4] = flags;
    for (unsigned i = 0; i < 4; ++i) row[5 + i] = font_word(sprite, 20 + i * 4);
    row[9] = s->objects->current_bank;
    uint32_t result = drawing_mode == 1 ? UINT32_C(0x887601c2) : x ^ y ^ flags;
    row[10] = result;
    if (drawing_mode == 2) {
        put_word(sprite, 20, font_word(sprite, 20) + 7);
        put_word(sprite, 8, font_width(sprite) + 2);
        s->objects->current_bank = (s->objects->current_bank + 1) % 3;
        s->destination = sprite->surface;
    }
    return result;
}

#ifndef DX_STANDALONE
static uint32_t WINAPI native_fast(uint32_t destination, uint32_t x, uint32_t y,
                                  uint32_t source, font_rect *rectangle, uint32_t flags) {
    uint32_t id = native_sprite_id((uint32_t)(uintptr_t)rectangle - 20); REQUIRE(id);
    REQUIRE(destination == *word(0x434960));
    REQUIRE(source == native_sprites[id - 1].surface);
    font_from_native();
    uint32_t result = drawing_blit_fast(NULL, &font, &sprites[id - 1], x, y, flags);
    font_to_native(); return result;
}
static void native_destination(uint32_t surface) {
    font_from_native(); uint32_t id = native_surface_id(surface);
    fixture_sprite_destination(&font, id ? &surfaces[id - 1] : NULL);
    /* Null selection is a valid store; font transport's draw domain is nonnull. */
    if (id) font_to_native(); else *word(0x434960) = 0;
}
static uint32_t native_transparent(uint32_t slot, uint32_t x, uint32_t y) {
    font_from_native(); uint32_t result = fixture_sprite_transparent(&font, slot, x, y);
    font_to_native(); return result;
}
static uint32_t native_opaque(uint32_t slot, uint32_t x, uint32_t y) {
    font_from_native(); uint32_t result = fixture_sprite_opaque(&font, slot, x, y);
    font_to_native(); return result;
}
static void drawing_install(int source) {
    font_install(source); font_vtable[7] = (uint32_t)(uintptr_t)native_fast;
    if (!source) return;
    REQUIRE(install_sprite_destination((void (*)(void))native_destination));
    REQUIRE(install_sprite_transparent((void (*)(void))native_transparent));
    REQUIRE(install_sprite_opaque((void (*)(void))native_opaque));
}
#endif

int main(int argc, char **argv) {
    REQUIRE(argc == 4 && (!strcmp(argv[1], "source") || !strcmp(argv[1], "original")));
    uint32_t seed = (uint32_t)strtoul(argv[2], NULL, 10);
    drawing_mode = (uint32_t)strtoul(argv[3], NULL, 10); REQUIRE(drawing_mode <= 2);
    font_setup(seed, 0); uint32_t results[4];
    static const unsigned char text[] = {'A','B','C'};
#ifndef DX_STANDALONE
    int source = !strcmp(argv[1], "source"); drawing_install(source); font_to_native();
    ((void (*)(uint32_t))(uintptr_t)0x40bd60)((uint32_t)(uintptr_t)&native_surfaces[1]);
    results[0] = ((uint32_t (*)(uint32_t,uint32_t,uint32_t))(uintptr_t)0x40bd90)(1,seed,seed*3);
    results[1] = ((uint32_t (*)(uint32_t,uint32_t,uint32_t))(uintptr_t)0x40bdd0)(5,seed+7,~seed);
    results[2] = ((uint32_t (*)(uint32_t,const unsigned char *))(uintptr_t)0x40c760)(3,text);
    results[3] = ((uint32_t (*)(uint32_t,uint32_t,uint32_t,const unsigned char *))(uintptr_t)0x40c6b0)(seed,seed,3,text);
    font_from_native();
    if (source) {
        REQUIRE(install_sprite_destination_intact() && install_sprite_transparent_intact() && install_sprite_opaque_intact());
        REQUIRE(drawing_entries[0] && drawing_entries[1] && drawing_entries[2]);
    }
#else
    font_bytes bytes = {text}; REQUIRE(!strcmp(argv[1], "source"));
    fixture_sprite_destination(&font, &surfaces[1]);
    results[0] = fixture_sprite_transparent(&font,1,seed,seed*3);
    results[1] = fixture_sprite_opaque(&font,5,seed+7,~seed);
    results[2] = fixture_font_measure(&font,3,&bytes);
    results[3] = fixture_font_line(&font,seed,seed,3,&bytes);
#endif
    fputs("{\"before_cleanup\":",stdout); font_observe_objects(); fputs(",\"drawing\":",stdout);
    spx_observer o = spx_observe_begin(stdout); spx_observe_u32s(&o,"results",results,4);
    spx_observe_array(&o,"fast_calls");
    for (uint32_t i=0;i<fast_count;++i) spx_observe_u32s(&o,NULL,fast_calls[i],11);
    spx_observe_end(&o); spx_observe_array(&o,"font_blits");
    for (uint32_t i=0;i<blit_count;++i) spx_observe_u32s(&o,NULL,blits[i],12);
    spx_observe_end(&o); REQUIRE(spx_observe_finish(&o));
#ifndef DX_STANDALONE
    font_to_native(); ((void (*)(void))(uintptr_t)0x40bcc0)(); font_from_native(); check_traps(source);
#else
    fixture_clear(&state);
#endif
    fputs(",\"after_cleanup\":",stdout); font_observe_objects(); fputs("}\n",stdout);
    fprintf(stderr,"DRAWING_SELECTED %u %u %u\n",drawing_entries[0],drawing_entries[1],drawing_entries[2]);
    return 0;
}

#ifndef DX_STANDALONE
static void drawing_run_case(void) {
    int count; char **args, **environment; struct native_startupinfo startup = {0};
    REQUIRE(__getmainargs(&count,&args,&environment,0,&startup) == 0);
    int result=main(count,args); fflush(NULL); ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_drawing_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance; (void)reserved;
    return reason != DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(drawing_run_case));
}
#endif
