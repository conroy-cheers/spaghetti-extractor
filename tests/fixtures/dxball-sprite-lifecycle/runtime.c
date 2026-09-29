/* Target services and observations shared by original machine and portable C. */
#define ASSET_LIBRARY_ONLY 1
#include "asset-runtime.c"
#include "lifecycle-runtime.h"

static uint32_t lifecycle_entries[2], lifecycle_mode, copies[8][13], copy_count;
void lifecycle_enter(unsigned operation) { REQUIRE(operation < 2); ++lifecycle_entries[operation]; }

uint32_t lifecycle_copy(void *unused, asset_state *s, font_state *drawing,
                         font_sprite *sprite, font_rect *source) {
    (void)unused; REQUIRE(s == &assets && drawing == &font && copy_count < 8);
    uint32_t id = surface_id(sprite->surface); REQUIRE(id);
    uint32_t *row = copies[copy_count++];
    row[0] = sprite_id(sprite); row[1] = id; row[2] = surface_id(drawing->destination);
    for (unsigned i = 0; i < 4; ++i) row[3+i] = font_word(sprite, 20+4*i);
    row[7] = source->left; row[8] = source->top; row[9] = source->right; row[10] = source->bottom;
    row[11] = 0x01000000; row[12] = lifecycle_mode == 3 ? 0x88760002 : 0;
    /* Deterministic controlled graphics storage, including pitch padding. */
    for (uint32_t y = 0; y < font_height(sprite); ++y)
        for (uint32_t x = 0; x < font_width(sprite); ++x)
            surface_pixels[id-1][y*pitches[id-1]+x] = (unsigned char)(source->left+x+17*(source->top+y));
    if (lifecycle_mode == 3) {
        asset_set_word(sprite, 20, source->left ^ 19);
        asset_set_word(sprite, 8, font_width(sprite)+7);
        ++drawing->spacing;
    }
    return row[12];
}

uint32_t lifecycle_restore_surface(void *unused, asset_state *s, font_surface *surface) {
    (void)unused; REQUIRE(s == &assets);
    uint32_t id = surface_id(surface), result = lifecycle_mode == 3 ? 0x88760003 : 0;
    asset_event(12, id, result, 0);
    if (surface_sizes[id-1]) memset(surface_pixels[id-1], 0xee, surface_sizes[id-1]);
    return result;
}

void lifecycle_reload(void *unused, asset_state *s, uint32_t bank) {
    (void)unused; REQUIRE(s == &assets && bank < 3);
    char name[20];
    for (unsigned i = 0; i < sizeof(name); ++i)
        name[i] = (char)(s->objects->banks[bank].retained[1+i/4] >> (8*(i%4)));
    REQUIRE(memchr(name, 0, sizeof(name)));
    asset_name input = {name}; fixture_sprite_load(s, bank, 1, &input);
}

#ifndef DX_STANDALONE
static int capture_allocating;
static uint32_t native_lifecycle_allocate(uint32_t bytes) {
    if (!capture_allocating) return native_asset_allocate(bytes);
    REQUIRE(bytes == 45); asset_from_native();
    font_sprite *sprite = asset_allocate_sprite(NULL, &assets); asset_to_native();
    return (uint32_t)(uintptr_t)&native_sprites[sprite_id(sprite)-1];
}
static uint32_t WINAPI native_lifecycle_copy(uint32_t destination, font_rect *dr, uint32_t source,
                                            font_rect *sr, uint32_t flags, void *effects) {
    if (flags == 0x01008000) return native_blit(destination, dr, source, sr, flags, effects);
    REQUIRE(flags == 0x01000000 && !effects && source == *word(0x434960));
    uint32_t id = native_sprite_id((uint32_t)(uintptr_t)dr-20); REQUIRE(id);
    REQUIRE(destination == native_sprites[id-1].surface);
    asset_from_native(); uint32_t result = lifecycle_copy(NULL, &assets, &font, &sprites[id-1], sr);
    asset_to_native(); return result;
}
static uint32_t WINAPI native_lifecycle_restore_surface(uint32_t surface) {
    uint32_t id = native_surface_id(surface); REQUIRE(id); asset_from_native();
    uint32_t result = lifecycle_restore_surface(NULL, &assets, &surfaces[id-1]); asset_to_native(); return result;
}
static uint32_t native_capture(uint32_t slot, uint32_t x, uint32_t y, uint32_t width, uint32_t height) {
    asset_from_native(); uint32_t result = fixture_sprite_capture(&assets, &font, slot, x, y, width, height);
    asset_to_native(); return result;
}
static void native_restore(void) {
    asset_from_native(); fixture_sprite_restore(&assets); asset_to_native();
}
static void lifecycle_install(int source) {
    asset_install(source);
    REQUIRE(spx_fixture_restore_entry(&install_asset_allocate_hook)); install_asset_allocate_hook.entry = NULL;
    REQUIRE(install_asset_allocate((void (*)(void))native_lifecycle_allocate));
    font_vtable[5] = (uint32_t)(uintptr_t)native_lifecycle_copy;
    font_vtable[27] = (uint32_t)(uintptr_t)native_lifecycle_restore_surface;
    if (source) {
        REQUIRE(install_capture((void (*)(void))native_capture));
        REQUIRE(install_restore(native_restore));
    }
}
#endif

static void name_bank(unsigned bank, const char *name, uint32_t mode) {
    struct cleanup_bank *row = &state.banks[bank]; row->retained[0] = mode;
    for (unsigned i = 0; i < 20; ++i) {
        uint32_t value = i < strlen(name) ? (unsigned char)name[i] : 0;
        unsigned shift = 8*(i%4);
        row->retained[1+i/4] = (row->retained[1+i/4] & ~(UINT32_C(255)<<shift)) | value<<shift;
    }
}

#ifndef LIFECYCLE_LIBRARY_ONLY
int main(int argc, char **argv) {
    REQUIRE(argc == 4); uint32_t seed = (uint32_t)strtoul(argv[2], NULL, 10);
    lifecycle_mode = (uint32_t)strtoul(argv[3], NULL, 10); REQUIRE(lifecycle_mode < 4);
    font_setup(seed, 0); assets.objects = &state;
    fail_at = lifecycle_mode == 1 ? 1 : 0; retries = lifecycle_mode == 2 ? 2 : 0;
    name_bank(0, "Sysfont.sbk", 1); name_bank(1, "Sfont.sbk", lifecycle_mode == 3 ? UINT32_MAX : 2);
    name_bank(2, "Thefont.sbk", 1);
    /* Restore visits slot 254, which the loader deliberately leaves alone. */
    state.banks[0].slots[254] = asset_allocate_sprite(NULL, &assets);
    font_sprite *last = asset_allocate_sprite(NULL, &assets);
    last->surface = &surfaces[0]; ++refs[0]; state.banks[2].slots[254] = last;
    uint32_t results[3] = {0}; unsigned char text_data[] = "DX-Ball";
    uint32_t width = 3+seed%7, height = 2+seed%5;
#ifndef DX_STANDALONE
    int source = !strcmp(argv[1], "source"); lifecycle_install(source); asset_to_native();
    capture_allocating = 1;
    results[0] = ((uint32_t (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))(uintptr_t)0x40be10)
        (3, seed, seed*3, width, height);
    capture_allocating = 0; asset_from_native();
#else
    REQUIRE(!strcmp(argv[1], "source"));
    results[0] = fixture_sprite_capture(&assets, &font, 3, seed, seed*3, width, height);
#endif
    guards[2] = assets.file ? 1 : 0;
    fputs("{\"captured\":", stdout); font_observe_objects();
#ifndef DX_STANDALONE
    ((void (*)(void))(uintptr_t)0x40bd00)(); asset_from_native();
    ((void (*)(uint32_t))(uintptr_t)0x40bd80)(0);
    results[1] = ((uint32_t (*)(uint32_t,const unsigned char *))(uintptr_t)0x40c760)(7, text_data);
    results[2] = ((uint32_t (*)(uint32_t,uint32_t,uint32_t,const unsigned char *))(uintptr_t)0x40c720)(100, 50, 7, text_data);
    asset_from_native();
    if (source) REQUIRE(install_capture_intact() && install_restore_intact() && install_load_intact()
                        && lifecycle_entries[0] && lifecycle_entries[1] && loader_entries == 2);
#else
    fixture_sprite_restore(&assets); font_bytes text = {text_data};
    fixture_font_select(&font, 0); results[1] = fixture_font_measure(&font, 7, &text);
    results[2] = fixture_font_center(&font, 100, 50, 7, &text);
#endif
    guards[2] = assets.file ? 1 : 0;
    fputs(",\"restored\":", stdout); font_observe_objects(); fputs(",\"lifecycle\":", stdout);
    spx_observer o = spx_observe_begin(stdout); spx_observe_u32s(&o, "results", results, 3);
    spx_observe_u64(&o, "file_position", file.position); spx_observe_u64(&o, "file_closed", file.closed);
    spx_observe_u32s(&o, "buffer_live", buffer_live, buffer_count);
    spx_observe_array(&o, "events");
    for (uint32_t i = 0; i < asset_event_count; ++i) spx_observe_u32s(&o, NULL, asset_events[i], 5);
    spx_observe_end(&o); spx_observe_array(&o, "copies");
    for (uint32_t i = 0; i < copy_count; ++i) spx_observe_u32s(&o, NULL, copies[i], 13);
    spx_observe_end(&o); spx_observe_array(&o, "pixels");
    for (uint32_t i = 0; i < surface_count; ++i) spx_observe_bytes(&o, NULL, surface_pixels[i], surface_sizes[i]);
    spx_observe_end(&o); spx_observe_array(&o, "text_blits");
    for (uint32_t i = 0; i < blit_count; ++i) spx_observe_u32s(&o, NULL, blits[i], 12);
    spx_observe_end(&o); REQUIRE(spx_observe_finish(&o));
#ifndef DX_STANDALONE
    asset_to_native(); ((void (*)(void))(uintptr_t)0x40bcc0)(); asset_from_native(); check_traps(source);
#else
    fixture_clear(&state);
#endif
    guards[2] = assets.file ? 1 : 0;
    fputs(",\"after_cleanup\":", stdout); font_observe_objects(); fputs("}\n", stdout);
    fprintf(stderr, "LIFECYCLE_SELECTED %u %u; loader %u\n", lifecycle_entries[0], lifecycle_entries[1], loader_entries);
    return 0;
}

#ifndef DX_STANDALONE
static void lifecycle_run_case(void) {
    int count; char **arguments, **environment; struct native_startupinfo startup = {0};
    REQUIRE(__getmainargs(&count, &arguments, &environment, 0, &startup) == 0);
    int result = main(count, arguments); fflush(NULL); ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_lifecycle_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved) {
    (void)instance; (void)reserved;
    return reason != DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL) == 0x400000 && install_startup(lifecycle_run_case));
}
#endif
#endif /* LIFECYCLE_LIBRARY_ONLY */
