#ifndef DX_STANDALONE
static uint32_t native_balls[NODES][15],native_surfaces[4],native_sprites[4][12],vtable[8];
static uint32_t *word(uint32_t address) { return (uint32_t *)(uintptr_t)address; }
static uint32_t ball_address(play_ball *p) { uint32_t id=ball_id(p); return id ? (uint32_t)(uintptr_t)native_balls[id-1] : 0; }
static play_ball *ball_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<NODES;++i) if (address==(uint32_t)(uintptr_t)native_balls[i]) { REQUIRE(ball_live[i]); return &balls[i]; }
    REQUIRE(0); return NULL;
}
static uint32_t surface_address(font_surface *p) { uint32_t id=surface_id(p); return id ? (uint32_t)(uintptr_t)&native_surfaces[id-1] : 0; }
static font_surface *surface_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<4;++i) if (address==(uint32_t)(uintptr_t)&native_surfaces[i]) return &surfaces[i];
    REQUIRE(0); return NULL;
}
#define EMPTY(name,type) static uint32_t name##_address(type *p) { REQUIRE(!p); return 0; } \
    static type *name##_view(uint32_t p) { REQUIRE(!p); return NULL; }
EMPTY(shot,play_shot) EMPTY(event,play_event) EMPTY(effect,play_effect)
#undef EMPTY
static void play_objects_to_native(void) {
    for (unsigned i=0;i<NODES;++i) if (ball_live[i]) { memcpy(native_balls[i],&balls[i],52); native_balls[i][13]=ball_address(balls[i].next); native_balls[i][14]=ball_address(balls[i].previous); }
}
static void play_objects_from_native(void) {
    for (unsigned i=0;i<NODES;++i) if (ball_live[i]) { memcpy(&balls[i],native_balls[i],52); balls[i].next=ball_view(native_balls[i][13]); balls[i].previous=ball_view(native_balls[i][14]); }
}
#define PARENT_WORDS(X) X(menu.score,0x431cbc) X(menu.input_ready,0x434994) X(damage.capability,0x4179fc) X(font.bank,0x43496c) X(scene.mouse_x,0x434970) X(scene.mouse_y,0x434978) \
    X(scene.mouse_buttons,0x434990) X(scene.presentation_mode,0x417a04) X(flow.next_scene,0x431fc4) X(flow.transition_pending,0x431fc8) \
    X(objects.current_bank,0x434968) X(pickups.count,0x431cb8) X(pickups.lives,0x431ca8) X(pickups.next_life,0x431c7c) X(pickups.paddle_sprite,0x431c84) \
    X(paddle.phase,0x431c64) X(paddle.last_tick,0x42ca50) X(paddle.spark_deadline,0x431c70) X(paddle.spark_sprite,0x42cc08) X(paddle.spark_width,0x431c18) \
    X(bricks.board_index,0x42ca54) X(progress.pending,0x42ca5c) X(progress.board_changed,0x431cc0) X(progress.warning_y,0x42cdc8) X(progress.warning_frames,0x431cb0)
static void play_parent_to_native(void) {
#define PUT(name,address) *word(address)=name;
    PARENT_WORDS(PUT)
#undef PUT
    *word(0x4349b4)=surface_address(title.back); *word(0x4349ac)=surface_address(flow.primary);
    *word(0x431fcc)=surface_address(flow.overlay); *word(0x434960)=surface_address(font.destination);
    memcpy((void *)0x42c148,palettes.current,1024); memcpy((void *)0x42c548,palettes.staged,1024);
    *word(0x4349b0)=surface_address(scene.flip); memcpy((void *)0x416068,&game.stereo_direction,8);
    *word(0x41a7e0)=surface_address(damage.background);
    for (unsigned i=0;i<4;++i) { native_sprites[i][0]=surface_address(sprites[i].surface); memcpy((unsigned char *)native_sprites[i]+4,sprites[i].retained,41); }
    for (unsigned b=0;b<3;++b) {
        uint32_t *row=word(0x433d18+b*1048);
        for (unsigned slot=0;slot<255;++slot) { font_sprite *sprite=objects.banks[b].slots[slot]; uint32_t address=0;
            for (unsigned i=0;i<4;++i) if (sprite==&sprites[i]) address=(uint32_t)(uintptr_t)native_sprites[i];
            REQUIRE(!sprite || address); row[slot]=address;
        }
        row[255]=objects.banks[b].count; memcpy(row+256,objects.banks[b].retained,24);
    }
}
static void play_parent_from_native(void) {
#define GET(name,address) name=*word(address);
    PARENT_WORDS(GET)
#undef GET
    title.back=surface_view(*word(0x4349b4)); flow.primary=surface_view(*word(0x4349ac));
    flow.overlay=surface_view(*word(0x431fcc)); font.destination=surface_view(*word(0x434960));
    memcpy(palettes.current,(void *)0x42c148,1024); memcpy(palettes.staged,(void *)0x42c548,1024);
    scene.flip=surface_view(*word(0x4349b0)); memcpy(&game.stereo_direction,(void *)0x416068,8);
    damage.background=surface_view(*word(0x41a7e0)); title.primary=flow.primary;
    for (unsigned i=0;i<4;++i) { sprites[i].surface=surface_view(native_sprites[i][0]); memcpy(sprites[i].retained,(unsigned char *)native_sprites[i]+4,41); }
    for (unsigned b=0;b<3;++b) {
        const uint32_t *row=word(0x433d18+b*1048);
        for (unsigned slot=0;slot<255;++slot) { font_sprite *sprite=NULL;
            for (unsigned i=0;i<4;++i) if (row[slot]==(uint32_t)(uintptr_t)native_sprites[i]) sprite=&sprites[i];
            REQUIRE(!row[slot] || sprite); objects.banks[b].slots[slot]=sprite;
        }
        objects.banks[b].count=row[255]; memcpy(objects.banks[b].retained,row+256,24);
    }
}
#include "play-native.h"
#include "motion-native.h"
static void game_to_native(void) { motion_to_native(); }
static void game_from_native(void) { motion_from_native(); }
#define NATIVE0(name) static void native_game_##name(void) { game_from_native(); game_##name(NULL,&game); game_to_native(); }
NATIVE0(load_board) NATIVE0(reset_damage) NATIVE0(stop_music)
#ifndef GAME_CONNECTED
NATIVE0(restart) NATIVE0(draw_score) NATIVE0(redraw_scene)
#else
static void native_game_redraw_scene(void) { ((void (*)(void))0x4043d0)(); }
#endif
#undef NATIVE0
#define NATIVE(name,params,...) static void native_game_##name params { game_from_native(); game_##name(NULL,&game,__VA_ARGS__); game_to_native(); }
NATIVE(select_bank,(uint32_t n),n) NATIVE(select_font,(uint32_t n),n) NATIVE(draw_board,(uint32_t n),n)
NATIVE(create_sprite,(uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e),a,b,c,d,e)
NATIVE(fade,(uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e),a,b,c,d,e)
#undef NATIVE
static void native_game_clear(uint32_t surface,uint32_t color) { game_from_native(); game_clear(NULL,&game,surface_view(surface),color); game_to_native(); }
static void native_game_image(uint32_t surface,const char *name,uint32_t mode,uint32_t x,uint32_t y) {
    game_from_native(); asset_name view={name}; game_image(NULL,&game,surface_view(surface),&view,mode,x,y); game_to_native();
}
static void native_game_load_bank(uint32_t bank,uint32_t mode,const char *name) { game_from_native(); asset_name view={name}; game_load_bank(NULL,&game,bank,mode,&view); game_to_native(); }
static void native_game_load_sound(uint32_t slot,const char *name) { game_from_native(); asset_name view={name}; game_load_sound(NULL,&game,slot,&view); game_to_native(); }
static void native_game_play_music(const char *name,uint32_t loop) { game_from_native(); asset_name view={name}; game_play_music(NULL,&game,&view,loop); game_to_native(); }
static void native_game_center(uint32_t x,uint32_t y,uint32_t length,const unsigned char *bytes) { game_from_native(); font_bytes view={bytes}; game_center(NULL,&game,x,y,length,&view); game_to_native(); }
static uint32_t native_game_random(uint32_t limit) { game_from_native(); uint32_t value=game_random(NULL,&game,limit); game_to_native(); return value; }
#define SURFACE(name) static void native_game_##name(uint32_t surface) { game_from_native(); game_##name(NULL,&game,surface_view(surface)); game_to_native(); }
SURFACE(damage_background) SURFACE(damage_destination)
#undef SURFACE
static uint32_t WINAPI native_game_blit(uint32_t destination,font_rect *dr,uint32_t source,font_rect *sr,uint32_t flags,void *effects) {
    REQUIRE(!effects); game_from_native(); game_blit(NULL,&game,surface_view(destination),dr,surface_view(source),sr,flags); game_to_native(); return 0x88760001;
}
static void native_game_enter(void) { game_from_native(); fixture_game_enter(&game); game_to_native(); }
static void native_game_redraw(void) { game_from_native(); fixture_game_redraw(&game); game_to_native(); }
static void native_game_key(uint32_t key) { game_from_native(); fixture_game_key(&game,key); game_to_native(); }
static void install(int source) {
    for (unsigned i=0;i<4;++i) native_surfaces[i]=(uint32_t)(uintptr_t)vtable;
    vtable[5]=(uint32_t)(uintptr_t)native_game_blit;
#define HOOK(name) REQUIRE(install_game_service_##name((void (*)(void))native_game_##name));
    HOOK(clear) HOOK(image) HOOK(load_bank) HOOK(select_bank) HOOK(select_font) HOOK(create_sprite) HOOK(load_sound)
    HOOK(load_board) HOOK(reset_damage) HOOK(damage_background) HOOK(damage_destination) HOOK(draw_board)
    HOOK(center) HOOK(fade) HOOK(redraw_scene) HOOK(random) HOOK(stop_music) HOOK(play_music)
#ifndef GAME_CONNECTED
    HOOK(restart) HOOK(draw_score)
#endif
#undef HOOK
    if (source) { REQUIRE(install_game_enter(native_game_enter)); REQUIRE(install_game_redraw(native_game_redraw)); REQUIRE(install_game_key((void (*)(void))native_game_key)); }
}
#endif
