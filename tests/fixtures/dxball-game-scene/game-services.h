/* Controlled platform effects; connected mode calls actual progression C. */
#ifdef GAME_CONNECTED
#include "progress-runtime.h"
#endif
static void observe_name(asset_name *name) { spx_observe_bytes(observer,"name",(const unsigned char *)name->text,strlen(name->text)); }
void game_clear(void *unused,game_scene_state *s,font_surface *surface,uint32_t color) {
    BEGIN(GAME_CLEAR,surface_id(surface),color);
    if (scenario==3) { flow.overlay=&surfaces[3]; title.back=&surfaces[1]; }
    (void)end(0);
}
void game_image(void *unused,game_scene_state *s,font_surface *surface,asset_name *name,uint32_t palette,uint32_t x,uint32_t y) {
    BEGIN(GAME_IMAGE,surface_id(surface),palette,x,y); observe_name(name);
    if (scenario==3) { title.back=&surfaces[2]; menu.score=77; }
    (void)end(0);
}
void game_load_bank(void *unused,game_scene_state *s,uint32_t bank,uint32_t mode,asset_name *name) {
    BEGIN(GAME_LOAD_BANK,bank,mode); REQUIRE(bank<3); observe_name(name); objects.banks[bank].count=69;
    if (scenario==3) { objects.banks[2].count=88; objects.banks[2].retained[0]=99; }
    (void)end(0);
}
void game_select_bank(void *unused,game_scene_state *s,uint32_t bank) {
    BEGIN(GAME_SELECT_BANK,bank); REQUIRE(bank<3); objects.current_bank=bank; (void)end(0);
}
void game_select_font(void *unused,game_scene_state *s,uint32_t bank) {
    BEGIN(GAME_SELECT_FONT,bank); font.bank=bank;
    if (scenario==3) { objects.banks[2].count=123; objects.banks[2].retained[0]=456; }
    (void)end(0);
}
void game_create_sprite(void *unused,game_scene_state *s,uint32_t slot,uint32_t left,uint32_t top,uint32_t right,uint32_t bottom) {
    BEGIN(GAME_CREATE_SPRITE,slot,left,top,right,bottom); REQUIRE(slot<255 && objects.current_bank<3);
    objects.banks[objects.current_bank].slots[slot]=&sprites[2]; dimensions(&sprites[2],right-left,bottom-top); (void)end(0);
}
void game_load_sound(void *unused,game_scene_state *s,uint32_t slot,asset_name *name) {
    BEGIN(GAME_LOAD_SOUND,slot); observe_name(name);
    if (scenario==3) { play.paused=9; menu.score=slot+77; pickups.next_life=slot+80; pickups.lives=slot+2; paddle.phase=5; paddle.last_tick=6; bricks.board_index=7; }
    (void)end(0);
}
void game_load_board(void *unused,game_scene_state *s) {
    BEGIN0(GAME_LOAD_BOARD); memset(&current_board,0,sizeof(current_board)); current_board.cells[1][2]=3; current_board.cells[5][4]=7;
    if (scenario==3) { bricks.board_index=4; pickups.lives=5; }
    (void)end(0);
}
void game_restart(void *unused,game_scene_state *s) {
#ifdef GAME_CONNECTED
    (void)unused; REQUIRE(s==&game); fixture_progress_restart(&progress);
#else
    BEGIN0(GAME_RESTART); progress.pending=0; progress.board_changed=0; play.paddle_x=300;
    if (scenario==3) { scene.presentation_mode=0; title.back=&surfaces[3]; }
    (void)end(0);
#endif
}
void game_reset_damage(void *unused,game_scene_state *s) {
    BEGIN0(GAME_RESET_DAMAGE); if (scenario==3) { scene.presentation_mode=1; flow.primary=&surfaces[2]; } (void)end(0);
}
void game_damage_background(void *unused,game_scene_state *s,font_surface *surface) {
    BEGIN(GAME_DAMAGE_BACKGROUND,surface_id(surface)); damage.background=surface;
    if (scenario==3) { scene.presentation_mode=0; scene.flip=&surfaces[0]; } (void)end(0);
}
void game_damage_destination(void *unused,game_scene_state *s,font_surface *surface) {
    BEGIN(GAME_DAMAGE_DESTINATION,surface_id(surface)); font.destination=surface; (void)end(0);
}
void game_blit(void *unused,game_scene_state *s,font_surface *destination,font_rect *dr,font_surface *source,font_rect *sr,uint32_t flags) {
    BEGIN(GAME_BLIT,surface_id(destination),dr->left,dr->top,dr->right,dr->bottom,
        surface_id(source),sr->left,sr->top,sr->right,sr->bottom,flags,dr==sr);
    ++blits;
    if (scenario==10) { dr->left+=3; dr->bottom-=2; sr->right-=5; title.back=&surfaces[3];
        if (blits==2) { damage.capability=1; scene.presentation_mode=0; scene.flip=&surfaces[2]; } }
    (void)end(0);
}
void game_draw_score(void *unused,game_scene_state *s) {
#ifdef GAME_CONNECTED
    (void)unused; REQUIRE(s==&game); fixture_progress_draw(&progress);
#else
    BEGIN0(GAME_DRAW_SCORE); if (scenario==10) { play.paused=0; scene.presentation_mode=1; } (void)end(0);
#endif
}
void game_draw_board(void *unused,game_scene_state *s,uint32_t mode) {
    BEGIN(GAME_DRAW_BOARD,mode); if (scenario==10) play.paused=1; (void)end(0);
}
void game_center(void *unused,game_scene_state *s,uint32_t x,uint32_t y,uint32_t length,font_bytes *bytes) {
    BEGIN(GAME_CENTER,x,y,length); REQUIRE(length<=16); spx_observe_bytes(observer,"text",bytes->data,length); (void)end(0);
}
void game_fade(void *unused,game_scene_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e) {
    BEGIN(GAME_FADE,a,b,c,d,e); ++fade_calls;
    if (scenario==16) { progress.pending=3; if (fade_calls==1) play.paused=7; } (void)end(0);
}
void game_redraw_scene(void *unused,game_scene_state *s) {
    (void)unused; REQUIRE(s==&game);
#ifdef GAME_CONNECTED
    REQUIRE(game_depth++<3); fixture_game_redraw(s); --game_depth;
#else
    begin(s,GAME_REDRAW_SCENE,NULL,0); if (scenario==16) { play.paused=9; progress.pending=5; } (void)end(0);
#endif
}
uint32_t game_random(void *unused,game_scene_state *s,uint32_t limit) { BEGIN(GAME_RANDOM,limit); REQUIRE(limit==6); return end(random_choice); }
void game_stop_music(void *unused,game_scene_state *s) { BEGIN0(GAME_STOP_MUSIC); if (scenario==21) random_choice=5; (void)end(0); }
void game_play_music(void *unused,game_scene_state *s,asset_name *name,uint32_t loop) { BEGIN(GAME_PLAY_MUSIC,loop); observe_name(name); (void)end(0); }
