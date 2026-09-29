/* Actual progression bodies call the new cleanup component over the same state. */
#include "progress-runtime.h"
static uint32_t progress_scenario,blits,sprite_calls,progress_entries[8];
void progress_enter(unsigned operation) { REQUIRE(operation<8); ++progress_entries[operation]; }
void progress_blit_fast(void *unused,progression_state *s,font_surface *destination,uint32_t x,uint32_t y,font_surface *source,font_rect *bounds,uint32_t flags) {
    BEGIN(100+PROGRESS_BLIT_FAST,surface_id(destination),x,y,surface_id(source),bounds->left,bounds->top,bounds->right,bounds->bottom,flags);
    ++blits;
    if (progress_scenario==7) { bounds->left+=3; bounds->bottom+=2; title.back=&surfaces[3]; pickups.lives=blits==1 ? 25 : 14; menu.score=777; }
    (void)end(0);
}
void progress_destination(void *unused,progression_state *s,font_surface *surface) {
    BEGIN(100+PROGRESS_DESTINATION,surface_id(surface)); font.destination=surface;
    if (progress_scenario==7) menu.score=888;
    (void)end(0);
}
void progress_text(void *unused,progression_state *s,uint32_t x,uint32_t y,uint32_t length,font_bytes *bytes) {
    BEGIN(100+PROGRESS_TEXT,x,y,length); REQUIRE(length<=10); spx_observe_bytes(observer,"text",bytes->data,length);
    if (progress_scenario==7) menu.score=999;
    (void)end(0);
}
void progress_damage(void *unused,progression_state *s,font_rect *bounds) {
    BEGIN(100+PROGRESS_DAMAGE,bounds->left,bounds->top,bounds->right,bounds->bottom); (void)end(0);
}
void progress_sprite(void *unused,progression_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    BEGIN(100+PROGRESS_SPRITE,slot,x,y); if (progress_scenario==7 && ++sprite_calls==2) pickups.lives=5; (void)end(0);
}
void progress_load_board(void *unused,progression_state *s) {
    BEGIN0(100+PROGRESS_LOAD_BOARD); memset(&current_board,0,sizeof(current_board));
    if (progress_scenario!=12) { current_board.cells[1][2]=7; current_board.cells[3][4]=8; current_board.cells[19][0]=2; }
    if (progress_scenario==15) { progress.pending=7; progress.board_changed=9; }
    (void)end(0);
}
void progress_stop_sound(void *unused,progression_state *s,uint32_t sound) {
    BEGIN(100+PROGRESS_STOP_SOUND,sound);
    if (progress_scenario==18) { play.paddle_x=UINT32_MAX; pickups.lives=9; progress.pending=77; }
    if (progress_scenario==22) { scene.mouse_x=333; motion.paddle_width=55; objects.current_bank=1; }
    (void)end(0);
}
uint32_t progress_pan(void *unused,progression_state *s,uint32_t x) { BEGIN(100+PROGRESS_PAN,x); return end(x+17); }
void progress_play_sound(void *unused,progression_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d) {
    BEGIN(100+PROGRESS_PLAY_SOUND,a,b,c,d); if (progress_scenario==18) progress.pending=99; (void)end(0);
}
void progress_wait(void *unused,progression_state *s,uint32_t count) {
    BEGIN(100+PROGRESS_WAIT,count); if (progress_scenario==19) { flow.next_scene=8; flow.transition_pending=9; pickups.lives=3; } (void)end(0);
}
void progress_redraw(void *unused,progression_state *s) {
    BEGIN0(100+PROGRESS_REDRAW); if (progress_scenario==22) { current_board.cells[1][2]=0; play.remaining_bricks=19; } (void)end(0);
}
void progress_palette(void *unused,progression_state *s,asset_name *name) {
    BEGIN0(100+PROGRESS_PALETTE); spx_observe_bytes(observer,"name",(const unsigned char *)name->text,strlen(name->text));
    REQUIRE(!strcmp(name->text,"mbbkgrnd.pcx"));
    for (unsigned i=0;i<256;++i) { palettes.staged[i][0]=(unsigned char)i; palettes.staged[i][1]=(unsigned char)(i*3); palettes.staged[i][2]=(unsigned char)(255-i); }
    if (progress_scenario==22) scene.mouse_x=123;
    (void)end(0);
}
void progress_fade(void *unused,progression_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e) {
    REQUIRE(s==&progress); round_fade(unused,&rounds,a,b,c,d,e);
}
void progress_create_ball(void *unused,progression_state *s) {
    BEGIN0(100+PROGRESS_CREATE_BALL); unsigned i=0; while (i<NODES && ball_live[i]) ++i; REQUIRE(i<NODES); ball_live[i]=1;
    play_ball *ball=&balls[i]; *ball=(play_ball){.x=play.paddle_x,.y=430,.sprite=1,.speed=5,.angle=45,.tick=91,.retained=71,.auxiliary=81,.attached=99};
    ball->previous=play.balls.last;
    if (play.balls.last) play.balls.last->next=ball; else play.balls.first=ball;
    play.balls.current=play.balls.last=ball; ++motion.ball_count;
    if (progress_scenario==22) { play.balls.current=play.balls.first; play.paddle_x+=11; progress.pending=13; progress.board_changed=14; }
    (void)end(0);
}
void progress_clear(void *unused,progression_state *s,font_surface *surface,uint32_t color) {
    REQUIRE(s==&progress); round_clear_surface(unused,&rounds,surface,color);
}
void progress_clear_objects(void *unused,progression_state *s) {
    (void)unused; REQUIRE(s==&progress); fixture_round_clear(&rounds);
}
void progress_reset_damage(void *unused,progression_state *s) {
    BEGIN0(100+PROGRESS_RESET_DAMAGE); if (progress_scenario==31) { flow.next_scene=2; pickups.lives=2; } (void)end(0);
}
