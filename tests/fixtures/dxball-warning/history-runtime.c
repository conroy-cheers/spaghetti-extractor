/* Portable replay of the retained actual-native frame provenance experiment. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "history.h"
#include "warning-runtime.h"
#include "play-runtime.h"
#include "paddle-runtime.h"
#include "pickup-runtime.h"
#include "particle-runtime.h"
static uint32_t mode,queue_calls,explosion_calls,particle_calls,blits,describes,locks,damages,warning_calls;
static uint32_t queued[2],exploded[2],descriptor[27];
static unsigned char pixels[640*480];
static warning_frame_history history;
static font_surface surface={1};
static font_sprite ordinary,warning_sprite;
static struct spx_opaque_cleanup_state_v5 objects;
static font_state font={.objects=&objects};
static flow_state flow;
static title_state title={.font=&font,.flow=&flow};
static scene_state scene={.animation=&title};
static menu_state menu={.scene=&scene};
static play_state play={.menu=&menu};
static board current_board;
static motion_state motion={.play=&play,.board=&current_board};
static pickup_state pickups={.motion=&motion};
static paddle_state paddle={.pickups=&pickups};
static brick_state bricks={.motion=&motion};
static progression_state progress={.paddle=&paddle,.bricks=&bricks};
static warning_state warning={.progression=&progress};
static particle_state particles={.destination=&title.software};
static play_ball ball;
static pickup drop;
static particle trail;
static void require(int value,const char *expression,unsigned line) {
    if (!value) { fprintf(stderr,"history-runtime.c:%u: adapter premise failed: %s\n",line,expression);exit(3); }
}
#define REQUIRE(test) require(!!(test),#test,__LINE__)
void play_enter(void) {}
void paddle_enter(unsigned op) { REQUIRE(op==1); }
void pickup_enter(unsigned op) { REQUIRE(op==2); }
void particle_enter(unsigned op) { REQUIRE(op==2); }
void warning_enter(unsigned op) { REQUIRE(op==0);++warning_calls; }
static void dimensions(font_sprite *sprite,uint32_t width,uint32_t height) {
    sprite->surface=&surface;
    for (unsigned i=0;i<4;++i) { sprite->retained[4+i]=(unsigned char)(width>>(8*i));sprite->retained[8+i]=(unsigned char)(height>>(8*i)); }
}
#define IGNORE_STATE(expected) (void)u;REQUIRE(s==&(expected))
void play_draw_paddle(void *u,play_state *s) { IGNORE_STATE(play);fixture_paddle_draw(&paddle); }
void play_draw_pickups(void *u,play_state *s) { IGNORE_STATE(play);fixture_pickup_draw(&pickups); }
void play_draw_trails(void *u,play_state *s) { IGNORE_STATE(play);fixture_particle_draw(&particles); }
void play_prepare_last_brick(void *u,play_state *s) {
    IGNORE_STATE(play);warning.fallback=history.words;fixture_warning_prepare(&warning);
}
void play_sprite(void *u,play_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    IGNORE_STATE(play);(void)slot;(void)x;(void)y;warning_history_frame_sprite(&history);++blits;
}
uint32_t play_elapsed(void *u,play_state *s,uint32_t previous,uint32_t delay) {
    IGNORE_STATE(play);(void)previous;(void)delay;return 0;
}
uint32_t paddle_elapsed(void *u,paddle_state *s,uint32_t previous,uint32_t delay) {
    IGNORE_STATE(paddle);(void)previous;(void)delay;return 0;
}
void paddle_sprite(void *u,paddle_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    IGNORE_STATE(paddle);(void)x;warning_history_paddle(&history,slot,play.paddle_y-y);++blits;
}
void pickup_sprite(void *u,pickup_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    IGNORE_STATE(pickups);(void)slot;(void)x;(void)y;warning_history_pickup_sprite(&history);++blits;
}
static void descriptor_fields(int locking) {
    descriptor[0]=108;descriptor[1]=14;descriptor[2]=480;descriptor[3]=640;descriptor[4]=640;
    if (mode==4) { if (locking) descriptor[21]=5;else { descriptor[20]=120;descriptor[21]=2; } }
    else { descriptor[20]=120;descriptor[21]=2;descriptor[22]=3; }
    warning_history_from_descriptor(&history,descriptor);
}
static void view_fields(pcx_view *view) {
    view->width=640;view->height=480;view->image.pitch=640;view->image.pixels=pixels;
}
void particle_describe(void *u,particle_state *s,font_surface *target,pcx_view *view) {
    IGNORE_STATE(particles);REQUIRE(target==&surface);++describes;
    warning_history_to_descriptor(&history,descriptor);descriptor_fields(0);view_fields(view);
}
uint32_t particle_lock(void *u,particle_state *s,font_surface *target,pcx_view *view) {
    IGNORE_STATE(particles);REQUIRE(target==&surface);++locks;descriptor_fields(1);view_fields(view);return 0;
}
void particle_unlock(void *u,particle_state *s,font_surface *target) { IGNORE_STATE(particles);REQUIRE(target==&surface); }
void particle_damage(void *u,particle_state *s,font_rect *bounds) { IGNORE_STATE(particles);(void)bounds;++damages; }
uint32_t warning_now(void *u,warning_state *s) { IGNORE_STATE(warning);return 2; }
uint32_t warning_random(void *u,warning_state *s,uint32_t limit) { IGNORE_STATE(warning);REQUIRE(limit);return 0; }
void warning_queue(void *u,warning_state *s,uint32_t column,uint32_t row) {
    IGNORE_STATE(warning);++queue_calls;queued[0]=column;queued[1]=row;
}
void warning_explosion(void *u,warning_state *s,uint32_t x,uint32_t y) {
    IGNORE_STATE(warning);++explosion_calls;exploded[0]=x;exploded[1]=y;
}
void warning_particle(void *u,warning_state *s,uint32_t x,uint32_t y,uint32_t dx,uint32_t dy,uint32_t color,uint32_t gravity) {
    IGNORE_STATE(warning);(void)x;(void)y;(void)dx;(void)dy;(void)color;(void)gravity;++particle_calls;
}
void warning_select_bank(void *u,warning_state *s,uint32_t bank) { IGNORE_STATE(warning);REQUIRE(bank<3);objects.current_bank=bank; }
/* Remaining adapters explicitly distinguish controlled no-ops from unreachable
 * services. Generated from the existing declarations, without new tool rules. */
#include "history-stubs.h"
int main(int argc,char **argv) {
    REQUIRE(argc==4);mode=(uint32_t)strtoul(argv[1],NULL,0);REQUIRE(mode<8);
    history.incoming_ebp=(uint32_t)strtoul(argv[2],NULL,0);history.incoming_esi=(uint32_t)strtoul(argv[3],NULL,0);
    dimensions(&ordinary,10,20);dimensions(&warning_sprite,159,479);
    for (unsigned i=0;i<sizeof(objects.banks[0].slots)/sizeof(objects.banks[0].slots[0]);++i)
        objects.banks[0].slots[i]=&ordinary;
    objects.banks[2].slots[1]=&warning_sprite;title.software=&surface;title.fast=1;
    /* Post-count/hit state independently established by the retained original
     * experiment. This replay starts at the actual frame boundary. */
    play.remaining_bricks=1;play.warning_sound=1;play.paddle_x=300;play.paddle_y=450;
    motion.paddle_width=50;pickups.paddle_sprite=68;
    ball=(play_ball){.x=50,.y=60,.sprite=1};drop=(pickup){.sprite=3,.x=100,.y=200};
    trail=(particle){.x=30,.y=40,.color=16};
    if (mode==1 || mode==5 || mode==6) play.balls.first=play.balls.last=&ball;
    if (mode==2 || mode==5 || mode==7) pickups.first=pickups.last=&drop;
    if (mode==3 || mode==4) particles.first=particles.last=&trail;
    fixture_play_update(&play);REQUIRE(warning_calls==1);
    uint32_t address=UINT32_C(0x42ca60)+queued[1]*20+queued[0];
    printf("{\"mode\":%u,\"incoming_ebp_esi\":[%u,%u],\"entry_words\":[%u,%u,%u],\"queue\":[%u,%u],\"queue_within_grid\":%s,\"queue_address\":%u,\"explosion\":[%u,%u],\"warning_calls\":[%u,%u,%u],\"drawing_calls\":[%u,%u,%u,%u]}\n",
        mode,history.incoming_ebp,history.incoming_esi,warning.fallback.y,warning.fallback.row,warning.fallback.column,
        queued[0],queued[1],queued[0]<20 && queued[1]<20 ? "true" : "false",address,exploded[0],exploded[1],
        queue_calls,explosion_calls,particle_calls,blits,describes,locks,damages);
    return 0;
}
