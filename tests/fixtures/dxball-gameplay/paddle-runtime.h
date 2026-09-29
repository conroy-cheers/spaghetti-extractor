/* Connect the real native paddle helper to the native or lifted frame, without
 * game startup. Asset dimensions come from the retained Mball2.sbk, not source. */
#include "paddle-sprites.h"
static uint32_t paddle_vtable[8],paddle_surface;
static uint32_t WINAPI paddle_clock(void) { return 1000; }
static uint32_t WINAPI paddle_blit(uint32_t destination,uint32_t x,uint32_t y,
                                  uint32_t surface,font_rect *rectangle,uint32_t flags) {
    REQUIRE(destination==(uint32_t)(uintptr_t)&paddle_surface);
    uint32_t values[]={surface,x,y,rectangle->left,rectangle->top,rectangle->right,rectangle->bottom,flags};
    spx_observe_object(observer,NULL); spx_observe_u32s(observer,"blit",values,8); spx_observe_end(observer); return 0;
}
static void paddle_mark(font_rect rectangle) {
    uint32_t values[]={rectangle.left,rectangle.top,rectangle.right,rectangle.bottom};
    spx_observe_object(observer,NULL); spx_observe_u32s(observer,"mark",values,4); spx_observe_end(observer);
}
static void paddle_setup(void) {
    play.paddle_x=509; play.paddle_y=450; play.gun=0;
    play.balls=(play_balls){0}; play.shots=(play_shots){0}; play.events=(play_events){0};
    play_to_native();
    for (unsigned i=1;i<sizeof(paddle_sprites)/sizeof(*paddle_sprites);++i) {
        paddle_sprites[i][0]=i;
        *play_word(0x433d18+i*4)=(uint32_t)(uintptr_t)&paddle_sprites[i];
    }
    *play_word(0x434968)=0; *play_word(0x431c78)=73; *play_word(0x431c84)=68;
    *play_word(0x431c64)=0; *play_word(0x42ca50)=0; *play_word(0x431c70)=0;
    paddle_vtable[7]=(uint32_t)(uintptr_t)paddle_blit; paddle_surface=(uint32_t)(uintptr_t)paddle_vtable;
    *play_word(0x41c728)=(uint32_t)(uintptr_t)&paddle_surface;
    DWORD old,ignored; REQUIRE(VirtualProtect((void *)0x415174,4,PAGE_READWRITE,&old));
    *play_word(0x415174)=(uint32_t)(uintptr_t)paddle_clock;
    REQUIRE(VirtualProtect((void *)0x415174,4,old,&ignored));
    REQUIRE(install_paddle_mark((void (*)(void))paddle_mark));
}
void play_draw_paddle(void *unused,play_state *s) {
    BEGIN0(PLAY_DRAW_PADDLE); spx_observe_array(observer,"drawing"); play_to_native();
    REQUIRE(spx_fixture_restore_entry(&install_play_service_draw_paddle_hook));
    ((void (*)(void))0x4067b0)();
    install_play_service_draw_paddle_hook.entry=NULL;
    REQUIRE(install_play_service_draw_paddle(native_draw_paddle)); play_from_native();
    spx_observe_end(observer); (void)end_call(0);
}
