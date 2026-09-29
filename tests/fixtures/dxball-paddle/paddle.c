#include "portable-component-implementation.h"
#include "paddle-state.h"

void lifted_paddle_move(spx_paddle_control_context_v5 *context,paddle_state *state)
{
    motion_state *motion=state->pickups->motion;
    play_state *play=motion->play;
    scene_state *scene=play->menu->scene;
    uint32_t half=font_half(motion->paddle_width),mouse=scene->mouse_x;
    play->paddle_y=450;
    play->paddle_x=mouse;
    if (font_signed(play->paddle_x)<font_signed(21+half)) play->paddle_x=21+half;
    if (font_signed(play->paddle_x)>font_signed(618-half)) play->paddle_x=618-half;
    if (!scene->animation->flow->windowed && play->paddle_x!=mouse) {
        context->services->cursor(context->services->context,state,play->paddle_x,scene->mouse_y);
        scene->mouse_x=play->paddle_x;
    }
    state->pickups->paddle_sprite=68;
}

void lifted_paddle_draw(spx_paddle_control_context_v5 *context,paddle_state *state)
{
    const spx_paddle_control_services_v5 *services=context->services;
    void *user=services->context;
    motion_state *motion=state->pickups->motion;
    play_state *play=motion->play;
    title_state *title=play->menu->scene->animation;
    uint32_t scale=(uint32_t)(font_signed(motion->paddle_width)/
        font_signed(font_width(motion_sprite(motion,state->pickups->paddle_sprite))));
    uint32_t sprite=state->phase+scale*4,offset;
    if (services->elapsed(user,state,state->last_tick,64)) {
        if (font_signed(++state->phase)>3) state->phase=0;
        state->last_tick=services->now(user,state);
    }
    uint32_t changed=play->changed;
    if (play->gun==1) { sprite+=104; offset=15; }
    else if (changed==1) { sprite+=84; offset=font_height(motion_sprite(motion,sprite))-14; }
    else { sprite+=64; offset=0; }
    if (changed==1) {
        uint32_t clock=services->clock(user,state);
        if (state->spark_deadline<clock || state->spark_width!=motion->paddle_width) {
            state->spark_sprite=services->random(user,state,4)+scale*4+124;
            state->spark_deadline=services->clock(user,state)+33;
            state->spark_width=motion->paddle_width;
        }
        uint32_t width=motion->paddle_width;
        volatile double scaled=(double)font_signed(width)*(play->gun==1 ? 0.075 : 0.03);
        uint32_t trim=(uint32_t)(int64_t)scaled;
        uint32_t x=play->paddle_x-font_half(width)+trim,y=play->paddle_y-14;
        font_sprite *spark=motion_sprite(motion,state->spark_sprite);
        uint32_t height=font_height(spark);
        font_rect source={trim,0,width-trim,height},damage={x,y,x+width,y+height};
        services->blit_fast(user,state,title->software,x,y,spark->surface,&source,17);
        services->damage(user,state,&damage);
    }
    services->sprite(user,state,sprite,play->paddle_x-font_half(motion->paddle_width),play->paddle_y-offset);
}
