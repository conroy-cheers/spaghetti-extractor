#include "portable-component-implementation.h"
#include "warning-state.h"

void lifted_warning_prepare(spx_last_brick_warning_context_v5 *context,warning_state *state)
{
    const spx_last_brick_warning_services_v5 *services=context->services;
    void *user=services->context;
    progression_state *progress=state->progression;
    motion_state *motion=progress->bricks->motion;
    play_state *play=motion->play;
    warning_input fallback=state->fallback;
    if (!play->warning_sound) {
        uint32_t random=services->random(user,state,20000);
        uint32_t now=services->now(user,state);
        play->warning_sound=random+now+40000;
    }
    uint32_t now=services->now(user,state),remaining=play->warning_sound-now;
    if (font_signed(remaining)>=1) {
        uint32_t half=remaining/2;
        if (half<3) half=3;
        services->loop_sound(user,state,21,0,0,0-half/3);
        return;
    }
    services->stop_sound(user,state,21);
    services->play_sound(user,state,22,0,0,0);
    uint32_t column=fallback.column,row=fallback.row,x=fallback.column,y=fallback.y;
    for (uint32_t c=0;c<20;++c) for (uint32_t r=0;r<20;++r) {
        unsigned char cell=motion->board->cells[r][c];
        if (cell && cell!=2) { column=c;row=r;x=35+30*c;y=57+15*r; }
    }
    services->queue(user,state,column,row);
    services->explosion(user,state,x,y);
    unsigned count=play->menu->scene->animation->fast ? 15 : 30;
    for (unsigned i=0;i<count;++i) {
        uint32_t dy=4-services->random(user,state,11);
        uint32_t dx=6-services->random(user,state,14);
        uint32_t py=y-7+services->random(user,state,15);
        uint32_t px=x-15+services->random(user,state,30);
        services->particle(user,state,px,py,dx,dy,16,1);
    }
    services->select_bank(user,state,2);
    font_sprite *sprite=motion_sprite(motion,1);
    uint32_t width=font_width(sprite),height=font_height(sprite);
    x-=font_half(width);y-=height;
    font_rect bounds={0,0,width,height};
    if (font_signed(x)<0) { bounds.left=0-x;x=0; }
    if (font_signed(x+width)>639) bounds.right=639-x;
    if (font_signed(y)<0) { bounds.top=0-y;y=0; }
    if (font_signed(y+height)>479) bounds.bottom=479-y;
    state->x=x;progress->warning_y=y;state->rectangle=bounds;
    progress->warning_frames=4;play->warning_sound=0;
    services->select_bank(user,state,0);
}

void lifted_warning_draw(spx_last_brick_warning_context_v5 *context,warning_state *state)
{
    progression_state *progress=state->progression;
    if (font_signed(progress->warning_frames)<=0) return;
    const spx_last_brick_warning_services_v5 *services=context->services;
    void *user=services->context;
    motion_state *motion=progress->bricks->motion;
    services->select_bank(user,state,2);
    font_sprite *sprite=motion_sprite(motion,1);
    services->blit_fast(user,state,motion->play->menu->scene->animation->software,
        state->x,progress->warning_y,sprite->surface,&state->rectangle,17);
    font_rect damage={state->x,progress->warning_y,state->x+state->rectangle.right,
        progress->warning_y+state->rectangle.bottom};
    services->damage(user,state,&damage);
    services->select_bank(user,state,0);
    --progress->warning_frames;
}
