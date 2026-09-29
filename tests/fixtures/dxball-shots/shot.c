#include "portable-component-implementation.h"
#include "motion-state.h"

void lifted_shot_remove(spx_shot_lifecycle_context_v5 *context,motion_state *state)
{
    play_shots *shots=&state->play->shots;
    play_shot *shot=shots->current;
    if (shot) {
        if (shot->previous) shot->previous->next=shot->next;
        if (shot->next) { shot->next->previous=shot->previous; shots->current=shot->next; }
        else shots->current=shot->previous;
        if (shot==shots->first) shots->first=shot->next;
        if (shot==shots->last) shots->last=shot->previous;
        context->services->free(context->services->context,state,(void *)shot);
    }
    --state->play->shot_count;
}

void lifted_shot_fire(spx_shot_lifecycle_context_v5 *context,motion_state *state)
{
    const spx_shot_lifecycle_services_v5 *services=context->services;
    play_state *play=state->play;
    for (unsigned side=0;side<2;++side) {
        play_shot *shot=(void *)services->allocate(services->context,state);
        if (shot) {
            shot->next=NULL; shot->previous=play->shots.last;
            if (play->shots.last) play->shots.last->next=shot; else play->shots.first=shot;
            play->shots.last=play->shots.current=shot;
        } else services->terminate(services->context,state,1);
        uint32_t half=font_half(font_width(motion_sprite(state,32)));
        volatile double offset=(double)play_signed(state->paddle_width)*(side ? 0.43 : -0.425);
        play->shots.current->x=play->paddle_x+(uint32_t)(int64_t)offset-half;
        play->shots.current->y=play->paddle_y-font_half(font_height(motion_sprite(state,32)));
    }
    play->shot_count+=2;
    services->stop_sound(services->context,state,17);
    uint32_t pan=services->pan(services->context,state,play->shots.current->x);
    services->play_sound(services->context,state,17,0,pan,0);
}

void lifted_shot_update(spx_shot_lifecycle_context_v5 *context,motion_state *state)
{
    const spx_shot_lifecycle_services_v5 *services=context->services;
    play_state *play=state->play;
    play_shots *shots=&play->shots;
    shots->current=shots->first;
    while (shots->current) {
        play_shot *shot=shots->current;
        shot->old_x=shot->x; shot->old_y=shot->y; shot->y-=8;
        uint32_t random=services->random(services->context,state,3);
        state->impact_dy=UINT32_C(0xfffffffe); state->impact_dx=1-random;
        shot=shots->current;
        uint32_t column=(uint32_t)(play_signed(shot->x+font_half(font_width(motion_sprite(state,32)))-20)/30);
        int64_t row=play_signed(shot->y-50)/15;
        if (play_signed(shot->y)<0) lifted_shot_remove(context,state);
        else if (row>=0 && row<20 && ((unsigned char *)state->board)[(uint32_t)row*20+column]) {
            if (!state->pierce) lifted_shot_remove(context,state);
            if (services->hit(services->context,state,column,(uint32_t)row)) play->menu->score+=4;
        }
        /* Removal already changes current; the native loop advances once more. */
        if (!shots->current) break;
        shots->current=shots->current->next;
        if (!shots->current) { shots->current=shots->first; break; }
    }
}
