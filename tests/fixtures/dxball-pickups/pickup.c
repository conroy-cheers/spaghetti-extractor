#include "portable-component-implementation.h"
#include "pickup-state.h"
#include <stdlib.h>

static uint32_t magnitude(uint32_t value) { return play_signed(value)<0 ? 0-value : value; }
static int advance(pickup_state *state) {
    if (state->current) {
        state->current=state->current->next;
        if (state->current) return 1;
        state->current=state->first;
    }
    return 0;
}
static void sound(spx_pickup_lifecycle_context_v5 *context,pickup_state *state,uint32_t id) {
    const spx_pickup_lifecycle_services_v5 *s=context->services;
    uint32_t pan=s->pan(s->context,state,state->current->x);
    s->play_sound(s->context,state,id,0,pan,0);
}
void lifted_pickup_create(spx_pickup_lifecycle_context_v5 *context,pickup_state *state,
                          uint32_t column,uint32_t row,uint32_t dx,uint32_t dy) {
    const spx_pickup_lifecycle_services_v5 *s=context->services;
    uint32_t chance=s->random(s->context,state,10);
    if (play_signed(state->count)>=1 || play_signed(chance)>1) return;
    uint32_t x=19+30*column,y=50+15*row;
    s->stop_sound(s->context,state,2);
    uint32_t pan=s->pan(s->context,state,x);
    s->play_sound(s->context,state,2,0,pan,0);
    uint32_t particles=state->motion->play->menu->scene->animation->fast ? 8 : 15;
    for (uint32_t i=0;i<particles;++i) {
        uint32_t vy=2-s->random(s->context,state,7),vx=4-s->random(s->context,state,9);
        uint32_t py=y+s->random(s->context,state,15),px=x+s->random(s->context,state,30);
        s->particle(s->context,state,px,py,vx,vy,16,1);
    }
    pickup *item=s->allocate(s->context,state);
    if (!item) exit(1);
    item->next=NULL; item->previous=state->last;
    if (state->last) state->last->next=item; else state->first=item;
    state->last=state->current=item;
    item->x=x; item->y=y; item->dx=dx; item->dy=dy; item->tick=0;
    uint32_t kind=s->random(s->context,state,19);
    if (kind<19) {
        if (kind<2 && s->random(s->context,state,5)!=1) kind=13;
        if (kind==14) kind=10;
        state->current->kind=kind; state->current->sprite=35+kind;
    }
    ++state->count;
}
void lifted_pickup_remove(spx_pickup_lifecycle_context_v5 *context,pickup_state *state) {
    pickup *item=state->current;
    if (item) {
        if (item->previous) item->previous->next=item->next;
        if (item->next) { item->next->previous=item->previous; state->current=item->next; }
        else state->current=item->previous;
        if (item==state->first) state->first=item->next;
        if (item==state->last) state->last=item->previous;
        context->services->free(context->services->context,state,item);
    }
    --state->count;
}
static void collect(spx_pickup_lifecycle_context_v5 *context,pickup_state *state) {
    const spx_pickup_lifecycle_services_v5 *s=context->services;
    motion_state *motion=state->motion; play_state *play=motion->play;
    play->menu->score+=100;
    switch (state->current->kind) {
    case 0:
        state->next_life=999999999; ++state->lives; sound(context,state,13);
        play->gun=motion->sticky=motion->pierce=0; break;
    case 1: sound(context,state,8); s->next_board(s->context,state); break;
    case 2: sound(context,state,8); s->unstick(s->context,state); break;
    case 3: sound(context,state,8); play->slow_balls=1; motion->gravity=0; break;
    case 4: sound(context,state,8); s->queue_explosive_bricks(s->context,state); break;
    case 5: sound(context,state,8); motion->pierce=1; break;
    case 6: sound(context,state,8); s->detonate_bricks(s->context,state); break;
    case 7: sound(context,state,8); play->power_balls=1; break;
    case 8: sound(context,state,8); play->gun=1; break;
    case 9: sound(context,state,8); motion->sticky=1; break;
    case 10: {
        s->release_attached(s->context,state); sound(context,state,10);
        uint32_t width=font_width(motion_sprite(motion,state->paddle_sprite));
        if (play_signed(motion->paddle_width)<play_signed(width)) motion->paddle_width=width;
        else {
            motion->paddle_width+=width;
            if (play_signed(motion->paddle_width)>play_signed(width*4)) motion->paddle_width=width*4;
        }
        s->move_paddle(s->context,state); break;
    }
    case 11: {
        s->release_attached(s->context,state); sound(context,state,11);
        uint32_t width=font_width(motion_sprite(motion,state->paddle_sprite));
        if (play_signed(motion->paddle_width)<=play_signed(width)) motion->paddle_width=(uint32_t)(play_signed(width)/2);
        else motion->paddle_width-=width;
        s->move_paddle(s->context,state); break;
    }
    case 12: sound(context,state,12); play->split_balls=1; break;
    case 13: s->lose_life(s->context,state); break;
    case 14: case 15: sound(context,state,9); play->speedup_balls=1; break;
    case 16:
        s->release_attached(s->context,state); sound(context,state,11);
        motion->paddle_width=(uint32_t)(play_signed(font_width(motion_sprite(motion,state->paddle_sprite)))/2);
        s->move_paddle(s->context,state); break;
    case 17: sound(context,state,9); motion->paddle_power=1; break;
    case 18: sound(context,state,9); play->fire_balls=1; break;
    default: break;
    }
}
void lifted_pickup_update(spx_pickup_lifecycle_context_v5 *context,pickup_state *state) {
    const spx_pickup_lifecycle_services_v5 *s=context->services;
    motion_state *motion=state->motion; play_state *play=motion->play;
    state->current=state->first;
    if (state->current) do {
        pickup *item=state->current;
        item->x+=item->dx; item->y+=item->dy;
        if (play_signed(++item->tick)>20) { ++item->dy; item->tick=0; }
        if (play_signed(item->x)<20) {
            item->x=20; item->dx=magnitude(item->dx);
            s->stop_sound(s->context,state,4); sound(context,state,4);
        }
        item=state->current;
        uint32_t right=619-font_width(motion_sprite(motion,item->sprite));
        if (play_signed(item->x)>play_signed(right)) {
            item->x=right; item->dx=0-magnitude(item->dx);
            s->stop_sound(s->context,state,4); sound(context,state,4);
        }
        item=state->current;
        if (play_signed(item->y)<0) {
            item->y=0; item->dy=magnitude(item->dy);
            s->stop_sound(s->context,state,4); sound(context,state,4);
        }
        item=state->current;
        font_sprite *sprite=motion_sprite(motion,item->sprite);
        if (play_signed(item->y)>play_signed(478-font_height(sprite))) lifted_pickup_remove(context,state);
        else {
            uint32_t half=(uint32_t)(play_signed(motion->paddle_width)/2);
            font_rect paddle={play->old_paddle_x-half+5,play->old_paddle_y,play->old_paddle_x+half-5,play->old_paddle_y+7};
            font_rect bounds={item->x,item->y,item->x+font_width(sprite),item->y+font_height(sprite)};
            if (s->overlap(s->context,state,&paddle,&bounds)) {
                collect(context,state); lifted_pickup_remove(context,state);
            }
        }
    } while (advance(state));
}
void lifted_pickup_draw(spx_pickup_lifecycle_context_v5 *context,pickup_state *state) {
    state->current=state->first;
    if (state->current) do {
        pickup *item=state->current;
        context->services->sprite(context->services->context,state,item->sprite,item->x,item->y);
    } while (advance(state));
}
