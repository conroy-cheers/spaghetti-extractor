#include "portable-component-implementation.h"
#include "brick-state.h"
#include <stdlib.h>
#include <string.h>

static brick_effect *append_effect(spx_brick_actions_context_v5 *context,brick_state *state) {
    brick_effect *effect=context->services->allocate_effect(context->services->context,state);
    if (!effect) exit(1);
    effect->next=NULL; effect->previous=state->last;
    if (state->last) state->last->next=effect;
    else state->first=effect;
    state->last=state->current=effect;
    return effect;
}
static void append_event(spx_brick_actions_context_v5 *context,brick_state *state,uint32_t column,uint32_t row) {
    play_state *play=state->motion->play;
    play->voice_pending=1;
    play_event *event=context->services->allocate_event(context->services->context,state);
    if (!event) exit(1);
    event->next=NULL; event->previous=play->events.last;
    if (play->events.last) play->events.last->next=event;
    else play->events.first=event;
    play->events.last=play->events.current=event;
    event->kind=1; event->column=column; event->row=row;
}
static void remove_effect(spx_brick_actions_context_v5 *context,brick_state *state) {
    brick_effect *effect=state->current;
    if (!effect) return;
    if (effect->previous) effect->previous->next=effect->next;
    if (effect->next) { effect->next->previous=effect->previous; state->current=effect->next; }
    else state->current=effect->previous;
    if (effect==state->first) state->first=effect->next;
    if (effect==state->last) state->last=effect->previous;
    context->services->free_effect(context->services->context,state,effect);
}

void lifted_brick_reset(spx_brick_actions_context_v5 *context,brick_state *state) {
    memset(state->motion->play->pending_cells,0,400);
    context->services->select_board(context->services->context,state,state->board_index);
}
void lifted_brick_queue(spx_brick_actions_context_v5 *context,brick_state *state,uint32_t column,uint32_t row) {
    if (context->services->read_cell(context->services->context,state,column,row))
        append_event(context,state,column,row);
}
void lifted_brick_blast(spx_brick_actions_context_v5 *context,brick_state *state,uint32_t column,uint32_t row) {
    brick_effect *effect=append_effect(context,state);
    effect->kind=1; effect->sprite=22; effect->x=20+30*column; effect->y=50+15*row;
    effect->frames=8; effect->delay=effect->tick=0;
    context->services->write_pending(context->services->context,state,column,row,1);
}
void lifted_brick_flash(spx_brick_actions_context_v5 *context,brick_state *state,
                        uint32_t column,uint32_t row,uint32_t tile,uint32_t transient) {
    brick_effect *effect=append_effect(context,state);
    effect->kind=2; effect->x=column; effect->y=row; effect->tile=(unsigned char)tile;
    effect->frames=transient ? 2 : 3; effect->sprite=transient ? 19 : 20;
    effect->delay=effect->tick=2;
    if (!transient) context->services->debris(context->services->context,state,column,row,
        state->motion->impact_dx,state->motion->impact_dy);
}
static void sound(spx_brick_actions_context_v5 *context,brick_state *state,uint32_t id,uint32_t pan) {
    const spx_brick_actions_services_v5 *services=context->services;
    services->stop_sound(services->context,state,id);
    services->play_sound(services->context,state,id,0,pan,0);
}
static void sparks(spx_brick_actions_context_v5 *context,brick_state *state,uint32_t column,uint32_t row) {
    const spx_brick_actions_services_v5 *services=context->services;
    uint32_t count=brick_title(state)->fast ? 4 : 8;
    for (uint32_t i=0;i<count;++i) {
        uint32_t dy=2-services->random(services->context,state,5);
        uint32_t dx=2-services->random(services->context,state,5);
        uint32_t y=50+15*row+services->random(services->context,state,15);
        uint32_t x=20+30*column+services->random(services->context,state,30);
        services->particle(services->context,state,x,y,dx,dy,119,1);
    }
}
uint32_t lifted_brick_hit(spx_brick_actions_context_v5 *context,brick_state *state,uint32_t column,uint32_t row) {
    const spx_brick_actions_services_v5 *services=context->services;
    uint32_t result=1,pan=services->pan(services->context,state,20+30*column);
    unsigned char *cell=&state->motion->board->cells[row][column];
    uint32_t tile=*cell;
    play_state *play=state->motion->play;
    switch (tile) {
    case 0: break;
    case 2:
        lifted_brick_flash(context,state,column,row,tile,1);
        if (state->motion->pierce) *cell=0; else result=0;
        sound(context,state,3,pan);
        break;
    case 3: case 4: case 7:
        lifted_brick_flash(context,state,column,row,tile,1);
        *cell=(unsigned char)(tile==7 ? 6 : tile+1);
        if (state->motion->pierce) { *cell=0; --play->remaining_bricks; }
        sound(context,state,tile==7 ? 19 : 1,pan);
        if (tile==7) sparks(context,state,column,row);
        break;
    case 8:
        append_event(context,state,column,row);
        break;
    case 21:
        lifted_brick_flash(context,state,column,row,tile,1);
        *cell=state->motion->pierce ? 0 : 2;
        sound(context,state,1,pan); --play->remaining_bricks;
        break;
    default:
        if (tile<=22) {
            lifted_brick_flash(context,state,column,row,tile,0); *cell=0;
            sound(context,state,7,pan); --play->remaining_bricks;
        } else *cell=0;
        break;
    }
    services->destination(services->context,state,brick_title(state)->back);
    services->cell(services->context,state,column,row,0);
    return result;
}

void lifted_brick_step_blast(spx_brick_actions_context_v5 *context,brick_state *state) {
    const spx_brick_actions_services_v5 *services=context->services;
    brick_effect *effect=state->current;
    ++effect->tick;
    if (play_signed(effect->tick)<play_signed(effect->delay)) return;
    --effect->frames;
    if (effect->frames==5) {
        uint32_t column=(uint32_t)(play_signed(effect->x-20)/30);
        uint32_t row=(uint32_t)(play_signed(effect->y-50)/15);
        if (services->read_cell(services->context,state,column,row)==8) {
            if (play_signed(row-1)>=0) {
                lifted_brick_queue(context,state,column,row-1);
                if (play_signed(column-1)>=0) lifted_brick_queue(context,state,column-1,row-1);
                if (play_signed(column+1)<20) lifted_brick_queue(context,state,column+1,row-1);
            }
            if (play_signed(row+1)<20) {
                lifted_brick_queue(context,state,column,row+1);
                if (play_signed(column-1)>=0) lifted_brick_queue(context,state,column-1,row+1);
                if (play_signed(column+1)<20) lifted_brick_queue(context,state,column+1,row+1);
            }
            if (play_signed(column-1)>=0) lifted_brick_queue(context,state,column-1,row);
            if (play_signed(column+1)<20) lifted_brick_queue(context,state,column+1,row);
        }
        uint32_t tile=services->read_cell(services->context,state,column,row);
        if (tile && tile!=2) --state->motion->play->remaining_bricks;
        services->write_cell(services->context,state,column,row,0);
    }
    effect=state->current;
    if (play_signed(effect->frames)<=0) {
        font_rect rectangle={effect->x,effect->y,effect->x+30,effect->y+15};
        services->blit_fast(services->context,state,brick_title(state)->back,effect->x,effect->y,
            brick_title(state)->flow->overlay,&rectangle,16);
        services->erase(services->context,state,&rectangle);
        effect=state->current;
        uint32_t column=(uint32_t)(play_signed(effect->x-20)/30),row=(uint32_t)(play_signed(effect->y-50)/15);
        services->write_pending(services->context,state,column,row,0);
        remove_effect(context,state);
    } else {
        services->destination(services->context,state,brick_title(state)->primary);
        effect=state->current;
        if (brick_title(state)->fast) services->sprite_fast(services->context,state,effect->sprite,effect->x,effect->y);
        else services->sprite_opaque(services->context,state,effect->sprite,effect->x,effect->y);
        ++state->current->sprite; state->current->tick=0;
    }
}
void lifted_brick_step_flash(spx_brick_actions_context_v5 *context,brick_state *state) {
    const spx_brick_actions_services_v5 *services=context->services;
    brick_effect *effect=state->current;
    uint32_t x=20+30*effect->x,y=50+15*effect->y;
    font_rect rectangle={x,y,x+30,y+15};
    ++effect->tick;
    if (play_signed(effect->tick)<play_signed(effect->delay)) return;
    --effect->frames;
    int finished=play_signed(effect->frames)<=0;
    services->destination(services->context,state,brick_title(state)->back);
    effect=state->current;
    services->cell(services->context,state,effect->x,effect->y,0);
    if (finished) remove_effect(context,state);
    else {
        services->sprite_transparent(services->context,state,state->current->sprite,x,y);
        ++state->current->sprite; state->current->tick=0;
    }
    services->erase(services->context,state,&rectangle);
}
void lifted_brick_advance(spx_brick_actions_context_v5 *context,brick_state *state) {
    state->current=state->first;
    while (state->current) {
        if (state->current->kind==1) lifted_brick_step_blast(context,state);
        else if (state->current->kind==2) lifted_brick_step_flash(context,state);
        if (!state->current) break;
        state->current=state->current->next;
        if (!state->current) { state->current=state->first; break; }
    }
}
