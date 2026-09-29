#include "portable-component-implementation.h"
#include "explosion-state.h"

void lifted_explosion_reset(spx_explosion_lifecycle_context_v5 *context,explosion_state *state)
{
    (void)context;
    state->roots->current=state->roots->first=NULL;
    state->last=NULL; state->retained=0;
}

void lifted_explosion_create(spx_explosion_lifecycle_context_v5 *context,explosion_state *state,uint32_t x,uint32_t y)
{
    explosion *item=context->services->allocate(context->services->context,state);
    if (item) {
        item->next=NULL; item->previous=state->last;
        if (state->last) state->last->next=item; else state->roots->first=(void *)item;
        state->last=item; state->roots->current=(void *)item;
    } else context->services->terminate(context->services->context,state,1);
    item=explosion_current(state); item->x=x-24; item->y=y-23; item->frame=0;
    if (play_signed(item->x)<0) item->x=0;
    if (play_signed(item->x+44)>639) item->x=595;
    if (play_signed(item->y)<0) item->y=0;
    if (play_signed(item->y+43)>479) item->y=436;
}

void lifted_explosion_draw(spx_explosion_lifecycle_context_v5 *context,explosion_state *state)
{
    const spx_explosion_lifecycle_services_v5 *services=context->services;
    state->roots->current=state->roots->first;
    while (explosion_current(state)) {
        explosion *item=explosion_current(state);
        services->sprite(services->context,state,item->frame+145,item->x,item->y);
        item=explosion_current(state);
        if (play_signed(++item->frame)>=22) {
            if (item->previous) item->previous->next=item->next;
            if (item->next) { item->next->previous=item->previous; state->roots->current=(void *)item->next; }
            else state->roots->current=(void *)item->previous;
            if (item==explosion_first(state)) state->roots->first=(void *)item->next;
            if (item==state->last) state->last=item->previous;
            services->free(services->context,state,item);
        }
        /* Preserve the native extra advance after unlinking an expired object. */
        item=explosion_current(state);
        if (!item) break;
        state->roots->current=(void *)item->next;
        if (!state->roots->current) { state->roots->current=state->roots->first; break; }
    }
}
