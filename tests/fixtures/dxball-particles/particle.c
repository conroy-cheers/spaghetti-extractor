#include "portable-component-implementation.h"
#include "particle-state.h"

static int next_particle(particle_state *state)
{
    if (state->current) {
        state->current=state->current->next;
        if (state->current) return 1;
        state->current=state->first;
    }
    return 0;
}

static void remove_particle(spx_particle_lifecycle_context_v5 *context,particle_state *state)
{
    particle *item=state->current;
    if (!item) return;
    if (item->previous) item->previous->next=item->next;
    if (item->next) {
        item->next->previous=item->previous;
        state->current=item->next;
    } else state->current=item->previous;
    if (item==state->first) state->first=item->next;
    if (item==state->last) state->last=item->previous;
    context->services->free(context->services->context,state,item);
}

void lifted_particle_create(spx_particle_lifecycle_context_v5 *context,particle_state *state,
                            uint32_t x,uint32_t y,uint32_t dx,uint32_t dy,uint32_t color,uint32_t gravity)
{
    if (font_signed(x)<=20 || font_signed(x)>=619 || font_signed(y)<=0 || font_signed(y)>=479) return;
    const spx_particle_lifecycle_services_v5 *services=context->services;
    particle *item=services->allocate(services->context,state);
    if (item) {
        item->next=NULL;
        item->previous=state->last;
        if (state->last) state->last->next=item;
        else state->first=item;
        state->current=state->last=item;
    } else services->terminate(services->context,state,1);
    item=state->current;
    item->x=x; item->y=y; item->dx=dx; item->dy=dy;
    item->color=color; item->age=0; item->color_tick=0;
    item->gravity=gravity; item->gravity_tick=0;
}

void lifted_particle_update(spx_particle_lifecycle_context_v5 *context,particle_state *state)
{
    state->current=state->first;
    if (!state->current) return;
    do {
        particle *item=state->current;
        item->x+=item->dx;
        item->y+=item->dy;
        if (item->gravity==1 && font_signed(++item->gravity_tick)>5) {
            ++item->dy;
            item->gravity_tick=0;
        }
        if (font_signed(item->x)<20 || font_signed(item->x)>618 ||
            font_signed(item->y)<0 || font_signed(item->y)>478) remove_particle(context,state);
        else if (font_signed(++item->color_tick)>4) {
            item->color_tick=0;
            ++item->color;
            if (font_signed(++item->age)>6) remove_particle(context,state);
        }
    } while (next_particle(state));
}

void lifted_particle_draw(spx_particle_lifecycle_context_v5 *context,particle_state *state)
{
    state->current=state->first;
    if (!state->current) return;
    const spx_particle_lifecycle_services_v5 *services=context->services;
    void *user=services->context;
    pcx_view view={0};
    services->describe(user,state,*state->destination,&view);
    while (services->lock(user,state,*state->destination,&view)) {}
    do {
        particle *item=state->current;
        unsigned char *pixel=view.image.pixels+(size_t)item->y*view.image.pitch+item->x;
        pixel[0]=pixel[1]=(unsigned char)item->color;
        pixel[view.image.pitch]=pixel[view.image.pitch+1]=(unsigned char)state->current->color;
        item=state->current;
        font_rect bounds={item->x,item->y,item->x+2,item->y+2};
        services->damage(user,state,&bounds);
    } while (next_particle(state));
    services->unlock(user,state,*state->destination);
}
