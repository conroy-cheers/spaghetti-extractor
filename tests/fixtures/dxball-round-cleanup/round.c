#include "portable-component-implementation.h"
#include "round-state.h"

/* The executable instantiates this same unlink operation for several record
 * layouts. Keep typed access to the existing objects; dispose after unlinking. */
#define REMOVE(name,record_type,list_type) \
static int remove_##name(spx_round_cleanup_context_v5 *context,round_state *state,list_type *list) { \
    record_type *item=list->current; \
    if (!item) return 0; \
    if (item->previous) item->previous->next=item->next; \
    if (item->next) { item->next->previous=item->previous; list->current=item->next; } \
    else list->current=item->previous; \
    if (item==list->first) list->first=item->next; \
    if (item==list->last) list->last=item->previous; \
    context->services->free(context->services->context,state,(round_storage *)(void *)item); \
    return 1; \
}
REMOVE(shot,play_shot,play_shots)
REMOVE(ball,play_ball,play_balls)
REMOVE(brick,brick_effect,brick_state)
REMOVE(event,play_event,play_events)
REMOVE(pickup,pickup,pickup_state)
REMOVE(particle,particle,particle_state)
#undef REMOVE

static int remove_explosion(spx_round_cleanup_context_v5 *context,round_state *state) {
    explosion_state *list=state->explosions;
    explosion *item=explosion_current(list);
    if (!item) return 0;
    if (item->previous) item->previous->next=item->next;
    if (item->next) { item->next->previous=item->previous; list->roots->current=(void *)item->next; }
    else list->roots->current=(void *)item->previous;
    if (item==explosion_first(list)) list->roots->first=(void *)item->next;
    if (item==list->last) list->last=item->previous;
    context->services->free(context->services->context,state,(round_storage *)(void *)item);
    return 1;
}

void lifted_round_clear(spx_round_cleanup_context_v5 *context,round_state *state) {
    pickup_state *pickups=state->progression->paddle->pickups;
    play_state *play=pickups->motion->play;
    while (remove_shot(context,state,&play->shots)) {}
    while (remove_ball(context,state,&play->balls)) {}
    while (remove_brick(context,state,state->progression->bricks)) {}
    while (remove_event(context,state,&play->events)) {}
    while (remove_pickup(context,state,pickups)) {}
    while (remove_particle(context,state,state->particles)) {}
    while (remove_ball(context,state,&state->powers->staged_balls)) {}
    while (remove_event(context,state,&state->powers->queued_cells)) {}
    while (remove_explosion(context,state)) {}
}

void lifted_round_leave(spx_round_cleanup_context_v5 *context,round_state *state,uint32_t full) {
    const spx_round_cleanup_services_v5 *s=context->services;
    title_state *title=state->progression->paddle->pickups->motion->play->menu->scene->animation;
    if (full) {
        if (!state->progression->pending) s->fade(s->context,state,1,6,0,255,0);
        s->clear_surface(s->context,state,title->back,0);
        s->clear_surface(s->context,state,title->flow->primary,0);
        s->release_sounds(s->context,state);
        s->clear_sprites(s->context,state);
        s->stop_music(s->context,state);
    }
    lifted_round_clear(context,state);
}
