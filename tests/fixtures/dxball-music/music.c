#include "portable-component-implementation.h"
#include "music-state.h"
#include <stddef.h>

void lifted_music_stop(spx_music_control_context_v5 *context,music_state *state) {
    const spx_music_control_services_v5 *s=context->services;
    if (state->current) {
        s->stop_stream(s->context,state,state->current->stream);
        s->release_stream(s->context,state,state->current->stream);
        s->free_record(s->context,state,state->current);
        state->current=NULL;
    }
}
uint32_t lifted_music_play(spx_music_control_context_v5 *context,music_state *state,
                           music_name *name,uint32_t start) {
    const spx_music_control_services_v5 *s=context->services;
    if (state->current) lifted_music_stop(context,state);
    music_record *record=s->allocate_record(s->context,state,8);
    state->current=record;
    if (s->load(s->context,state,record,name,0,1)) goto failed;
    state->current->playing=0;
    if (start) {
        if (s->start_stream(s->context,state,state->current->stream,1)) {
            s->release_stream(s->context,state,state->current->stream);
            goto failed;
        }
        state->current->playing=1;
    }
    return 1;
failed:
    s->free_record(s->context,state,state->current);
    state->current=NULL;
    return 0;
}
void lifted_music_resume(spx_music_control_context_v5 *context,music_state *state) {
    const spx_music_control_services_v5 *s=context->services;
    if (state->current && !s->start_stream(s->context,state,state->current->stream,1))
        state->current->playing=1;
}
void lifted_music_pause(spx_music_control_context_v5 *context,music_state *state) {
    const spx_music_control_services_v5 *s=context->services;
    if (state->current && !s->pause_stream(s->context,state,state->current->stream))
        state->current->playing=0;
}
