#include "portable-component-implementation.h"
#include "audio-state.h"
#include <stddef.h>

void lifted_audio_restore(spx_audio_bank_context_v5 *context,audio_state *state,audio_history *history) {
    const spx_audio_bank_services_v5 *services=context->services;
    void *user=services->context;
    if (!state->device) return;
    audio_status_word status={history->restore_status};
    for (unsigned slot=0;slot<50;++slot) {
        if (!state->slots[slot]) continue;
        services->status(user,state,state->slots[slot]->buffer,&status);
        if (!(status.flags&2) || services->restore_buffer(user,state,state->slots[slot]->buffer)) continue;
        char saved_name[256];
        unsigned i=0;
        do { saved_name[i]=(char)state->slots[slot]->payload[i]; } while (saved_name[i++]);
        audio_name name={saved_name};
        services->load_sample(user,state,slot,&name);
    }
}

static void play(spx_audio_bank_context_v5 *context,audio_state *state,audio_history *history,
                 uint32_t slot,uint32_t frequency,uint32_t pan,uint32_t volume,uint32_t flags) {
    const spx_audio_bank_services_v5 *services=context->services;
    void *user=services->context;
    if (!state->device || !state->slots[slot]) return;
    if (frequency) services->frequency(user,state,state->slots[slot]->buffer,frequency);
    if (pan) services->pan(user,state,state->slots[slot]->buffer,pan);
    if (volume) services->volume(user,state,state->slots[slot]->buffer,volume);
    uint32_t result=services->play(user,state,state->slots[slot]->buffer,flags);
    if (result==2 || result==UINT32_C(0x88780096)) {
        lifted_audio_restore(context,state,history);
        (void)services->play(user,state,state->slots[slot]->buffer,flags);
    }
}

void lifted_audio_play(spx_audio_bank_context_v5 *context,audio_state *state,audio_history *history,
                       uint32_t slot,uint32_t frequency,uint32_t pan,uint32_t volume) {
    play(context,state,history,slot,frequency,pan,volume,0);
}
void lifted_audio_loop(spx_audio_bank_context_v5 *context,audio_state *state,audio_history *history,
                       uint32_t slot,uint32_t frequency,uint32_t pan,uint32_t volume) {
    play(context,state,history,slot,frequency,pan,volume,1);
}
void lifted_audio_stop(spx_audio_bank_context_v5 *context,audio_state *state,audio_history *history,uint32_t slot) {
    const spx_audio_bank_services_v5 *services=context->services;
    void *user=services->context;
    if (!state->device || !state->slots[slot]) return;
    /* GetStatus writes into the original argument slot; its HRESULT is ignored. */
    audio_status_word status={slot};
    services->status(user,state,state->slots[slot]->buffer,&status);
    if (status.flags&2) lifted_audio_restore(context,state,history);
    services->stop(user,state,state->slots[slot]->buffer);
    services->position(user,state,state->slots[slot]->buffer,0);
}
void lifted_audio_stop_all(spx_audio_bank_context_v5 *context,audio_state *state,audio_history *history) {
    for (unsigned slot=0;slot<50;++slot) lifted_audio_stop(context,state,history,slot);
}
void lifted_audio_release_one(spx_audio_bank_context_v5 *context,audio_state *state,audio_history *history,uint32_t slot) {
    const spx_audio_bank_services_v5 *services=context->services;
    void *user=services->context;
    (void)history;
    if (!state->slots[slot]) return;
    if (state->device && state->slots[slot]->buffer) {
        services->release_buffer(user,state,state->slots[slot]->buffer);
        state->slots[slot]->buffer=NULL;
    }
    services->free_sample(user,state,state->slots[slot]);
    state->slots[slot]=NULL;
}
void lifted_audio_release_all(spx_audio_bank_context_v5 *context,audio_state *state,audio_history *history) {
    for (unsigned slot=0;slot<50;++slot) lifted_audio_release_one(context,state,history,slot);
}
void lifted_audio_suspend(spx_audio_bank_context_v5 *context,audio_state *state,audio_history *history) {
    const spx_audio_bank_services_v5 *services=context->services;
    void *user=services->context;
    lifted_audio_stop_all(context,state,history);
    for (unsigned slot=0;slot<50;++slot) {
        if (!state->slots[slot] || !state->slots[slot]->buffer) continue;
        services->release_buffer(user,state,state->slots[slot]->buffer);
        state->slots[slot]->buffer=NULL;
    }
    if (state->primary) {
        services->release_buffer(user,state,state->primary);
        state->primary=NULL;
    }
    if (state->device) {
        services->release_device(user,state,state->device);
        state->device=NULL;
    }
}
void lifted_audio_shutdown(spx_audio_bank_context_v5 *context,audio_state *state,audio_history *history) {
    lifted_audio_release_all(context,state,history);
    lifted_audio_suspend(context,state,history);
}
