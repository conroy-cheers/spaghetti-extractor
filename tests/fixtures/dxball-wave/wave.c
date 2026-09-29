#include "portable-component-implementation.h"
#include "wave-state.h"
#include <stddef.h>
#include <string.h>

static uint32_t little_word(const unsigned char *p) {
    return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

uint32_t lifted_wave_parse(spx_wave_loader_context_v5 *context, wave_bytes *file, wave_result *result) {
    (void)context;
    const unsigned char *bytes=file->bytes;
    if (little_word(bytes)!=UINT32_C(0x46464952) || little_word(bytes+8)!=UINT32_C(0x45564157)) return 0;
    uint32_t end=little_word(bytes+4)+8;
    for (uint32_t cursor=12;cursor<end;) {
        uint32_t kind=little_word(bytes+cursor), length=little_word(bytes+cursor+4);
        cursor+=8;
        if (kind==UINT32_C(0x20746d66)) {
            if (length<14) return 0;
            result->format=bytes+cursor;
        } else if (kind==UINT32_C(0x61746164)) {
            result->data=bytes+cursor;
            result->length=length;
            return 1;
        }
        cursor+=(length+1)&~UINT32_C(1);
    }
    return 0;
}

void lifted_wave_load(spx_wave_loader_context_v5 *context, audio_state *state,
                     wave_history *history, uint32_t slot, audio_name *name) {
    const spx_wave_loader_services_v5 *services=context->services;
    void *user=services->context;
    services->release_one(user,state,slot);
    audio_sample *sample=services->allocate(user,state,37);
    if (!sample) services->terminate(user,1);
    state->slots[slot]=sample;
    wave_bytes *file=services->read_file(user,state,name,0,1);
    if (!file) {
        services->free_sample(user,state,state->slots[slot]);
        return;
    }
    wave_result result={history->format,NULL,0};
    if (!lifted_wave_parse(context,file,&result)) goto failed;
    if (state->device) {
        wave_buffer_spec spec={20,0xe2,result.length,0,result.format};
        if (services->create_buffer(user,state,state->device,state->slots[slot],&spec)) goto failed;
        wave_locked locked;
        if (services->lock(user,state,state->slots[slot]->buffer,result.length,&locked)) goto failed;
        memcpy(locked.first,result.data,locked.first_bytes);
        if (locked.second_bytes) memcpy(locked.second,result.data+locked.first_bytes,locked.second_bytes);
        services->unlock(user,state,state->slots[slot]->buffer,&locked);
        wave_word frequency={state->slots[slot]->payload+20};
        services->frequency(user,state,state->slots[slot]->buffer,&frequency);
        wave_word pan={state->slots[slot]->payload+24};
        services->pan(user,state,state->slots[slot]->buffer,&pan);
        wave_word volume={state->slots[slot]->payload+28};
        services->volume(user,state,state->slots[slot]->buffer,&volume);
    } else {
        state->slots[slot]->buffer=NULL;
    }
    services->free_file(user,state,file);
    strcpy((char *)state->slots[slot]->payload,name->text);
    return;
failed:
    services->free_file(user,state,file);
    services->free_sample(user,state,state->slots[slot]);
}
