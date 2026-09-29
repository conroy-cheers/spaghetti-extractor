#include "portable-component-implementation.h"
#include "setup-state.h"
#include <stddef.h>

enum { CREATE_FAILED,NO_DRIVER,BUSY,COOPERATIVE_FAILED,PRIMARY_FAILED,PLAY_FAILED };
static const char *message_text(uint32_t reason) {
    switch (reason) {
    case CREATE_FAILED:return "Direct X failed to start the sound system.  \nDo you wish to continue this application without sound?";
    case NO_DRIVER:return "Direct X can not find your sound card.  \nDo you wish to continue this application without sound?";
    case BUSY:return "Another Windows application has control of the sound system. \nABORT will exit.  RETRY will attempt to get sound system after other application releases it.  IGNORE will continue without sound effects.";
    case COOPERATIVE_FAILED:return "Direct X sound system failed to get the proper cooperation level with another application.  \nDo you wish to continue this program without sound?";
    case PRIMARY_FAILED:return "Direct X sound system failed to initialize. \n (lpPrimaryBuffer create) \nDo you wish to continue this program without sound?";
    default:return "Direct X sound system failed to initialize. \n (lpPrimaryBuffer playLooping) \nDo you wish to continue this program without sound?";
    }
}
static uint32_t ask(spx_audio_setup_context_v5 *context,audio_setup_state *state,shell_handle *window,uint32_t reason) {
    audio_name text={message_text(reason)},caption={"DX-Ball"};
    return context->services->message(context->services->context,state,window,&text,&caption,reason==BUSY ? 0x42 : 0x24);
}
static void release_device(spx_audio_setup_context_v5 *context,audio_setup_state *state) {
    context->services->release_device(context->services->context,state,state->bank->device);
    state->bank->device=NULL;
}
void lifted_audio_focus(spx_audio_setup_context_v5 *context,audio_setup_state *state,shell_handle *window) {
    const spx_audio_setup_services_v5 *services=context->services;
    void *user=services->context;
    audio_state *bank=state->bank;
    if (bank->device) return;
    for (;;) {
        uint32_t result=services->create_device(user,state);
        if (!result) break;
        if (state->application->graphics) { bank->device=NULL;return; }
        if (result==UINT32_C(0x8878000a)) {
            uint32_t answer=ask(context,state,window,BUSY);
            if (answer==3) services->terminate(user,state,10);
            if (answer==5) { bank->device=NULL;return; }
        } else {
            uint32_t no_driver=result==UINT32_C(0x88780078);
            if (ask(context,state,window,no_driver ? NO_DRIVER : CREATE_FAILED)==7)
                services->terminate(user,state,no_driver ? 11 : 12);
            bank->device=NULL;return;
        }
    }
    if (services->cooperative(user,state,bank->device,window,1)) {
        if (!state->application->graphics && ask(context,state,window,COOPERATIVE_FAILED)==7)
            services->terminate(user,state,13);
        release_device(context,state);return;
    }
    audio_buffer_spec primary={20,1,0,0,NULL};
    if (services->create_primary(user,state,bank->device,&primary)) {
        if (!state->application->graphics && ask(context,state,window,PRIMARY_FAILED)==7)
            services->terminate(user,state,13);
        if (bank->primary) {
            services->release_buffer(user,state,bank->primary);
            bank->primary=NULL;
        }
        release_device(context,state);return;
    }
    if (services->play_primary(user,state,bank->primary,1)) {
        if (!state->application->graphics && ask(context,state,window,PLAY_FAILED)==7)
            services->terminate(user,state,13);
        services->release_buffer(user,state,bank->primary);
        bank->primary=NULL;release_device(context,state);return;
    }
    for (unsigned slot=0;slot<50;++slot) {
        if (!bank->slots[slot]) continue;
        char saved_name[256];unsigned i=0;
        do { saved_name[i]=(char)bank->slots[slot]->payload[i]; } while (saved_name[i++]);
        audio_name name={saved_name};
        services->load_sample(user,state,slot,&name);
    }
}
void lifted_audio_initialize(spx_audio_setup_context_v5 *context,audio_setup_state *state,shell_handle *window) {
    context->services->release_all(context->services->context,state);
    lifted_audio_focus(context,state,window);
}
