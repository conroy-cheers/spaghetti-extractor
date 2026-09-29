#include "portable-component-implementation.h"
#include "display-state.h"
#include <stddef.h>

enum { FAIL_DRAW,FAIL_COOPERATIVE,FAIL_MODE,FAIL_PRIMARY,FAIL_ATTACHED,
       FAIL_BACK,FAIL_CLIPPER,FAIL_CLIPPER_WINDOW,FAIL_ATTACH_PRIMARY,FAIL_ATTACH_FLIP };

static const char *failure_text(uint32_t fullscreen,uint32_t stage) {
    switch (stage) {
    case FAIL_DRAW: return "Direct X could not initialize. (DX Object failed)";
    case FAIL_COOPERATIVE: return fullscreen ?
        "Direct X could not initialize. (Exclusive/Fullscreen failed)" :
        "Direct X could not initialize.(Coop Normal failed)";
    case FAIL_MODE: return "Direct X could not initialize. (640x480 failed)";
    case FAIL_PRIMARY: return fullscreen ?
        "Direct X could not initialize. (Primary Failed)" :
        "Direct X could not initialize. (Primary failed)";
    case FAIL_BACK: return "Direct X could not initialize. (Offscreen failed)";
    case FAIL_CLIPPER: return "Direct X could not initialize.(Clipper failed)";
    case FAIL_CLIPPER_WINDOW: return "Direct X could not initialize. (Clipper SetHWnd failed)";
    default: return "Direct X could not initialize. (Clipper->Primary failed)";
    }
}

static uint32_t failed(spx_display_setup_context_v5 *context,display_state *state,
                       uint32_t fullscreen,uint32_t stage) {
    const spx_display_setup_services_v5 *services=context->services;
    void *user=services->context;
    if (!fullscreen || stage<=FAIL_PRIMARY) {
        asset_name text={failure_text(fullscreen,stage)},caption={"DX-Ball"};
        services->show_window(user,state,state->window,0);
        services->message(user,state,state->window,&text,&caption,0);
    }
    services->destroy_window(user,state,state->window);
    return 0;
}

static uint32_t initialize(spx_display_setup_context_v5 *context,display_state *state,
                           shell_handle *instance,uint32_t show,display_history *history,uint32_t fullscreen) {
    const spx_display_setup_services_v5 *services=context->services;
    void *user=services->context;
    shell_state *application=state->application;
    scene_state *scene=application->scene;
    title_state *title=scene->animation;
    asset_name name={"DX-Ball"};
    display_class window_class={.style=3,.events=state->events,.instance=instance,.menu=&name,.name=&name};
    window_class.icon=services->load_icon(user,state,instance,32512);
    window_class.cursor=services->load_cursor(user,state,NULL,32512);
    window_class.brush=services->stock_object(user,state,4);
    services->register_class(user,state,&window_class);
    state->window=services->create_window(user,state,instance,&name,UINT32_C(0x80000000),640,480);
    if (!state->window) return 0;
    services->show_window(user,state,state->window,show);
    services->update_window(user,state,state->window);
    services->focus_window(user,state,state->window);
    services->show_window(user,state,state->window,0);
    services->initialize_sound(user,state,state->window);
    services->show_window(user,state,state->window,5);
    if (services->create_draw(user,state)) return failed(context,state,fullscreen,FAIL_DRAW);
    if (services->cooperative(user,state,application->graphics,state->window,fullscreen ? 17 : 8))
        return failed(context,state,fullscreen,FAIL_COOPERATIVE);
    if (fullscreen && services->display_mode(user,state,application->graphics,640,480,8))
        return failed(context,state,fullscreen,FAIL_MODE);
    scene->presentation_mode=fullscreen ? 0 : 1;
    if (!fullscreen) state->damage->capability=0;
    display_caps caps={380,history->capability_flags,history->video_memory};
    services->capabilities(user,state,application->graphics,&caps);
    scene->no_hardware=(caps.flags>>25)&1U;
    if (fullscreen) {
        title->fast=scene->no_hardware;
        if (!scene->no_hardware && caps.video_memory<310000) {
            title->fast=1;scene->low_memory=1;
        }
    }
    display_surface descriptor={.size=108,.flags=1,.caps=0x200};
    if (fullscreen && state->damage->capability) {
        descriptor.flags=0x21;descriptor.caps=0x218;descriptor.backbuffers=state->damage->capability;
    }
    if (services->create_surface(user,state,application->graphics,&descriptor,0))
        return failed(context,state,fullscreen,FAIL_PRIMARY);
    if (fullscreen && state->damage->capability &&
        services->attached_surface(user,state,title->primary,4))
        return failed(context,state,fullscreen,FAIL_ATTACHED);
    descriptor.flags=7;descriptor.caps=0x40;descriptor.height=480;descriptor.width=640;
    if (services->create_surface(user,state,application->graphics,&descriptor,1))
        return failed(context,state,fullscreen,FAIL_BACK);
    if (state->damage->clipped==1) {
        if (services->create_clipper(user,state,application->graphics))
            return failed(context,state,fullscreen,FAIL_CLIPPER);
        if (services->clipper_window(user,state,state->clipper,state->window,0))
            return failed(context,state,fullscreen,FAIL_CLIPPER_WINDOW);
        if (services->attach_clipper(user,state,title->primary,state->clipper))
            return failed(context,state,fullscreen,FAIL_ATTACH_PRIMARY);
        if (fullscreen && scene->flip && services->attach_clipper(user,state,scene->flip,state->clipper))
            return failed(context,state,fullscreen,FAIL_ATTACH_FLIP);
    }
    /* Private native helpers at 0x40bc90 and 0x40bd60. Clearing a table does
     * not dispose its former objects, and the six retained words survive. */
    for (unsigned bank=0;bank<3;++bank) {
        for (unsigned slot=0;slot<255;++slot) title->font->objects->banks[bank].slots[slot]=NULL;
        title->font->objects->banks[bank].count=0;
    }
    title->font->destination=title->primary;
    return 1;
}

uint32_t lifted_display_windowed(spx_display_setup_context_v5 *context,display_state *state,
                                 shell_handle *instance,uint32_t show,display_history *history) {
    return initialize(context,state,instance,show,history,0);
}
uint32_t lifted_display_fullscreen(spx_display_setup_context_v5 *context,display_state *state,
                                   shell_handle *instance,uint32_t show,display_history *history) {
    return initialize(context,state,instance,show,history,1);
}
