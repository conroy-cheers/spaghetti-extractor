#include "portable-component-implementation.h"
#include "shell-state.h"
#include <stdlib.h>

shell_handle *lifted_shell_acquire(spx_application_shell_context_v5 *context,shell_state *state) {
    asset_name application_name={"DX-Ball"};
    const spx_application_shell_services_v5 *services=context->services;
    void *user=services->context;
    if (services->open_semaphore(user,state,2,0,&application_name)) return NULL;
    state->instance_lock=services->create_semaphore(user,state,1,0,1,&application_name);
    return state->instance_lock;
}

void lifted_shell_release(spx_application_shell_context_v5 *context,shell_state *state) {
    if (state->instance_lock) {
        context->services->close_handle(context->services->context,state,state->instance_lock);
        state->instance_lock=NULL;
    }
}

uint32_t lifted_shell_run(spx_application_shell_context_v5 *context,shell_state *state,
                          shell_handle *instance,uint32_t show) {
    const spx_application_shell_services_v5 *services=context->services;
    void *user=services->context;
    if (!lifted_shell_acquire(context,state)) {
        asset_name application_name={"DX-Ball"};
        asset_name already_running={"DX-Ball is already running."};
        services->message_box(user,state,NULL,&already_running,&application_name,0);
        services->terminate(user,state,0);
        abort(); /* The selected exit service never returns. */
    }
    uint32_t initialized=state->scene->animation->flow->windowed ?
        services->windowed_graphics(user,state,instance,show) :
        services->fullscreen_graphics(user,state,instance,show);
    if (!initialized) return 0;
    services->initialize_clock(user,state);
    services->initialize_trig(user,state);
    state->control=state->shift=0;
    services->cursor_position(user,state,&state->cursor);
    state->scene->mouse_buttons=0;
    state->scene->mouse_x=state->cursor.x;state->scene->mouse_y=state->cursor.y;
    shell_message message;
    for (;;) {
        if (services->peek_message(user,state,&message)) {
            /* The original treats GetMessage's -1 result as nonzero too. */
            if (!services->get_message(user,state,&message)) return message.wparam;
            services->translate_message(user,state,&message);
            services->dispatch_message(user,state,&message);
        } else if (state->active) services->frame(user,state);
        else services->wait_message(user,state);
    }
}

uint32_t lifted_shell_event(spx_application_shell_context_v5 *context,shell_state *state,
                            shell_handle *window,uint32_t message,uint32_t wparam,uint32_t lparam) {
    const spx_application_shell_services_v5 *services=context->services;
    void *user=services->context;
    title_state *title=state->scene->animation;
    flow_state *flow=title->flow;
    switch (message) {
    case SHELL_CREATE: case SHELL_ERASE_BACKGROUND: return 0;
    case SHELL_DESTROY:
        services->shutdown(user,state,0);
        services->stop_sounds(user,state);
        services->stop_music(user,state);
        if (state->graphics) {
            services->clear_sprites(user,state);
            if (title->back) { services->release_surface(user,state,title->back);title->back=NULL; }
            if (title->primary) {
                services->release_surface(user,state,title->primary);
                title->primary=NULL;state->scene->flip=NULL;
            }
            if (state->palette) { services->release_palette(user,state,state->palette);state->palette=NULL; }
            /* The original clears the DirectDraw pointer without Release. */
            state->graphics=NULL;
        }
        lifted_shell_release(context,state);
        services->post_quit(user,state,wparam);
        return 0;
    case SHELL_FOCUS_GAIN:
        state->suspended=0;
        if (state->graphics) services->focus_sounds(user,state,window);
        services->resume_music(user,state);
        return 0;
    case SHELL_FOCUS_LOSS:
        if (!state->suspended) services->suspend_sounds(user,state);
        services->pause_music(user,state);flow->refresh_needed=1;
        return 0;
    case SHELL_ACTIVATE:
        state->active=wparam;state->control=state->shift=0;return 0;
    case SHELL_SET_CURSOR:
        services->set_cursor(user,state,NULL);return 1;
    case SHELL_POWER:
        if (wparam==1) state->suspended=1;
        if (wparam==2 || wparam==3) state->suspended=0;
        return 0;
    case SHELL_KEY_DOWN:
        if (wparam==27) {
            if (!flow->scene) {
                services->leave_scene(user,state,1);
                services->post_message(user,state,window,16,0,0);
            } else { flow->transition_pending=1;flow->next_scene=0; }
        } else services->key(user,state,wparam);
        if (wparam==17) state->control=1;
        if (wparam==16) state->shift=1;
        return 0;
    case SHELL_KEY_UP:
        if (wparam==17) state->control=0;
        if (wparam==16) state->shift=0;
        return 0;
    case SHELL_MOUSE_MOVE:
        services->cursor_position(user,state,&state->cursor);
        state->scene->mouse_x=state->cursor.x;state->scene->mouse_y=state->cursor.y;
        break;
    case SHELL_LEFT_DOWN: case SHELL_RIGHT_DOWN:
        services->capture(user,state,window);state->scene->mouse_buttons=message==SHELL_LEFT_DOWN ? 1 : 2;return 0;
    case SHELL_LEFT_UP: case SHELL_RIGHT_UP:
        services->release_capture(user,state);state->scene->mouse_buttons=0;return 0;
    case SHELL_POWER_BROADCAST:
        if (wparam==0 || wparam==4) state->suspended=1;
        if (wparam==2 || wparam==6 || wparam==7) state->suspended=0;
        return 0;
    case SHELL_QUERY_PALETTE:
        if (state->graphics && title->primary && !flow->first_frame)
            services->palette_entries(user,state,state->palette,title->palettes);
        return 0;
    default: break;
    }
    return services->default_event(user,state,window,message,wparam,lparam);
}
