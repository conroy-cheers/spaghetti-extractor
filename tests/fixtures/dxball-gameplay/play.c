#include "portable-component-implementation.h"
#include "play-state.h"

static uint32_t angle_index(uint32_t angle)
{
    return play_signed(angle)<0 ? 360-(0-angle)%360 : angle%360;
}

static void set_velocity(play_state *state,play_ball *ball)
{
    uint32_t x_sign=play_signed(ball->dx)>0 ? 1 : UINT32_MAX;
    uint32_t y_sign=play_signed(ball->dy)>0 ? 1 : UINT32_MAX;
    uint32_t index=angle_index(ball->angle);
    /* Materialize the target's binary64 operations before integer truncation. */
    volatile double horizontal=(double)state->cosine[index]/1024.0;
    horizontal=horizontal*(double)play_signed(ball->speed);
    horizontal=horizontal*1.2;
    volatile double vertical=(double)state->sine[index]/1024.0;
    vertical=vertical*(double)play_signed(ball->speed);
    uint32_t dx=(uint32_t)(int64_t)horizontal,dy=(uint32_t)(int64_t)-vertical;
    if (play_signed(dx)<0) dx=0-dx;
    if (play_signed(dy)<0) dy=0-dy;
    ball->dx=dx*x_sign;
    ball->dy=dy*y_sign;
}

static int next_ball(play_balls *balls)
{
    if (balls->current) {
        balls->current=balls->current->next;
        if (balls->current) return 1;
        balls->current=balls->first;
    }
    return 0;
}

static int next_shot(play_shots *shots)
{
    if (shots->current) {
        shots->current=shots->current->next;
        if (shots->current) return 1;
        shots->current=shots->first;
    }
    return 0;
}

static int next_event(play_events *events)
{
    if (events->current) {
        events->current=events->current->next;
        if (events->current) return 1;
        events->current=events->first;
    }
    return 0;
}

static void remove_event(spx_gameplay_frame_context_v5 *context,play_state *state)
{
    play_events *events=&state->events;
    play_event *event=events->current;
    if (!event) return;
    if (event->previous) event->previous->next=event->next;
    if (event->next) {
        event->next->previous=event->previous;
        events->current=event->next;
    } else events->current=event->previous;
    if (event==events->first) events->first=event->next;
    if (event==events->last) events->last=event->previous;
    context->services->free_event(context->services->context,state,event);
}

void lifted_play_update(spx_gameplay_frame_context_v5 *context,play_state *state)
{
    const spx_gameplay_frame_services_v5 *services=context->services;
    void *user=services->context;
    scene_state *scene=state->menu->scene;
    if (state->paused==1) {
        if (services->elapsed(user,state,state->last_tick,32)) {
            services->cycle(user,state,224,231,1);
            state->last_tick=services->now(user,state);
        }
        return;
    }
    state->changed=0;
    services->refresh_score(user,state);
    services->move_paddle(user,state);
    services->move_balls(user,state);
    services->move_shots(user,state);
    services->move_pickups(user,state);
    services->move_trails(user,state);
    if (scene->presentation_mode) services->wait(user,state,1);
    services->restore_damage(user,state);
    state->old_paddle_x=state->paddle_x;
    state->old_paddle_y=state->paddle_y;
    services->advance_brick_effects(user,state);
    state->shots.current=state->shots.first;
    if (state->shots.current) do {
        play_shot *shot=state->shots.current;
        services->sprite(user,state,32,shot->x,shot->y);
    } while (next_shot(&state->shots));
    services->draw_explosions(user,state);
    services->draw_paddle(user,state);
    state->balls.current=state->balls.first;
    if (state->balls.current) do {
        play_ball *ball=state->balls.current;
        services->sprite(user,state,ball->sprite,ball->x,ball->y);
    } while (next_ball(&state->balls));
    services->draw_pickups(user,state);
    services->draw_trails(user,state);
    if (state->remaining_bricks==1) services->prepare_last_brick(user,state);
    else if (play_signed(state->remaining_bricks)>1 && state->warning_sound) {
        state->warning_sound=0;
        services->stop_sound(user,state,21);
    }
    services->draw_last_brick(user,state);
    if (!scene->presentation_mode) services->present(user,state);
    if (services->elapsed(user,state,state->last_tick,20)) {
        services->cycle(user,state,224,231,1);
        state->last_tick=services->now(user,state);
    }
    state->events.current=state->events.first;
    if (state->events.current) do {
        play_event *event=state->events.current;
        if (event->kind==1 && !services->read_pending(user,state,event->column,event->row)) {
            services->hit_tile(user,state,event->column,event->row);
            state->menu->score+=4;
            uint32_t dx=services->random(user,state,5)-2;
            event=state->events.current;
            services->spawn_debris(user,state,event->column,event->row,dx,UINT32_C(0xfffffffe));
        }
        remove_event(context,state);
        /* The native loop advances again after unlinking. Keep this behavior,
         * including the intervening node that survives a multi-node batch. */
    } while (next_event(&state->events));
    if (state->voice_pending==1) {
        uint32_t sound=services->random(user,state,3)+30;
        services->stop_sound(user,state,sound);
        services->play_sound(user,state,sound,0,0,0);
        state->voice_pending=0;
    }
    if (state->slow_balls==1) {
        state->balls.current=state->balls.first;
        if (state->balls.current) do {
            play_ball *ball=state->balls.current;
            ball->speed=4;
            set_velocity(state,ball);
            if (ball->sprite!=61) ball->sprite=1;
        } while (next_ball(&state->balls));
        state->slow_balls=0;
    }
    if (state->speedup_balls==1) {
        state->balls.current=state->balls.first;
        if (state->balls.current) do {
            play_ball *ball=state->balls.current;
            ball->speed+=2;
            if (play_signed(ball->speed)>9) ball->speed=9;
            set_velocity(state,ball);
        } while (next_ball(&state->balls));
        state->speedup_balls=0;
    }
    if (state->fire_balls==1) {
        state->balls.current=state->balls.first;
        if (state->balls.current) do {
            state->balls.current->sprite=55;
        } while (next_ball(&state->balls));
        state->fire_balls=0;
    }
    if (state->split_balls==1) {
        services->split(user,state);
        state->split_balls=0;
    }
    if (state->power_balls==1) {
        services->power(user,state);
        state->power_balls=0;
    }
    if (play_signed(state->remaining_bricks)<=0) {
        state->brick_effects.current=state->brick_effects.first;
        if (!state->brick_effects.current) {
            state->explosions.current=state->explosions.first;
            if (!state->explosions.current) services->next_board(user,state);
        }
    }
    services->advance_stage(user,state);
    if (scene->mouse_buttons==1) {
        state->launch_pressed=1;
        if (state->gun==1 && play_signed(state->shot_count)<6) services->fire(user,state);
        scene->mouse_buttons=0;
    } else {
        state->launch_pressed=0;
        if (scene->mouse_buttons==2) scene->mouse_buttons=0;
    }
}
