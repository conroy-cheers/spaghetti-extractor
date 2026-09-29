#include "portable-component-implementation.h"
#include "motion-state.h"
#include <stdlib.h>

static uint32_t magnitude(uint32_t value) {
    return play_signed(value)<0 ? 0-value : value;
}
static uint32_t scaled(uint32_t value,double factor) {
    volatile double product=(double)play_signed(value)*factor;
    return (uint32_t)(int64_t)product;
}
static uint32_t angle_index(uint32_t angle) {
    return play_signed(angle)<0 ? 360-(0-angle)%360 : angle%360;
}
static void sound(spx_ball_motion_context_v5 *context,motion_state *state,uint32_t id) {
    const spx_ball_motion_services_v5 *services=context->services;
    services->stop_sound(services->context,state,id);
    uint32_t pan=services->pan(services->context,state,state->play->balls.current->x);
    services->play_sound(services->context,state,id,0,pan,0);
}
static void count_bounce(motion_state *state) {
    ++state->play->balls.current->retained;
    ++state->play->balls.current->tick;
}

void lifted_motion_rebound(spx_ball_motion_context_v5 *context,motion_state *state) {
    play_state *play=state->play;
    play_ball *ball=play->balls.current;
    uint32_t center=ball->x+font_half(font_width(motion_sprite(state,ball->sprite)));
    double left=(double)play_signed(play->paddle_x)-(double)play_signed(font_half(state->paddle_width));
    volatile float position=(float)(((double)play_signed(center)-left)/(double)play_signed(state->paddle_width));
    if (position<=0.07) { ball->angle=150; sound(context,state,16); }
    else if (position<=0.20) ball->angle=135;
    else if (position<=0.35) ball->angle=120;
    else if (position<=0.50) ball->angle=105;
    else if (position<=0.65) ball->angle=75;
    else if (position<=0.80) ball->angle=60;
    else if (position<=0.93) ball->angle=45;
    else { ball->angle=30; sound(context,state,16); }
    ball=play->balls.current;
    if (play_signed(ball->angle)>30 && play_signed(ball->angle)<150)
        ball->y=play->paddle_y-font_height(motion_sprite(state,ball->sprite));
    volatile double dx=(double)play->cosine[angle_index(ball->angle)]/1024.0;
    dx=dx*(double)play_signed(ball->speed); dx=dx*1.2;
    ball->dx=(uint32_t)(int64_t)dx;
    volatile double dy=(double)play->sine[angle_index(ball->angle)]/1024.0;
    dy=dy*(double)play_signed(ball->speed);
    ball->dy=(uint32_t)(int64_t)-dy;
}

void lifted_motion_create(spx_ball_motion_context_v5 *context,motion_state *state) {
    play_state *play=state->play;
    ++state->ball_count;
    play_ball *ball=context->services->allocate(context->services->context,state);
    if (!ball) exit(1);
    ball->next=NULL; ball->previous=play->balls.last;
    if (play->balls.last) play->balls.last->next=ball;
    else play->balls.first=ball;
    play->balls.last=play->balls.current=ball;
    ball->sprite=1; ball->x=play->paddle_x+1;
    ball->y=play->paddle_y-font_height(motion_sprite(state,ball->sprite));
    ball->old_x=ball->x; ball->old_y=ball->y;
    ball->dx=ball->dy=ball->angle=0; ball->speed=5;
    ball->retained=ball->attached=ball->auxiliary=ball->tick=0;
    lifted_motion_rebound(context,state);
}

void lifted_motion_remove(spx_ball_motion_context_v5 *context,motion_state *state) {
    if (play_signed(state->ball_count)<=0) return;
    play_balls *balls=&state->play->balls;
    play_ball *ball=balls->current;
    if (ball) {
        if (ball->previous) ball->previous->next=ball->next;
        if (ball->next) { ball->next->previous=ball->previous; balls->current=ball->next; }
        else balls->current=ball->previous;
        if (ball==balls->first) balls->first=ball->next;
        if (ball==balls->last) balls->last=ball->previous;
        context->services->free(context->services->context,state,ball);
    }
    --state->ball_count;
}

uint32_t lifted_motion_contact(spx_ball_motion_context_v5 *context,motion_state *state,uint32_t x,uint32_t y) {
    if (play_signed(y)<50 || play_signed(y)>349) return 0;
    int64_t column=play_signed(x-20)/30,row=play_signed(y-50)/15;
    if (column<0) column=0; else if (column>19) column=19;
    if (row<0) row=0; else if (row>19) row=19;
    unsigned char *cell=&state->board->cells[row][column];
    if (!*cell) return 0;
    const spx_ball_motion_services_v5 *services=context->services;
    if (state->play->balls.current->sprite==61) {
        if (*cell==2) ++state->play->remaining_bricks;
        *cell=8;
        if (!state->pierce) services->explosion(services->context,state,x,y);
    }
    if (services->hit(services->context,state,(uint32_t)column,(uint32_t)row))
        state->play->menu->score+=2*state->play->balls.current->speed;
    return 1;
}

static void trail(spx_ball_motion_context_v5 *context,motion_state *state) {
    const spx_ball_motion_services_v5 *services=context->services;
    play_state *play=state->play;
    play_ball *ball=play->balls.current;
    if (ball->sprite!=61) return;
    uint32_t limit=(play->menu->scene->animation->fast ? 14u : 11u)-ball->speed;
    if (services->random(services->context,state,limit)) return;
    ball=play->balls.current;
    uint32_t dy=font_half(ball->dy),dx=font_half(ball->dx);
    uint32_t y=services->random(services->context,state,font_height(motion_sprite(state,61)));
    y+=play->balls.current->y;
    uint32_t x=services->random(services->context,state,font_width(motion_sprite(state,61)));
    x+=play->balls.current->x;
    services->particle(services->context,state,x,y,dx,dy,95,0);
}

static void paddle_collision(spx_ball_motion_context_v5 *context,motion_state *state) {
    const spx_ball_motion_services_v5 *services=context->services;
    play_state *play=state->play;
    play_ball *ball=play->balls.current;
    font_sprite *sprite=motion_sprite(state,ball->sprite);
    uint32_t half=font_half(state->paddle_width);
    font_rect paddle={play->old_paddle_x-half,play->old_paddle_y,play->old_paddle_x+half,play->old_paddle_y+7};
    font_rect bounds={ball->x,ball->y,ball->x+font_width(sprite),ball->y+font_height(sprite)};
    if (!services->overlap(services->context,state,&paddle,&bounds)) return;
    ball=play->balls.current;
    if (play_signed(ball->dy)<=0) return;
    ball->tick=0;
    if (play_signed(ball->retained)>40) {
        ++ball->speed; if (play_signed(ball->speed)>9) ball->speed=9;
        ball->retained=0;
    }
    if (state->paddle_power==1) services->paddle_power(services->context,state);
    if (state->sticky==1) {
        sound(context,state,18); ball=play->balls.current;
        ball->attached=1; ball->auxiliary=ball->x-play->paddle_x;
        uint32_t sign=play_signed(ball->auxiliary)>0 ? 1 : UINT32_MAX;
        uint32_t maximum=scaled(state->paddle_width,0.4);
        if (play_signed(magnitude(ball->auxiliary))>play_signed(maximum)) {
            ball->auxiliary=maximum*sign;
            ball->auxiliary-=font_half(font_width(motion_sprite(state,ball->sprite)));
        }
        return;
    }
    sound(context,state,0); lifted_motion_rebound(context,state);
    if (play_signed(play->balls.current->speed)<=7) return;
    uint32_t pan=services->pan(services->context,state,play->balls.current->x);
    services->play_sound(services->context,state,15,0,pan,0);
    uint32_t count=play->menu->scene->animation->fast ? 6 : 10;
    for (uint32_t i=0;i<count;++i) {
        uint32_t dy=UINT32_MAX-services->random(services->context,state,3);
        uint32_t dx=3-services->random(services->context,state,7);
        ball=play->balls.current;
        services->particle(services->context,state,ball->x,ball->y,dx,dy,176,1);
    }
}

static void brick_collisions(spx_ball_motion_context_v5 *context,motion_state *state) {
    play_state *play=state->play;
    play_ball *ball=play->balls.current;
    state->impact_dx=ball->dx; state->impact_dy=font_half(ball->dy);
    font_sprite *sprite=motion_sprite(state,ball->sprite);
    uint32_t x=ball->x+font_half(font_width(sprite)),y=ball->y;
    int upwards=play_signed(ball->dy)<0;
    if (!upwards) y+=font_height(sprite);
    if (lifted_motion_contact(context,state,x,y)) {
        ball=play->balls.current;
        if (!state->pierce) {
            uint32_t remainder=(uint32_t)(play_signed(y-50)%15);
            ball->dy=upwards ? magnitude(ball->dy) : 0-magnitude(ball->dy);
            ball->y+=upwards ? 15-remainder : 0-remainder;
        }
        count_bounce(state);
    }
    ball=play->balls.current;
    int leftwards=play_signed(ball->dx)<0;
    for (unsigned sample=0;sample<2;++sample) {
        ball=play->balls.current; sprite=motion_sprite(state,ball->sprite);
        x=leftwards ? ball->x-2 : ball->x+font_width(sprite)+2;
        y=ball->y-scaled(font_height(sprite),sample ? -0.85 : -0.15);
        if (lifted_motion_contact(context,state,x,y)) {
            ball=play->balls.current;
            if (!state->pierce) ball->dx=leftwards ? magnitude(ball->dx) : 0-magnitude(ball->dx);
            count_bounce(state); break;
        }
    }
}

void lifted_motion_update(spx_ball_motion_context_v5 *context,motion_state *state) {
    const spx_ball_motion_services_v5 *services=context->services;
    play_state *play=state->play;
    play->balls.current=play->balls.first;
    if (!play->balls.current) { services->lose_life(services->context,state); return; }
    do {
        play_ball *ball=play->balls.current;
        if (ball->attached) {
            if (play->launch_pressed==1) { ball->attached=0; lifted_motion_rebound(context,state); }
            play->changed=1; ball=play->balls.current;
            ball->old_x=ball->x; ball->old_y=ball->y;
            ball->x=play->paddle_x+ball->auxiliary;
            ball->y=play->paddle_y-font_height(motion_sprite(state,ball->sprite));
        } else {
            ball->old_x=ball->x; ball->old_y=ball->y;
            ball->x+=ball->dx; ball->y+=ball->dy;
            if (state->gravity) ++ball->y;
            trail(context,state); ball=play->balls.current;
            if (play_signed(ball->y)>play_signed(479-font_height(motion_sprite(state,ball->sprite)))) {
                sound(context,state,5); lifted_motion_remove(context,state);
            } else {
                if (play_signed(ball->x)<20) {
                    ball->x=20; ball->dx=magnitude(ball->dx); sound(context,state,4); count_bounce(state);
                }
                ball=play->balls.current;
                uint32_t right=619-font_width(motion_sprite(state,ball->sprite));
                if (play_signed(ball->x)>play_signed(right)) {
                    ball->x=right; ball->dx=0-magnitude(ball->dx); sound(context,state,4); count_bounce(state);
                }
                ball=play->balls.current;
                if (play_signed(ball->y)<0) {
                    ball->y=0; ball->dy=magnitude(ball->dy); sound(context,state,4); count_bounce(state);
                }
                paddle_collision(context,state); brick_collisions(context,state);
                if (play_signed(play->balls.current->tick)>300) {
                    services->unstick(services->context,state); play->balls.current->tick=0;
                }
            }
        }
        /* Removal and callbacks can change the cursor. Advance from that live
         * cursor, preserving the original extra advance after deletion. */
        if (!play->balls.current) break;
        play->balls.current=play->balls.current->next;
        if (!play->balls.current) { play->balls.current=play->balls.first; break; }
    } while (1);
}
