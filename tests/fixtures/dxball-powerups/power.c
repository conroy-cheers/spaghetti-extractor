#include "portable-component-implementation.h"
#include "power-state.h"

static int next_ball(play_balls *list) {
    if (!list->current) return 0;
    list->current=list->current->next;
    if (list->current) return 1;
    list->current=list->first; return 0;
}
static int next_cell(play_events *list) {
    if (!list->current) return 0;
    list->current=list->current->next;
    if (list->current) return 1;
    list->current=list->first; return 0;
}
static void append_ball(play_balls *list,play_ball *ball) {
    ball->next=NULL; ball->previous=list->last;
    if (list->last) list->last->next=ball; else list->first=ball;
    list->last=list->current=ball;
}
static void copy_ball(play_ball *destination,const play_ball *source) {
    play_ball *next=destination->next,*previous=destination->previous;
    *destination=*source; destination->next=next; destination->previous=previous;
}
void lifted_power_split(spx_powerup_actions_context_v5 *context,powerup_state *state) {
    const spx_powerup_actions_services_v5 *s=context->services;
    play_balls *balls=&state->motion->play->balls,*staged=&state->staged_balls;
    balls->current=balls->first;
    if (balls->current) do {
        play_ball *ball=s->allocate_ball(s->context,state);
        if (ball) append_ball(staged,ball); else s->terminate(s->context,state,1);
        copy_ball(staged->current,balls->current);
        ball=staged->current;
        if (ball->attached==1 && play_signed(--ball->speed)<4) ball->speed=4;
        ball->dx=0-ball->dx;
    } while (next_ball(balls));
    staged->current=staged->first;
    if (staged->current) do {
        ++state->motion->ball_count;
        play_ball *ball=s->allocate_ball(s->context,state);
        if (ball) append_ball(balls,ball); else s->terminate(s->context,state,1);
        copy_ball(balls->current,staged->current);
    } while (next_ball(staged));
    while (staged->current) {
        play_ball *ball=staged->current;
        if (ball->previous) ball->previous->next=ball->next;
        if (ball->next) { ball->next->previous=ball->previous; staged->current=ball->next; }
        else staged->current=ball->previous;
        if (ball==staged->first) staged->first=ball->next;
        if (ball==staged->last) staged->last=ball->previous;
        s->free_ball(s->context,state,ball);
    }
}
static void expand_cell(spx_powerup_actions_context_v5 *context,powerup_state *state,uint32_t column,uint32_t row) {
    unsigned char *cell=&state->motion->board->cells[row][column];
    if (*cell==8) return;
    if (*cell==0 || *cell==2) ++state->motion->play->remaining_bricks;
    *cell=8;
    context->services->cell(context->services->context,state,column,row,0);
}
void lifted_power_expand(spx_powerup_actions_context_v5 *context,powerup_state *state) {
    const spx_powerup_actions_services_v5 *s=context->services;
    play_events *list=&state->queued_cells;
    for (uint32_t column=0;column<20;++column) for (uint32_t row=0;row<20;++row) {
        if (state->motion->board->cells[row][column]!=8) continue;
        play_event *item=s->allocate_cell(s->context,state);
        if (item) {
            item->next=NULL; item->previous=list->last;
            if (list->last) list->last->next=item; else list->first=item;
            list->last=list->current=item;
        } else s->terminate(s->context,state,1);
        list->current->column=column; list->current->row=row;
    }
    s->destination(s->context,state,state->motion->play->menu->scene->animation->back);
    list->current=list->first;
    if (list->current) do {
        uint32_t column=list->current->column,row=list->current->row;
        if (play_signed(column)>0) expand_cell(context,state,column-1,row);
        if (play_signed(column)<19) expand_cell(context,state,column+1,row);
        if (play_signed(row)>0) expand_cell(context,state,column,row-1);
        if (play_signed(row)<19) expand_cell(context,state,column,row+1);
    } while (next_cell(list));
    while (list->current) {
        play_event *item=list->current;
        if (item->previous) item->previous->next=item->next;
        if (item->next) { item->next->previous=item->previous; list->current=item->next; }
        else list->current=item->previous;
        if (item==list->first) list->first=item->next;
        if (item==list->last) list->last=item->previous;
        s->free_cell(s->context,state,item);
    }
}
void lifted_power_soften(spx_powerup_actions_context_v5 *context,powerup_state *state) {
    const spx_powerup_actions_services_v5 *s=context->services;
    state->motion->paddle_power=0;
    s->destination(s->context,state,state->motion->play->menu->scene->animation->back);
    for (uint32_t column=0;column<20;++column) for (uint32_t row=0;row<20;++row) {
        unsigned char *cell=&state->motion->board->cells[row][column];
        if (*cell==2 || *cell==21) {
            if (*cell==2) ++state->motion->play->remaining_bricks;
            *cell=20; s->cell(s->context,state,column,row,0);
        }
        if (*cell==7) { *cell=6; s->cell(s->context,state,column,row,0); }
        if (*cell==3 || *cell==4) { *cell=5; s->cell(s->context,state,column,row,0); }
    }
}
void lifted_power_detonate(spx_powerup_actions_context_v5 *context,powerup_state *state) {
    const spx_powerup_actions_services_v5 *s=context->services;
    for (uint32_t column=0;column<20;++column) for (uint32_t row=0;row<20;++row)
        if (state->motion->board->cells[row][column]==8 && s->hit(s->context,state,column,row))
            state->motion->play->menu->score+=4;
}
void lifted_power_super(spx_powerup_actions_context_v5 *context,powerup_state *state) {
    (void)context; play_balls *balls=&state->motion->play->balls;
    balls->current=balls->first;
    if (balls->current) do { balls->current->sprite=61; } while (next_ball(balls));
}
void lifted_power_drop(spx_powerup_actions_context_v5 *context,powerup_state *state) {
    const spx_powerup_actions_services_v5 *s=context->services;
    s->stop_sound(s->context,state,20); s->play_sound(s->context,state,20,0,0,0);
    int changed=0;
    for (uint32_t column=0;column<20;++column) for (int row=18;row>=0;--row) {
        unsigned char *from=&state->motion->board->cells[row][column],*to=&state->motion->board->cells[row+1][column];
        if (*from && !*to) { *to=*from; *from=0; changed=1; }
    }
    if (changed) {
        title_state *title=state->motion->play->menu->scene->animation;
        font_rect region={20,50,620,350};
        s->blit(s->context,state,title->back,&region,title->flow->overlay,&region,UINT32_C(0x1000000));
        s->destination(s->context,state,title->back);
        for (uint32_t column=0;column<20;++column) for (uint32_t row=0;row<20;++row)
            if (state->motion->board->cells[row][column]) s->cell(s->context,state,column,row,1);
        s->damage(s->context,state,&region);
    }
}
void lifted_power_release(spx_powerup_actions_context_v5 *context,powerup_state *state) {
    play_balls *balls=&state->motion->play->balls;
    balls->current=balls->first;
    if (balls->current) do {
        if (balls->current->attached==1) {
            balls->current->attached=0;
            context->services->rebound(context->services->context,state);
        }
    } while (next_ball(balls));
}
