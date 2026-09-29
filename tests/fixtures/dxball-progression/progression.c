#include "portable-component-implementation.h"
#include "progression-state.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

void lifted_progress_draw(spx_gameplay_progression_context_v5 *context,progression_state *state) {
    const spx_gameplay_progression_services_v5 *s=context->services;
    pickup_state *pickups=state->paddle->pickups;
    play_state *play=pickups->motion->play;
    title_state *title=play->menu->scene->animation;
    char number[11]; snprintf(number,sizeof(number),"%" PRIu32,play->menu->score);
    uint32_t length=(uint32_t)strlen(number); font_bytes bytes={(const unsigned char *)number};
    font_rect region={20,0,20+35*length,32};
    s->blit_fast(s->context,state,title->back,20,0,title->flow->overlay,&region,16);
    s->destination(s->context,state,title->back);
    s->text(s->context,state,30,31,length,&bytes);
    s->damage(s->context,state,&region);
    uint32_t lives=pickups->lives;
    if (play_signed(lives)>10) lives=10;
    region=(font_rect){598-22*lives,0,620,16};
    s->blit_fast(s->context,state,title->back,region.left,0,title->flow->overlay,&region,16);
    if (play_signed(pickups->lives)>20) pickups->lives=20;
    uint32_t x=598,y=2;
    for (uint32_t i=1;play_signed(i)<=play_signed(pickups->lives-1);++i) {
        s->sprite(s->context,state,31,x,y); x-=22;
        if (i==10) { x=598; y+=8; }
    }
    s->damage(s->context,state,&region);
}
void lifted_progress_refresh(spx_gameplay_progression_context_v5 *context,progression_state *state) {
    pickup_state *pickups=state->paddle->pickups;
    menu_state *menu=pickups->motion->play->menu;
    /* The existing next_life field is the native cached score. */
    if (pickups->next_life==menu->score) return;
    if (menu->score>999999999) menu->score=0;
    lifted_progress_draw(context,state); pickups->next_life=menu->score;
}
uint32_t lifted_progress_count(spx_gameplay_progression_context_v5 *context,progression_state *state) {
    (void)context; const board *board=state->paddle->pickups->motion->board;
    uint32_t count=0;
    for (unsigned column=0;column<20;++column) for (unsigned row=0;row<20;++row)
        if (board->cells[row][column] && board->cells[row][column]!=2) ++count;
    return count;
}
void lifted_progress_next(spx_gameplay_progression_context_v5 *context,progression_state *state) {
    flow_state *flow=state->paddle->pickups->motion->play->menu->scene->animation->flow;
    ++state->bricks->board_index; state->pending=state->board_changed=1;
    if (play_signed(state->bricks->board_index)>49) { flow->transition_pending=1; flow->next_scene=3; }
    else context->services->load_board(context->services->context,state);
    if (!lifted_progress_count(context,state)) {
        state->paddle->pickups->lives=0; flow->transition_pending=1; flow->next_scene=3;
    }
}
void lifted_progress_lose(spx_gameplay_progression_context_v5 *context,progression_state *state) {
    const spx_gameplay_progression_services_v5 *s=context->services;
    pickup_state *pickups=state->paddle->pickups;
    --pickups->lives; pickups->next_life=999999999;
    s->stop_sound(s->context,state,14);
    uint32_t pan=s->pan(s->context,state,pickups->motion->play->paddle_x);
    s->play_sound(s->context,state,14,0,pan,0); state->pending=1;
}
void lifted_progress_over(spx_gameplay_progression_context_v5 *context,progression_state *state) {
    context->services->wait(context->services->context,state,30);
    flow_state *flow=state->paddle->pickups->motion->play->menu->scene->animation->flow;
    flow->transition_pending=1; flow->next_scene=3;
}
void lifted_progress_restart(spx_gameplay_progression_context_v5 *context,progression_state *state) {
    const spx_gameplay_progression_services_v5 *s=context->services;
    paddle_state *paddle=state->paddle; pickup_state *pickups=paddle->pickups;
    motion_state *motion=pickups->motion; play_state *play=motion->play;
    play->remaining_bricks=lifted_progress_count(context,state);
    s->redraw(s->context,state);
    asset_name name={"mbbkgrnd.pcx"}; s->palette(s->context,state,&name);
    s->fade(s->context,state,1,6,0,255,1);
    motion->sticky=play->gun=play->slow_balls=play->speedup_balls=play->fire_balls=play->split_balls=0;
    motion->pierce=play->power_balls=motion->gravity=motion->paddle_power=play->warning_sound=0;
    s->stop_sound(s->context,state,21);
    play->paddle_x=play->menu->scene->mouse_x-(uint32_t)(play_signed(motion->paddle_width)/2);
    state->warning_y=2; state->warning_frames=0;
    paddle->spark_deadline=paddle->spark_sprite=paddle->spark_width=0;
    play->paddle_y=450; play->old_paddle_x=play->old_paddle_y=0;
    pickups->paddle_sprite=68; motion->paddle_width=font_width(motion_sprite(motion,68));
    motion->ball_count=pickups->count=play->last_tick=play->launch_pressed=play->shot_count=0;
    s->create_ball(s->context,state); play->balls.current->attached=1;
    state->board_changed=state->pending=0;
}
void lifted_progress_advance(spx_gameplay_progression_context_v5 *context,progression_state *state) {
    const spx_gameplay_progression_services_v5 *s=context->services;
    pickup_state *pickups=state->paddle->pickups; play_state *play=pickups->motion->play;
    title_state *title=play->menu->scene->animation;
    if (state->pending!=1) return;
    if (!state->board_changed) {
        for (unsigned i=0;i<256;++i) {
            unsigned char *entry=title->palettes->staged[i];
            unsigned average=((unsigned)entry[0]+entry[1]+entry[2])/3;
            entry[0]=entry[1]=entry[2]=(unsigned char)average;
        }
        s->fade(s->context,state,1,3,0,255,1);
    }
    s->fade(s->context,state,1,6,0,255,0);
    s->clear(s->context,state,title->back,0);
    s->clear(s->context,state,title->flow->primary,0);
    memset(play->pending_cells,0,sizeof(play->pending_cells));
    s->clear_objects(s->context,state); s->reset_damage(s->context,state);
    if (title->flow->next_scene==3) return;
    if (play_signed(pickups->lives)<1) lifted_progress_over(context,state);
    else lifted_progress_restart(context,state);
}
