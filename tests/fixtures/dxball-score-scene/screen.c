#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "portable-component-implementation.h"
#include "screen-state.h"
#include "screen-data.h"

static void draw_text(spx_score_scene_context_v5 *context, score_screen *state, uint32_t x, uint32_t y,
                      const unsigned char *data, uint32_t length, int centered) {
    font_bytes bytes={data}; const spx_score_scene_services_v5 *services=context->services;
    if (centered) services->center(services->context,state->menu->scene,x,y,length,&bytes);
    else services->text(services->context,state->menu->scene,x,y,length,&bytes);
}

static void show_scores(spx_score_scene_context_v5 *context, score_screen *state) {
    const spx_score_scene_services_v5 *services=context->services; void *user=services->context;
    scene_state *scene=state->menu->scene; asset_name image={"highscor.pcx"};
    services->fade(user,scene,1,6,0,255,0);
    state->show_table=1;
    services->image(user,scene,scene->animation->flow->overlay,&image,2,0,0);
    services->redraw_scene(user,scene); services->fade(user,scene,1,6,0,255,1);
}

void lifted_screen_enter(spx_score_scene_context_v5 *context, score_screen *state) {
    const spx_score_scene_services_v5 *services=context->services; void *user=services->context;
    scene_state *scene=state->menu->scene; title_state *title=scene->animation;
    asset_name image={"highscor.pcx"}, bank0={"mainmenu.sbk"}, bank1={"sysfont.sbk"}, track={"acker-gs.mds"};
    services->reset_damage(user,scene); services->clear(user,scene,title->flow->overlay,0);
    services->image(user,scene,title->flow->overlay,&image,2,0,0);
    services->load_bank(user,scene,0,1,&bank0); services->load_bank(user,scene,1,0,&bank1);
    services->select_bank(user,scene,0); services->select_font(user,scene,1);
    services->load_track(user,state->menu,&track,1); services->damage_background(user,scene,title->back);
    services->damage_destination(user,scene,scene->presentation_mode ? title->primary : scene->flip);
    services->load_scores(user,state->scores);
    state->name[0]=0; state->length=0; state->last_tick=0; state->blink=0; state->highlight=UINT32_MAX;
    state->entering=state->menu->score>=score_value(&state->scores->entries[14]); state->show_table=0;
    services->redraw_scene(user,scene); services->fade(user,scene,1,6,0,255,1);
}

void lifted_screen_draw_table(spx_score_scene_context_v5 *context, score_screen *state) {
    const spx_score_scene_services_v5 *services=context->services; void *user=services->context;
    scene_state *scene=state->menu->scene; font_state *font=scene->animation->font;
    for (uint32_t i=0,y=170;i<15;++i,y+=20) {
        if (i==state->highlight) {
            services->line(user,scene,font->destination,5,y-14,635,y-14,200);
            services->line(user,scene,font->destination,5,y+5,635,y+5,200);
            services->line(user,scene,font->destination,5,y-14,5,y+4,200);
            services->line(user,scene,font->destination,635,y-14,635,y+4,200);
        }
        const score_entry *entry=&state->scores->entries[i];
        draw_text(context,state,10,y,(const unsigned char *)entry->name,(uint32_t)strlen(entry->name),0);
        char number[11]; snprintf(number,sizeof(number),"%" PRIu32,score_value(entry));
        uint32_t length=(uint32_t)strlen(number); font_bytes bytes={(const unsigned char *)number};
        uint32_t width=services->measure(user,font,length,&bytes);
        draw_text(context,state,630-width,y,bytes.data,length,0);
    }
}

void lifted_screen_redraw(spx_score_scene_context_v5 *context, score_screen *state) {
    const spx_score_scene_services_v5 *services=context->services; void *user=services->context;
    scene_state *scene=state->menu->scene; title_state *title=scene->animation; font_rect full={0,0,640,480};
    services->clear(user,scene,title->primary,0);
    if (!scene->presentation_mode) services->clear(user,scene,scene->flip,0);
    services->clear(user,scene,title->back,0);
    services->blit(user,scene,title->back,&full,title->flow->overlay,&full,0x01000000);
    services->sprite_destination(user,scene,title->back);
    if (state->show_table==1) lifted_screen_draw_table(context,state);
    else if (state->entering==1) {
        draw_text(context,state,320,170,screen_text_congratulations,sizeof(screen_text_congratulations),1);
        draw_text(context,state,70,200,screen_text_prompt,sizeof(screen_text_prompt),0);
    } else {
        draw_text(context,state,320,170,screen_text_score,sizeof(screen_text_score),1);
        char number[11]; snprintf(number,sizeof(number),"%" PRIu32,state->menu->score);
        draw_text(context,state,320,200,(const unsigned char *)number,(uint32_t)strlen(number),1);
    }
    services->blit(user,scene,title->primary,&full,title->back,&full,0x01000000);
    if (!scene->presentation_mode) services->blit(user,scene,scene->flip,&full,title->back,&full,0x01000000);
}

void lifted_screen_update(spx_score_scene_context_v5 *context, score_screen *state) {
    const spx_score_scene_services_v5 *services=context->services; void *user=services->context;
    scene_state *scene=state->menu->scene; title_state *title=scene->animation;
    if (scene->presentation_mode) services->wait(user,scene,1);
    services->restore_damage(user,scene);
    scene->cursor_x=scene->mouse_x; scene->cursor_y=scene->mouse_y;
    if (font_signed(scene->cursor_x)>599) scene->cursor_x=599;
    if (font_signed(scene->cursor_x)<8) scene->cursor_x=8;
    if (font_signed(scene->cursor_y)>447) scene->cursor_y=447;
    if (state->entering==1) {
        services->sprite_destination(user,scene,scene->presentation_mode ? title->primary : scene->flip);
        uint32_t length=(uint32_t)strlen(state->name); font_bytes bytes={(const unsigned char *)state->name};
        draw_text(context,state,70,230,bytes.data,length,0);
        if (state->blink==1) {
            uint32_t width=services->measure(user,title->font,length,&bytes);
            draw_text(context,state,71+width,230,screen_text_cursor,sizeof(screen_text_cursor),0);
        }
        if (services->elapsed(user,state->menu,state->last_tick,300)) {
            state->blink=1-state->blink; state->last_tick=services->now(user,state->menu);
        }
        font_rect dirty={0,210,639,234}; services->damage(user,state,&dirty);
    }
    if (!scene->presentation_mode) services->present(user,scene);
    if (state->show_table==1 && state->entering==0 && services->elapsed(user,state->menu,state->last_tick,100)) {
        state->last_tick=services->now(user,state->menu);
        services->cycle_dots_palette(user,state->menu,200,207,1);
    }
    if (scene->mouse_buttons==1) {
        if (state->entering) services->wait(user,scene,1);
        else if (!state->show_table) show_scores(context,state);
        else { title->flow->transition_pending=1; title->flow->next_scene=0; }
        scene->mouse_buttons=0;
    } else if (scene->mouse_buttons==2) scene->mouse_buttons=0;
}

void lifted_screen_edit(spx_score_scene_context_v5 *context, score_screen *state, uint32_t key) {
    const spx_score_scene_services_v5 *services=context->services; void *user=services->context;
    unsigned char character=(unsigned char)key;
    if (character==13) {
        scores_name name={state->name};
        state->highlight=services->insert_score(user,state->scores,&name,state->menu->score);
        state->entering=0; show_scores(context,state);
    }
    if (character==8 && font_signed(state->length)>0) state->name[--state->length]=0;
    if (character==' ' || (character>='0' && character<='9')) {
        if (font_signed(state->length)>=30) services->wait(user,state->menu->scene,1);
        else { state->name[state->length++]=(char)character; state->name[state->length]=0; }
    }
    if (character>='A' && character<='Z') {
        if (state->shift!=1) character=(unsigned char)(character-'A'+'a');
        if (font_signed(state->length)>=30) services->wait(user,state->menu->scene,1);
        else { state->name[state->length++]=(char)character; state->name[state->length]=0; }
    }
}

void lifted_screen_key(spx_score_scene_context_v5 *context, score_screen *state, uint32_t key) {
    if (state->entering==1) lifted_screen_edit(context,state,key);
}
