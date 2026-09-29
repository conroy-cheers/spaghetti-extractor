#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "portable-component-implementation.h"
#include "menu-state.h"
#include "menu-data.h"

static void draw_text(spx_menu_scene_context_v5 *context, menu_state *state, uint32_t x, uint32_t y,
                      const unsigned char *data, uint32_t length, int centered) {
    font_bytes text = {data};
    if (centered) context->services->center(context->services->context,state->scene,x,y,length,&text);
    else context->services->text(context->services->context,state->scene,x,y,length,&text);
}

void lifted_menu_enter(spx_menu_scene_context_v5 *context, menu_state *state) {
    const spx_menu_scene_services_v5 *services = context->services; void *user = services->context;
    scene_state *scene = state->scene; title_state *title = scene->animation;
    asset_name image = {"mainmenu.pcx"}, bank0 = {"mainmenu.sbk"}, bank1 = {"thefont.sbk"}, bank2 = {"sfont.sbk"};
    asset_name track = {"ethno_pa.mds"};
    services->reset_damage(user,scene); services->clear(user,scene,title->flow->overlay,0);
    services->image(user,scene,title->flow->overlay,&image,2,0,0);
    services->load_bank(user,scene,0,1,&bank0); services->load_bank(user,scene,1,0,&bank1);
    services->load_bank(user,scene,2,0,&bank2); services->select_bank(user,scene,0); services->select_font(user,scene,1);
    services->load_track(user,state,&track,1); services->damage_background(user,scene,title->back);
    state->last_tick = 0;
    services->damage_destination(user,scene,scene->presentation_mode ? title->primary : scene->flip);
    services->redraw_scene(user,scene); lifted_menu_initialize_dots(context,state); lifted_menu_animate(context,state);
    services->restore_damage(user,scene);
    if (!scene->presentation_mode) services->present(user,scene);
    services->fade(user,scene,1,6,0,255,1);
}

void lifted_menu_redraw(spx_menu_scene_context_v5 *context, menu_state *state) {
    const spx_menu_scene_services_v5 *services = context->services; void *user = services->context;
    scene_state *scene = state->scene; title_state *title = scene->animation;
    font_rect full = {0,0,640,480};
    services->clear(user,scene,title->primary,0);
    if (!scene->presentation_mode) services->clear(user,scene,scene->flip,0);
    services->clear(user,scene,title->back,0);
    services->blit(user,scene,title->back,&full,title->flow->overlay,&full,0x01000000);
    services->sprite_destination(user,scene,title->back); services->select_font(user,scene,2);
    services->wait(user,scene,1);
    if (state->score) {
        char score[128]; snprintf(score,sizeof(score),"Last Score - %" PRIu32,state->score);
        draw_text(context,state,3,10,(const unsigned char *)score,(uint32_t)strlen(score),0);
    }
#define TEXT(x,y,name,centered) do { services->wait(user,scene,1); \
    draw_text(context,state,x,y,menu_text_##name,sizeof(menu_text_##name),centered); } while (0)
    TEXT(615,10,version,0); TEXT(485,130,author,0); TEXT(3,465,copyright,0); TEXT(3,475,distribution,0);
    services->select_font(user,scene,1); TEXT(317,210,based_on,1); TEXT(317,250,by,1);
#undef TEXT
    services->blit(user,scene,title->primary,&full,title->back,&full,0x01000000);
    if (!scene->presentation_mode) services->blit(user,scene,scene->flip,&full,title->back,&full,0x01000000);
}

void lifted_menu_update(spx_menu_scene_context_v5 *context, menu_state *state) {
    const spx_menu_scene_services_v5 *services = context->services; void *user = services->context;
    scene_state *scene = state->scene;
    if (scene->presentation_mode) services->wait(user,scene,1);
    services->restore_damage(user,scene);
    scene->cursor_x = scene->mouse_x; scene->cursor_y = scene->mouse_y;
    if (font_signed(scene->cursor_x) > 599) scene->cursor_x = 599;
    if (font_signed(scene->cursor_x) < 8) scene->cursor_x = 8;
    if (font_signed(scene->cursor_y) > 447) scene->cursor_y = 447;
    lifted_menu_animate(context,state);
    if (!scene->presentation_mode) services->present(user,scene);
    services->cycle_palette(user,state,48,63,1);
    if (scene->mouse_buttons == 1) {
        scene->animation->flow->transition_pending = 1; scene->animation->flow->next_scene = 1; scene->mouse_buttons = 0;
    } else if (scene->mouse_buttons == 2) scene->mouse_buttons = 0;
}

void lifted_menu_key(spx_menu_scene_context_v5 *context, menu_state *state, uint32_t key) {
    (void)context;
    if ((unsigned char)key == 0x70 && state->input_ready) {
        state->scene->animation->flow->transition_pending = 1; state->scene->animation->flow->next_scene = 2;
    }
}

void lifted_menu_leave(spx_menu_scene_context_v5 *context, menu_state *state, uint32_t reason) {
    if (!reason) return;
    const spx_menu_scene_services_v5 *services = context->services; void *user = services->context;
    scene_state *scene = state->scene; title_state *title = scene->animation;
    font_rect full = {0,0,640,480};
    services->fade(user,scene,1,6,0,255,0);
    services->clear(user,scene,title->back,0); services->clear(user,scene,title->primary,0);
    if (!scene->presentation_mode) services->blit(user,scene,scene->flip,&full,title->back,&full,0x01000000);
    services->release_banks(user,scene); services->release_sounds(user,scene); services->release_track(user,scene);
}

void lifted_menu_initialize_dots(spx_menu_scene_context_v5 *context, menu_state *state) {
    (void)context; uint32_t x = 116, y = 41, phase = 0;
    for (unsigned i = 0; i < 287; ++i) {
        menu_dot *dot = &state->dots[i]; *dot = (menu_dot){x,y,phase,menu_pattern[i]};
        if (dot->kind == 1) { dot->y -= 5; dot->phase += 30; }
        x += 10; phase += 20;
        if (x-116 > 400) { x = 116; y += 10; phase = y-41; }
    }
    for (unsigned i = 0; i < 360; ++i) {
        state->offsets[i][0] = (uint32_t)((int64_t)state->cosine[i]*4/1024);
        state->offsets[i][1] = (uint32_t)((int64_t)state->scene->animation->sine[i]*3/1024);
    }
}

static void advance(menu_dot *dot) {
    dot->phase += 30;
    if (font_signed(dot->phase) > 359) dot->phase = (uint32_t)(font_signed(dot->phase)%360);
}

void lifted_menu_animate(spx_menu_scene_context_v5 *context, menu_state *state) {
    const spx_menu_scene_services_v5 *services = context->services; void *user = services->context;
    if (!services->elapsed(user,state,state->last_tick,50)) return;
    scene_state *scene = state->scene; title_state *title = scene->animation;
    font_rect rectangle = {112,37,530,115}; pcx_view view = {0};
    services->sprite_destination(user,scene,title->back);
    services->blit_fast(user,state,title->font->destination,112,37,title->flow->overlay,&rectangle,0x10);
    services->describe(user,title->font->destination,&view);
    while (services->lock(user,title->font->destination,&view)) {}
    for (unsigned i = 0; i < 287; ++i) {
        menu_dot *dot = &state->dots[i];
        if (dot->kind != 0) continue;
        advance(dot);
        uint32_t x = dot->x+state->offsets[dot->phase][0], y = dot->y+state->offsets[dot->phase][1];
        view.image.pixels[(size_t)y*view.image.pitch+x] = 200;
    }
    services->unlock(user,title->font->destination);
    for (unsigned i = 0; i < 287; ++i) {
        menu_dot *dot = &state->dots[i];
        if (dot->kind != 1) continue;
        advance(dot);
        uint32_t x = dot->x+state->offsets[dot->phase][0], y = dot->y+state->offsets[dot->phase][1];
        services->sprite(user,state,1,x,y);
    }
    services->damage(user,state,&rectangle); services->cycle_dots_palette(user,state,200,207,1);
    state->last_tick = services->now(user,state);
}
