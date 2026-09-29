#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "portable-component-implementation.h"
#include "editor-state.h"
#include "editor-data.h"

static void text(spx_board_editor_context_v5 *context,board_editor *state,uint32_t x,uint32_t y,
                 const unsigned char *data,uint32_t length) {
    font_bytes bytes={data};
    context->services->text(context->services->context,state->menu->scene,x,y,length,&bytes);
}

void lifted_editor_enter(spx_board_editor_context_v5 *context,board_editor *state) {
    const spx_board_editor_services_v5 *s=context->services; void *user=s->context;
    scene_state *scene=state->menu->scene; title_state *title=scene->animation;
    asset_name image={"mbbkgrnd.pcx"},banks[]={{"mball2.sbk"},{"sfont.sbk"},{"mainmenu.sbk"}};
    s->reset_damage(user,scene); s->clear(user,scene,title->flow->overlay,0);
    s->image(user,scene,title->flow->overlay,&image,2,0,0);
    for (uint32_t i=0;i<3;++i) s->load_bank(user,scene,i,1,&banks[i]);
    s->select_bank(user,scene,0); s->select_font(user,scene,1);
    s->damage_background(user,scene,title->back);
    s->damage_destination(user,scene,scene->presentation_mode ? title->primary : scene->flip);
    state->selected_tile=1; s->reset_regions(user,state,23); state->index=0;
    s->select_board(user,state->boards,0); s->redraw_scene(user,scene); s->fade(user,scene,1,6,0,255,1);
}

void lifted_editor_draw_palette(spx_board_editor_context_v5 *context,board_editor *state) {
    const spx_board_editor_services_v5 *s=context->services; void *user=s->context;
    scene_state *scene=state->menu->scene; s->sprite_destination(user,scene,scene->animation->back);
    for (uint32_t kind=1,x=20,y=385;kind<=22;++kind) {
        uint32_t slot=s->sprite_id(user,kind); s->sprite(user,state->menu,slot,x,y);
        font_rect region={x,y,x+30,y+15}; s->define_region(user,state,kind,&region);
        x+=32; if (x>280) { x=20; y+=17; }
    }
}

void lifted_editor_draw_status(spx_board_editor_context_v5 *context,board_editor *state) {
    const spx_board_editor_services_v5 *s=context->services; void *user=s->context;
    scene_state *scene=state->menu->scene; title_state *title=scene->animation;
    uint32_t slot=s->sprite_id(user,state->selected_tile);
    if (slot) s->sprite(user,state->menu,slot,25,5);
    else {
        font_rect rectangle={25,5,55,20};
        s->blit_fast(user,state->menu,title->font->destination,25,5,title->flow->overlay,&rectangle,0x10);
    }
    font_rect rectangle={65,5,639,20};
    s->blit_fast(user,state->menu,title->font->destination,65,5,title->flow->overlay,&rectangle,0x10);
    char number[12]; snprintf(number,sizeof(number),"%" PRId64,font_signed(state->index+1));
    text(context,state,75,17,(const unsigned char *)number,(uint32_t)strlen(number));
    for (uint32_t i=0;i<6;++i) text(context,state,360,380+10*i,editor_help[i].data,editor_help[i].length);
}

void lifted_editor_redraw(spx_board_editor_context_v5 *context,board_editor *state) {
    const spx_board_editor_services_v5 *s=context->services; void *user=s->context;
    scene_state *scene=state->menu->scene; title_state *title=scene->animation; font_rect full={0,0,640,480};
    s->clear(user,scene,title->primary,0);
    if (!scene->presentation_mode) s->clear(user,scene,scene->flip,0);
    s->clear(user,scene,title->back,0);
    s->blit(user,scene,title->back,&full,title->flow->overlay,&full,0x01000000);
    s->draw_board(user,state,0); lifted_editor_draw_palette(context,state); lifted_editor_draw_status(context,state);
    s->blit(user,scene,title->primary,&full,title->back,&full,0x01000000);
    if (!scene->presentation_mode) s->blit(user,scene,scene->flip,&full,title->back,&full,0x01000000);
}

static int on_board(uint32_t x,uint32_t y) {
    return font_signed(x)>20 && font_signed(x)<620 && font_signed(y)>50 && font_signed(y)<350;
}

static void paint(spx_board_editor_context_v5 *context,board_editor *state,uint32_t value) {
    scene_state *scene=state->menu->scene;
    /* The strict rectangle checked by the caller makes both quotients 0..19. */
    uint32_t column=(scene->cursor_x-20)/30,row=(scene->cursor_y-50)/15;
    state->boards->current.cells[row][column]=(unsigned char)value;
    context->services->draw_cell(context->services->context,state,column,row,0);
    context->services->store_board(context->services->context,state->boards,state->index);
}

void lifted_editor_update(spx_board_editor_context_v5 *context,board_editor *state) {
    const spx_board_editor_services_v5 *s=context->services; void *user=s->context;
    scene_state *scene=state->menu->scene;
    if (scene->presentation_mode) s->wait(user,scene,1);
    s->restore_damage(user,scene); scene->cursor_x=scene->mouse_x; scene->cursor_y=scene->mouse_y;
    if (font_signed(scene->cursor_x)>599) scene->cursor_x=599;
    if (font_signed(scene->cursor_x)<8) scene->cursor_x=8;
    if (font_signed(scene->cursor_y)>447) scene->cursor_y=447;
    s->select_bank(user,scene,2);
    uint32_t hit=s->hit_region(user,state,scene->cursor_x,scene->cursor_y);
    s->cursor(user,state,hit ? 6 : 4,scene->cursor_x,scene->cursor_y);
    s->select_bank(user,scene,0);
    if (!scene->presentation_mode) s->present(user,scene);
    if (scene->mouse_buttons==1) {
        if (on_board(scene->cursor_x,scene->cursor_y)) paint(context,state,state->selected_tile);
        else if (s->hit_region(user,state,scene->cursor_x,scene->cursor_y)) {
            state->selected_tile=s->hit_region(user,state,scene->cursor_x,scene->cursor_y);
            lifted_editor_draw_status(context,state); font_rect rectangle={0,0,639,49};
            s->damage(user,state->menu,&rectangle);
        }
        if (!state->menu->input_ready) scene->mouse_buttons=0;
    }
    if (scene->mouse_buttons==2) {
        if (on_board(scene->cursor_x,scene->cursor_y)) paint(context,state,0);
        if (!state->menu->input_ready) scene->mouse_buttons=0;
    }
}

void lifted_editor_key(spx_board_editor_context_v5 *context,board_editor *state,uint32_t key) {
    const spx_board_editor_services_v5 *s=context->services; void *user=s->context;
    scene_state *scene=state->menu->scene; board_name name={"default.bds"};
    switch ((unsigned char)key) {
    case 8:
        memset(&state->boards->current,0,sizeof(board)); s->redraw_scene(user,scene); break;
    case 'N':
        s->store_board(user,state->boards,state->index); ++state->index;
        if (font_signed(state->index)>49) state->index=49;
        s->select_board(user,state->boards,state->index); s->redraw_scene(user,scene); break;
    case 'P':
        s->store_board(user,state->boards,state->index); --state->index;
        if (font_signed(state->index)<0) state->index=0;
        s->select_board(user,state->boards,state->index); s->redraw_scene(user,scene); break;
    case 'L':
        s->load_boards(user,state->boards,&name); state->index=0;
        s->select_board(user,state->boards,0); s->redraw_scene(user,scene); break;
    case 'S':
        s->store_board(user,state->boards,state->index); s->save_boards(user,state->boards,&name); break;
    }
}

void lifted_editor_leave(spx_board_editor_context_v5 *context,board_editor *state,uint32_t reason) {
    if (!reason) return;
    const spx_board_editor_services_v5 *s=context->services; void *user=s->context;
    scene_state *scene=state->menu->scene;
    s->fade(user,scene,1,6,0,255,0); s->clear(user,scene,scene->animation->primary,0);
    s->release_banks(user,scene); s->release_sounds(user,scene); s->release_track(user,scene);
}
