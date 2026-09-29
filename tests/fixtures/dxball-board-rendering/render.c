#include "portable-component-implementation.h"
#include "render-state.h"

void lifted_render_cell(spx_board_rendering_context_v5 *context,board_renderer *state,
                        uint32_t column,uint32_t row,uint32_t mode) {
    const spx_board_rendering_services_v5 *s=context->services; void *user=s->context;
    scene_state *scene=state->menu->scene; title_state *title=scene->animation;
    uint32_t x=20+30*column,y=50+15*row;
    font_rect rectangle={x,y,x+30,y+15};
    unsigned kind=state->boards->current.cells[row][column];
    if (kind==0 || (kind==7 && title->flow->scene==1)) {
        s->blit_fast(user,state->menu,title->font->destination,x,y,title->flow->overlay,&rectangle,0x10);
    } else if (kind<=22) {
        static const unsigned char sprites[]={0,3,4,5,6,7,8,19,9,10,11,12,13,14,15,16,17,18,56,57,58,59,60};
        s->sprite(user,state->menu,sprites[kind],x,y);
    }
    if (!mode) s->damage(user,state->menu,&rectangle);
}

void lifted_render_draw(spx_board_rendering_context_v5 *context,board_renderer *state,uint32_t mode) {
    scene_state *scene=state->menu->scene;
    context->services->sprite_destination(context->services->context,scene,scene->animation->back);
    for (uint32_t column=0;column<20;++column)
        for (uint32_t row=0;row<20;++row) lifted_render_cell(context,state,column,row,mode);
}
