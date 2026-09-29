#include <string.h>
#include "portable-component-implementation.h"
#include "board-state.h"
#include "board-data.h"

void lifted_board_load(spx_board_data_context_v5 *context,board_set *state,board_name *name) {
    const spx_board_data_services_v5 *services=context->services; void *user=services->context;
    state->file=services->open(user,state,name,0);
    if (state->file) {
        board_bytes bytes={(unsigned char *)state->saved,sizeof(state->saved)};
        services->read(user,state,state->file,&bytes); services->close(user,state,state->file);
    }
}

void lifted_board_save(spx_board_data_context_v5 *context,board_set *state,board_name *name) {
    const spx_board_data_services_v5 *services=context->services; void *user=services->context;
    state->file=services->open(user,state,name,1);
    if (state->file) {
        board_bytes bytes={(unsigned char *)state->saved,sizeof(state->saved)};
        services->write(user,state,state->file,&bytes); services->close(user,state,state->file);
    }
}

void lifted_board_select(spx_board_data_context_v5 *context,board_set *state,uint32_t index) {
    (void)context; memcpy(&state->current,&state->saved[index],sizeof(board));
}

void lifted_board_store(spx_board_data_context_v5 *context,board_set *state,uint32_t index) {
    (void)context; memcpy(&state->saved[index],&state->current,sizeof(board));
}

uint32_t lifted_board_sprite(spx_board_data_context_v5 *context,uint32_t kind) {
    (void)context;
    return kind<sizeof(board_sprite_ids)/sizeof(board_sprite_ids[0]) ? board_sprite_ids[kind] : kind;
}
