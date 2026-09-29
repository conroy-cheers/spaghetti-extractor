#include "portable-component-implementation.h"
#include "scores-state.h"
#include "scores-data.h"

void lifted_scores_load(spx_score_table_context_v5 *context,scores_state *state) {
    const spx_score_table_services_v5 *services=context->services; void *user=services->context;
    state->file=services->open(user,state,0);
    if (state->file) {
        scores_bytes bytes={(unsigned char *)state->entries,sizeof(state->entries)};
        services->read(user,state,state->file,&bytes);
        services->close(user,state,state->file);
    }
}

static void save(spx_score_table_context_v5 *context,scores_state *state) {
    const spx_score_table_services_v5 *services=context->services; void *user=services->context;
    state->file=services->open(user,state,1);
    if (state->file) {
        scores_bytes bytes={(unsigned char *)state->entries,sizeof(state->entries)};
        services->write(user,state,state->file,&bytes);
        services->close(user,state,state->file);
    }
}

void lifted_scores_initialize(spx_score_table_context_v5 *context,scores_state *state) {
    for (unsigned i=0;i<15;++i) {
        strcpy(state->entries[i].name,scores_default_names[i]);
        score_set_value(&state->entries[i],150-10*i);
    }
    if (context->services->access(context->services->context,state,0) == UINT32_MAX) save(context,state);
}

uint32_t lifted_scores_insert(spx_score_table_context_v5 *context,scores_state *state,scores_name *name,uint32_t value) {
    lifted_scores_load(context,state);
    if (value < score_value(&state->entries[14])) return UINT32_MAX;
    unsigned rank=15;
    while (rank && score_value(&state->entries[rank-1]) <= value) --rank;
    for (unsigned i=14;i>rank;--i) {
        /* Only the terminated name is moved. Bytes after its NUL stay in place. */
        strcpy(state->entries[i].name,state->entries[i-1].name);
        score_set_value(&state->entries[i],score_value(&state->entries[i-1]));
    }
    strcpy(state->entries[rank].name,name->text);
    score_set_value(&state->entries[rank],value);
    if (!context->services->access(context->services->context,state,2)) save(context,state);
    return rank;
}
