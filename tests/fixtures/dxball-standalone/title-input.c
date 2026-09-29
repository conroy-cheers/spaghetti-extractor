#include "program-state.h"
#include "portable-component-implementation.h"

/* Like menu key, title key has an empty allowed-service set. */
void dxball_program_title_key(dxball_program *p, uint32_t key) {
    dxball_program_refresh_views(p);
    spx_title_scene_context_v5 context = {0};
    lifted_scene_key(&context, &p->scene, key);
}
