#include "program-state.h"
#include "portable-component-implementation.h"

/* This operation declares no services. Calling its exported C API avoids
 * introducing the menu's rendering/audio dependencies for an input-only call. */
void dxball_program_menu_key(dxball_program *p, uint32_t key) {
    dxball_program_refresh_views(p);
    spx_menu_scene_context_v5 context = {0};
    lifted_menu_key(&context, &p->menu, key);
}
