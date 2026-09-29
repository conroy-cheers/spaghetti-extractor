#include "portable-component-implementation.h"
#include "graphics-state.h"

void lifted_graphics_bind(spx_graphics_bind_context_v5 *context,
                          struct spx_opaque_dx_graphics_v5 *state,
                          uint32_t surface) {
  (void)context;
  state->current_surface = surface;
}
