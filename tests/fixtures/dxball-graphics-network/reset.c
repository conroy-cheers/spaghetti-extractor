#include "portable-component-implementation.h"
#include "graphics-state.h"

void lifted_graphics_reset(spx_graphics_reset_context_v5 *context,
                           struct spx_opaque_dx_graphics_v5 *state) {
  (void)context;
  for (uint32_t bank = 0; bank < 3; ++bank) {
    state->banks[bank].count = 0;
    for (uint32_t slot = 0; slot < 255; ++slot)
      state->banks[bank].slots[slot] = 0;
  }
}
