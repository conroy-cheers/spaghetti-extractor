#include "portable-component-implementation.h"
#include "graphics-state.h"

uint32_t lifted_graphics_blit(spx_graphics_blit_context_v5 *context,
                              struct spx_opaque_dx_graphics_v5 *state,
                              uint32_t index, uint32_t x, uint32_t y) {
  const struct dx_sprite *sprite = state->banks[state->bank_index].slots[index];
  return context->services->blit_fast(context->services->context, state,
      state->current_surface, x, y, sprite->surface,
      sprite->rectangle[0], sprite->rectangle[1],
      sprite->rectangle[2], sprite->rectangle[3], UINT32_C(0x11));
}
