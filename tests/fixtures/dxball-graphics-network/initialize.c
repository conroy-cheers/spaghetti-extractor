#include "portable-component-implementation.h"
#include "graphics-state.h"

static uint32_t failed(spx_graphics_initialize_context_v5 *context,
                       struct spx_opaque_dx_graphics_v5 *state, uint32_t kind) {
  /* The original reloads the window between calls. An admitted callback may
   * change it during hide/message; capturing it once would change behavior. */
  context->services->hide(context->services->context, state, state->window);
  (void)context->services->message(context->services->context, state,
                                  state->window, kind);
  context->services->destroy(context->services->context, state, state->window);
  return 0;
}

uint32_t lifted_graphics_initialize(spx_graphics_initialize_context_v5 *context,
                                    struct spx_opaque_dx_graphics_v5 *state) {
  if (context->services->create_draw(context->services->context, state) != 0)
    return failed(context, state, 1);
  if (context->services->cooperative(context->services->context, state,
          state->directdraw, state->window, 8) != 0)
    return failed(context, state, 2);
  state->initialized = 1;
  state->capability_mode = 0;
  uint32_t caps = context->services->caps(context->services->context, state,
                                        state->directdraw);
  state->video_memory = (caps >> 25) & 1U;
  if (context->services->create_surface(context->services->context, state,
          state->directdraw, 0) != 0)
    return failed(context, state, 3);
  if (context->services->create_surface(context->services->context, state,
          state->directdraw, 1) != 0)
    return failed(context, state, 4);
  if (state->clipper_mode == 1) {
    if (context->services->create_clipper(context->services->context, state,
            state->directdraw) != 0)
      return failed(context, state, 5);
    if (context->services->clipper_window(context->services->context, state,
            state->clipper, state->window) != 0)
      return failed(context, state, 6);
    if (context->services->attach(context->services->context, state,
            state->primary, state->clipper) != 0)
      return failed(context, state, 7);
  }
  context->services->reset(context->services->context, state);
  context->services->bind(context->services->context, state, state->primary);
  return 1;
}
