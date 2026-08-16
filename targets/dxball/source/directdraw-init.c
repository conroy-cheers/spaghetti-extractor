#include "portable-component-implementation.h"

uint32_t dxball_directdraw_initialize(
    spx_dxball_directdraw_init_context_v2 *context,
    spx_resource_v2 window) {
  const spx_resource_v2 directdraw =
      context->services->directdraw_create(context->services->context);
  const uint32_t cooperative = context->services->set_cooperative_level(
      context->services->context, directdraw, window, UINT32_C(17));
  if (cooperative != 0U) {
    (void)context->services->message_box(
        context->services->context, window, cooperative);
    context->services->destroy_window(context->services->context, window);
    return cooperative;
  }
  const spx_resource_v2 primary =
      context->services->create_primary_surface(
          context->services->context, directdraw);
  (void)context->services->create_backbuffer(
      context->services->context, primary);
  return 0U;
}
