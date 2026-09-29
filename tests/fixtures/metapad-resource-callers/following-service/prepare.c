#include "portable-component-implementation.h"
uint32_t prepare_notice(spx_resource_notice_prefix_context_v5 *context,
    const spx_view_v5 *module, const spx_view_v5 *buffer,
    const spx_view_v5 *main_window, const spx_view_v5 *caption) {
  (void)module; (void)buffer;
  spx_view_v5 text = context->services->resource_text(context->services->context, 31U);
  uint64_t window;
  if (main_window->read(main_window->access_context, main_window->base, 0U, 4U, &window)) return 0U;
  return context->services->message_box(context->services->context,
      (uint32_t)window, &text, caption, 48U);
}
