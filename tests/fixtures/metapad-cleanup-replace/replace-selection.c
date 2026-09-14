#include "portable-component-implementation.h"

/* Both original mode guards belong to this operation. A tagged result keeps
 * every SendMessage result representable, including UINT32_MAX. */
spx_outcome_v5 replace_selection(spx_cleanup_replace_context_v5 *context,
    const spx_view_v5 *text, const spx_view_v5 *suppress_notice,
    const spx_view_v5 *main_window, const spx_view_v5 *edit_window,
    const spx_view_v5 *caption, uint32_t mode) {
  if (mode != 2U && mode != 3U) {
    uint32_t removed = context->services->cleanup(context->services->context,
        text, suppress_notice, main_window, edit_window, caption);
    if (removed == UINT32_MAX) return (spx_outcome_v5){1U, 0U};
  }
  uint64_t window;
  if (edit_window->read(edit_window->access_context, edit_window->base,
        0U, 4U, &window)) return (spx_outcome_v5){1U, 0U};
  uint32_t result = context->services->send_message(context->services->context,
      (uint32_t)window, 194U, 1U, text);
  return (spx_outcome_v5){0U, result};
}
