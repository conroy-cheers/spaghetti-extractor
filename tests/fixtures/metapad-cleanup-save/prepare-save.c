#include "portable-component-implementation.h"

/* Save-path cleanup and count adjustment, corresponding to 0x5c2a..0x5c3f.
 * The two outgoing machine argument pushes belong to continuation transport.
 * The returned count is distinct from the adjusted length: every uint32 length,
 * including wraparound subtraction, remains representable. */
uint32_t prepare_save(spx_cleanup_save_context_v5 *context,
    const spx_view_v5 *text, const spx_view_v5 *suppress_notice,
    const spx_view_v5 *main_window, const spx_view_v5 *edit_window,
    const spx_view_v5 *caption, const spx_view_v5 *length) {
  uint32_t removed = context->services->cleanup(context->services->context,
      text, suppress_notice, main_window, edit_window, caption);
  if (removed == UINT32_MAX) return UINT32_MAX;
  uint64_t previous;
  if (length->read(length->access_context, length->base, 0, 4, &previous))
    return UINT32_MAX;
  if (length->write(length->access_context, length->base, 0, 4,
        (uint32_t)previous - removed)) return UINT32_MAX;
  return removed;
}
