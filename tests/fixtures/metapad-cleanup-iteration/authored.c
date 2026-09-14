#include "portable-component-implementation.h"

/* Candidate for the complete retained 0x55b7 operation. Access failures return
 * UINT32_MAX pending checked outcome transport; this is not a qualified fault
 * implementation. In particular, no successful-allocation premise is claimed.
 */
uint32_t cleanup(spx_text_cleanup_context_v5 *context,
    const spx_view_v5 *text, const spx_view_v5 *suppress_notice,
    const spx_view_v5 *main_window, const spx_view_v5 *edit_window,
    const spx_view_v5 *caption) {
  SPX_PROOF_BEGIN(cleanup);
  uint32_t length = context->services->length(context->services->context, text);
  spx_view_v5 scratch = context->services->allocate(
      context->services->context, 64U, length + 1U);
  SPX_PROOF_SYNC(allocated, 1, caption, edit_window, main_window, suppress_notice, text, scratch);
  length = context->services->length(context->services->context, text);

  uint32_t input = 0, output = 0, removed = 0;
  uint8_t a, b, c;
  /* The original uses signed JGE against 3 after the second length call. */
  if (length < 3U || length >= 2147483648U) {
    for (uint32_t k = 2; k != 0U; --k) {
      if (spx_view_read_u8(text, input, &a)) return UINT32_MAX;
      if (a) {
        if (spx_view_write_u8(&scratch, output, a)) return UINT32_MAX;
        ++input;
        ++output;
      }
    }
  }
  for (;;) {
    SPX_PROOF_SYNC(loop, 1, caption, edit_window, main_window, suppress_notice, text, input, output, removed, scratch);
    if (spx_view_read_u8(text, input, &a)) return UINT32_MAX;
    if (!a) break;
    SPX_PROOF_SYNC(lookahead_one, 1, caption, edit_window, main_window, suppress_notice, text, a, input, output, removed, scratch);
    if (spx_view_read_u8(text, input + 1U, &b)) return UINT32_MAX;
    if (!b) break;
    SPX_PROOF_SYNC(lookahead_two, 1, caption, edit_window, main_window, suppress_notice, text, a, b, input, output, removed, scratch);
    if (spx_view_read_u8(text, input + 2U, &c)) return UINT32_MAX;
    if (!c) break;
    SPX_PROOF_SYNC(advance, 1, caption, edit_window, main_window, suppress_notice, text, a, b, c, input, output, removed, scratch);
    if (a == 13U && b == 13U && c == 10U) ++removed;
    else {
      if (spx_view_write_u8(&scratch, output, a)) return UINT32_MAX;
      ++output;
    }
    ++input;
  }
  SPX_PROOF_SYNC(tail, 1, caption, edit_window, main_window, suppress_notice, text, input, output, removed, scratch);
  for (uint32_t k = 0; k < 2U; ++k) {
    if (k == 1U) SPX_PROOF_SYNC(tail_second, 1, caption, edit_window, main_window, suppress_notice, text, input, k, output, removed, scratch);
    if (spx_view_read_u8(text, input, &a)) return UINT32_MAX;
    if (a) {
      if (spx_view_write_u8(&scratch, output, a)) return UINT32_MAX;
      ++input;
      ++output;
    }
  }

  SPX_PROOF_SYNC(tail_done, 1, caption, edit_window, main_window, suppress_notice, text, removed, scratch);

  /* There is no terminator store in the original loop. Copy-back relies on
   * the selected allocator's zero initialization and the live scratch tail. */
  if (removed) context->services->copy(context->services->context, text, &scratch);
  context->services->release(context->services->context, scratch.base);
  SPX_PROOF_SYNC(notice, 1, caption, edit_window, main_window, suppress_notice, text, removed);
  if (removed) {
    SPX_PROOF_SYNC(notice_active, 1, caption, edit_window, main_window, suppress_notice, text, removed);
    uint64_t value;
    if (suppress_notice->read(suppress_notice->access_context,
          suppress_notice->base, 0, 4, &value)) return UINT32_MAX;
    if ((uint32_t)value == 0U) {
      spx_view_v5 message = context->services->resource_text(context->services->context, 31U);
      if (main_window->read(main_window->access_context,
            main_window->base, 0, 4, &value)) return UINT32_MAX;
      context->services->message(context->services->context,
          (uint32_t)value, &message, caption, 48U);
    }
    if (edit_window->read(edit_window->access_context,
          edit_window->base, 0, 4, &value)) return UINT32_MAX;
    context->services->focus(context->services->context, (uint32_t)value);
  }
  SPX_PROOF_SYNC(notice_finish, 1, caption, edit_window, main_window, suppress_notice, text, removed);
  return removed;
}
