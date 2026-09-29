#include "portable-component-implementation.h"

uint32_t gnu_hello_get_quoting_style(spx_quoting_style_context_v5 *context,
                                    const spx_view_v5 *options) {
  SPX_PROOF_BEGIN(get);
  const spx_view_v5 *selected = options->base.object != 0U ? options : &context->state.defaults;
  uint64_t style = 0;
  if (selected->read(selected->access_context, selected->base, 0, 4, &style))
    return 0;
  return (uint32_t)style;
}

void gnu_hello_set_quoting_style(spx_quoting_style_context_v5 *context,
                               const spx_view_v5 *options, uint32_t style) {
  SPX_PROOF_BEGIN(set);
  const spx_view_v5 *selected = options->base.object != 0U ? options : &context->state.defaults;
  (void)selected->write(selected->access_context, selected->base, 0, 4, style);
}

uint32_t gnu_hello_set_char_quoting(spx_quoting_style_context_v5 *context,
                                  const spx_view_v5 *options,
                                  uint32_t character, uint32_t setting) {
  SPX_PROOF_BEGIN(set_character);
  const spx_view_v5 *selected = options->base.object != 0U ? options : &context->state.defaults;
  uint32_t byte = character & 255U;
  uint32_t shift = byte & 31U;
  uint32_t offset = 8U + 4U * (byte >> 5);
  uint64_t word = 0;
  if (selected->read(selected->access_context, selected->base, offset, 4, &word))
    return 0;
  uint32_t old = ((uint32_t)word >> shift) & 1U;
  uint32_t updated = (uint32_t)word ^ (((setting & 1U) ^ old) << shift);
  (void)selected->write(selected->access_context, selected->base, offset, 4, updated);
  return old;
}
