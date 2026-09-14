#include "portable-component-implementation.h"

/* 0x1284 returns its shared buffer even when LoadStringA reports failure.
 * The checked current-memory contract depends on the selected output service.
 * Access-failure transport remains unqualified, as in the enclosing candidate.
 */
spx_view_v5 resource_text(spx_resource_text_context_v5 *context, uint32_t id) {
  SPX_PROOF_BEGIN(get);
  uint32_t module=0U;
  for (uint32_t i=0; i<4U; ++i) {
    uint64_t byte;
    const spx_view_v5 *view=&context->state.module;
    if (view->read(view->access_context,view->base,i,1U,&byte)) return (spx_view_v5){0};
    module |= (uint32_t)byte << (8U*i);
  }
  spx_view_v5 buffer = context->state.buffer;
  context->services->load_string(context->services->context,
      (uint32_t)module, id, &buffer, (uint32_t)buffer.extent);
  return buffer;
}
