#include "portable-component-implementation.h"

/* 0x1284 returns its shared buffer even when LoadStringA reports failure.
 * The checked current-memory contract depends on the selected output service.
 * Access-failure transport remains unqualified, as in the enclosing candidate.
 */
spx_view_v5 resource_text(spx_resource_text_context_v5 *context, uint32_t id) {
  SPX_PROOF_BEGIN(get);
  uint64_t module;
  const spx_view_v5 *module_cell = &context->state.module;
  if (module_cell->read(module_cell->access_context,
        module_cell->base, 0, 4, &module)) return (spx_view_v5){0};
  spx_view_v5 buffer = context->state.buffer;
  context->services->load_string(context->services->context,
      (uint32_t)module, id, &buffer, (uint32_t)buffer.extent);
  return buffer;
}
