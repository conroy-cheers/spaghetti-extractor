#include "portable-component-implementation.h"

/* 0x1284 returns its shared buffer even when LoadStringA reports failure.
 * A terminated message is a consumer obligation, not this helper's promise.
 * Access-failure transport remains unqualified, as in the enclosing candidate.
 */
spx_view_v5 resource_text(spx_resource_text_context_v5 *context, uint32_t id) {
  uint64_t module;
  const spx_view_v5 *module_cell = &context->state.module;
  if (module_cell->read(module_cell->access_context,
        module_cell->base, 0, 4, &module)) return (spx_view_v5){0};
  context->services->load_string(context->services->context,
      (uint32_t)module, id, &context->state.buffer, 500U);
  return context->state.buffer;
}
