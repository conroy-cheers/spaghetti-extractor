#include "portable-component-implementation.h"

static uint32_t read_cell(const spx_view_v5 *cell) {
  uint64_t bits = 0;
  (void)cell->read(cell->access_context, cell->base, 0U, 4U, &bits);
  return (uint32_t)bits;
}

static void write_cell(const spx_view_v5 *cell, uint32_t bits) {
  (void)cell->write(cell->access_context, cell->base, 0U, 4U, bits);
}

/* Each errno call supplies its actual returned view. A native address token is
 * passed to the release service; it is never cast to a host pointer here.
 * Applicability still requires checked live cell access and release semantics.
 */
void preserve_errno_free(spx_preserve_errno_free_context_v5 *context,
                         uint32_t allocation_token) {
  SPX_PROOF_BEGIN(release);
  spx_view_v5 cell = context->services->errno_cell(context->services->context);
  uint32_t first = read_cell(&cell);
  cell = context->services->errno_cell(context->services->context);
  uint32_t second = read_cell(&cell);
  cell = context->services->errno_cell(context->services->context);
  write_cell(&cell, 0U);

  context->services->release_allocation(context->services->context,
                                         allocation_token);

  cell = context->services->errno_cell(context->services->context);
  uint32_t restored = read_cell(&cell) == 0U ? second : first;
  cell = context->services->errno_cell(context->services->context);
  write_cell(&cell, restored);
}
