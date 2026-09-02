#include "portable-component-implementation.h"

uint32_t fixture_interface_stale_exercise(
    spx_fixture_interface_stale_context_v5 *context) {
  spx_resource_v2 root = {0};
  uint32_t filled;

  (void)context->services->create(context->services->context, &root);
  filled = context->services->fill_record(context->services->context, root);
  (void)context->services->release(context->services->context, root);
  return filled;
}
