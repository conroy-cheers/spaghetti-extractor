#include "portable-component-implementation.h"

uint32_t component_service_branch_run(
    spx_service_branch_context_v2 *context,
    uint32_t value) {
  uint32_t choice = context->services->choose(
      context->services->context, value);
  return choice == UINT32_C(0) ? UINT32_C(11) : choice;
}
