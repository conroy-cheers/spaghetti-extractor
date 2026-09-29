#include "portable-component-implementation.h"

spx_jv_value_v2 lifted_array_concat(
    spx_array_concat_context_v5 *context,
    spx_jv_value_v2 left, spx_jv_value_v2 right) {
  const spx_array_concat_services_v5 *services = context->services;
  void *environment = services->context;
  uint32_t count = services->length(environment, services->copy(environment, right));
  for (uint32_t index = 0; index < count; ++index) {
    spx_jv_value_v2 item = services->get(
        environment, services->copy(environment, right), index);
    left = services->append(environment, left, item);
    if (!services->valid(environment, left))
      break;
  }
  services->release(environment, right);
  return left;
}
