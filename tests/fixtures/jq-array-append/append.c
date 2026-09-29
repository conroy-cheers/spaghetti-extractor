#include "portable-component-implementation.h"

spx_jv_value_v2 lifted_array_append(
    spx_array_append_context_v5 *context,
    spx_jv_value_v2 value, spx_jv_value_v2 item) {
  const spx_array_append_services_v5 *services = context->services;
  void *environment = services->context;
  uint32_t index = services->length(environment, services->copy(environment, value));
  return services->set(environment, value, index, item);
}
