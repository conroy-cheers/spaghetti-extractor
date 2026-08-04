#include "implementation.h"

uint32_t classify_opaque_value(opaque_value_services *services,
                               opaque_value4 value) {
  return services->classify(services->context, value);
}
