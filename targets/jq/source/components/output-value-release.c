#include "implementation.h"

void consume_opaque_value(opaque_value_consumer_services *services,
                          opaque_value4 value, uint32_t auxiliary) {
  services->consume(services->context, value, auxiliary);
}
