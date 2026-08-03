#include "implementation.h"

uint32_t load_invalid_parameter_handler(static_word_services *services) {
  return services->load_word(services->context);
}
