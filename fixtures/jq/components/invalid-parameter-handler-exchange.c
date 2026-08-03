#include "implementation.h"

uint32_t exchange_invalid_parameter_handler(static_word_services *services,
                                            uint32_t replacement) {
  return services->exchange_word(services->context, replacement);
}
