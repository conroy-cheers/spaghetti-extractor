#include "implementation.h"

int classify_prefixed_token(prefixed_token_services *services, uint32_t token) {
  uint8_t second;

  if (services->load_byte(services->context, token) !=
      PREFIXED_TOKEN_REQUIRED_BYTE)
    return 0;

  second = services->load_byte(services->context, token + UINT32_C(1));
  if (second == PREFIXED_TOKEN_ACCEPTED_BYTE)
    return 1;

  return services->test_byte(services->context, second) != 0;
}
