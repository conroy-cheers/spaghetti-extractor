#include <stdint.h>

uint32_t bounded_string_length(const uint8_t *bytes, uint32_t limit) {
  uint32_t index;

  for (index = 0U; index < limit; ++index) {
    if (bytes[index] == 0U)
      break;
  }
  return index;
}
