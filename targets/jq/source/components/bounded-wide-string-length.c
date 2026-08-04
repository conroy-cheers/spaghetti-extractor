#include <stdint.h>

uint32_t bounded_wide_string_length(const uint16_t *elements, uint32_t limit) {
  uint32_t index;

  for (index = 0U; index < limit; ++index) {
    if (elements[index] == 0U)
      break;
  }
  return index;
}
