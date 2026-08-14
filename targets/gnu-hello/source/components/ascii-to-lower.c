#include <stdint.h>

uint32_t gnu_hello_ascii_to_lower(uint32_t value) {
  if (value >= (uint32_t)'A' && value <= (uint32_t)'Z')
    return value + UINT32_C(0x20);
  return value;
}
