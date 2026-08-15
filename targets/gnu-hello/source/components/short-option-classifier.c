#include <stdint.h>

uint32_t gnu_hello_short_option_classifier(uint16_t value) {
  return value != UINT16_C(523);
}
