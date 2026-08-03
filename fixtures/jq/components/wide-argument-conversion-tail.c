#include "implementation.h"

wide_conversion_result convert_one_wide_argument(
    wide_conversion_services *services, uint32_t source,
    uint32_t destination, uint32_t destination_bytes) {
  wide_conversion_result result;
  result.destination = destination;
  result.converted_units = services->convert(
      services->context, WIDE_CONVERSION_CODE_PAGE, 0U, source,
      WIDE_CONVERSION_SOURCE_NUL_TERMINATED, destination, destination_bytes,
      0U, 0U);
  return result;
}
