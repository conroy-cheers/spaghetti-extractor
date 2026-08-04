#include "implementation.h"

uint32_t validated_pe32_image_base(pe32_header_summary header,
                                      uint32_t image_base) {
  if (header.dos_magic != UINT16_C(0x5a4d) ||
      header.pe_signature != UINT32_C(0x00004550) ||
      header.optional_header_magic != UINT16_C(0x010b))
    return 0U;
  return image_base;
}
