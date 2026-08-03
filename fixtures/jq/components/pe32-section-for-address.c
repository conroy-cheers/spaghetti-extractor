#include "implementation.h"

uint32_t validated_pe32_section_for_address(
    pe32_section_reader *reader, uint32_t section_table,
    uint16_t section_count, uint32_t image_base, uint32_t address,
    uint32_t *read_ok) {
  uint32_t index;
  uint32_t target_rva = address - image_base;
  *read_ok = 1U;
  for (index = 0U; index < section_count; ++index) {
    uint32_t header = section_table + index * UINT32_C(40);
    uint32_t virtual_address =
        reader->read_u32(reader->context, header + UINT32_C(12), read_ok);
    uint32_t virtual_size;
    if (*read_ok == 0U)
      return 0U;
    if (target_rva < virtual_address)
      continue;
    virtual_size =
        reader->read_u32(reader->context, header + UINT32_C(8), read_ok);
    if (*read_ok == 0U)
      return 0U;
    if (target_rva < virtual_address + virtual_size)
      return header;
  }
  return 0U;
}
