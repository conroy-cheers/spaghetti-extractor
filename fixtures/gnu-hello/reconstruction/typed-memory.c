#include "implementation.h"

static uint32_t even_parity_low_byte(uint32_t value) {
  value ^= value >> 4;
  value &= UINT32_C(0x0f);
  return (UINT32_C(0x9669) >> value) & UINT32_C(1);
}

static uint32_t read_after_write(uint32_t address, uint32_t initial,
                                 uint32_t write_8_address,
                                 uint32_t write_8_value,
                                 uint32_t write_4_address,
                                 uint32_t write_4_value) {
  uint32_t result = initial;
  uint32_t index;

  for (index = 0U; index < 4U; ++index) {
    const uint32_t byte_address = address + index;
    const uint32_t offset_8 = byte_address - write_8_address;
    const uint32_t offset_4 = byte_address - write_4_address;
    uint32_t byte_value = (initial >> (index * 8U)) & UINT32_C(0xff);

    if (offset_8 < 4U)
      byte_value = (write_8_value >> (offset_8 * 8U)) & UINT32_C(0xff);
    if (offset_4 < 4U)
      byte_value = (write_4_value >> (offset_4 * 8U)) & UINT32_C(0xff);
    result &= ~(UINT32_C(0xff) << (index * 8U));
    result |= byte_value << (index * 8U);
  }
  return result;
}

bool reconstruct_region(const reconstructed_region_inputs *inputs,
                        reconstructed_region_outputs *outputs) {
  const uint32_t object_4_address = inputs->register_ebx + UINT32_C(4);
  const uint32_t object_8_address = inputs->register_ebx + UINT32_C(8);
  const uint32_t object_8 =
      inputs->memory_view_01_p8 + inputs->memory_view_00_p12;
  const uint32_t object_4 = inputs->memory_view_01_p4 | UINT32_C(0x1c0);
  const uint32_t stack_adjusted = inputs->register_esp + UINT32_C(76);

  outputs->memory_view_01_p8 = object_8;
  outputs->write_memory_view_01_p8 = true;
  outputs->memory_view_01_p4 = object_4;
  outputs->write_memory_view_01_p4 = true;

  outputs->register_eax = read_after_write(
      inputs->register_esp + UINT32_C(16), inputs->memory_view_00_p16,
      object_8_address, object_8, object_4_address, object_4);
  outputs->register_edx = read_after_write(
      inputs->register_esp + UINT32_C(20), inputs->memory_view_00_p20,
      object_8_address, object_8, object_4_address, object_4);
  outputs->register_ebx = read_after_write(
      inputs->register_esp + UINT32_C(76), inputs->memory_view_00_p76,
      object_8_address, object_8, object_4_address, object_4);
  outputs->register_esi = read_after_write(
      inputs->register_esp + UINT32_C(80), inputs->memory_view_00_p80,
      object_8_address, object_8, object_4_address, object_4);
  outputs->register_edi = read_after_write(
      inputs->register_esp + UINT32_C(84), inputs->memory_view_00_p84,
      object_8_address, object_8, object_4_address, object_4);
  outputs->register_ebp = read_after_write(
      inputs->register_esp + UINT32_C(88), inputs->memory_view_00_p88,
      object_8_address, object_8, object_4_address, object_4);
  outputs->register_ecx = inputs->register_ebx;
  outputs->register_esp = inputs->register_esp + UINT32_C(92);

  outputs->flag_cf = stack_adjusted < inputs->register_esp;
  outputs->flag_of =
      ((~(inputs->register_esp ^ UINT32_C(76)) &
        (inputs->register_esp ^ stack_adjusted) & UINT32_C(0x80000000)) != 0U);
  outputs->flag_pf = even_parity_low_byte(stack_adjusted);
  outputs->flag_sf = stack_adjusted >> 31;
  outputs->flag_zf = stack_adjusted == 0U;

  outputs->control_kind = RECONSTRUCTED_JUMP;
  outputs->target_rva = UINT32_C(0x0000bf30);
  outputs->value = 0U;
  return true;
}
