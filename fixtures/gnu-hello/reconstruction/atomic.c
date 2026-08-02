#include "implementation.h"

static uint32_t even_parity_low_byte(uint32_t value) {
  value ^= value >> 4;
  value &= UINT32_C(0x0f);
  return (UINT32_C(0x9669) >> value) & UINT32_C(1);
}

bool reconstruct_region(const reconstructed_region_inputs *inputs,
                        reconstructed_region_outputs *outputs) {
  const uint32_t difference = UINT32_C(0) - inputs->atomic_00_observed;

  outputs->register_eax = inputs->atomic_00_observed;
  outputs->flag_cf = UINT32_C(0) < inputs->atomic_00_observed;
  outputs->flag_of =
      ((inputs->atomic_00_observed & difference & UINT32_C(0x80000000)) != 0U);
  outputs->flag_pf = even_parity_low_byte(difference);
  outputs->flag_sf = difference >> 31;
  outputs->flag_zf = inputs->atomic_00_exchanged;
  outputs->control_kind = RECONSTRUCTED_BRANCH;
  outputs->target_rva = inputs->atomic_00_exchanged
                            ? UINT32_C(0x0000105c)
                            : UINT32_C(0x00001038);
  outputs->value = 0U;
  return true;
}
