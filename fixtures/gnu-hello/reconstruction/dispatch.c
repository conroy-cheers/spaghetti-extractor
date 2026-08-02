#include "implementation.h"

bool reconstruct_region(const reconstructed_region_inputs *inputs,
                        reconstructed_region_outputs *outputs) {
  const uint32_t selector = inputs->register_eax & UINT32_C(0xff);

  if (selector >= UINT32_C(36))
    return false;

  outputs->register_edx = selector;
  outputs->control_kind = RECONSTRUCTED_INDIRECT_JUMP;
  outputs->target_rva = 0U;
  outputs->value = inputs->memory_view_00_p4330740;
  return true;
}
