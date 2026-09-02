"""Generated C fragments for native code-capability state."""

from __future__ import annotations


def capability_authorization_source_v1(max_generations: int) -> str:
    return f'''static void spx_native_capability_lock(
    spx_native_capability_state *cap) {{
  while (__atomic_exchange_n(&cap->lock, 1U, __ATOMIC_ACQUIRE) != 0U)
    __asm__ volatile ("pause");
}}

static void spx_native_capability_unlock(
    spx_native_capability_state *cap) {{
  __atomic_store_n(&cap->lock, 0U, __ATOMIC_RELEASE);
}}

static uint32_t spx_native_capability_authorize(
    uint32_t capability_index, uint32_t owner_thread) {{
  spx_native_capability_state *cap;
  const spx_native_capability_lifetime_range *lifetime;
  uint32_t slot, authorized = 0U;
  if (capability_index >= spx_native_capability_count) return 0U;
  lifetime = spx_native_capability_lifetime_for(capability_index);
  if (lifetime == 0) return 0U;
  cap = &spx_native_capabilities[capability_index];
  spx_native_capability_lock(cap);
  for (slot = 0U; slot < {max_generations}U; ++slot) {{
    spx_native_capability_generation *generation = &cap->generations[slot];
    if (generation->active == 0U || generation->generation == 0U ||
        (generation->escaped == 0U && generation->owner_thread != owner_thread))
      continue;
    authorized = 1U;
    if (lifetime->lifetime_mode == 1U) generation->active = 0U;
    break;
  }}
  spx_native_capability_unlock(cap);
  return authorized;
}}'''


__all__ = ["capability_authorization_source_v1"]
