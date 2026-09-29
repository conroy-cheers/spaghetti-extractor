/* Bounded fixture representation: tokens hold no native pointer or value bytes.
 * A process-local table owns native references until transfer. Native jv sharing
 * and copy-on-write are preserved by retaining the actual jv, not reconstructing
 * an object from an address. This is executable fixture support, not a heap proof.
 */
#include <stdio.h>
#include <stdlib.h>
enum { SPX_VALUE_CAPACITY = 32, SPX_VALUE_TAG = 0x53505856 };
static struct { jv value; uint32_t generation; int live; } spx_values[SPX_VALUE_CAPACITY];
static void spx_value_fault(const char *reason) {
  fprintf(stderr, "private value representation: %s\n", reason);
  exit(4);
}
static size_t spx_value_slot(spx_jv_value_v2 value) {
  if (value.metadata != SPX_VALUE_TAG || value.size == 0 || value.size > SPX_VALUE_CAPACITY || value.payload_high != 0)
    spx_value_fault("invalid token or incompatible representation");
  size_t slot = value.size - 1;
  if (!spx_values[slot].live || spx_values[slot].generation != value.payload_low)
    spx_value_fault("expired token or transferred ownership");
  return slot;
}
spx_jv_value_v2 spx_value_pack(jv value) {
  for (size_t slot = 0; slot < SPX_VALUE_CAPACITY; ++slot) {
    if (!spx_values[slot].live) {
      if (spx_values[slot].generation == UINT32_MAX)
        spx_value_fault("generation exhausted");
      spx_values[slot].generation++;
      spx_values[slot].value = value;
      spx_values[slot].live = 1;
      return (spx_jv_value_v2){SPX_VALUE_TAG, (uint32_t)slot + 1, spx_values[slot].generation, 0};
    }
  }
  spx_value_fault("bounded table exhausted");
  return (spx_jv_value_v2){0};
}
jv spx_value_borrow(spx_jv_value_v2 value) { return spx_values[spx_value_slot(value)].value; }
jv spx_value_take(spx_jv_value_v2 value) {
  size_t slot = spx_value_slot(value);
  spx_values[slot].live = 0;
  return spx_values[slot].value;
}
void spx_values_finish(void) {
  for (size_t slot = 0; slot < SPX_VALUE_CAPACITY; ++slot)
    if (spx_values[slot].live)
      spx_value_fault("unreleased owned value");
}
