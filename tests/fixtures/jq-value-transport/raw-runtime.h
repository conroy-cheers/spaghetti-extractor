#include <string.h>
_Static_assert(sizeof(jv) == sizeof(spx_jv_value_v2), "PE32 raw jv transport differs");
spx_jv_value_v2 spx_value_pack(jv value) {
  spx_jv_value_v2 result;
  memcpy(&result, &value, sizeof(result));
  return result;
}
jv spx_value_borrow(spx_jv_value_v2 value) {
  jv result;
  memcpy(&result, &value, sizeof(result));
  return result;
}
jv spx_value_take(spx_jv_value_v2 value) { return spx_value_borrow(value); }
void spx_values_finish(void) { }
