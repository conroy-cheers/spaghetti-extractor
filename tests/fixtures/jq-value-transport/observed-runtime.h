/* Instrumented reference transport. Native storage remains in libjq. The
 * generic observer tracks tokens, frames and aliases, not native heap safety.
 * Immediates also occupy transport slots; an outstanding token is not by itself
 * proof of a native allocation leak. Object addresses are diagnostic hints only.
 */
#include "comparison-resources.h"
enum { SPX_OBSERVED_VALUE_TAG = 0x53505857 };
static jv spx_observed_values[SPX_RESOURCE_CAPACITY];
static spx_resource_token spx_observed_token(spx_jv_value_v2 value) {
  if (value.metadata!=SPX_OBSERVED_VALUE_TAG || value.payload_high!=0)
    return (spx_resource_token){0,0};
  return (spx_resource_token){value.size,value.payload_low};
}
spx_jv_value_v2 spx_value_pack(jv value) {
  jv_kind kind=jv_get_kind(value);
  uint64_t object=(kind==JV_KIND_STRING || kind==JV_KIND_ARRAY || kind==JV_KIND_OBJECT)
    ? (uint64_t)(uintptr_t)value.u.ptr : 0;
  spx_resource_token token=spx_resource_acquire(object);
  spx_observed_values[spx_resource_slot(token)]=value;
  return (spx_jv_value_v2){SPX_OBSERVED_VALUE_TAG,token.slot,token.generation,0};
}
jv spx_value_borrow(spx_jv_value_v2 value) {
  return spx_observed_values[spx_resource_borrow(spx_observed_token(value))];
}
jv spx_value_take(spx_jv_value_v2 value) {
  spx_resource_token token=spx_observed_token(value);
  jv result=spx_observed_values[spx_resource_slot(token)];
  spx_resource_consume(token);
  return result;
}
/* Exit accounting belongs to each selected operation contract. No blanket
 * zero-live-reference rule or automatic freeing of escaped native references. */
void spx_values_finish(void) { }
