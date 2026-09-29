/* Reusable fixture bridge for this component's local test and its consumers.
 * Its generated interface is compiled in a separate translation unit.
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "jv.h"
#include "portable-component-implementation.h"
#include "comparison-input-domain.h"

#include "value-transport.h"

static spx_jv_value_v2 copy_value(void *environment, spx_jv_value_v2 value) {
  (void)environment;
  return spx_value_pack(jv_copy(spx_value_borrow(value)));
}
static uint32_t length(void *environment, spx_jv_value_v2 value) {
  (void)environment;
  return (uint32_t)jv_array_length(spx_value_take(value));
}
static spx_jv_value_v2 set(void *environment, spx_jv_value_v2 value, uint32_t index, spx_jv_value_v2 item) {
  (void)environment;
  return spx_value_pack(jv_array_set(spx_value_take(value), (int)index, spx_value_take(item)));
}

spx_jv_value_v2 spx_fixture_array_append_portable(spx_jv_value_v2 value, spx_jv_value_v2 item) {
  jv native_value=spx_value_borrow(value), native_item=spx_value_borrow(item);
  if (!jv_is_valid(native_value) || jv_get_kind(native_value) != JV_KIND_ARRAY || !jv_is_valid(native_item)) {
    fprintf(stderr, "dependency assumption violated: append requires an array and valid item\n");
    exit(4);
  }
  uint32_t input_words[1] = {(uint32_t)jv_array_length(jv_copy(native_value))};
  if (!spx_comparison_admit_input(input_words, 1))
    exit(77);
  spx_array_append_services_v5 services = {0};
  services.copy = copy_value;
  services.length = length;
  services.set = set;
  spx_array_append_context_v5 context = {0};
  context.services = &services;
  return lifted_array_append(&context, value, item);
}

jv spx_fixture_array_append(jv value, jv item) {
  jv result=spx_value_take(spx_fixture_array_append_portable(spx_value_pack(value),spx_value_pack(item)));
  spx_values_finish();
  return result;
}
