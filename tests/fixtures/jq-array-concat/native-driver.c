/* Test adapter: invokes the real PE32 libjq and the generated component ABI.
 * This file is fixture code, not authored component code or a checked summary.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "jv.h"
#include "portable-component-implementation.h"
#include "controlled-append.h"
#include "comparison-input-domain.h"
#include "comparison-selection.h"
#include "value-transport.h"

static int use_selected_append;

static spx_jv_value_v2 copy_value(void *context, spx_jv_value_v2 value) {
  (void)context;
  return spx_value_pack(jv_copy(spx_value_borrow(value)));
}

static uint32_t length(void *context, spx_jv_value_v2 value) {
  (void)context;
  return (uint32_t)jv_array_length(spx_value_take(value));
}

static spx_jv_value_v2 get(void *context, spx_jv_value_v2 value, uint32_t index) {
  (void)context;
  return spx_value_pack(jv_array_get(spx_value_take(value), (int)index));
}

static spx_jv_value_v2 append(void *context, spx_jv_value_v2 value, spx_jv_value_v2 item) {
  (void)context;
  if (use_selected_append)
    return spx_fixture_selected_append(value, item);
  return spx_value_pack(jv_array_append(spx_value_take(value), spx_value_take(item)));
}

static void release(void *context, spx_jv_value_v2 value) {
  (void)context;
  jv_free(spx_value_take(value));
}

static uint32_t valid(void *context, spx_jv_value_v2 value) {
  (void)context;
  return (uint32_t)spx_value_valid(value);
}

static void observation(const char *name, jv value) {
  jv string = jv_dump_string(value, 0);
  printf("\"%s\":%s", name, jv_string_value(string));
  jv_free(string);
}

/* The oracle and replacement must receive the declared case, even when a
 * fixture edit accidentally changes both sides in the same way. Logical
 * equality alone does not establish the sharing used by these cases. */
static void check_setup(long scenario, jv left, jv right) {
  const char *expected_left = scenario == 3 ? "[{\"nested\":[7,8]}]" : "[1,2]";
  const char *expected_right = scenario == 0 ? "[]" : scenario == 2 ? "[1,2]" :
      scenario == 3 ? expected_left : scenario == 4 ? "[2]" : "[3,4]";
  if (!jv_equal(jv_copy(left), jv_parse(expected_left)) ||
      !jv_equal(jv_copy(right), jv_parse(expected_right))) {
    fprintf(stderr, "fixture setup has wrong logical input contents\n");
    exit(6);
  }
  if ((scenario == 2 || scenario == 4) && left.u.ptr != right.u.ptr) {
    fprintf(stderr, "fixture setup lost required whole-array or slice alias\n");
    exit(6);
  }
  if (scenario == 3) {
    jv a = jv_array_get(jv_copy(left), 0), b = jv_array_get(jv_copy(right), 0);
    int shared = a.u.ptr == b.u.ptr;
    jv_free(a); jv_free(b);
    if (!shared) {
      fprintf(stderr, "fixture setup lost required nested-object alias\n");
      exit(6);
    }
  }
  if (scenario == 5 && jv_get_refcnt(left) != 1) {
    fprintf(stderr, "fixture setup lost unique mutable destination\n");
    exit(6);
  }
}

int main(int argc, char **argv) {
  if ((argc != 3 && argc != 4) || (strcmp(argv[1], "original") && strcmp(argv[1], "source")))
    return 2;
  const char *mode = argc == 4 ? argv[3] : "real";
  int selected = !strcmp(mode, "supplier");
  int controlled = strcmp(mode, "real") != 0 && !selected;
  int failure_at = !strcmp(mode, "fail-first") ? 1 : !strcmp(mode, "fail-second") ? 2 : 0;
  if (controlled && !failure_at && strcmp(mode, "controlled"))
    return 2;
  if (selected && !spx_fixture_selected_append)
    return 2;
  use_selected_append = selected && !strcmp(argv[1], "source");
  char *end;
  long scenario = strtol(argv[2], &end, 10);
  if (!*argv[2] || *end || scenario < 0 || scenario > 5)
    return 2;
  jv left = jv_parse("[1,2]");
  jv right = jv_parse("[3,4]");
  if (scenario == 0) {
    jv_free(right);
    right = jv_array();
  } else if (scenario == 2) {
    jv_free(right);
    right = jv_copy(left);
  } else if (scenario == 3) {
    jv_free(left);
    jv_free(right);
    jv shared = jv_parse("{\"nested\":[7,8]}");
    left = jv_array_append(jv_array(), jv_copy(shared));
    right = jv_array_append(jv_array(), shared);
  } else if (scenario == 4) {
    jv_free(right);
    right = jv_array_slice(jv_copy(left), 1, 2);
  }
  check_setup(scenario, left, right);
  /* Scenario 5 leaves the destination unique to exercise actual in-place writes.
   * The others retain references to observe copy-on-write and input preservation.
   */
  jv kept_left = scenario == 5 ? jv_null() : jv_copy(left);
  jv kept_right = jv_copy(right);
  uint32_t input_words[2] = {(uint32_t)jv_array_length(jv_copy(left)), (uint32_t)jv_array_length(jv_copy(right))};
  if (!spx_comparison_admit_input(input_words, 2)) {
    jv_free(left); jv_free(right); jv_free(kept_left); jv_free(kept_right);
    return 77;
  }
  spx_array_concat_services_v5 services = {0};
  services.copy = copy_value;
  services.length = length;
  services.get = get;
  services.append = append;
  services.release = release;
  services.valid = valid;
  spx_array_concat_context_v5 context = {0};
  context.services = &services;
  spx_fixture_entry_hook hook = {0};
  if (controlled) {
    control_start(left, right, failure_at);
    const unsigned char prefix[5] = {0x56, 0x53, 0x83, 0xec, 0x64};
    /* Pinned append range [0x287bd,0x288b3): remove its complete body during
     * the comparison, so any interior entry traps instead of running old code. */
    if (!spx_fixture_redirect_body(&hook, "libjq-1.dll", "jv_array_append",
          prefix, 0xf6, (void (*)(void))controlled_append)) {
      fprintf(stderr, "fixture failed to bind pinned append entry\n");
      return 5;
    }
  }
  jv result = !strcmp(argv[1], "original") ? jv_array_concat(left, right) :
      spx_value_take(lifted_array_concat(&context, spx_value_pack(left), spx_value_pack(right)));
  spx_values_finish();
  if (controlled && !spx_fixture_restore_entry(&hook)) {
    fprintf(stderr, "fixture failed to restore append entry\n");
    return 5;
  }
  printf("{\"input_words\":[%u,%u],\"scenario\":%ld,\"dependency_mode\":\"%s\",\"right_references\":%d,"
      "\"outcome\":\"%s\",\"interactions\":", (unsigned)input_words[0], (unsigned)input_words[1], scenario, mode, jv_get_refcnt(kept_right),
      jv_is_valid(result) ? "array" : "invalid");
  if (controlled)
    control_observation();
  else
    printf("null"); /* Intermediate original calls are not observed in real mode. */
  printf(",");
  if (jv_is_valid(result))
    observation("result", result);
  else {
    printf("\"result\":null");
    jv_free(result);
  }
  printf(",");
  observation("left_after", kept_left);
  printf(",");
  observation("right_after", kept_right);
  printf("}\n");
  return 0;
}
