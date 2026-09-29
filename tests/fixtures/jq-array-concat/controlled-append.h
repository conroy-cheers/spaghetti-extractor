/* Argument/state-sensitive executable dependency fixture. Uses real array_set
 * for successful writes; injected invalid outcomes are conditional tests, not
 * evidence that this libjq allocator can produce a recoverable failure.
 */
#include "pe32-entry-hook.h"

static struct {
  int calls, failure_at, terminal;
  jv expected_left, expected_right;
  jv destinations[8], items[8];
  int references[8];
} control;

static void assumption_failed(const char *message) {
  fprintf(stderr, "dependency assumption violated: %s\n", message);
  exit(4);
}

static jv logical_clone(jv value) {
  jv text = jv_dump_string(jv_copy(value), 0);
  jv result = jv_parse(jv_string_value(text));
  jv_free(text);
  return result;
}

static jv controlled_append(jv value, jv item) {
  int index = control.calls;
  if (control.terminal || index >= 8 ||
      index >= jv_array_length(jv_copy(control.expected_right)))
    assumption_failed("unexpected append after completion");
  if (!jv_equal(jv_copy(value), jv_copy(control.expected_left)))
    assumption_failed("append destination differs from current logical state");
  jv expected_item = jv_array_get(jv_copy(control.expected_right), index);
  if (!jv_equal(jv_copy(item), jv_copy(expected_item)))
    assumption_failed("append item differs from the next right-array element");
  /* Strings retain observations without adding a reference to the live array. */
  control.references[index] = jv_get_refcnt(value);
  control.destinations[index] = jv_dump_string(jv_copy(value), 0);
  control.items[index] = jv_dump_string(jv_copy(item), 0);
  ++control.calls;
  if (control.calls == control.failure_at) {
    control.terminal = 1;
    jv_free(expected_item);
    jv_free(value);
    jv_free(item);
    return jv_invalid();
  }
  int length = jv_array_length(jv_copy(value));
  control.expected_left = jv_array_set(control.expected_left, length, expected_item);
  return jv_array_set(value, length, item);
}

static void control_start(jv left, jv right, int failure_at) {
  control.expected_left = logical_clone(left);
  control.expected_right = logical_clone(right);
  control.failure_at = failure_at;
}

static void control_observation(void) {
  int required = jv_array_length(jv_copy(control.expected_right));
  if (control.failure_at && control.failure_at < required)
    required = control.failure_at;
  if (control.calls != required)
    assumption_failed("consumer omitted a required append");
  printf("[");
  for (int index = 0; index < control.calls; ++index) {
    printf("%s{\"operation\":\"append\",\"destination\":%s,\"item\":%s,"
        "\"destination_references\":%d,\"outcome\":\"%s\"}",
        index ? "," : "", jv_string_value(control.destinations[index]),
        jv_string_value(control.items[index]), control.references[index],
        index + 1 == control.failure_at ? "invalid" : "array");
    jv_free(control.destinations[index]);
    jv_free(control.items[index]);
  }
  printf("]");
  jv_free(control.expected_left);
  jv_free(control.expected_right);
}
