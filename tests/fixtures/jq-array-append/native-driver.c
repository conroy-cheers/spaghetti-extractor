#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "jv.h"
#include "comparison-input-domain.h"

jv spx_fixture_array_append(jv value, jv item);

static void observation(const char *name, jv value) {
  jv text = jv_dump_string(value, 0);
  printf("\"%s\":%s", name, jv_string_value(text));
  jv_free(text);
}

int main(int argc, char **argv) {
  if (argc != 3 || (strcmp(argv[1], "original") && strcmp(argv[1], "source")))
    return 2;
  char *end;
  long scenario = strtol(argv[2], &end, 10);
  if (!*argv[2] || *end || scenario < 0 || scenario > 4)
    return 2;
  jv value = scenario == 0 ? jv_array() : jv_parse("[1,2]");
  jv item = jv_number(3);
  if (scenario == 2) {
    jv_free(value);
    item = jv_parse("{\"nested\":[7,8]}");
    value = jv_array_append(jv_array(), jv_copy(item));
  } else if (scenario == 3) {
    value = jv_array_slice(value, 1, 2);
  } else if (scenario == 4) {
    item = jv_copy(value);
  }
  jv kept_value = scenario == 0 ? jv_null() : jv_copy(value);
  jv kept_item = jv_copy(item);
  uint32_t input_words[1] = {(uint32_t)jv_array_length(jv_copy(value))};
  if (!spx_comparison_admit_input(input_words, 1)) {
    jv_free(value); jv_free(item); jv_free(kept_value); jv_free(kept_item);
    return 77;
  }
  jv result = !strcmp(argv[1], "original") ? jv_array_append(value, item) : spx_fixture_array_append(value, item);
  if (!jv_is_valid(result)) {
    fprintf(stderr, "unexpected invalid result in admitted append case\n");
    return 3;
  }
  printf("{\"input_words\":[%u],\"scenario\":%ld,", (unsigned)input_words[0], scenario);
  observation("result", result);
  printf(","); observation("value_after", kept_value);
  printf(","); observation("item_after", kept_item);
  printf("}\n");
  return 0;
}
