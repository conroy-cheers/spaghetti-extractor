#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "jv.h"
#pragma GCC diagnostic pop
#include "comparison-input-domain.h"
#include "binary-driver.h"

jv spx_fixture_array_append(jv, jv);
static int append_case_fields(const char *left, const char *right, const char *mode) {
    (void)right;
    if (strcmp(mode, "unique") && strcmp(mode, "unique-address") && strcmp(mode, "retained") && strcmp(mode, "aliased")) return 2;
    jv value = jv_parse(left);
    if (jv_get_kind(value) != JV_KIND_ARRAY) { jv_free(value); return 77; }
    uint32_t words[1] = {(uint32_t)jv_array_length(value)};
    if (!spx_comparison_admit_input(words, 1)) return 77;
    printf("\"input_words\":[%u],", (unsigned)words[0]);
    return 0;
}
int main(int argc, char **argv) {
    const struct spx_jq_binary_driver driver = {
        "array-append", jv_array_append, spx_fixture_array_append,
        JV_KIND_ARRAY, SPX_JQ_ANY_VALID, append_case_fields
    };
    return spx_jq_binary_main(argc, argv, &driver);
}
