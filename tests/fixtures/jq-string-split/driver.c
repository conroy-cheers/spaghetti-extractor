#include "string-native.h"
#include "binary-driver.h"

extern jv fixture_string_split(jv, jv);
int main(int argc, char **argv) {
    const struct spx_jq_binary_driver driver = {
        "string-split", jv_string_split, fixture_string_split, JV_KIND_STRING, JV_KIND_STRING, NULL
    };
    return spx_jq_binary_main(argc, argv, &driver);
}
