#include "array-indexes-native.h"
#include "binary-driver.h"

int main(int argc, char **argv) {
    const struct spx_jq_binary_driver driver = {
        "array-indexes", jv_array_indexes, fixture_array_indexes, JV_KIND_ARRAY, JV_KIND_ARRAY, NULL
    };
    return spx_jq_binary_main(argc, argv, &driver);
}
