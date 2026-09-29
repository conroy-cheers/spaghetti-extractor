#include "object-mutable-native.h"
#include "binary-driver.h"

int main(int argc, char **argv) {
    const struct spx_jq_binary_driver driver = {
        "object-delete", jv_object_delete, fixture_object_delete, JV_KIND_OBJECT, JV_KIND_STRING, NULL
    };
    return spx_jq_binary_main(argc, argv, &driver);
}
