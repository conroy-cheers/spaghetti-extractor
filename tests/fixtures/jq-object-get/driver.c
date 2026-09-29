#include "object-native.h"
#include "binary-driver.h"

/* Keep an absent key distinct from a present JSON null in the existing driver.
 * This observation wrapper is outside the replaced native entry. */
static jv sample(jv object, jv key) {
    struct spx_opaque_object_table_v5 table;
    object_contents(object, &table);
    uint32_t hash = object_key_hash(key);
    int32_t index;
    memcpy(&index, table.buckets + (hash & (table.capacity * 2U - 1U)) * sizeof(index), sizeof(index));
    unsigned steps = 0;
    for (int32_t cursor = index; cursor != -1; cursor = object_slot(&table, cursor).next) ++steps;
    fprintf(stderr, "object-get-bucket-length=%u\n", steps);
    jv result = jv_object_get(object, key);
    int valid = jv_is_valid(result);
    if (!valid) { jv_free(result); result = jv_null(); }
    return jv_array_append(jv_array_append(jv_array(), jv_bool(valid)), result);
}
int main(int argc, char **argv) {
    const struct spx_jq_binary_driver driver = {
        "object-get", sample, fixture_object_get, JV_KIND_OBJECT, JV_KIND_STRING, NULL
    };
    return spx_jq_binary_main(argc, argv, &driver);
}
