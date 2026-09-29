#include "object-storage-native.h"
void jvp_object_free(jv value) {
    jq_object_cell input = object_pack(value); fixture_object_release(&input);
}
