#include "object-storage-native.h"
jv jvp_object_unshare(jv value) {
    jq_object_cell input = object_pack(value), output;
    fixture_object_unshare(&input, &output); return object_unpack(output);
}
