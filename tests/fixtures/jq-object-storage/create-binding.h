#include "object-storage-native.h"
jv jvp_object_new(int capacity) {
    jq_object_cell output; fixture_object_create((uint32_t)capacity, &output); return object_unpack(output);
}
