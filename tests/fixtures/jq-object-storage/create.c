#include "portable-component-implementation.h"
#include "object-storage.h"

void lifted_object_create(spx_object_create_context_v5 *context, uint32_t capacity, jq_object_cell *output) {
    struct jq_object_storage *object = (struct jq_object_storage *)
        context->services->allocate(context->services->context, capacity);
    object->refcnt.count = 1;
    object->next_free = 0;
    for (uint32_t i = 0; i < capacity; ++i) {
        object->slots[i].next = i ? (int32_t)(i - 1U) : -1;
        object->slots[i].hash = 0;
        object->slots[i].key = jq_value_store(jq_null_value());
        object->slots[i].value = jq_value_store(jq_null_value());
    }
    int32_t *buckets = jq_object_buckets(object, capacity);
    for (uint32_t i = 0; i < capacity * 2U; ++i) buckets[i] = -1;
    jq_native_value value = {135, 0, 0, (int)capacity, {.ptr = &object->refcnt}};
    output->value = jq_value_load(value);
}
