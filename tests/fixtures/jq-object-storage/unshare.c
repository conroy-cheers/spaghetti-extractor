#include "portable-component-implementation.h"
#include "object-storage.h"
#include <string.h>

void lifted_object_unshare(spx_object_unshare_context_v5 *context, jq_object_cell *input, jq_object_cell *output) {
    struct jq_object_storage *before = jq_object_data(input);
    if (before->refcnt.count == 1) { *output = *input; return; }
    jq_object_cell original = *input;
    uint32_t capacity = (uint32_t)input->value.size;
    const spx_object_unshare_services_v5 *services = context->services;
    services->create(services->context, capacity, output);
    struct jq_object_storage *after = jq_object_data(output);
    after->next_free = before->next_free;
    for (uint32_t i = 0; i < capacity; ++i) {
        after->slots[i] = before->slots[i];
        if (jq_kind(jq_value_load(before->slots[i].key)) == 1U) continue;
        jq_object_cell key = {jq_value_load(before->slots[i].key)};
        jq_object_cell value = {jq_value_load(before->slots[i].value)}, copied;
        services->copy(services->context, &key, &copied);
        after->slots[i].key = jq_value_store(copied.value);
        services->copy(services->context, &value, &copied);
        after->slots[i].value = jq_value_store(copied.value);
    }
    memcpy(jq_object_buckets(after, capacity), jq_object_buckets(before, capacity),
           sizeof(int32_t) * capacity * 2U);
    services->release_object(services->context, &original);
}
