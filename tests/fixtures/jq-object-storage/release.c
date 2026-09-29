#include "portable-component-implementation.h"
#include "object-storage.h"

void lifted_object_release(spx_object_release_context_v5 *context, jq_object_cell *input) {
    struct jq_object_storage *object = jq_object_data(input);
    if (--object->refcnt.count != 0) return;
    for (int32_t i = 0; i < input->value.size; ++i) {
        struct jq_object_slot *slot = &object->slots[i];
        if (jq_kind(jq_value_load(slot->key)) == 1U) continue;
        jq_object_cell key = {jq_value_load(slot->key)}, value = {jq_value_load(slot->value)};
        context->services->release_value(context->services->context, &key);
        context->services->release_value(context->services->context, &value);
    }
    context->services->dispose(context->services->context, (struct spx_opaque_object_memory_v5 *)object);
}
