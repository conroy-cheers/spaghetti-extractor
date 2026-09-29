#include "portable-component-implementation.h"
#include "value-layout.h"

void lifted_storage_create(spx_storage_create_context_v5 *context, uint32_t capacity,
                           struct spx_opaque_jq_value_v5 *output) {
    const spx_storage_create_services_v5 *services = context->services;
    jq_array *array = (jq_array *)services->allocate(services->context, capacity);
    array->refcnt.count = 1;
    array->length = 0;
    array->alloc_length = jq_signed_word(capacity);
    jq_value value = jq_array_value(array);
    output->value = value;
}
