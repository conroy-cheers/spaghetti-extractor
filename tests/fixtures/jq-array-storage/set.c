#include "portable-component-implementation.h"
#include "value-layout.h"

void lifted_storage_set(spx_storage_set_context_v5 *context,
                        struct spx_opaque_jq_value_v5 *input, int32_t index,
                        struct spx_opaque_jq_value_v5 *item,
                        struct spx_opaque_jq_value_v5 *output) {
    const spx_storage_set_services_v5 *services = context->services;
    void *environment = services->context;
    jq_value value = input->value;
    if (index < 0) index = jq_signed_word((uint32_t)value.size + (uint32_t)index);
    if (index < 0 || index > (INT32_MAX >> 2) - (int)value.offset) {
        services->release(environment, input);
        services->release(environment, item);
        services->error(environment, index < 0 ? 1U : 2U, output);
        return;
    }
    jq_array *array = (jq_array *)value.u.ptr;
    int position = index + value.offset;
    if (position < array->alloc_length && array->refcnt.count == 1) {
        for (int i = array->length; i <= position; ++i)
            array->elements[i] = jq_value_store(jq_null_value());
        if (array->length <= position) array->length = position + 1;
        if (value.size <= index) value.size = index + 1;
    } else {
        int length = value.size > index ? value.size : index + 1;
        struct spx_opaque_jq_value_v5 replacement;
        services->create(environment, (uint32_t)length * 3U / 2U, &replacement);
        jq_array *fresh = (jq_array *)replacement.value.u.ptr;
        for (int i = 0; i < value.size; ++i) {
            struct spx_opaque_jq_value_v5 old = {jq_value_load(array->elements[i + value.offset])}, copied;
            services->copy(environment, &old, &copied);
            fresh->elements[i] = jq_value_store(copied.value);
        }
        for (int i = value.size; i < length; ++i)
            fresh->elements[i] = jq_value_store(jq_null_value());
        fresh->length = length;
        services->release(environment, input);
        value = replacement.value;
        value.size = length;
        array = fresh;
        position = index;
    }
    struct spx_opaque_jq_value_v5 previous = {jq_value_load(array->elements[position])};
    services->release(environment, &previous);
    array->elements[position] = jq_value_store(item->value);
    output->value = value;
}
