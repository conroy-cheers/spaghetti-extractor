#include "portable-component-implementation.h"
#include "value-layout.h"

void lifted_storage_get(spx_storage_get_context_v5 *context,
                        struct spx_opaque_jq_value_v5 *input, int32_t index,
                        struct spx_opaque_jq_value_v5 *output) {
    const spx_storage_get_services_v5 *services = context->services;
    void *environment = services->context;
    jq_value value = input->value;
    output->value = jq_invalid_value();
    if (index >= 0 && index < value.size) {
        jq_array *array = (jq_array *)value.u.ptr;
        struct spx_opaque_jq_value_v5 item = {jq_value_load(array->elements[index + value.offset])};
        services->copy(environment, &item, output);
    }
    services->release(environment, input);
}
