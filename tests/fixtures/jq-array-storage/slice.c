#include "portable-component-implementation.h"
#include "value-layout.h"

void lifted_storage_slice(spx_storage_slice_context_v5 *context,
                          struct spx_opaque_jq_value_v5 *input, int32_t start, int32_t end,
                          struct spx_opaque_jq_value_v5 *output) {
    const spx_storage_slice_services_v5 *services = context->services;
    void *environment = services->context;
    jq_value value = input->value;
    if (start < 0) start = jq_signed_word((uint32_t)value.size + (uint32_t)start);
    if (end < 0) end = jq_signed_word((uint32_t)value.size + (uint32_t)end);
    if (start < 0) start = 0;
    if (start > value.size) start = value.size;
    if (end > value.size) end = value.size;
    if (end < start) end = start;
    if (start == end) {
        services->release(environment, input);
        services->create(environment, 16U, output);
    } else if ((uint32_t)value.offset + (uint32_t)start >= 65536U) {
        struct spx_opaque_jq_value_v5 result;
        services->create(environment, (uint32_t)(end - start), &result);
        for (int i = start; i < end; ++i) {
            struct spx_opaque_jq_value_v5 borrowed, element, next;
            services->copy(environment, input, &borrowed);
            services->get(environment, &borrowed, i, &element);
            services->set(environment, &result, result.value.size, &element, &next);
            result = next;
        }
        services->release(environment, input);
        *output = result;
    } else {
        value.offset = (unsigned short)((unsigned)value.offset + (unsigned)start);
        value.size = end - start;
        output->value = value;
    }
}
