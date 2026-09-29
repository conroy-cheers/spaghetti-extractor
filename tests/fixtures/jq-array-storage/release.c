#include "portable-component-implementation.h"
#include "value-layout.h"

void lifted_storage_release(spx_storage_release_context_v5 *context,
                           struct spx_opaque_jq_value_v5 *input) {
    const spx_storage_release_services_v5 *services = context->services;
    void *environment = services->context;
    jq_value value = input->value;
    if (!jq_allocated(value)) return;
    if (jq_kind(value) != 6U) {
        services->foreign_release(environment, input);
        return;
    }
    jq_array *array = (jq_array *)value.u.ptr;
    array->refcnt.count = jq_signed_word((uint32_t)array->refcnt.count - 1U);
    if (array->refcnt.count != 0) return;
    /* The backing array owns every initialized element, including elements
     * outside a live slice. Freeing only the visible view would leak them. */
    for (int i = 0; i < array->length; ++i) {
        struct spx_opaque_jq_value_v5 item = {jq_value_load(array->elements[i])};
        /* Immediate values have no allocation and release has no effect. */
        if (jq_allocated(item.value)) services->release(environment, &item);
    }
    services->dispose(environment, (struct spx_opaque_jq_memory_v5 *)array);
}
