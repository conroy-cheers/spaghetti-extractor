#include "portable-component-implementation.h"
#include "value-layout.h"

void lifted_storage_copy(spx_storage_copy_context_v5 *context,
                        struct spx_opaque_jq_value_v5 *input,
                        struct spx_opaque_jq_value_v5 *output) {
    (void)context;
    jq_value value = input->value;
    if (jq_allocated(value))
        value.u.ptr->count = jq_signed_word((uint32_t)value.u.ptr->count + 1U);
    output->value = value;
}
