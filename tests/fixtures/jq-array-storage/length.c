#include "portable-component-implementation.h"
#include "value-layout.h"

int32_t lifted_storage_length(spx_storage_length_context_v5 *context,
                             struct spx_opaque_jq_value_v5 *input) {
    int32_t length=input->value.size;
    context->services->release(context->services->context,input);
    return length;
}
