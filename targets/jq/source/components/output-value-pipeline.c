#include "portable-component-implementation.h"

void jq_output_value_pipeline_run(
    spx_output_value_pipeline_context_v5 *context,
    spx_jv_value_v2 value,
    spx_resource_v2 stream) {
  SPX_PROOF_BEGIN(run);
  const spx_jv_value_v2 copied = context->services->copy_value(
      context->services->context, value);
  context->services->dump_value(
      context->services->context, copied, stream);
}
