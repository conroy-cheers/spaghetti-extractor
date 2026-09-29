#include "portable-component-implementation.h"
spx_view_v5 prepare_notice(spx_resource_notice_prefix_context_v5 *context,
 const spx_view_v5 *module, const spx_view_v5 *buffer) {
 (void)module;(void)buffer;
 return context->services->resource_text(context->services->context,31U);
}
