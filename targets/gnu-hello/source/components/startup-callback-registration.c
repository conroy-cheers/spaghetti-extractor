#include "portable-component-implementation.h"

spx_callback_previous_exception_filter_v2 *
gnu_hello_startup_callback_registration(
    spx_startup_callback_registration_context_v2 *context,
    spx_callback_exception_filter_v2 *handler) {
  SPX_PROOF_BEGIN(install);
  return context->services->set_unhandled_exception_filter(
      context->services->context, handler);
}
