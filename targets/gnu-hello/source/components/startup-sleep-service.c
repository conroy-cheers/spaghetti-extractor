#include "portable-component-implementation.h"

void gnu_hello_startup_sleep_service(
    spx_startup_sleep_service_context_v2 *context) {
  SPX_PROOF_BEGIN(delay);
  context->services->sleep_milliseconds(
      context->services->context, UINT32_C(1000));
}
