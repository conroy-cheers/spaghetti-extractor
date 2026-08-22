#include "portable-component-implementation.h"

void gnu_hello_startup_sleep_service(
    spx_startup_sleep_service_context_v2 *context) {
  context->services->sleep_milliseconds(
      context->services->context, UINT32_C(1000));
}
