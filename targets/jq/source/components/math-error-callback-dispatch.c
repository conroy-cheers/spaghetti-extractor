#include "implementation.h"

uint32_t dispatch_optional_fp64_record(
    optional_fp64_record_callback *callback,
    optional_fp64_record record) {
  if (callback->target != 0U)
    callback->invoke(callback->context, callback->target, &record);
  return 0U;
}
