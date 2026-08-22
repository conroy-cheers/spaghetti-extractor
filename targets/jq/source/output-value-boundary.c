#include "boundary.h"

void jq_output_value_release(jv value) {
  jv_free(value);
}

void jq_output_value_dump(jv value, FILE_ptr stream, spx_i32 flags) {
  jv_dumpf(value, stream, flags);
}

spx_i32 jq_output_value_pipeline(jv value, FILE_ptr stream, spx_i32 flags) {
  jv_dumpf(value, stream, flags);
  return 0;
}
