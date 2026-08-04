#include "implementation.h"

labeled_opaque_value_prefix prepare_labeled_opaque_value_prefix(
    opaque_label_services *services, uint32_t stream_context,
    opaque_value4 value) {
  labeled_opaque_value_prefix result;
  result.value = value;
  result.stream = services->open_stream(services->context, OPAQUE_LABEL_MODE);
  result.stream_context = stream_context & OPAQUE_LABEL_CONTEXT_MASK;
  result.label = services->make_label(services->context, OPAQUE_LABEL_TEXT);
  return result;
}
