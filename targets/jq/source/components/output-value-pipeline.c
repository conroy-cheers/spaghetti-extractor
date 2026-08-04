#include "implementation.h"

void prepare_and_dump_opaque_output(opaque_output_services *services) {
  uint32_t stream = services->open_stream(services->context, 1U);
  opaque_value4 source = services->load_source(services->context);
  opaque_copy_result copied =
      services->copy_value(services->context, source, stream);
  services->dump_value(services->context, copied.value, copied.stream, 2U);
}
