#include "implementation.h"

uint32_t write_constant_buffer(byte_output_service *service,
                               const uint8_t *buffer,
                               uint32_t element_size,
                               uint32_t element_count,
                               uintptr_t stream) {
  return service->write(service->context, buffer, element_size,
                        element_count, stream);
}
