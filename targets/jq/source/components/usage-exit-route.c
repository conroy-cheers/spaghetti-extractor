#include "implementation.h"

void normalize_usage_status(status_service *service,
                            int32_t sign_source,
                            uint32_t status) {
  if (sign_source < 0 && status == 0U)
    status = 2U;
  service->terminate(service->context, status);
}
