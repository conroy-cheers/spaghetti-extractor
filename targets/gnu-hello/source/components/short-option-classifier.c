#include "portable-component-implementation.h"

uint32_t gnu_hello_short_option_classifier(
    spx_short_option_classifier_context_v2 *context,
    uint16_t value) {
  SPX_PROOF_BEGIN(classify);
  (void)context;
  return value != UINT16_C(523);
}
