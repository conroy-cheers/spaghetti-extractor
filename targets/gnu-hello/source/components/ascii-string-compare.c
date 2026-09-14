#include "portable-component-implementation.h"

static int32_t gnu_hello_ascii_string_compare_difference(
    uint32_t left,
    uint32_t right) {
  uint32_t difference = left - right;

  if (difference <= UINT32_C(2147483647))
    return (int32_t)difference;
  return (-2147483647 - 1) +
      (int32_t)(difference - UINT32_C(2147483648));
}

int32_t gnu_hello_ascii_string_compare(
    spx_ascii_string_compare_context_v5 *context,
    const spx_bytes_view_v2 *left,
    const spx_bytes_view_v2 *right) {
  uint32_t offset = 0U;
  int32_t result = 0;
  uint8_t left_byte = 0U;
  uint8_t right_byte = 0U;
  uint32_t left_lower;
  uint32_t right_lower;
  int64_t base_difference;

  SPX_PROOF_BEGIN(compare);
  if (spx_ref_difference(left->base, right->base, &base_difference) == SPX_REF_OK &&
      base_difference == INT64_C(0))
    return 0;
  for (;;) {
    if (left->read_u8(left->context, offset, &left_byte) != 0U ||
        right->read_u8(right->context, offset, &right_byte) != 0U)
      return 0;
    left_lower = context->services->lower_ascii(
        context->services->context, (uint32_t)left_byte) & UINT32_C(255);
    right_lower = context->services->lower_ascii(
        context->services->context, (uint32_t)right_byte) & UINT32_C(255);
    if (left_lower == 0U || left_lower != right_lower) {
      result = gnu_hello_ascii_string_compare_difference(left_lower, right_lower);
      return result;
    }
    SPX_PROOF_SYNC(
        scan,
        offset < left->extent && offset < right->extent,
        left, right, offset, result);
    offset += 1U;
  }
}
