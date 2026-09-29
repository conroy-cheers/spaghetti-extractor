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
  uint32_t result = 0U;
  uint8_t left_byte = 0U;
  uint8_t right_byte = 0U;
  uint32_t left_lower;
  uint32_t right_lower;
  int64_t base_difference;

  SPX_PROOF_BEGIN(compare);
  if (spx_ref_difference(left->base, right->base, &base_difference) != SPX_REF_OK ||
      base_difference != INT64_C(0)) {
  for (;;) {
    SPX_PROOF_SYNC(
        scan,
        offset < SPX_PROOF_NUL_EXTENT(left) && offset < SPX_PROOF_NUL_EXTENT(right),
        left, right, offset, result);
    if (left->read_u8(left->context, offset, &left_byte) != 0U)
      break;
    left_lower = context->services->lower_ascii(
        context->services->context, (uint32_t)left_byte) & UINT32_C(255);
    SPX_PROOF_SYNC(
        left_converted,
        offset < SPX_PROOF_NUL_EXTENT(left) &&
            offset < SPX_PROOF_NUL_EXTENT(right) &&
            left_lower <= UINT32_C(255) &&
            (offset + 1U != SPX_PROOF_NUL_EXTENT(left) || left_lower == 0U),
        left, right, offset, result, left_lower);
    if (right->read_u8(right->context, offset, &right_byte) != 0U)
      break;
    right_lower = context->services->lower_ascii(
        context->services->context, (uint32_t)right_byte) & UINT32_C(255);
    SPX_PROOF_SYNC(
        decide,
        offset < SPX_PROOF_NUL_EXTENT(left) &&
            offset < SPX_PROOF_NUL_EXTENT(right) &&
            left_lower <= UINT32_C(255) && right_lower <= UINT32_C(255) &&
            (offset + 1U != SPX_PROOF_NUL_EXTENT(left) || left_lower == 0U) &&
            (offset + 1U != SPX_PROOF_NUL_EXTENT(right) || right_lower == 0U),
        left, right, offset, result, left_lower, right_lower);
    if (left_lower == 0U || left_lower != right_lower) {
      result = left_lower - right_lower;
      break;
    }
    offset += 1U;
  }
  }
  SPX_PROOF_SYNC(finish, 1, left, right, result);
  return gnu_hello_ascii_string_compare_difference(result, 0U);
}
