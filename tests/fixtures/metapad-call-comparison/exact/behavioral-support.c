#include "behavioral-c.h"

uint32_t spx_mask(uint32_t width) {
  return width >= 32U ? 0xffffffffU : ((1U << width) - 1U);
}

uint32_t spx_read(spx_runtime *rt, uint32_t address, uint32_t width, uint32_t *fault) {
  if (rt == 0 || rt->read == 0) { *fault = 1U; return 0U; }
  return rt->read(rt->context, address, width, fault);
}

void spx_write(spx_runtime *rt, uint32_t address, uint32_t width, uint32_t value, uint32_t *fault) {
  if (rt == 0 || rt->write == 0) { *fault = 1U; return; }
  rt->write(rt->context, address, width, value, fault);
}

uint32_t spx_undefined(spx_runtime *rt, uint32_t slot,
    const spx_machine_state *input, uint32_t defined_value) {
  return rt != 0 && rt->undefined_value != 0
      ? rt->undefined_value(rt->context, slot, input, defined_value) : slot;
}

void spx_sync_eflags(spx_machine_state *state) {
  const uint32_t represented =
      (1U << 0) | (1U << 2) | (1U << 6) | (1U << 7) |
      (1U << 10) | (1U << 11);
  state->eflags = (state->eflags & ~represented) |
      ((state->cf & 1U) << 0) |
      ((state->pf & 1U) << 2) |
      ((state->zf & 1U) << 6) |
      ((state->sf & 1U) << 7) |
      ((state->df & 1U) << 10) |
      ((state->of & 1U) << 11);
}

uint32_t spx_sign_extend(uint32_t width, uint32_t value) {
  uint32_t mask = spx_mask(width);
  uint32_t sign = 1U << (width - 1U);
  value &= mask;
  return (value ^ sign) - sign;
}

uint32_t spx_sar(uint32_t width, uint32_t value, uint32_t amount) {
  amount &= 31U;
  return (uint32_t)(((int32_t)spx_sign_extend(width, value)) >> amount) & spx_mask(width);
}

uint32_t spx_msb(uint32_t width, uint32_t value) {
  return (value >> (width - 1U)) & 1U;
}

uint32_t spx_parity(uint32_t value) {
  value ^= value >> 4U;
  value &= 0xfU;
  return (0x9669U >> value) & 1U;
}

uint32_t spx_add_overflow(uint32_t width, uint32_t left, uint32_t right, uint32_t result) {
  return ((~(left ^ right) & (left ^ result)) >> (width - 1U)) & 1U;
}

uint32_t spx_sub_overflow(uint32_t width, uint32_t left, uint32_t right, uint32_t result) {
  return (((left ^ right) & (left ^ result)) >> (width - 1U)) & 1U;
}

uint32_t spx_imul_high(uint32_t left, uint32_t right) {
  return (uint32_t)(((int64_t)(int32_t)left * (int64_t)(int32_t)right) >> 32U);
}

uint32_t spx_mul_high(uint32_t left, uint32_t right) {
  return (uint32_t)(((uint64_t)left * (uint64_t)right) >> 32U);
}

uint32_t spx_udiv_pair(
    uint32_t high, uint32_t low, uint32_t divisor, uint32_t *remainder) {
  uint64_t rest = high;
  uint32_t quotient = 0U;
  uint32_t index;
  if (divisor == 0U || high >= divisor) {
    if (remainder != 0) *remainder = 0U;
    return 0U;
  }
  for (index = 0U; index < 32U; ++index) {
    rest = (rest << 1U) | ((low >> 31U) & 1U);
    low <<= 1U;
    quotient <<= 1U;
    if (rest >= divisor) {
      rest -= divisor;
      quotient |= 1U;
    }
  }
  if (remainder != 0) *remainder = (uint32_t)rest;
  return quotient;
}

uint32_t spx_udiv_quot(uint32_t high, uint32_t low, uint32_t divisor) {
  return spx_udiv_pair(high, low, divisor, 0);
}

uint32_t spx_udiv_rem(uint32_t high, uint32_t low, uint32_t divisor) {
  uint32_t remainder = 0U;
  (void)spx_udiv_pair(high, low, divisor, &remainder);
  return remainder;
}

uint32_t spx_udiv_valid(uint32_t high, uint32_t low, uint32_t divisor) {
  (void)low;
  return divisor != 0U && high < divisor;
}

uint32_t spx_bsr(uint32_t value) {
  uint32_t index = 0U;
  while (value >>= 1U) { ++index; }
  return index;
}

uint32_t spx_tzcnt(uint32_t value) {
  uint32_t count = 0U;
  if (value == 0U) return 32U;
  while ((value & 1U) == 0U) { value >>= 1U; ++count; }
  return count;
}

uint32_t spx_shift_cf(uint32_t kind, uint32_t width, uint32_t value, uint32_t count) {
  count &= 31U;
  value &= spx_mask(width);
  if (count == 0U || count > width) return 0U;
  if (kind == 0U) return (value >> (width - count)) & 1U;
  return (value >> (count - 1U)) & 1U;
}

uint32_t spx_shift_of(
    uint32_t kind, uint32_t width, uint32_t value, uint32_t count, uint32_t result) {
  count &= 31U;
  if (count != 1U) return 0U;
  if (kind == 0U) return spx_msb(width, result) ^ spx_shift_cf(kind, width, value, count);
  if (kind == 1U) return spx_msb(width, value);
  return 0U;
}

uint32_t spx_sbb_borrow(
    uint32_t width, uint32_t left, uint32_t right, uint32_t carry, uint32_t result) {
  uint32_t mask = spx_mask(width);
  uint64_t subtrahend = (uint64_t)(right & mask) + (uint64_t)(carry & 1U);
  (void)result;
  return (uint64_t)(left & mask) < subtrahend;
}

uint32_t spx_sbb_overflow(
    uint32_t width, uint32_t left, uint32_t right, uint32_t carry, uint32_t result) {
  uint32_t mask = spx_mask(width);
  (void)carry;
  return ((((left & mask) ^ (right & mask)) & ((left & mask) ^ (result & mask)))
      >> (width - 1U)) & 1U;
}

spx_step_result spx_call_status_result(
    spx_call_status status, uint32_t source_rva) {
  if (status == SPX_CALL_DIVIDE_ERROR)
    return (spx_step_result){ SPX_DIVIDE_ERROR, source_rva, 0U };
  if (status == SPX_CALL_MEMORY_FAULT)
    return (spx_step_result){ SPX_MEMORY_FAULT, source_rva, 0U };
  if (status == SPX_CALL_EXTERNAL_FAULT)
    return (spx_step_result){ SPX_EXTERNAL_FAULT, source_rva, 0U };
  if (status == SPX_CALL_NONLOCAL)
    return (spx_step_result){ SPX_NONLOCAL, 0U, 0U };
  return (spx_step_result){ SPX_UNIMPLEMENTED, source_rva, 0U };
}

uint32_t spx_adc_carry_checked(
    uint32_t width, uint32_t left, uint32_t right, uint32_t carry,
    uint32_t result, uint32_t *semantic_fault) {
  uint64_t mask, sum;
  if (width == 0U || width > 32U || carry > 1U) {
    *semantic_fault = 1U;
    return 0U;
  }
  mask = width == 32U ? 0xffffffffULL : ((1ULL << width) - 1ULL);
  sum = ((uint64_t)left & mask) + ((uint64_t)right & mask) + carry;
  if (((uint32_t)sum & (uint32_t)mask) != (result & (uint32_t)mask)) {
    *semantic_fault = 1U;
    return 0U;
  }
  return (uint32_t)((sum >> width) & 1ULL);
}

uint32_t spx_adc_overflow_checked(
    uint32_t width, uint32_t left, uint32_t right, uint32_t carry,
    uint32_t result, uint32_t *semantic_fault) {
  uint32_t mask, sign;
  uint64_t sum;
  if (width == 0U || width > 32U || carry > 1U) {
    *semantic_fault = 1U;
    return 0U;
  }
  mask = width == 32U ? 0xffffffffU : ((1U << width) - 1U);
  left &= mask; right &= mask; result &= mask;
  sum = (uint64_t)left + (uint64_t)right + carry;
  if (((uint32_t)sum & mask) != result) {
    *semantic_fault = 1U;
    return 0U;
  }
  sign = 1U << (width - 1U);
  return ((~(left ^ right) & (left ^ result) & sign) != 0U) ? 1U : 0U;
}
