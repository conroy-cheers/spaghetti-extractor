#ifndef SPX_BEHAVIORAL_C_H
#define SPX_BEHAVIORAL_C_H

#include "state-machine-runtime.h"

uint32_t spx_mask(uint32_t width);
uint32_t spx_read(
    spx_runtime *rt, uint32_t address, uint32_t width, uint32_t *fault);
void spx_write(
    spx_runtime *rt, uint32_t address, uint32_t width, uint32_t value,
    uint32_t *fault);
uint32_t spx_undefined(
    spx_runtime *rt, uint32_t slot, const spx_machine_state *input,
    uint32_t defined_value);
void spx_sync_eflags(spx_machine_state *state);
uint32_t spx_sign_extend(uint32_t width, uint32_t value);
uint32_t spx_sar(uint32_t width, uint32_t value, uint32_t amount);
uint32_t spx_msb(uint32_t width, uint32_t value);
uint32_t spx_parity(uint32_t value);
uint32_t spx_add_overflow(
    uint32_t width, uint32_t left, uint32_t right, uint32_t result);
uint32_t spx_sub_overflow(
    uint32_t width, uint32_t left, uint32_t right, uint32_t result);
uint32_t spx_imul_high(uint32_t left, uint32_t right);
uint32_t spx_mul_high(uint32_t left, uint32_t right);
uint32_t spx_udiv_quot(uint32_t high, uint32_t low, uint32_t divisor);
uint32_t spx_udiv_rem(uint32_t high, uint32_t low, uint32_t divisor);
uint32_t spx_udiv_valid(uint32_t high, uint32_t low, uint32_t divisor);
uint32_t spx_bsr(uint32_t value);
uint32_t spx_tzcnt(uint32_t value);
uint32_t spx_shift_cf(
    uint32_t kind, uint32_t width, uint32_t value, uint32_t count);
uint32_t spx_shift_of(
    uint32_t kind, uint32_t width, uint32_t value, uint32_t count,
    uint32_t result);
uint32_t spx_sbb_borrow(
    uint32_t width, uint32_t left, uint32_t right, uint32_t carry,
    uint32_t result);
uint32_t spx_sbb_overflow(
    uint32_t width, uint32_t left, uint32_t right, uint32_t carry,
    uint32_t result);
spx_step_result spx_call_status_result(
    spx_call_status status, uint32_t source_rva);
uint32_t spx_adc_carry_checked(
    uint32_t width, uint32_t left, uint32_t right, uint32_t carry,
    uint32_t result, uint32_t *semantic_fault);
uint32_t spx_adc_overflow_checked(
    uint32_t width, uint32_t left, uint32_t right, uint32_t carry,
    uint32_t result, uint32_t *semantic_fault);

typedef spx_step_result (*spx_region_override_fn)(
    spx_runtime *, spx_machine_state *);
typedef struct spx_region_override {
  uint32_t entry_rva;
  spx_region_override_fn function;
  uint32_t fallback_on_unimplemented;
  const char *replacement_id;
  const char *cluster_id;
} spx_region_override;

spx_step_result spx_sub_00001284(spx_runtime *runtime, spx_machine_state *state, uint32_t entry_rva);
spx_step_result spx_sub_000012c0(spx_runtime *runtime, spx_machine_state *state, uint32_t entry_rva);

extern const uint32_t spx_behavioral_transfer_count;
uint32_t spx_behavioral_has_unit(uint32_t source_rva);
uint32_t spx_behavioral_function_owner(
    uint32_t source_rva, uint32_t *owner_rva);
spx_step_result spx_behavioral_step(
    spx_runtime *runtime, spx_machine_state *state, uint32_t source_rva);
spx_call_status spx_behavioral_run(
    spx_runtime *runtime, uint32_t entry_rva,
    const spx_machine_state *input, spx_machine_state *output);

#endif
