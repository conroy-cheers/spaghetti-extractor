"""Native allocation freshness, family and captured owner-word checks."""

from ..external.range_bindings import RangeBindingError, range_ownership_fields
from .runtime_model import CandidateRuntimeError


def ownership_fields(rules):
    try:
        rows, families = range_ownership_fields([rule.payload() for rule in rules])
    except RangeBindingError as exc:
        raise CandidateRuntimeError(str(exc)) from exc
    return rows, len(families)


def range_ownership_source():
    return r'''
static uint32_t spx_native_external_argument(
    const spx_native_external_range_rule *, const spx_call_event *,
    const spx_external_call_snapshot *, uint32_t, uint32_t *);
static spx_call_status spx_native_add_external_range_for_rule(
    const spx_native_external_range_rule *, uint32_t, uint32_t);

static spx_call_status spx_native_range_owner_word(
    const spx_native_external_range_rule *rule,
    const spx_call_event *event, const spx_external_call_snapshot *snapshot,
    uint32_t *owner) {
  *owner = 0U;
  if (rule->ownership_family > spx_native_ownership_family_count ||
      (rule->ownership_family == 0U && rule->ownership_owner_argument != 0U) ||
      (rule->ownership_owner_argument != 0U &&
       !spx_native_external_argument(rule, event, snapshot,
            rule->ownership_owner_argument - 1U, owner))) {
    spx_native_diagnostic_reason = 0x2210U;
    return SPX_CALL_UNIMPLEMENTED;
  }
  return SPX_CALL_OK;
}

static spx_call_status spx_native_validate_release_owner(
    const spx_native_external_range_rule *rule,
    const spx_call_event *event, const spx_external_call_snapshot *snapshot) {
  spx_native_context *context = &spx_native_context_value;
  uint32_t pointer, owner, i;
  if (spx_native_range_owner_word(rule, event, snapshot, &owner) != SPX_CALL_OK ||
      !spx_native_external_argument(rule, event, snapshot, rule->argument, &pointer)) {
    spx_native_diagnostic_reason = 0x2210U;
    return SPX_CALL_UNIMPLEMENTED;
  }
  if (pointer == 0U) return SPX_CALL_OK;
  for (i = 0U; i < context->external_range_count; ++i) {
    const spx_native_external_range *range = &context->external_ranges[i];
    if (range->start == pointer) {
      if (range->ownership_family != rule->ownership_family) {
        spx_native_diagnostic_reason = 0x2211U;
        spx_native_diagnostic_value = pointer;
        spx_native_diagnostic_aux = range->ownership_family;
        spx_native_diagnostic_detail = rule->ownership_family;
        return SPX_CALL_UNIMPLEMENTED;
      }
      if (range->ownership_owner != owner) {
        spx_native_diagnostic_reason = 0x2212U;
        spx_native_diagnostic_value = pointer;
        spx_native_diagnostic_aux = range->ownership_owner;
        spx_native_diagnostic_detail = owner;
        return SPX_CALL_UNIMPLEMENTED;
      }
      return SPX_CALL_OK;
    }
    if (range->ownership_family != 0U && pointer > range->start &&
        pointer - range->start < range->size) {
      spx_native_diagnostic_reason = 0x2214U;
      spx_native_diagnostic_value = pointer;
      return SPX_CALL_UNIMPLEMENTED;
    }
  }
  if (rule->ownership_family != 0U) {
    spx_native_diagnostic_reason = 0x2213U;
    spx_native_diagnostic_value = pointer;
    return SPX_CALL_UNIMPLEMENTED;
  }
  return SPX_CALL_OK;
}

static spx_call_status spx_native_add_owned_range_for_rule(
    const spx_native_external_range_rule *rule, const spx_call_event *event,
    const spx_external_call_snapshot *snapshot, uint32_t pointer, uint32_t size) {
  spx_native_context *context = &spx_native_context_value;
  uint32_t owner, i;
  spx_call_status status;
  if (spx_native_range_owner_word(rule, event, snapshot, &owner) != SPX_CALL_OK)
    return SPX_CALL_UNIMPLEMENTED;
  if (rule->ownership_family != 0U) {
    /* Fresh owned storage cannot occupy the mapped image or any live borrowed
       range. Checking only previously owned allocations would grant a new
       lifetime to storage whose existing authority is still live. */
    if (context->image_size != 0U &&
        (pointer == context->image_base ||
         ((uint64_t)pointer < (uint64_t)context->image_base + context->image_size &&
          (uint64_t)context->image_base < (uint64_t)pointer + size))) {
      spx_native_diagnostic_reason = 0x2113U;
      spx_native_diagnostic_value = pointer;
      return SPX_CALL_UNIMPLEMENTED;
    }
    for (i = 0U; i < context->external_range_count; ++i) {
      const spx_native_external_range *range = &context->external_ranges[i];
      if (pointer == range->start ||
          ((uint64_t)pointer < (uint64_t)range->start + range->size &&
           (uint64_t)range->start < (uint64_t)pointer + size)) {
        spx_native_diagnostic_reason = 0x2111U;
        spx_native_diagnostic_value = pointer;
        return SPX_CALL_UNIMPLEMENTED;
      }
    }
  }
  status = spx_native_add_external_range_for_rule(rule, pointer, size);
  if (status != SPX_CALL_OK) return status;
  for (i = 0U; i < context->external_range_count; ++i) {
    if (context->external_ranges[i].start != pointer) continue;
    context->external_ranges[i].ownership_family = rule->ownership_family;
    context->external_ranges[i].ownership_owner = owner;
    return SPX_CALL_OK;
  }
  return SPX_CALL_UNIMPLEMENTED;
}
'''


def range_allocation_result_source():
    return r'''
static spx_call_status spx_native_record_range_allocation(
    const spx_native_external_range_rule *rule, const spx_call_event *event,
    const spx_external_call_snapshot *snapshot, const spx_machine_state *output) {
  uint32_t pointer, size;
  if (!spx_native_state_register(output, rule->register_index, &pointer) ||
      (!rule->nullable && pointer == 0U)) {
    spx_native_diagnostic_reason = 0x2101U;
    return SPX_CALL_UNIMPLEMENTED;
  }
  if (pointer == 0U) return SPX_CALL_OK;
  if (!spx_native_range_size(rule, event, snapshot, pointer, &size)) {
    spx_native_diagnostic_reason = 0x2101U;
    return SPX_CALL_UNIMPLEMENTED;
  }
  if (size == 0U && rule->ownership_family == 0U) return SPX_CALL_OK;
  return spx_native_add_owned_range_for_rule(rule, event, snapshot, pointer, size);
}
'''
