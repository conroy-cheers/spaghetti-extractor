"""Native lowering of the canonical whole-range release contract."""

from ..external.range_release import RangeReleaseError, parse_range_release
from .runtime_model import CandidateRuntimeError, NativeExternalRangeRule
from .runtime_range_ownership import range_ownership_source
from .runtime_range_allocation import allocation_tables, range_allocation_source


def release_tables(rules: tuple[NativeExternalRangeRule, ...]):
    fields = []
    guards = []
    for rule in rules:
        if rule.action != "release_argument_range":
            if rule.release is not None:
                raise CandidateRuntimeError("non-release range rule carries release metadata")
            fields.append((0, 0, 0))
            continue
        if rule.release is None:
            raise CandidateRuntimeError("range release rule lacks explicit success condition")
        try:
            release = parse_range_release(rule.release.payload(),
                                          argument_words=rule.argument_count,
                                          context=rule.contract_id)
        except RangeReleaseError as exc:
            raise CandidateRuntimeError(str(exc)) from exc
        code = {"always": 1, "eax_zero": 2, "eax_nonzero": 3}[release.success]
        fields.append((code, len(guards), len(release.argument_equals)))
        guards.extend(release.argument_equals)
    rows = "\n".join(f"  {{ {index}U, {value}U }}," for index, value in guards)
    declaration = '''typedef struct spx_native_release_argument_guard {
  uint32_t argument, value;
} spx_native_release_argument_guard;
static const spx_native_release_argument_guard spx_native_release_argument_guards[] = {
''' + (rows or "  { 0U, 0U },") + '''
};
static const uint32_t spx_native_release_argument_guard_count = ''' + str(len(guards)) + "U;\n"
    return fields, declaration + allocation_tables(rules)


def range_release_source() -> str:
    return range_ownership_source() + range_allocation_source() + r'''
static uint32_t spx_native_external_argument(
    const spx_native_external_range_rule *, const spx_call_event *,
    const spx_external_call_snapshot *, uint32_t, uint32_t *);
static spx_call_status spx_native_release_external_range(uint32_t, uint32_t);

static spx_call_status spx_native_validate_release_arguments(
    const spx_native_external_range_rule *rule,
    const spx_call_event *event, const spx_external_call_snapshot *snapshot) {
  uint32_t i;
  if (rule->release_success < 1U || rule->release_success > 3U ||
      rule->release_guard_start > spx_native_release_argument_guard_count ||
      rule->release_guard_count >
          spx_native_release_argument_guard_count - rule->release_guard_start) {
    spx_native_diagnostic_reason = 0x2205U;
    return SPX_CALL_UNIMPLEMENTED;
  }
  for (i = 0U; i < rule->release_guard_count; ++i) {
    const spx_native_release_argument_guard *guard =
        &spx_native_release_argument_guards[rule->release_guard_start + i];
    uint32_t observed;
    if (!spx_native_external_argument(rule, event, snapshot, guard->argument, &observed)) {
      spx_native_diagnostic_reason = 0x2205U;
      return SPX_CALL_UNIMPLEMENTED;
    }
    if (observed != guard->value) {
      spx_native_diagnostic_reason = 0x2206U;
      spx_native_diagnostic_value = guard->argument;
      spx_native_diagnostic_aux = observed;
      spx_native_diagnostic_detail = guard->value;
      return SPX_CALL_UNIMPLEMENTED;
    }
  }
  return spx_native_validate_release_owner(rule, event, snapshot);
}

static spx_call_status spx_native_validate_release_calls(
    const spx_call_event *event, const spx_external_call_snapshot *snapshot) {
  uint32_t i;
  for (i = 0U; i < spx_native_external_range_rule_count; ++i) {
    const spx_native_external_range_rule *rule = &spx_native_external_range_rules[i];
    if (!spx_native_external_range_rule_matches(rule, event) ||
        rule->target_iat_rva != snapshot->target_iat_rva ||
        rule->target_catalog_index != snapshot->target_catalog_index)
      continue;
    if (rule->action == 1U) {
      uint32_t owner;
      if (spx_native_validate_allocation_arguments(rule, i, event, snapshot) != SPX_CALL_OK)
        return SPX_CALL_UNIMPLEMENTED;
      if (spx_native_range_owner_word(rule, event, snapshot, &owner) != SPX_CALL_OK)
        return SPX_CALL_UNIMPLEMENTED;
    }
    if (rule->action != 2U) continue;
    if (spx_native_validate_release_arguments(rule, event, snapshot) != SPX_CALL_OK)
      return SPX_CALL_UNIMPLEMENTED;
  }
  return SPX_CALL_OK;
}

static spx_call_status spx_native_apply_range_release(
    const spx_native_external_range_rule *rule,
    const spx_call_event *event, const spx_external_call_snapshot *snapshot,
    const spx_machine_state *output) {
  uint32_t pointer;
  if (spx_native_validate_release_arguments(rule, event, snapshot) != SPX_CALL_OK)
    return SPX_CALL_UNIMPLEMENTED;
  if ((rule->release_success == 2U && output->eax != 0U) ||
      (rule->release_success == 3U && output->eax == 0U))
    return SPX_CALL_OK;
  if (!spx_native_external_argument(rule, event, snapshot, rule->argument, &pointer)) {
    spx_native_diagnostic_reason = 0x2201U;
    return SPX_CALL_UNIMPLEMENTED;
  }
  return spx_native_release_external_range(pointer, rule->instruction_rva);
}
'''
