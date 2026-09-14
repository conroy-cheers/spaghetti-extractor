"""Native admission of checked allocation argument domains before callthrough."""

from ..external.range_allocation import RangeAllocationError, parse_range_allocation
from .runtime_model import CandidateRuntimeError


def allocation_tables(rules):
    rows = []
    slices = []
    for rule in rules:
        allocation = rule.allocation
        if allocation is None:
            slices.append((len(rows), 0))
            continue
        if rule.action != "add_result_range" or rule.ownership is None:
            raise CandidateRuntimeError("allocation metadata requires an owned result range")
        try:
            allocation = parse_range_allocation(allocation.payload(),
                argument_words=rule.argument_count, context=rule.contract_id)
        except RangeAllocationError as exc:
            raise CandidateRuntimeError(str(exc)) from exc
        slices.append((len(rows), len(allocation.argument_masks)))
        rows.extend(allocation.argument_masks)
    guards = '\n'.join(f'  {{ {index}U, {mask}U }},' for index, mask in rows) or '  { 0U, 0U },'
    domains = '\n'.join(f'  {{ {start}U, {count}U }},' for start, count in slices) or '  { 0U, 0U },'
    return f'''
typedef struct {{ uint32_t argument, allowed_mask; }} spx_native_allocation_argument_guard;
typedef struct {{ uint32_t start, count; }} spx_native_allocation_argument_domain;
static const spx_native_allocation_argument_guard spx_native_allocation_argument_guards[] = {{
{guards}
}};
static const spx_native_allocation_argument_domain spx_native_allocation_argument_domains[] = {{
{domains}
}};
static const uint32_t spx_native_allocation_argument_guard_count = {len(rows)}U;
static const uint32_t spx_native_allocation_argument_domain_count = {len(slices)}U;
'''


def range_allocation_source():
    return r'''
static uint32_t spx_native_external_argument(
    const spx_native_external_range_rule *, const spx_call_event *,
    const spx_external_call_snapshot *, uint32_t, uint32_t *);

static spx_call_status spx_native_validate_allocation_arguments(
    const spx_native_external_range_rule *rule, uint32_t index,
    const spx_call_event *event, const spx_external_call_snapshot *snapshot) {
  uint32_t i;
  if (index >= spx_native_allocation_argument_domain_count) {
    spx_native_diagnostic_reason = 0x2220U;
    return SPX_CALL_UNIMPLEMENTED;
  }
  const spx_native_allocation_argument_domain *domain = &spx_native_allocation_argument_domains[index];
  if (domain->start > spx_native_allocation_argument_guard_count ||
      domain->count > spx_native_allocation_argument_guard_count - domain->start) {
    spx_native_diagnostic_reason = 0x2220U;
    return SPX_CALL_UNIMPLEMENTED;
  }
  for (i = 0U; i < domain->count; ++i) {
    const spx_native_allocation_argument_guard *guard =
        &spx_native_allocation_argument_guards[domain->start + i];
    uint32_t observed;
    if (!spx_native_external_argument(rule, event, snapshot, guard->argument, &observed)) {
      spx_native_diagnostic_reason = 0x2220U;
      return SPX_CALL_UNIMPLEMENTED;
    }
    if ((observed & ~guard->allowed_mask) != 0U) {
      spx_native_diagnostic_reason = 0x2221U;
      spx_native_diagnostic_value = guard->argument;
      spx_native_diagnostic_aux = observed;
      spx_native_diagnostic_detail = guard->allowed_mask;
      return SPX_CALL_UNIMPLEMENTED;
    }
  }
  return SPX_CALL_OK;
}
'''
