"""Generation-safe allocation registration in the canonical native runtime."""


def allocation_lifetime_source() -> str:
    return r"""static uint32_t spx_native_next_external_lifecycle_sequence(
    spx_native_context *context) {
  if (context->external_lifecycle_sequence != 0xffffffffU)
    ++context->external_lifecycle_sequence;
  return context->external_lifecycle_sequence;
}

static void spx_native_record_external_lifecycle(
    spx_native_context *context, uint32_t operation,
    spx_call_status status, uint32_t instruction_rva,
    uint32_t start, uint32_t size, uint32_t producer_rva,
    uint32_t producer_action, uint32_t generation) {
  spx_native_external_lifecycle_event *event;
  if (context == 0) return;
  event = &context->external_lifecycle_events[context->external_lifecycle_next];
  event->sequence = spx_native_next_external_lifecycle_sequence(context);
  event->operation = operation;
  event->status = (uint32_t)status;
  event->instruction_rva = instruction_rva;
  event->start = start;
  event->size = size;
  event->producer_rva = producer_rva;
  event->producer_action = producer_action;
  event->generation = generation;
  context->external_lifecycle_next =
      (context->external_lifecycle_next + 1U) %
      SPX_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS;
  if (context->external_lifecycle_count <
      SPX_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS)
    ++context->external_lifecycle_count;
}

static spx_call_status spx_native_add_external_range(
    uint32_t start, uint32_t size, uint32_t producer_rva,
    uint32_t producer_action, uint32_t external_range_rule_selector,
    uint64_t object_id) {
  spx_native_context *context = &spx_native_context_value;
  uint32_t generation, i;
  if (start == 0U || start > 0xffffffffU - size) {
    spx_native_record_external_lifecycle(
        context, 1U, SPX_CALL_UNIMPLEMENTED, producer_rva,
        start, size, producer_rva, producer_action, 0U);
    return SPX_CALL_UNIMPLEMENTED;
  }
  /* Generations identify allocation lifetimes. Diagnostic sequence saturation
     must never turn a later allocation into an earlier reference's origin. */
  if (context->external_lifecycle_sequence == 0xffffffffU) {
    spx_native_record_external_lifecycle(
        context, 1U, SPX_CALL_UNIMPLEMENTED, producer_rva,
        start, size, producer_rva, producer_action, 0U);
    spx_native_diagnostic_reason = 0x2103U;
    spx_native_diagnostic_value = context->external_lifecycle_sequence;
    spx_native_diagnostic_aux = start;
    spx_native_diagnostic_detail = producer_rva;
    return SPX_CALL_UNIMPLEMENTED;
  }
  generation = context->external_lifecycle_sequence + 1U;
  if (object_id == 0U) {
    if (context->external_object_sequence != 0xffffffffU)
      ++context->external_object_sequence;
    object_id = context->external_object_sequence;
  }
  for (i = 0U; i < context->external_range_count; ++i) {
    if (context->external_ranges[i].start == start) {
      if (context->external_ranges[i].ownership_family != 0U) {
        spx_native_diagnostic_reason = 0x2112U;
        spx_native_diagnostic_value = start;
        return SPX_CALL_UNIMPLEMENTED;
      }
      context->external_ranges[i].size = size;
      context->external_ranges[i].producer_rva = producer_rva;
      context->external_ranges[i].producer_action = producer_action;
      context->external_ranges[i].generation = generation;
      context->external_ranges[i].external_range_rule_selector =
          external_range_rule_selector;
      context->external_ranges[i].object_id = object_id;
      spx_native_record_external_lifecycle(
          context, 2U, SPX_CALL_OK, producer_rva,
          start, size, producer_rva, producer_action, generation);
      return SPX_CALL_OK;
    }
  }
  if (context->external_range_count == SPX_NATIVE_MAX_EXTERNAL_RANGES) {
    spx_native_record_external_lifecycle(
        context, 1U, SPX_CALL_UNIMPLEMENTED, producer_rva,
        start, size, producer_rva, producer_action, generation);
    return SPX_CALL_UNIMPLEMENTED;
  }
  context->external_ranges[context->external_range_count].start = start;
  context->external_ranges[context->external_range_count].size = size;
  context->external_ranges[context->external_range_count].producer_rva = producer_rva;
  context->external_ranges[context->external_range_count].producer_action =
      producer_action;
  context->external_ranges[context->external_range_count].generation = generation;
  context->external_ranges[context->external_range_count].external_range_rule_selector =
      external_range_rule_selector;
  context->external_ranges[context->external_range_count].object_id = object_id;
  context->external_ranges[context->external_range_count].ownership_family = 0U;
  context->external_ranges[context->external_range_count].ownership_owner = 0U;
  ++context->external_range_count;
  spx_native_record_external_lifecycle(
      context, 1U, SPX_CALL_OK, producer_rva,
      start, size, producer_rva, producer_action, generation);
  return SPX_CALL_OK;
}

"""
