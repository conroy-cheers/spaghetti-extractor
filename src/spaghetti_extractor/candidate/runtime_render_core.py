"""Core native runtime C template rendering."""

from __future__ import annotations

from .runtime_model import NativeRuntimePlan


def _native_runtime_source_core(plan: NativeRuntimePlan) -> str:
    return f'''  return stage_b_program_lookup(0x{plan.entry_rva:08x}U) != 0;
}}

uint32_t stage_b_native_machine_fallback_allowed(uint32_t rva) {{
  uint32_t low = 0U, high = stage_b_native_implementation_dispatch_count;
  while (low < high) {{
    uint32_t middle = low + (high - low) / 2U;
    uint32_t observed = stage_b_native_implementation_dispatches[middle].rva;
    if (observed < rva) low = middle + 1U;
    else high = middle;
  }}
  return low < stage_b_native_implementation_dispatch_count &&
      stage_b_native_implementation_dispatches[low].rva == rva &&
      stage_b_native_implementation_dispatches[low].implementation_class == 0U;
}}

static uint32_t stage_b_native_write_allowed(uint32_t address, uint32_t width) {{
  stage_b_native_context *context = &stage_b_native_context_value;
  uint32_t end, image_end, i, matched = 0U;
  if (!stage_b_native_range_end(address, width, &end) ||
      !stage_b_native_range_end(context->image_base, context->image_size, &image_end))
    return 0U;
  if (stage_b_native_inside_external_range(context, address, end)) return 1U;
  if (stage_b_native_inside_thread_environment(context, address, end)) return 1U;
  if (end <= context->image_base || address >= image_end)
    return address >= context->stack_low && end <= context->stack_high;
  for (i = 0U; i < context->section_count; ++i) {{
    uint32_t section = context->section_table + i * 40U;
    uint32_t virtual_size = stage_b_native_u32(section + 8U);
    uint32_t raw_size = stage_b_native_u32(section + 16U);
    uint32_t rva = stage_b_native_u32(section + 12U);
    uint32_t size = virtual_size > raw_size ? virtual_size : raw_size;
    uint32_t section_start;
    if (rva > 0xffffffffU - context->image_base) return 0U;
    section_start = context->image_base + rva;
    if (stage_b_native_inside(address, end, section_start, size)) {{
      if ((stage_b_native_u32(section + 36U) &
          STAGE_B_NATIVE_IMAGE_SCN_MEM_EXECUTE) != 0U)
        return 0U;
      matched = 1U;
    }}
  }}
  return matched;
}}

static uint32_t stage_b_native_read_allowed(uint32_t address, uint32_t width) {{
  stage_b_native_context *context = &stage_b_native_context_value;
  uint32_t end, image_end, i;
  if (!stage_b_native_range_end(address, width, &end) ||
      !stage_b_native_range_end(context->image_base, context->image_size, &image_end))
    return 0U;
  if (address >= context->stack_low && end <= context->stack_high)
    return 1U;
  if (stage_b_native_inside_external_range(context, address, end)) return 1U;
  if (stage_b_native_inside_thread_environment(context, address, end)) return 1U;
  if (address < context->image_base || end > image_end)
    return 0U;
  if (end <= context->image_base + context->headers_size)
    return 1U;
  for (i = 0U; i < context->section_count; ++i) {{
    uint32_t section = context->section_table + i * 40U;
    uint32_t virtual_size = stage_b_native_u32(section + 8U);
    uint32_t raw_size = stage_b_native_u32(section + 16U);
    uint32_t rva = stage_b_native_u32(section + 12U);
    uint32_t size = virtual_size > raw_size ? virtual_size : raw_size;
    uint32_t section_start;
    if (rva > 0xffffffffU - context->image_base) return 0U;
    section_start = context->image_base + rva;
    if (stage_b_native_inside(address, end, section_start, size)) return 1U;
  }}
  return 0U;
}}

static uint32_t stage_b_native_state_register(
    const stage_b_machine_state *state, uint32_t index, uint32_t *value) {{
  if (state == 0 || value == 0) return 0U;
  switch (index) {{
    case 0U: *value = state->eax; return 1U;
    case 1U: *value = state->ebx; return 1U;
    case 2U: *value = state->ecx; return 1U;
    case 3U: *value = state->edx; return 1U;
    case 4U: *value = state->esi; return 1U;
    case 5U: *value = state->edi; return 1U;
    case 6U: *value = state->ebp; return 1U;
    case 7U: *value = state->esp; return 1U;
    default: return 0U;
  }}
}}

static stage_b_native_callable_binding *stage_b_native_callable_binding_for(
    uint32_t capability_id) {{
  stage_b_native_context *context = &stage_b_native_context_value;
  uint32_t i;
  for (i = 0U; i < stage_b_native_callable_binding_count; ++i)
    if (context->callable_bindings[i].capability_id == capability_id)
      return &context->callable_bindings[i];
  return (stage_b_native_callable_binding *)0;
}}

static uint32_t stage_b_native_callable_target_matches(
    const stage_b_call_event *event) {{
  uint32_t route_index, route_seen = 0U;
  if (event == 0 || event->kind != STAGE_B_CALL_INDIRECT) return 1U;
  for (route_index = 0U;
       route_index < stage_b_native_callable_route_count; ++route_index) {{
    const stage_b_native_callable_route *route =
        &stage_b_native_callable_routes[route_index];
    stage_b_native_callable_binding *binding;
    if (route->instruction_rva != event->instruction_rva) continue;
    route_seen = 1U;
    binding = stage_b_native_callable_binding_for(route->capability_id);
    if (binding != 0 && binding->bound != 0U &&
        binding->target_word == event->target_rva)
      return 1U;
  }}
  return route_seen == 0U;
}}

static stage_b_call_status stage_b_native_record_callable_result(
    const stage_b_call_event *event, const stage_b_machine_state *output) {{
  stage_b_native_context *context = &stage_b_native_context_value;
  uint32_t i;
  for (i = 0U; i < stage_b_native_callable_resolver_count; ++i) {{
    const stage_b_native_callable_resolver *resolver =
        &stage_b_native_callable_resolvers[i];
    stage_b_native_callable_binding *binding;
    uint32_t target, image_end;
    if (resolver->instruction_rva != event->instruction_rva) continue;
    if (!stage_b_native_state_register(
            output, resolver->result_register, &target))
      return STAGE_B_CALL_UNIMPLEMENTED;
    if (target == 0U)
      return resolver->nullable != 0U
          ? STAGE_B_CALL_OK : STAGE_B_CALL_UNIMPLEMENTED;
    if (!stage_b_native_range_end(
            context->image_base, context->image_size, &image_end) ||
        (target >= context->image_base && target < image_end))
      return STAGE_B_CALL_UNIMPLEMENTED;
    binding = stage_b_native_callable_binding_for(resolver->capability_id);
    if (binding == 0) return STAGE_B_CALL_UNIMPLEMENTED;
    if (binding->bound != 0U && binding->target_word != target)
      return STAGE_B_CALL_UNIMPLEMENTED;
    binding->target_word = target;
    binding->bound = 1U;
  }}
  return STAGE_B_CALL_OK;
}}

static uint32_t stage_b_native_external_range_rule_matches(
    const stage_b_native_external_range_rule *rule,
    const stage_b_call_event *event) {{
  const stage_b_native_context *context = &stage_b_native_context_value;
  uint32_t iat_address, target;
  if (rule == 0 || event == 0 ||
      rule->instruction_rva != event->instruction_rva)
    return 0U;
  if (rule->target_iat_rva == 0U) return 1U;
  if (event->kind != STAGE_B_CALL_INDIRECT ||
      rule->target_iat_rva > context->image_size ||
      context->image_base > 0xffffffffU - rule->target_iat_rva)
    return 0U;
  iat_address = context->image_base + rule->target_iat_rva;
  target = stage_b_native_u32(iat_address);
  return target != 0U && event->target_rva == target;
}}

#ifdef STAGE_B_NATIVE_DIAGNOSTIC_FAILURE_TRAP
static void stage_b_native_record_external_trace(
    uint32_t phase, const stage_b_call_event *call,
    const stage_b_external_call_snapshot *snapshot,
    const stage_b_machine_state *state, stage_b_call_status status) {{
  stage_b_native_context *context = &stage_b_native_context_value;
  stage_b_native_external_trace_event *event;
  uint32_t index;
  if (call == 0 || snapshot == 0 || state == 0) return;
  index = context->external_trace_next;
  event = &context->external_trace_events[index];
  if (context->external_trace_sequence != 0xffffffffU)
    ++context->external_trace_sequence;
  event->sequence = context->external_trace_sequence;
  event->phase = phase;
  event->instruction_rva = call->instruction_rva;
  event->target_rva = call->target_rva;
  event->target_iat_rva = snapshot->target_iat_rva;
  event->kind = (uint32_t)call->kind;
  event->status = (uint32_t)status;
  event->eax = state->eax;
  event->esp = state->esp;
  event->eflags = state->eflags;
  context->external_trace_next =
      (index + 1U) % STAGE_B_NATIVE_MAX_EXTERNAL_TRACE_EVENTS;
  if (context->external_trace_count < STAGE_B_NATIVE_MAX_EXTERNAL_TRACE_EVENTS)
    ++context->external_trace_count;
}}
#endif

static uint32_t stage_b_native_external_site_authorized(uint32_t rva) {{
  uint32_t low = 0U, high = stage_b_native_authorized_external_site_count;
  while (low < high) {{
    uint32_t middle = low + (high - low) / 2U;
    if (stage_b_native_authorized_external_sites[middle] < rva)
      low = middle + 1U;
    else
      high = middle;
  }}
  return low < stage_b_native_authorized_external_site_count &&
      stage_b_native_authorized_external_sites[low] == rva;
}}

stage_b_call_status stage_b_native_runtime_capture_external_call(
    const stage_b_call_event *event, const stage_b_machine_state *input,
    stage_b_external_call_snapshot *snapshot) {{
  uint32_t i, found = 0U, direct_binding_seen = 0U;
  if (event == 0 || input == 0 || snapshot == 0 ||
      stage_b_native_context_value.initialized == 0U) {{
    stage_b_native_diagnostic_reason = 0x2003U;
    return STAGE_B_CALL_UNIMPLEMENTED;
  }}
  if (!stage_b_native_external_site_authorized(event->instruction_rva)) {{
    stage_b_native_diagnostic_reason = 0x2009U;
    stage_b_native_diagnostic_value = event->instruction_rva;
    stage_b_native_diagnostic_aux = event->target_rva;
    return STAGE_B_CALL_UNIMPLEMENTED;
  }}
  if (event->kind == STAGE_B_CALL_INDIRECT &&
      event->target_rva >= stage_b_native_context_value.image_base &&
      event->target_rva - stage_b_native_context_value.image_base <
          stage_b_native_context_value.image_size) {{
    stage_b_native_diagnostic_reason = 0x200aU;
    stage_b_native_diagnostic_value = event->instruction_rva;
    stage_b_native_diagnostic_aux = event->target_rva;
    return STAGE_B_CALL_UNIMPLEMENTED;
  }}
  if (!stage_b_native_callable_target_matches(event)) {{
    stage_b_native_diagnostic_reason = 0x200bU;
    stage_b_native_diagnostic_value = event->instruction_rva;
    stage_b_native_diagnostic_aux = event->target_rva;
    return STAGE_B_CALL_UNIMPLEMENTED;
  }}
  snapshot->instruction_rva = event->instruction_rva;
  snapshot->target_iat_rva = 0U;
  snapshot->argument_base_offset = 0U;
  snapshot->argument_count = 0U;
  for (i = 0U; i < stage_b_native_external_range_rule_count; ++i) {{
    const stage_b_native_external_range_rule *rule =
        &stage_b_native_external_range_rules[i];
    if (!stage_b_native_external_range_rule_matches(rule, event)) continue;
    if ((rule->target_iat_rva == 0U && snapshot->target_iat_rva != 0U) ||
        (rule->target_iat_rva != 0U && direct_binding_seen != 0U) ||
        (rule->target_iat_rva != 0U && snapshot->target_iat_rva != 0U &&
         snapshot->target_iat_rva != rule->target_iat_rva)) {{
      stage_b_native_diagnostic_reason = 0x2008U;
      stage_b_native_diagnostic_value = event->target_rva;
      stage_b_native_diagnostic_aux = snapshot->target_iat_rva;
      stage_b_native_diagnostic_detail = rule->target_iat_rva;
      return STAGE_B_CALL_UNIMPLEMENTED;
    }}
    if (rule->target_iat_rva == 0U)
      direct_binding_seen = 1U;
    else
      snapshot->target_iat_rva = rule->target_iat_rva;
    if (rule->argument_count > STAGE_B_MAX_EXTERNAL_ARGUMENTS ||
        (found != 0U &&
         (snapshot->argument_base_offset != rule->argument_base_offset ||
          snapshot->argument_count != rule->argument_count))) {{
      stage_b_native_diagnostic_reason = 0x2004U;
      return STAGE_B_CALL_UNIMPLEMENTED;
    }}
    snapshot->argument_base_offset = rule->argument_base_offset;
    snapshot->argument_count = rule->argument_count;
    found = 1U;
  }}
  for (i = 0U; i < snapshot->argument_count; ++i) {{
    uint32_t offset, address, value;
    if (i > 0x3fffffffU) {{
      stage_b_native_diagnostic_reason = 0x2005U;
      return STAGE_B_CALL_UNIMPLEMENTED;
    }}
    offset = i * 4U;
    if (snapshot->argument_base_offset > 0xffffffffU - offset ||
        input->esp >
            0xffffffffU - (snapshot->argument_base_offset + offset)) {{
      stage_b_native_diagnostic_reason = 0x2005U;
      return STAGE_B_CALL_UNIMPLEMENTED;
    }}
    address = input->esp + snapshot->argument_base_offset + offset;
    if (!stage_b_native_read_allowed(address, 4U)) {{
      stage_b_native_diagnostic_reason = 0x2005U;
      return STAGE_B_CALL_UNIMPLEMENTED;
    }}
    value = stage_b_native_u32(address);
    if (event->arguments != 0 && i < event->argument_count &&
        event->arguments[i] != value) {{
      stage_b_native_diagnostic_reason = 0x2006U;
      return STAGE_B_CALL_UNIMPLEMENTED;
    }}
    snapshot->arguments[i] = value;
  }}
#ifdef STAGE_B_NATIVE_DIAGNOSTIC_FAILURE_TRAP
  stage_b_native_record_external_trace(
      1U, event, snapshot, input, STAGE_B_CALL_OK);
#endif
  return STAGE_B_CALL_OK;
}}

static uint32_t stage_b_native_external_argument(
    const stage_b_native_external_range_rule *rule,
    const stage_b_call_event *event,
    const stage_b_external_call_snapshot *snapshot,
    uint32_t index, uint32_t *value) {{
  if (rule == 0 || event == 0 || snapshot == 0 || value == 0 ||
      snapshot->instruction_rva != event->instruction_rva ||
      snapshot->target_iat_rva != rule->target_iat_rva ||
      snapshot->argument_base_offset != rule->argument_base_offset ||
      snapshot->argument_count != rule->argument_count ||
      index >= snapshot->argument_count)
    return 0U;
  if (event->arguments != 0 && index < event->argument_count &&
      event->arguments[index] != snapshot->arguments[index])
    return 0U;
  *value = snapshot->arguments[index];
  return 1U;
}}

static uint32_t stage_b_native_zero_run_extent(
    uint32_t start, uint32_t unit_bytes, uint32_t zero_units,
    uint32_t max_units, uint32_t *extent) {{
  uint32_t index, run = 0U;
  if (start == 0U || extent == 0 ||
      (unit_bytes != 1U && unit_bytes != 2U && unit_bytes != 4U) ||
      zero_units == 0U || zero_units > max_units)
    return 0U;
  for (index = 0U; index < max_units; ++index) {{
    uint32_t offset, address, value;
    if (index > 0xffffffffU / unit_bytes) return 0U;
    offset = index * unit_bytes;
    if (start > 0xffffffffU - offset) return 0U;
    address = start + offset;
    value = unit_bytes == 1U
        ? (uint32_t)*(const volatile uint8_t *)(uintptr_t)address
        : unit_bytes == 2U
        ? (uint32_t)stage_b_native_u16(address)
        : stage_b_native_u32(address);
    run = value == 0U ? run + 1U : 0U;
    if (run == zero_units) {{
      if (index == 0xffffffffU / unit_bytes) return 0U;
      *extent = (index + 1U) * unit_bytes;
      return 1U;
    }}
  }}
  return 0U;
}}

static uint32_t stage_b_native_range_size(
    const stage_b_native_external_range_rule *rule,
    const stage_b_call_event *event,
    const stage_b_external_call_snapshot *snapshot,
    uint32_t pointer, uint32_t *size) {{
  uint32_t left, right;
  if (rule == 0 || event == 0 || size == 0) return 0U;
  if (rule->size_kind == 1U) {{
    *size = rule->size_value;
  }} else if (rule->size_kind == 2U) {{
    if (!stage_b_native_external_argument(
            rule, event, snapshot, rule->size_argument, &left))
      return 0U;
    if (rule->size_value != 0U && left > 0xffffffffU / rule->size_value)
      return 0U;
    *size = left * rule->size_value;
  }} else if (rule->size_kind == 3U) {{
    if (!stage_b_native_external_argument(
            rule, event, snapshot, rule->size_argument, &left) ||
        !stage_b_native_external_argument(
            rule, event, snapshot, rule->size_right_argument, &right))
      return 0U;
    if (right != 0U && left > 0xffffffffU / right) return 0U;
    *size = left * right;
  }} else if (rule->size_kind == 4U) {{
    if (pointer == 0U) return rule->nullable != 0U;
    if (!stage_b_native_zero_run_extent(
            pointer, rule->termination_unit_bytes,
            rule->termination_zero_units, rule->termination_max_units, size))
      return 0U;
  }} else {{
    return 0U;
  }}
  return *size >= rule->minimum_size;
}}

static uint32_t stage_b_native_next_external_lifecycle_sequence(
    stage_b_native_context *context) {{
  if (context->external_lifecycle_sequence != 0xffffffffU)
    ++context->external_lifecycle_sequence;
  return context->external_lifecycle_sequence;
}}

static void stage_b_native_record_external_lifecycle(
    stage_b_native_context *context, uint32_t operation,
    stage_b_call_status status, uint32_t instruction_rva,
    uint32_t start, uint32_t size, uint32_t producer_rva,
    uint32_t producer_action, uint32_t generation) {{
  stage_b_native_external_lifecycle_event *event;
  if (context == 0) return;
  event = &context->external_lifecycle_events[context->external_lifecycle_next];
  event->sequence = stage_b_native_next_external_lifecycle_sequence(context);
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
      STAGE_B_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS;
  if (context->external_lifecycle_count <
      STAGE_B_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS)
    ++context->external_lifecycle_count;
}}

static stage_b_call_status stage_b_native_add_external_range(
    uint32_t start, uint32_t size, uint32_t producer_rva,
    uint32_t producer_action) {{
  stage_b_native_context *context = &stage_b_native_context_value;
  uint32_t end, generation, i;
  if (!stage_b_native_range_end(start, size, &end)) {{
    stage_b_native_record_external_lifecycle(
        context, 1U, STAGE_B_CALL_UNIMPLEMENTED, producer_rva,
        start, size, producer_rva, producer_action, 0U);
    return STAGE_B_CALL_UNIMPLEMENTED;
  }}
  generation = context->external_lifecycle_sequence == 0xffffffffU
      ? 0xffffffffU : context->external_lifecycle_sequence + 1U;
  for (i = 0U; i < context->external_range_count; ++i) {{
    if (context->external_ranges[i].start == start) {{
      context->external_ranges[i].size = size;
      context->external_ranges[i].producer_rva = producer_rva;
      context->external_ranges[i].producer_action = producer_action;
      context->external_ranges[i].generation = generation;
      stage_b_native_record_external_lifecycle(
          context, 2U, STAGE_B_CALL_OK, producer_rva,
          start, size, producer_rva, producer_action, generation);
      return STAGE_B_CALL_OK;
    }}
  }}
  if (context->external_range_count == STAGE_B_NATIVE_MAX_EXTERNAL_RANGES) {{
    stage_b_native_record_external_lifecycle(
        context, 1U, STAGE_B_CALL_UNIMPLEMENTED, producer_rva,
        start, size, producer_rva, producer_action, generation);
    return STAGE_B_CALL_UNIMPLEMENTED;
  }}
  context->external_ranges[context->external_range_count].start = start;
  context->external_ranges[context->external_range_count].size = size;
  context->external_ranges[context->external_range_count].producer_rva = producer_rva;
  context->external_ranges[context->external_range_count].producer_action =
      producer_action;
  context->external_ranges[context->external_range_count].generation = generation;
  ++context->external_range_count;
  stage_b_native_record_external_lifecycle(
      context, 1U, STAGE_B_CALL_OK, producer_rva,
      start, size, producer_rva, producer_action, generation);
  return STAGE_B_CALL_OK;
}}

static stage_b_call_status stage_b_native_release_external_range(
    uint32_t start, uint32_t instruction_rva) {{
  stage_b_native_context *context = &stage_b_native_context_value;
  uint32_t i, operation = 4U;
  if (start == 0U) return STAGE_B_CALL_OK;
  for (i = 0U; i < context->external_range_count; ++i) {{
    if (context->external_ranges[i].start == start) {{
      stage_b_native_external_range released = context->external_ranges[i];
      --context->external_range_count;
      context->external_ranges[i] =
          context->external_ranges[context->external_range_count];
      stage_b_native_record_external_lifecycle(
          context, 3U, STAGE_B_CALL_OK, instruction_rva,
          released.start, released.size, released.producer_rva,
          released.producer_action, released.generation);
      return STAGE_B_CALL_OK;
    }}
  }}
  for (i = 0U; i < context->external_range_count; ++i) {{
    uint32_t end;
    if (stage_b_native_range_end(
            context->external_ranges[i].start,
            context->external_ranges[i].size, &end) &&
        start > context->external_ranges[i].start && start < end) {{
      operation = 5U;
      stage_b_native_diagnostic_aux = context->external_ranges[i].start;
      stage_b_native_diagnostic_detail = end;
      break;
    }}
  }}
  if (operation == 4U) {{
    uint32_t offset;
    for (offset = 0U; offset < context->external_lifecycle_count; ++offset) {{
      uint32_t index =
          (context->external_lifecycle_next +
           STAGE_B_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS - 1U - offset) %
          STAGE_B_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS;
      const stage_b_native_external_lifecycle_event *event =
          &context->external_lifecycle_events[index];
      if (event->start != start) continue;
      if (event->operation == 3U) operation = 6U;
      stage_b_native_diagnostic_aux = event->instruction_rva;
      stage_b_native_diagnostic_detail = event->producer_rva;
      break;
    }}
  }}
  stage_b_native_record_external_lifecycle(
      context, operation, STAGE_B_CALL_UNIMPLEMENTED, instruction_rva,
      start, 0U, 0U, 0U, 0U);
  stage_b_native_diagnostic_value = start;
  stage_b_native_diagnostic_reason =
      operation == 5U ? 0x2204U : operation == 6U ? 0x2203U : 0x2202U;
  return STAGE_B_CALL_UNIMPLEMENTED;
}}

static uint32_t stage_b_native_terminated_extent(
    uint32_t start, uint32_t unit_bytes, uint32_t max_units,
    uint32_t *extent) {{
  uint32_t index;
  if (start == 0U || extent == 0 ||
      (unit_bytes != 1U && unit_bytes != 2U && unit_bytes != 4U))
    return 0U;
  for (index = 0U; index < max_units; ++index) {{
    uint32_t offset, address, value;
    if (index > 0xffffffffU / unit_bytes) return 0U;
    offset = index * unit_bytes;
    if (start > 0xffffffffU - offset) return 0U;
    address = start + offset;
    value = unit_bytes == 1U
        ? (uint32_t)*(const volatile uint8_t *)(uintptr_t)address
        : unit_bytes == 2U
        ? (uint32_t)stage_b_native_u16(address)
        : stage_b_native_u32(address);
    if (value == 0U) {{
      if (index == 0xffffffffU / unit_bytes) return 0U;
      *extent = (index + 1U) * unit_bytes;
      return 1U;
    }}
  }}
  return 0U;
}}

static stage_b_call_status stage_b_native_add_external_pointee_ranges(
    const stage_b_native_external_range_rule *rule,
    uint32_t cell) {{
  uint32_t vector, index;
  if (rule == 0 || cell == 0U ||
      cell > 0xffffffffU - rule->pointee_offset)
    return STAGE_B_CALL_UNIMPLEMENTED;
  vector = stage_b_native_u32(cell + rule->pointee_offset);
  if (vector == 0U) return STAGE_B_CALL_OK;
  for (index = 0U; index < rule->max_elements; ++index) {{
    uint32_t offset, element, extent;
    stage_b_call_status status;
    if (index > 0x3fffffffU) return STAGE_B_CALL_UNIMPLEMENTED;
    offset = index * 4U;
    if (vector > 0xffffffffU - offset) return STAGE_B_CALL_UNIMPLEMENTED;
    element = stage_b_native_u32(vector + offset);
    if (element == 0U) {{
      if (index == 0x3fffffffU) return STAGE_B_CALL_UNIMPLEMENTED;
      return stage_b_native_add_external_range(
          vector, (index + 1U) * 4U,
          rule->instruction_rva, rule->action);
    }}
    if (!stage_b_native_terminated_extent(
            element, rule->element_unit_bytes, rule->element_max_units,
            &extent))
      return STAGE_B_CALL_UNIMPLEMENTED;
    status = stage_b_native_add_external_range(
        element, extent, rule->instruction_rva, rule->action);
    if (status != STAGE_B_CALL_OK) return status;
  }}
  return STAGE_B_CALL_UNIMPLEMENTED;
}}

static stage_b_call_status stage_b_native_add_external_interface_ranges(
    const stage_b_native_external_range_rule *rule, uint32_t cell) {{
  uint32_t object, vtable;
  stage_b_call_status status;
  if (rule == 0 || cell == 0U ||
      cell > 0xffffffffU - rule->pointee_offset)
    return STAGE_B_CALL_UNIMPLEMENTED;
  object = stage_b_native_u32(cell + rule->pointee_offset);
  if (object == 0U)
    return rule->nullable != 0U
        ? STAGE_B_CALL_OK : STAGE_B_CALL_UNIMPLEMENTED;
  status = stage_b_native_add_external_range(
      object, rule->minimum_size, rule->instruction_rva, rule->action);
  if (status != STAGE_B_CALL_OK) return status;
  vtable = stage_b_native_u32(object);
  if (vtable == 0U) return STAGE_B_CALL_UNIMPLEMENTED;
  return stage_b_native_add_external_range(
      vtable, rule->size_value, rule->instruction_rva, rule->action);
}}

stage_b_call_status stage_b_native_runtime_record_external_result(
    const stage_b_call_event *event,
    const stage_b_external_call_snapshot *snapshot,
    const stage_b_machine_state *output) {{
  uint32_t i;
  if (event == 0 || snapshot == 0 || output == 0 ||
      snapshot->instruction_rva != event->instruction_rva ||
      stage_b_native_context_value.initialized == 0U) {{
    stage_b_native_diagnostic_reason = 0x2001U;
    return STAGE_B_CALL_UNIMPLEMENTED;
  }}
#ifdef STAGE_B_NATIVE_DIAGNOSTIC_FAILURE_TRAP
  stage_b_native_record_external_trace(
      2U, event, snapshot, output, STAGE_B_CALL_OK);
#endif
  if (stage_b_native_record_callable_result(event, output) != STAGE_B_CALL_OK) {{
    stage_b_native_diagnostic_reason = 0x2002U;
    return STAGE_B_CALL_UNIMPLEMENTED;
  }}
  for (i = 0U; i < stage_b_native_external_range_rule_count; ++i) {{
    const stage_b_native_external_range_rule *rule =
        &stage_b_native_external_range_rules[i];
    stage_b_call_status status;
    uint32_t pointer, size;
    if (!stage_b_native_external_range_rule_matches(rule, event) ||
        rule->target_iat_rva != snapshot->target_iat_rva)
      continue;
    if (rule->action == 1U) {{
      if (!stage_b_native_state_register(output, rule->register_index, &pointer) ||
          (!rule->nullable && pointer == 0U) ||
          !stage_b_native_range_size(rule, event, snapshot, pointer, &size)) {{
        stage_b_native_diagnostic_reason = 0x2101U;
        return STAGE_B_CALL_UNIMPLEMENTED;
      }}
      if (pointer == 0U || size == 0U) continue;
      status = stage_b_native_add_external_range(
          pointer, size, rule->instruction_rva, rule->action);
    }} else if (rule->action == 2U) {{
      if (!stage_b_native_external_argument(
              rule, event, snapshot, rule->argument, &pointer)) {{
        stage_b_native_diagnostic_reason = 0x2201U;
        return STAGE_B_CALL_UNIMPLEMENTED;
      }}
      status = stage_b_native_release_external_range(
          pointer, rule->instruction_rva);
    }} else if (rule->action == 3U) {{
      if (!stage_b_native_state_register(
              output, rule->register_index, &pointer)) {{
        stage_b_native_diagnostic_reason = 0x2301U;
        return STAGE_B_CALL_UNIMPLEMENTED;
      }}
      status = stage_b_native_add_external_pointee_ranges(rule, pointer);
    }} else if (rule->action == 4U) {{
      if (!stage_b_native_external_argument(
              rule, event, snapshot, rule->argument, &pointer)) {{
        stage_b_native_diagnostic_reason = 0x2401U;
        return STAGE_B_CALL_UNIMPLEMENTED;
      }}
      status = stage_b_native_add_external_pointee_ranges(
          rule, pointer);
    }} else if (rule->action == 5U) {{
      if ((int32_t)output->eax < 0) continue;
      if (!stage_b_native_external_argument(
              rule, event, snapshot, rule->argument, &pointer)) {{
        stage_b_native_diagnostic_reason = 0x2501U;
        return STAGE_B_CALL_UNIMPLEMENTED;
      }}
      status = stage_b_native_add_external_interface_ranges(rule, pointer);
    }} else {{
      stage_b_native_diagnostic_reason = 0x2f01U;
      return STAGE_B_CALL_UNIMPLEMENTED;
    }}
    if (status != STAGE_B_CALL_OK) {{
      if (rule->action == 2U && stage_b_native_diagnostic_reason == 0U) {{
        stage_b_native_diagnostic_value =
            stage_b_native_context_value.external_range_count;
        stage_b_native_diagnostic_aux = pointer;
        stage_b_native_diagnostic_detail =
            stage_b_native_context_value.external_range_count != 0U
            ? stage_b_native_context_value.external_ranges[
                stage_b_native_context_value.external_range_count - 1U].start
            : 0U;
      }}
      if (stage_b_native_diagnostic_reason == 0U)
        stage_b_native_diagnostic_reason =
            0x2000U + rule->action * 0x100U + 2U;
      return status;
    }}
  }}
  return STAGE_B_CALL_OK;
}}

static uint32_t stage_b_native_flat_read(
    void *opaque, uint32_t address, uint32_t width, uint32_t *fault) {{
  const volatile uint8_t *p;
  uint32_t end, value = 0U, i;
  stage_b_native_context *context = (stage_b_native_context *)opaque;
  if (fault == 0) return 0U;
  *fault = 1U;
  if (context == 0 || context->initialized == 0U ||
      (width != 1U && width != 2U && width != 4U) ||
      !stage_b_native_range_end(address, width, &end) ||
      !stage_b_native_read_allowed(address, width)) {{
    stage_b_native_diagnostic_reason = 0x3001U;
    stage_b_native_diagnostic_value = address;
    stage_b_native_diagnose_external_range(context, address);
    return 0U;
  }}
  (void)end;
  p = (const volatile uint8_t *)(uintptr_t)address;
  for (i = 0U; i < width; ++i) value |= (uint32_t)p[i] << (i * 8U);
  *fault = 0U;
  return value;
}}

static void stage_b_native_flat_write(
    void *opaque, uint32_t address, uint32_t width, uint32_t value,
    uint32_t *fault) {{
  volatile uint8_t *p;
  uint32_t i;
  stage_b_native_context *context = (stage_b_native_context *)opaque;
  if (fault == 0) return;
  *fault = 1U;
  if (context == 0 || context->initialized == 0U ||
      (width != 1U && width != 2U && width != 4U) ||
      !stage_b_native_write_allowed(address, width)) {{
    stage_b_native_diagnostic_reason = 0x3002U;
    stage_b_native_diagnostic_value = address;
    stage_b_native_diagnose_external_range(context, address);
    return;
  }}
  p = (volatile uint8_t *)(uintptr_t)address;
  for (i = 0U; i < width; ++i) p[i] = (uint8_t)(value >> (i * 8U));
  *fault = 0U;
}}

static void stage_b_native_atomic_compare_exchange(
    void *opaque, uint32_t address, uint32_t width,
    uint32_t expected, uint32_t desired,
    uint32_t *observed, uint32_t *exchanged, uint32_t *fault) {{
  stage_b_native_context *context = (stage_b_native_context *)opaque;
  uint32_t end;
  if (fault == 0) return;
  *fault = 1U;
  if (observed == 0 || exchanged == 0 || context == 0 ||
      context->initialized == 0U ||
      (width != 1U && width != 2U && width != 4U) ||
      !stage_b_native_range_end(address, width, &end) ||
      !stage_b_native_read_allowed(address, width) ||
      !stage_b_native_write_allowed(address, width))
    return;
  (void)end;
  if (width == 1U) {{
    uint8_t prior = (uint8_t)expected;
    *exchanged = __atomic_compare_exchange_n(
        (volatile uint8_t *)(uintptr_t)address, &prior, (uint8_t)desired,
        0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    *observed = prior;
  }} else if (width == 2U) {{
    uint16_t prior = (uint16_t)expected;
    *exchanged = __atomic_compare_exchange_n(
        (volatile uint16_t *)(uintptr_t)address, &prior, (uint16_t)desired,
        0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    *observed = prior;
  }} else {{
    uint32_t prior = expected;
    *exchanged = __atomic_compare_exchange_n(
        (volatile uint32_t *)(uintptr_t)address, &prior, desired,
        0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    *observed = prior;
  }}
  *fault = 0U;
}}

static void stage_b_native_atomic_exchange(
    void *opaque, uint32_t address, uint32_t width,
    uint32_t desired, uint32_t *observed, uint32_t *fault) {{
  stage_b_native_context *context = (stage_b_native_context *)opaque;
  uint32_t end;
  if (fault == 0) return;
  *fault = 1U;
  if (observed == 0 || context == 0 || context->initialized == 0U ||
      (width != 1U && width != 2U && width != 4U) ||
      !stage_b_native_range_end(address, width, &end) ||
      !stage_b_native_read_allowed(address, width) ||
      !stage_b_native_write_allowed(address, width))
    return;
  (void)end;
  if (width == 1U)
    *observed = __atomic_exchange_n(
        (volatile uint8_t *)(uintptr_t)address, (uint8_t)desired,
        __ATOMIC_SEQ_CST);
  else if (width == 2U)
    *observed = __atomic_exchange_n(
        (volatile uint16_t *)(uintptr_t)address, (uint16_t)desired,
        __ATOMIC_SEQ_CST);
  else
    *observed = __atomic_exchange_n(
        (volatile uint32_t *)(uintptr_t)address, desired, __ATOMIC_SEQ_CST);
  *fault = 0U;
}}

void stage_b_runtime_atomic_compare_exchange(
    stage_b_runtime *runtime, uint32_t address, uint32_t width,
    uint32_t expected, uint32_t desired,
    uint32_t *observed, uint32_t *exchanged, uint32_t *fault) {{
  if (fault == 0) return;
  *fault = 1U;
  if (runtime == 0) return;
  stage_b_native_atomic_compare_exchange(
      runtime->context, address, width, expected, desired,
      observed, exchanged, fault);
}}

void stage_b_runtime_atomic_exchange(
    stage_b_runtime *runtime, uint32_t address, uint32_t width,
    uint32_t desired, uint32_t *observed, uint32_t *fault) {{
  if (fault == 0) return;
  *fault = 1U;
  if (runtime == 0) return;
  stage_b_native_atomic_exchange(
      runtime->context, address, width, desired, observed, fault);
}}

static uint32_t stage_b_native_undefined_value(
    void *opaque, uint32_t slot, const stage_b_machine_state *input,
    uint32_t defined_value) {{
  stage_b_native_context *context = (stage_b_native_context *)opaque;
  uint32_t low = 0U, high = stage_b_native_undefined_policy_count;
  if (context == 0 || context->initialized == 0U) return 0U;
  while (low < high) {{
    uint32_t middle = low + (high - low) / 2U;
    if (stage_b_native_undefined_policies[middle].slot < slot) low = middle + 1U;
    else high = middle;
  }}
  if (low == stage_b_native_undefined_policy_count ||
      stage_b_native_undefined_policies[low].slot != slot) {{
    if (context->undefined_fault == 0U) {{
      context->undefined_fault_slot = slot;
      context->undefined_fault_rva = input != 0 ? input->original_rva : 0U;
    }}
    context->undefined_fault = 1U;
    return 0U;
  }}
  if (stage_b_native_undefined_policies[low].policy == 0U) return 0U;
  if (stage_b_native_undefined_policies[low].policy == 1U)
    return defined_value;
  if (context->undefined_fault == 0U) {{
    context->undefined_fault_slot = slot;
    context->undefined_fault_rva = input != 0 ? input->original_rva : 0U;
  }}
  context->undefined_fault = 1U;
  return 0U;
}}

static uint32_t stage_b_native_resolve_code_target(
    stage_b_runtime *runtime, uint32_t target_word, uint32_t *target_rva) {{
  stage_b_native_context *context;
  uint32_t rva, low = 0U, high = stage_b_native_transfer_count;
  if (runtime == 0 || target_rva == 0 || runtime->context == 0) return 1U;
  context = (stage_b_native_context *)runtime->context;
  if (context->initialized == 0U || target_word < context->image_base)
    return 1U;
  rva = target_word - context->image_base;
  {{
    uint32_t range_low = 0U, range_high = stage_b_native_noncode_range_count;
    while (range_low < range_high) {{
      uint32_t middle = range_low + (range_high - range_low) / 2U;
      if (stage_b_native_noncode_ranges[middle].rva_end <= rva)
        range_low = middle + 1U;
      else
        range_high = middle;
    }}
    if (range_low < stage_b_native_noncode_range_count &&
        stage_b_native_noncode_ranges[range_low].rva_start <= rva &&
        rva < stage_b_native_noncode_ranges[range_low].rva_end)
      return 1U;
  }}
  while (low < high) {{
    uint32_t middle = low + (high - low) / 2U;
    if (stage_b_native_transfer_rvas[middle] < rva) low = middle + 1U;
    else high = middle;
  }}
  if (low == stage_b_native_transfer_count ||
      stage_b_native_transfer_rvas[low] != rva || stage_b_program_lookup(rva) == 0)
    return 1U;
  *target_rva = rva;
  return 0U;
}}

static uint32_t stage_b_native_callable_argument_value(
    const stage_b_native_callable_argument *source,
    const stage_b_machine_state *input, uint32_t *value) {{
  uint32_t address;
  if (source == 0 || input == 0 || value == 0) return 0U;
  if (source->kind == 0U)
    return stage_b_native_state_register(input, source->register_index, value);
  if (source->kind == 1U) {{
    if (input->esp > 0xffffffffU - source->value) return 0U;
    address = input->esp + source->value;
    if (!stage_b_native_read_allowed(address, 4U)) return 0U;
    *value = stage_b_native_u32(address);
    return 1U;
  }}
  if (source->kind == 2U) {{
    *value = source->value;
    return 1U;
  }}
  return 0U;
}}

static uint32_t stage_b_native_callable_footprints_valid(
    const stage_b_native_callable_route *route,
    const uint32_t *arguments) {{
  uint32_t i;
  if (route == 0 ||
      route->footprint_offset > stage_b_native_callable_footprint_count ||
      route->footprint_count >
          stage_b_native_callable_footprint_count - route->footprint_offset)
    return 0U;
  for (i = 0U; i < route->footprint_count; ++i) {{
    const stage_b_native_callable_footprint *footprint =
        &stage_b_native_callable_footprints[route->footprint_offset + i];
    uint32_t start, end;
    if (arguments == 0 || footprint->base_argument >= route->argument_count)
      return 0U;
    start = arguments[footprint->base_argument];
    if (start == 0U) {{
      if (footprint->nullable != 0U) continue;
      return 0U;
    }}
    if (start > 0xffffffffU - footprint->offset ||
        !stage_b_native_range_end(
            start + footprint->offset, footprint->size, &end))
      return 0U;
    start += footprint->offset;
    if (footprint->access == 0U) {{
      if (!stage_b_native_read_allowed(start, footprint->size)) return 0U;
    }} else if (footprint->access == 1U) {{
      if (!stage_b_native_write_allowed(start, footprint->size)) return 0U;
    }} else {{
      return 0U;
    }}
    (void)end;
  }}
  return 1U;
}}

static uint32_t stage_b_native_callable_preserved(
    uint32_t mask, const stage_b_machine_state *input,
    const stage_b_machine_state *output) {{
  uint32_t index;
  for (index = 0U; index < 8U; ++index) {{
    uint32_t before, after;
    if ((mask & (1U << index)) == 0U) continue;
    if (!stage_b_native_state_register(input, index, &before) ||
        !stage_b_native_state_register(output, index, &after) || before != after)
      return 0U;
  }}
  return 1U;
}}

static stage_b_call_status stage_b_native_invoke_callable_external_jump(
    stage_b_runtime *runtime, uint32_t source_rva, uint32_t target_word,
    const stage_b_machine_state *input, stage_b_machine_state *output) {{
  uint32_t route_index;
  if (runtime != &stage_b_native_runtime_instance || input == 0 || output == 0)
    return STAGE_B_CALL_UNIMPLEMENTED;
  for (route_index = 0U;
       route_index < stage_b_native_callable_route_count; ++route_index) {{
    const stage_b_native_callable_route *route =
        &stage_b_native_callable_routes[route_index];
    stage_b_native_callable_binding *binding;
    stage_b_call_event event = {{0}};
    uint32_t arguments[64];
    uint32_t argument_index;
    stage_b_call_status status;
    if (route->source_rva != source_rva) continue;
    binding = stage_b_native_callable_binding_for(route->capability_id);
    if (binding == 0 || binding->bound == 0U ||
        binding->target_word != target_word)
      continue;
    if (route->argument_count > 64U ||
        route->argument_offset > stage_b_native_callable_argument_count ||
        route->argument_count >
            stage_b_native_callable_argument_count - route->argument_offset)
      return STAGE_B_CALL_UNIMPLEMENTED;
    for (argument_index = 0U;
         argument_index < route->argument_count; ++argument_index)
      if (!stage_b_native_callable_argument_value(
              &stage_b_native_callable_arguments[
                  route->argument_offset + argument_index],
              input, &arguments[argument_index]))
        return STAGE_B_CALL_UNIMPLEMENTED;
    if (!stage_b_native_callable_footprints_valid(route, arguments))
      return STAGE_B_CALL_UNIMPLEMENTED;
    event.kind = STAGE_B_CALL_INDIRECT;
    event.instruction_rva = route->instruction_rva;
    event.call_index = route->abi_contract_id;
    event.target_rva = target_word;
    event.arguments = arguments;
    event.argument_count = route->argument_count;
    *output = *input;
    status = stage_b_dispatch_external_call(runtime, &event, input, output);
    if (status != STAGE_B_CALL_OK) return status;
    if (input->esp > 0xffffffffU - route->stack_result_delta ||
        output->esp != input->esp + route->stack_result_delta ||
        !stage_b_native_callable_preserved(
            route->preserved_register_mask, input, output))
      return STAGE_B_CALL_UNIMPLEMENTED;
    return STAGE_B_CALL_OK;
  }}
  return STAGE_B_CALL_UNIMPLEMENTED;
}}

#ifdef STAGE_B_NATIVE_DIAGNOSTIC_FAILURE_TRAP
static void stage_b_native_trace_transfer(
    void *raw_context, uint32_t rva,
    const stage_b_machine_state *state) {{
  stage_b_native_context *context = (stage_b_native_context *)raw_context;
  stage_b_native_transfer_trace_event *event;
  uint32_t index;
  if (context != &stage_b_native_context_value || state == 0) return;
  index = context->transfer_trace_next;
  event = &context->transfer_trace_events[index];
  event->sequence = ++context->transfer_trace_sequence;
  event->rva = rva;
  event->df = state->df;
  event->esp = state->esp;
  context->transfer_trace_next =
      (index + 1U) % STAGE_B_NATIVE_MAX_TRANSFER_TRACE_EVENTS;
  if (context->transfer_trace_count < STAGE_B_NATIVE_MAX_TRANSFER_TRACE_EVENTS)
    ++context->transfer_trace_count;
}}
#endif

stage_b_runtime stage_b_native_runtime_instance = {{
  .context = &stage_b_native_context_value,
  .read = stage_b_native_flat_read,
  .write = stage_b_native_flat_write,
  .atomic_compare_exchange = stage_b_native_atomic_compare_exchange,
  .atomic_exchange = stage_b_native_atomic_exchange,
  .undefined_value = stage_b_native_undefined_value,
  .external_call_fallback = stage_b_dispatch_external_call,
#ifdef STAGE_B_NATIVE_DIAGNOSTIC_FAILURE_TRAP
  .trace_transfer = stage_b_native_trace_transfer,
#else
  .trace_transfer = 0,
#endif
'''
