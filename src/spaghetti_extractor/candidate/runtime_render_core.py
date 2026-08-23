"""Core native runtime C template rendering."""

from __future__ import annotations

from .runtime_model import NativeRuntimePlan


def _native_runtime_source_core(plan: NativeRuntimePlan) -> str:
    runtime_context_initializer = "0"
    ingress_checks = " &&\n      ".join(
        f"spx_program_lookup(0x{int(row['target_rva']):08x}U) != 0"
        for row in plan.ingress_descriptors
    ) or "0U"
    return f'''  return {ingress_checks};
}}

uint32_t spx_native_machine_fallback_allowed(uint32_t rva) {{
  uint32_t low = 0U, high = spx_native_implementation_dispatch_count;
  while (low < high) {{
    uint32_t middle = low + (high - low) / 2U;
    uint32_t observed = spx_native_implementation_dispatches[middle].rva;
    if (observed < rva) low = middle + 1U;
    else high = middle;
  }}
  return low < spx_native_implementation_dispatch_count &&
      spx_native_implementation_dispatches[low].rva == rva &&
      spx_native_implementation_dispatches[low].implementation_class == 0U;
}}

static uint32_t spx_native_write_allowed(uint32_t address, uint32_t width) {{
  spx_native_context *context = &spx_native_context_value;
  uint32_t end, image_end, i, matched = 0U;
  if (!spx_native_range_end(address, width, &end) ||
      !spx_native_range_end(context->image_base, context->image_size, &image_end))
    return 0U;
  if (spx_native_inside_external_range(context, address, end)) return 1U;
  if (spx_native_inside_thread_environment(context, address, end)) return 1U;
  if (end <= context->image_base || address >= image_end)
    return address >= context->stack_low && end <= context->stack_high;
  for (i = 0U; i < context->section_count; ++i) {{
    uint32_t section = context->section_table + i * 40U;
    uint32_t virtual_size = spx_native_u32(section + 8U);
    uint32_t raw_size = spx_native_u32(section + 16U);
    uint32_t rva = spx_native_u32(section + 12U);
    uint32_t size = virtual_size > raw_size ? virtual_size : raw_size;
    uint32_t section_start;
    if (rva > 0xffffffffU - context->image_base) return 0U;
    section_start = context->image_base + rva;
    if (spx_native_inside(address, end, section_start, size)) {{
      if ((spx_native_u32(section + 36U) &
          SPX_NATIVE_IMAGE_SCN_MEM_EXECUTE) != 0U)
        return 0U;
      matched = 1U;
    }}
  }}
  return matched;
}}

static uint32_t spx_native_read_allowed(uint32_t address, uint32_t width) {{
  spx_native_context *context = &spx_native_context_value;
  uint32_t end, image_end, i;
  if (!spx_native_range_end(address, width, &end) ||
      !spx_native_range_end(context->image_base, context->image_size, &image_end))
    return 0U;
  if (address >= context->stack_low && end <= context->stack_high)
    return 1U;
  if (spx_native_inside_external_range(context, address, end)) return 1U;
  if (spx_native_inside_thread_environment(context, address, end)) return 1U;
  if (address < context->image_base || end > image_end)
    return 0U;
  if (end <= context->image_base + context->headers_size)
    return 1U;
  for (i = 0U; i < context->section_count; ++i) {{
    uint32_t section = context->section_table + i * 40U;
    uint32_t virtual_size = spx_native_u32(section + 8U);
    uint32_t raw_size = spx_native_u32(section + 16U);
    uint32_t rva = spx_native_u32(section + 12U);
    uint32_t size = virtual_size > raw_size ? virtual_size : raw_size;
    uint32_t section_start;
    if (rva > 0xffffffffU - context->image_base) return 0U;
    section_start = context->image_base + rva;
    if (spx_native_inside(address, end, section_start, size)) return 1U;
  }}
  return 0U;
}}

static uint32_t spx_native_state_register(
    const spx_machine_state *state, uint32_t index, uint32_t *value) {{
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

static spx_native_callable_binding *spx_native_callable_binding_for(
    uint32_t capability_id) {{
  spx_native_context *context = &spx_native_context_value;
  uint32_t i;
  for (i = 0U; i < spx_native_callable_binding_count; ++i)
    if (context->callable_bindings[i].capability_id == capability_id)
      return &context->callable_bindings[i];
  return (spx_native_callable_binding *)0;
}}

static uint32_t spx_native_callable_target_matches(
    const spx_call_event *event) {{
  uint32_t route_index, route_seen = 0U;
  if (event == 0 || event->kind != SPX_CALL_INDIRECT) return 1U;
  for (route_index = 0U;
       route_index < spx_native_callable_route_count; ++route_index) {{
    const spx_native_callable_route *route =
        &spx_native_callable_routes[route_index];
    spx_native_callable_binding *binding;
    if (route->instruction_rva != event->instruction_rva) continue;
    route_seen = 1U;
    binding = spx_native_callable_binding_for(route->capability_id);
    if (binding != 0 && binding->bound != 0U &&
        binding->target_word == event->target_rva)
      return 1U;
  }}
  return route_seen == 0U;
}}

static spx_call_status spx_native_record_callable_result(
    const spx_call_event *event, const spx_machine_state *output) {{
  spx_native_context *context = &spx_native_context_value;
  uint32_t i;
  for (i = 0U; i < spx_native_callable_resolver_count; ++i) {{
    const spx_native_callable_resolver *resolver =
        &spx_native_callable_resolvers[i];
    spx_native_callable_binding *binding;
    uint32_t target, image_end;
    if (resolver->instruction_rva != event->instruction_rva) continue;
    if (!spx_native_state_register(
            output, resolver->result_register, &target))
      return SPX_CALL_UNIMPLEMENTED;
    if (target == 0U)
      return resolver->nullable != 0U
          ? SPX_CALL_OK : SPX_CALL_UNIMPLEMENTED;
    if (!spx_native_range_end(
            context->image_base, context->image_size, &image_end) ||
        (target >= context->image_base && target < image_end))
      return SPX_CALL_UNIMPLEMENTED;
    binding = spx_native_callable_binding_for(resolver->capability_id);
    if (binding == 0) return SPX_CALL_UNIMPLEMENTED;
    if (binding->bound != 0U && binding->target_word != target)
      return SPX_CALL_UNIMPLEMENTED;
    binding->target_word = target;
    binding->bound = 1U;
  }}
  return SPX_CALL_OK;
}}

static uint32_t spx_native_external_range_rule_matches(
    const spx_native_external_range_rule *rule,
    const spx_call_event *event) {{
  const spx_native_context *context = &spx_native_context_value;
  uint32_t iat_address, target;
  if (rule == 0 || event == 0 ||
      rule->instruction_rva != event->instruction_rva)
    return 0U;
  if (rule->target_iat_rva == 0U) return 1U;
  if (event->kind != SPX_CALL_INDIRECT ||
      rule->target_iat_rva > context->image_size ||
      context->image_base > 0xffffffffU - rule->target_iat_rva)
    return 0U;
  iat_address = context->image_base + rule->target_iat_rva;
  target = spx_native_u32(iat_address);
  return target != 0U && event->target_rva == target;
}}

static uint32_t spx_native_external_site_authorized(uint32_t rva) {{
  uint32_t low = 0U, high = spx_native_authorized_external_site_count;
  while (low < high) {{
    uint32_t middle = low + (high - low) / 2U;
    if (spx_native_authorized_external_sites[middle] < rva)
      low = middle + 1U;
    else
      high = middle;
  }}
  return low < spx_native_authorized_external_site_count &&
      spx_native_authorized_external_sites[low] == rva;
}}

spx_call_status spx_native_runtime_capture_external_call(
    const spx_call_event *event, const spx_machine_state *input,
    spx_external_call_snapshot *snapshot) {{
  uint32_t i, found = 0U, direct_binding_seen = 0U;
  if (event == 0 || input == 0 || snapshot == 0 ||
      spx_native_context_value.initialized == 0U) {{
    spx_native_diagnostic_reason = 0x2003U;
    return SPX_CALL_UNIMPLEMENTED;
  }}
  if (!spx_native_external_site_authorized(event->instruction_rva)) {{
    spx_native_diagnostic_reason = 0x2009U;
    spx_native_diagnostic_value = event->instruction_rva;
    spx_native_diagnostic_aux = event->target_rva;
    return SPX_CALL_UNIMPLEMENTED;
  }}
  if (event->kind == SPX_CALL_INDIRECT &&
      event->target_rva >= spx_native_context_value.image_base &&
      event->target_rva - spx_native_context_value.image_base <
          spx_native_context_value.image_size) {{
    spx_native_diagnostic_reason = 0x200aU;
    spx_native_diagnostic_value = event->instruction_rva;
    spx_native_diagnostic_aux = event->target_rva;
    return SPX_CALL_UNIMPLEMENTED;
  }}
  if (!spx_native_callable_target_matches(event)) {{
    spx_native_diagnostic_reason = 0x200bU;
    spx_native_diagnostic_value = event->instruction_rva;
    spx_native_diagnostic_aux = event->target_rva;
    return SPX_CALL_UNIMPLEMENTED;
  }}
  snapshot->instruction_rva = event->instruction_rva;
  snapshot->target_iat_rva = 0U;
  snapshot->argument_base_offset = 0U;
  snapshot->argument_count = 0U;
  for (i = 0U; i < spx_native_external_range_rule_count; ++i) {{
    const spx_native_external_range_rule *rule =
        &spx_native_external_range_rules[i];
    if (!spx_native_external_range_rule_matches(rule, event)) continue;
    if ((rule->target_iat_rva == 0U && snapshot->target_iat_rva != 0U) ||
        (rule->target_iat_rva != 0U && direct_binding_seen != 0U) ||
        (rule->target_iat_rva != 0U && snapshot->target_iat_rva != 0U &&
         snapshot->target_iat_rva != rule->target_iat_rva)) {{
      spx_native_diagnostic_reason = 0x2008U;
      spx_native_diagnostic_value = event->target_rva;
      spx_native_diagnostic_aux = snapshot->target_iat_rva;
      spx_native_diagnostic_detail = rule->target_iat_rva;
      return SPX_CALL_UNIMPLEMENTED;
    }}
    if (rule->target_iat_rva == 0U)
      direct_binding_seen = 1U;
    else
      snapshot->target_iat_rva = rule->target_iat_rva;
    if (rule->argument_count > SPX_MAX_EXTERNAL_ARGUMENTS ||
        (found != 0U &&
         (snapshot->argument_base_offset != rule->argument_base_offset ||
          snapshot->argument_count != rule->argument_count))) {{
      spx_native_diagnostic_reason = 0x2004U;
      return SPX_CALL_UNIMPLEMENTED;
    }}
    snapshot->argument_base_offset = rule->argument_base_offset;
    snapshot->argument_count = rule->argument_count;
    found = 1U;
  }}
  for (i = 0U; i < snapshot->argument_count; ++i) {{
    uint32_t offset, address, value;
    if (i > 0x3fffffffU) {{
      spx_native_diagnostic_reason = 0x2005U;
      return SPX_CALL_UNIMPLEMENTED;
    }}
    offset = i * 4U;
    if (snapshot->argument_base_offset > 0xffffffffU - offset ||
        input->esp >
            0xffffffffU - (snapshot->argument_base_offset + offset)) {{
      spx_native_diagnostic_reason = 0x2005U;
      return SPX_CALL_UNIMPLEMENTED;
    }}
    address = input->esp + snapshot->argument_base_offset + offset;
    if (!spx_native_read_allowed(address, 4U)) {{
      spx_native_diagnostic_reason = 0x2005U;
      return SPX_CALL_UNIMPLEMENTED;
    }}
    value = spx_native_u32(address);
    if (event->arguments != 0 && i < event->argument_count &&
        event->arguments[i] != value) {{
      spx_native_diagnostic_reason = 0x2006U;
      return SPX_CALL_UNIMPLEMENTED;
    }}
    snapshot->arguments[i] = value;
  }}
  return SPX_CALL_OK;
}}

static uint32_t spx_native_external_argument(
    const spx_native_external_range_rule *rule,
    const spx_call_event *event,
    const spx_external_call_snapshot *snapshot,
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

static uint32_t spx_native_zero_run_extent(
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
        ? (uint32_t)spx_native_u16(address)
        : spx_native_u32(address);
    run = value == 0U ? run + 1U : 0U;
    if (run == zero_units) {{
      if (index == 0xffffffffU / unit_bytes) return 0U;
      *extent = (index + 1U) * unit_bytes;
      return 1U;
    }}
  }}
  return 0U;
}}

static uint32_t spx_native_range_size(
    const spx_native_external_range_rule *rule,
    const spx_call_event *event,
    const spx_external_call_snapshot *snapshot,
    uint32_t pointer, uint32_t *size) {{
  uint32_t left, right;
  if (rule == 0 || event == 0 || size == 0) return 0U;
  if (rule->size_kind == 1U) {{
    *size = rule->size_value;
  }} else if (rule->size_kind == 2U) {{
    if (!spx_native_external_argument(
            rule, event, snapshot, rule->size_argument, &left))
      return 0U;
    if (rule->size_value != 0U && left > 0xffffffffU / rule->size_value)
      return 0U;
    *size = left * rule->size_value;
  }} else if (rule->size_kind == 3U) {{
    if (!spx_native_external_argument(
            rule, event, snapshot, rule->size_argument, &left) ||
        !spx_native_external_argument(
            rule, event, snapshot, rule->size_right_argument, &right))
      return 0U;
    if (right != 0U && left > 0xffffffffU / right) return 0U;
    *size = left * right;
  }} else if (rule->size_kind == 4U) {{
    if (pointer == 0U) return rule->nullable != 0U;
    if (!spx_native_zero_run_extent(
            pointer, rule->termination_unit_bytes,
            rule->termination_zero_units, rule->termination_max_units, size))
      return 0U;
  }} else {{
    return 0U;
  }}
  return *size >= rule->minimum_size;
}}

static uint32_t spx_native_next_external_lifecycle_sequence(
    spx_native_context *context) {{
  if (context->external_lifecycle_sequence != 0xffffffffU)
    ++context->external_lifecycle_sequence;
  return context->external_lifecycle_sequence;
}}

static void spx_native_record_external_lifecycle(
    spx_native_context *context, uint32_t operation,
    spx_call_status status, uint32_t instruction_rva,
    uint32_t start, uint32_t size, uint32_t producer_rva,
    uint32_t producer_action, uint32_t generation) {{
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
}}

static spx_call_status spx_native_add_external_range(
    uint32_t start, uint32_t size, uint32_t producer_rva,
    uint32_t producer_action) {{
  spx_native_context *context = &spx_native_context_value;
  uint32_t end, generation, i;
  if (!spx_native_range_end(start, size, &end)) {{
    spx_native_record_external_lifecycle(
        context, 1U, SPX_CALL_UNIMPLEMENTED, producer_rva,
        start, size, producer_rva, producer_action, 0U);
    return SPX_CALL_UNIMPLEMENTED;
  }}
  generation = context->external_lifecycle_sequence == 0xffffffffU
      ? 0xffffffffU : context->external_lifecycle_sequence + 1U;
  if (context->external_object_sequence != 0xffffffffU)
    ++context->external_object_sequence;
  for (i = 0U; i < context->external_range_count; ++i) {{
    if (context->external_ranges[i].start == start) {{
      context->external_ranges[i].size = size;
      context->external_ranges[i].producer_rva = producer_rva;
      context->external_ranges[i].producer_action = producer_action;
      context->external_ranges[i].generation = generation;
      context->external_ranges[i].object_id = context->external_object_sequence;
      spx_native_record_external_lifecycle(
          context, 2U, SPX_CALL_OK, producer_rva,
          start, size, producer_rva, producer_action, generation);
      return SPX_CALL_OK;
    }}
  }}
  if (context->external_range_count == SPX_NATIVE_MAX_EXTERNAL_RANGES) {{
    spx_native_record_external_lifecycle(
        context, 1U, SPX_CALL_UNIMPLEMENTED, producer_rva,
        start, size, producer_rva, producer_action, generation);
    return SPX_CALL_UNIMPLEMENTED;
  }}
  context->external_ranges[context->external_range_count].start = start;
  context->external_ranges[context->external_range_count].size = size;
  context->external_ranges[context->external_range_count].producer_rva = producer_rva;
  context->external_ranges[context->external_range_count].producer_action =
      producer_action;
  context->external_ranges[context->external_range_count].generation = generation;
  context->external_ranges[context->external_range_count].object_id =
      context->external_object_sequence;
  ++context->external_range_count;
  spx_native_record_external_lifecycle(
      context, 1U, SPX_CALL_OK, producer_rva,
      start, size, producer_rva, producer_action, generation);
  return SPX_CALL_OK;
}}

static spx_call_status spx_native_release_external_range(
    uint32_t start, uint32_t instruction_rva) {{
  spx_native_context *context = &spx_native_context_value;
  uint32_t i, operation = 4U;
  if (start == 0U) return SPX_CALL_OK;
  for (i = 0U; i < context->external_range_count; ++i) {{
    if (context->external_ranges[i].start == start) {{
      spx_native_external_range released = context->external_ranges[i];
      --context->external_range_count;
      context->external_ranges[i] =
          context->external_ranges[context->external_range_count];
      spx_native_record_external_lifecycle(
          context, 3U, SPX_CALL_OK, instruction_rva,
          released.start, released.size, released.producer_rva,
          released.producer_action, released.generation);
      return SPX_CALL_OK;
    }}
  }}
  for (i = 0U; i < context->external_range_count; ++i) {{
    uint32_t end;
    if (spx_native_range_end(
            context->external_ranges[i].start,
            context->external_ranges[i].size, &end) &&
        start > context->external_ranges[i].start && start < end) {{
      operation = 5U;
      spx_native_diagnostic_aux = context->external_ranges[i].start;
      spx_native_diagnostic_detail = end;
      break;
    }}
  }}
  if (operation == 4U) {{
    uint32_t offset;
    for (offset = 0U; offset < context->external_lifecycle_count; ++offset) {{
      uint32_t index =
          (context->external_lifecycle_next +
           SPX_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS - 1U - offset) %
          SPX_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS;
      const spx_native_external_lifecycle_event *event =
          &context->external_lifecycle_events[index];
      if (event->start != start) continue;
      if (event->operation == 3U) operation = 6U;
      spx_native_diagnostic_aux = event->instruction_rva;
      spx_native_diagnostic_detail = event->producer_rva;
      break;
    }}
  }}
  spx_native_record_external_lifecycle(
      context, operation, SPX_CALL_UNIMPLEMENTED, instruction_rva,
      start, 0U, 0U, 0U, 0U);
  spx_native_diagnostic_value = start;
  spx_native_diagnostic_reason =
      operation == 5U ? 0x2204U : operation == 6U ? 0x2203U : 0x2202U;
  return SPX_CALL_UNIMPLEMENTED;
}}

static uint32_t spx_native_terminated_extent(
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
        ? (uint32_t)spx_native_u16(address)
        : spx_native_u32(address);
    if (value == 0U) {{
      if (index == 0xffffffffU / unit_bytes) return 0U;
      *extent = (index + 1U) * unit_bytes;
      return 1U;
    }}
  }}
  return 0U;
}}

static spx_call_status spx_native_add_external_pointee_ranges(
    const spx_native_external_range_rule *rule,
    uint32_t cell) {{
  uint32_t vector, index;
  if (rule == 0 || cell == 0U ||
      cell > 0xffffffffU - rule->pointee_offset)
    return SPX_CALL_UNIMPLEMENTED;
  vector = spx_native_u32(cell + rule->pointee_offset);
  if (vector == 0U) return SPX_CALL_OK;
  for (index = 0U; index < rule->max_elements; ++index) {{
    uint32_t offset, element, extent;
    spx_call_status status;
    if (index > 0x3fffffffU) return SPX_CALL_UNIMPLEMENTED;
    offset = index * 4U;
    if (vector > 0xffffffffU - offset) return SPX_CALL_UNIMPLEMENTED;
    element = spx_native_u32(vector + offset);
    if (element == 0U) {{
      if (index == 0x3fffffffU) return SPX_CALL_UNIMPLEMENTED;
      return spx_native_add_external_range(
          vector, (index + 1U) * 4U,
          rule->instruction_rva, rule->action);
    }}
    if (!spx_native_terminated_extent(
            element, rule->element_unit_bytes, rule->element_max_units,
            &extent))
      return SPX_CALL_UNIMPLEMENTED;
    status = spx_native_add_external_range(
        element, extent, rule->instruction_rva, rule->action);
    if (status != SPX_CALL_OK) return status;
  }}
  return SPX_CALL_UNIMPLEMENTED;
}}

static spx_call_status spx_native_add_external_interface_ranges(
    const spx_native_external_range_rule *rule, uint32_t cell) {{
  uint32_t object, vtable;
  spx_call_status status;
  if (rule == 0 || cell == 0U ||
      cell > 0xffffffffU - rule->pointee_offset)
    return SPX_CALL_UNIMPLEMENTED;
  object = spx_native_u32(cell + rule->pointee_offset);
  if (object == 0U)
    return rule->nullable != 0U
        ? SPX_CALL_OK : SPX_CALL_UNIMPLEMENTED;
  status = spx_native_add_external_range(
      object, rule->minimum_size, rule->instruction_rva, rule->action);
  if (status != SPX_CALL_OK) return status;
  vtable = spx_native_u32(object);
  if (vtable == 0U) return SPX_CALL_UNIMPLEMENTED;
  return spx_native_add_external_range(
      vtable, rule->size_value, rule->instruction_rva, rule->action);
}}

spx_call_status spx_native_runtime_record_external_result(
    const spx_call_event *event,
    const spx_external_call_snapshot *snapshot,
    const spx_machine_state *output) {{
  uint32_t i;
  if (event == 0 || snapshot == 0 || output == 0 ||
      snapshot->instruction_rva != event->instruction_rva ||
      spx_native_context_value.initialized == 0U) {{
    spx_native_diagnostic_reason = 0x2001U;
    return SPX_CALL_UNIMPLEMENTED;
  }}
  if (spx_native_record_callable_result(event, output) != SPX_CALL_OK) {{
    spx_native_diagnostic_reason = 0x2002U;
    return SPX_CALL_UNIMPLEMENTED;
  }}
  for (i = 0U; i < spx_native_external_range_rule_count; ++i) {{
    const spx_native_external_range_rule *rule =
        &spx_native_external_range_rules[i];
    spx_call_status status;
    uint32_t pointer, size;
    if (!spx_native_external_range_rule_matches(rule, event) ||
        rule->target_iat_rva != snapshot->target_iat_rva)
      continue;
    if (rule->action == 1U) {{
      if (!spx_native_state_register(output, rule->register_index, &pointer) ||
          (!rule->nullable && pointer == 0U) ||
          !spx_native_range_size(rule, event, snapshot, pointer, &size)) {{
        spx_native_diagnostic_reason = 0x2101U;
        return SPX_CALL_UNIMPLEMENTED;
      }}
      if (pointer == 0U || size == 0U) continue;
      status = spx_native_add_external_range(
          pointer, size, rule->instruction_rva, rule->action);
    }} else if (rule->action == 2U) {{
      if (!spx_native_external_argument(
              rule, event, snapshot, rule->argument, &pointer)) {{
        spx_native_diagnostic_reason = 0x2201U;
        return SPX_CALL_UNIMPLEMENTED;
      }}
      status = spx_native_release_external_range(
          pointer, rule->instruction_rva);
    }} else if (rule->action == 3U) {{
      if (!spx_native_state_register(
              output, rule->register_index, &pointer)) {{
        spx_native_diagnostic_reason = 0x2301U;
        return SPX_CALL_UNIMPLEMENTED;
      }}
      status = spx_native_add_external_pointee_ranges(rule, pointer);
    }} else if (rule->action == 4U) {{
      if (!spx_native_external_argument(
              rule, event, snapshot, rule->argument, &pointer)) {{
        spx_native_diagnostic_reason = 0x2401U;
        return SPX_CALL_UNIMPLEMENTED;
      }}
      status = spx_native_add_external_pointee_ranges(
          rule, pointer);
    }} else if (rule->action == 5U) {{
      if ((int32_t)output->eax < 0) continue;
      if (!spx_native_external_argument(
              rule, event, snapshot, rule->argument, &pointer)) {{
        spx_native_diagnostic_reason = 0x2501U;
        return SPX_CALL_UNIMPLEMENTED;
      }}
      status = spx_native_add_external_interface_ranges(rule, pointer);
    }} else {{
      spx_native_diagnostic_reason = 0x2f01U;
      return SPX_CALL_UNIMPLEMENTED;
    }}
    if (status != SPX_CALL_OK) {{
      if (rule->action == 2U && spx_native_diagnostic_reason == 0U) {{
        spx_native_diagnostic_value =
            spx_native_context_value.external_range_count;
        spx_native_diagnostic_aux = pointer;
        spx_native_diagnostic_detail =
            spx_native_context_value.external_range_count != 0U
            ? spx_native_context_value.external_ranges[
                spx_native_context_value.external_range_count - 1U].start
            : 0U;
      }}
      if (spx_native_diagnostic_reason == 0U)
        spx_native_diagnostic_reason =
            0x2000U + rule->action * 0x100U + 2U;
      return status;
    }}
  }}
  return SPX_CALL_OK;
}}

static uint32_t spx_native_flat_read(
    void *opaque, uint32_t address, uint32_t width, uint32_t *fault) {{
  const volatile uint8_t *p;
  uint32_t end, value = 0U, i;
  spx_native_context *context = (spx_native_context *)opaque;
  if (fault == 0) return 0U;
  *fault = 1U;
  if (context == 0 || context->initialized == 0U ||
      (width != 1U && width != 2U && width != 4U) ||
      !spx_native_range_end(address, width, &end) ||
      !spx_native_read_allowed(address, width)) {{
    spx_native_diagnostic_reason = 0x3001U;
    spx_native_diagnostic_value = address;
    spx_native_diagnose_external_range(context, address);
    return 0U;
  }}
  (void)end;
  p = (const volatile uint8_t *)(uintptr_t)address;
  for (i = 0U; i < width; ++i) value |= (uint32_t)p[i] << (i * 8U);
  *fault = 0U;
  return value;
}}

static void spx_native_flat_write(
    void *opaque, uint32_t address, uint32_t width, uint32_t value,
    uint32_t *fault) {{
  volatile uint8_t *p;
  uint32_t i;
  spx_native_context *context = (spx_native_context *)opaque;
  if (fault == 0) return;
  *fault = 1U;
  if (context == 0 || context->initialized == 0U ||
      (width != 1U && width != 2U && width != 4U) ||
      !spx_native_write_allowed(address, width)) {{
    spx_native_diagnostic_reason = 0x3002U;
    spx_native_diagnostic_value = address;
    spx_native_diagnose_external_range(context, address);
    return;
  }}
  p = (volatile uint8_t *)(uintptr_t)address;
  for (i = 0U; i < width; ++i) p[i] = (uint8_t)(value >> (i * 8U));
  *fault = 0U;
}}

static void spx_native_atomic_compare_exchange(
    void *opaque, uint32_t address, uint32_t width,
    uint32_t expected, uint32_t desired,
    uint32_t *observed, uint32_t *exchanged, uint32_t *fault) {{
  spx_native_context *context = (spx_native_context *)opaque;
  uint32_t end;
  if (fault == 0) return;
  *fault = 1U;
  if (observed == 0 || exchanged == 0 || context == 0 ||
      context->initialized == 0U ||
      (width != 1U && width != 2U && width != 4U) ||
      !spx_native_range_end(address, width, &end) ||
      !spx_native_read_allowed(address, width) ||
      !spx_native_write_allowed(address, width))
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

static void spx_native_atomic_exchange(
    void *opaque, uint32_t address, uint32_t width,
    uint32_t desired, uint32_t *observed, uint32_t *fault) {{
  spx_native_context *context = (spx_native_context *)opaque;
  uint32_t end;
  if (fault == 0) return;
  *fault = 1U;
  if (observed == 0 || context == 0 || context->initialized == 0U ||
      (width != 1U && width != 2U && width != 4U) ||
      !spx_native_range_end(address, width, &end) ||
      !spx_native_read_allowed(address, width) ||
      !spx_native_write_allowed(address, width))
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

void spx_runtime_atomic_compare_exchange(
    spx_runtime *runtime, uint32_t address, uint32_t width,
    uint32_t expected, uint32_t desired,
    uint32_t *observed, uint32_t *exchanged, uint32_t *fault) {{
  if (fault == 0) return;
  *fault = 1U;
  if (runtime == 0 || runtime->atomic_compare_exchange == 0) return;
  runtime->atomic_compare_exchange(
      runtime->context, address, width, expected, desired,
      observed, exchanged, fault);
}}

void spx_runtime_atomic_exchange(
    spx_runtime *runtime, uint32_t address, uint32_t width,
    uint32_t desired, uint32_t *observed, uint32_t *fault) {{
  if (fault == 0) return;
  *fault = 1U;
  if (runtime == 0 || runtime->atomic_exchange == 0) return;
  runtime->atomic_exchange(
      runtime->context, address, width, desired, observed, fault);
}}

static uint32_t spx_native_undefined_value(
    void *opaque, uint32_t slot, const spx_machine_state *input,
    uint32_t defined_value) {{
  spx_native_context *context = (spx_native_context *)opaque;
  uint32_t low = 0U, high = spx_native_undefined_policy_count;
  if (context == 0 || context->initialized == 0U) return 0U;
  while (low < high) {{
    uint32_t middle = low + (high - low) / 2U;
    if (spx_native_undefined_policies[middle].slot < slot) low = middle + 1U;
    else high = middle;
  }}
  if (low == spx_native_undefined_policy_count ||
      spx_native_undefined_policies[low].slot != slot) {{
    if (context->undefined_fault == 0U) {{
      context->undefined_fault_slot = slot;
      context->undefined_fault_rva = input != 0 ? input->original_rva : 0U;
    }}
    context->undefined_fault = 1U;
    return 0U;
  }}
  if (spx_native_undefined_policies[low].policy == 0U) return 0U;
  if (spx_native_undefined_policies[low].policy == 1U)
    return defined_value;
  if (context->undefined_fault == 0U) {{
    context->undefined_fault_slot = slot;
    context->undefined_fault_rva = input != 0 ? input->original_rva : 0U;
  }}
  context->undefined_fault = 1U;
  return 0U;
}}

static uint32_t spx_native_resolve_code_target(
    spx_runtime *runtime, uint32_t target_word, uint32_t *target_rva) {{
  spx_native_context *context;
  uint32_t rva, low = 0U, high = spx_native_transfer_count;
  if (runtime == 0 || target_rva == 0 || runtime->context == 0) return 1U;
  context = (spx_native_context *)runtime->context;
  if (context->initialized == 0U || target_word < context->image_base)
    return 1U;
  rva = target_word - context->image_base;
  {{
    uint32_t range_low = 0U, range_high = spx_native_noncode_range_count;
    while (range_low < range_high) {{
      uint32_t middle = range_low + (range_high - range_low) / 2U;
      if (spx_native_noncode_ranges[middle].rva_end <= rva)
        range_low = middle + 1U;
      else
        range_high = middle;
    }}
    if (range_low < spx_native_noncode_range_count &&
        spx_native_noncode_ranges[range_low].rva_start <= rva &&
        rva < spx_native_noncode_ranges[range_low].rva_end)
      return 1U;
  }}
  while (low < high) {{
    uint32_t middle = low + (high - low) / 2U;
    if (spx_native_transfer_rvas[middle] < rva) low = middle + 1U;
    else high = middle;
  }}
  if (low == spx_native_transfer_count ||
      spx_native_transfer_rvas[low] != rva || spx_program_lookup(rva) == 0)
    return 1U;
  *target_rva = rva;
  return 0U;
}}

static uint32_t spx_native_callable_argument_value(
    const spx_native_callable_argument *source,
    const spx_machine_state *input, uint32_t *value) {{
  uint32_t address;
  if (source == 0 || input == 0 || value == 0) return 0U;
  if (source->kind == 0U)
    return spx_native_state_register(input, source->register_index, value);
  if (source->kind == 1U) {{
    if (input->esp > 0xffffffffU - source->value) return 0U;
    address = input->esp + source->value;
    if (!spx_native_read_allowed(address, 4U)) return 0U;
    *value = spx_native_u32(address);
    return 1U;
  }}
  if (source->kind == 2U) {{
    *value = source->value;
    return 1U;
  }}
  return 0U;
}}

static uint32_t spx_native_callable_footprints_valid(
    const spx_native_callable_route *route,
    const uint32_t *arguments) {{
  uint32_t i;
  if (route == 0 ||
      route->footprint_offset > spx_native_callable_footprint_count ||
      route->footprint_count >
          spx_native_callable_footprint_count - route->footprint_offset)
    return 0U;
  for (i = 0U; i < route->footprint_count; ++i) {{
    const spx_native_callable_footprint *footprint =
        &spx_native_callable_footprints[route->footprint_offset + i];
    uint32_t start, end;
    if (arguments == 0 || footprint->base_argument >= route->argument_count)
      return 0U;
    start = arguments[footprint->base_argument];
    if (start == 0U) {{
      if (footprint->nullable != 0U) continue;
      return 0U;
    }}
    if (start > 0xffffffffU - footprint->offset ||
        !spx_native_range_end(
            start + footprint->offset, footprint->size, &end))
      return 0U;
    start += footprint->offset;
    if (footprint->access == 0U) {{
      if (!spx_native_read_allowed(start, footprint->size)) return 0U;
    }} else if (footprint->access == 1U) {{
      if (!spx_native_write_allowed(start, footprint->size)) return 0U;
    }} else {{
      return 0U;
    }}
    (void)end;
  }}
  return 1U;
}}

static uint32_t spx_native_callable_preserved(
    uint32_t mask, const spx_machine_state *input,
    const spx_machine_state *output) {{
  uint32_t index;
  for (index = 0U; index < 8U; ++index) {{
    uint32_t before, after;
    if ((mask & (1U << index)) == 0U) continue;
    if (!spx_native_state_register(input, index, &before) ||
        !spx_native_state_register(output, index, &after) || before != after)
      return 0U;
  }}
  return 1U;
}}

static spx_call_status spx_native_invoke_callable_external_jump(
    spx_runtime *runtime, uint32_t source_rva, uint32_t target_word,
    const spx_machine_state *input, spx_machine_state *output) {{
  uint32_t route_index;
  if (runtime != &spx_native_runtime_instance || input == 0 || output == 0)
    return SPX_CALL_UNIMPLEMENTED;
  for (route_index = 0U;
       route_index < spx_native_callable_route_count; ++route_index) {{
    const spx_native_callable_route *route =
        &spx_native_callable_routes[route_index];
    spx_native_callable_binding *binding;
    spx_call_event event = {{0}};
    uint32_t arguments[64];
    uint32_t argument_index;
    spx_call_status status;
    if (route->source_rva != source_rva) continue;
    binding = spx_native_callable_binding_for(route->capability_id);
    if (binding == 0 || binding->bound == 0U ||
        binding->target_word != target_word)
      continue;
    if (route->argument_count > 64U ||
        route->argument_offset > spx_native_callable_argument_count ||
        route->argument_count >
            spx_native_callable_argument_count - route->argument_offset)
      return SPX_CALL_UNIMPLEMENTED;
    for (argument_index = 0U;
         argument_index < route->argument_count; ++argument_index)
      if (!spx_native_callable_argument_value(
              &spx_native_callable_arguments[
                  route->argument_offset + argument_index],
              input, &arguments[argument_index]))
        return SPX_CALL_UNIMPLEMENTED;
    if (!spx_native_callable_footprints_valid(route, arguments))
      return SPX_CALL_UNIMPLEMENTED;
    event.kind = SPX_CALL_INDIRECT;
    event.instruction_rva = route->instruction_rva;
    event.call_index = route->abi_contract_id;
    event.target_rva = target_word;
    event.arguments = arguments;
    event.argument_count = route->argument_count;
    *output = *input;
    status = spx_dispatch_external_call(runtime, &event, input, output);
    if (status != SPX_CALL_OK) return status;
    if (input->esp > 0xffffffffU - route->stack_result_delta ||
        output->esp != input->esp + route->stack_result_delta ||
        !spx_native_callable_preserved(
            route->preserved_register_mask, input, output))
      return SPX_CALL_UNIMPLEMENTED;
    return SPX_CALL_OK;
  }}
  return SPX_CALL_UNIMPLEMENTED;
}}

static spx_boundary_status spx_native_resolve_reference(
    void *opaque, uint32_t address, uint32_t requested_extent,
    uint32_t permissions, uint32_t nullable, uint32_t allow_one_past,
    spx_machine_reference_v1 *result) {{
  spx_native_context *context = (spx_native_context *)opaque;
  uint32_t count = 0U, base = 0U, extent = 0U, generation = 0U;
  uint32_t domain = 0U, object = 0U, i;
  if (context == 0 || result == 0) return SPX_BOUNDARY_UNSUPPORTED;
  if (address == 0U) {{
    if (nullable == 0U) return SPX_BOUNDARY_MEMORY_FAULT;
    result->domain = result->object = result->generation = 0U;
    result->offset = result->extent = 0U;
    result->permissions = 0U;
    return SPX_BOUNDARY_OK;
  }}
#define SPX_CONSIDER_ORIGIN(d, o, g, b, e) do {{                         \
    uint32_t spx_end = (b) + (e);                                       \
    uint32_t spx_inside = address >= (b) && address < spx_end;           \
    uint32_t spx_one_past = allow_one_past != 0U && address == spx_end;  \
    if ((spx_inside || spx_one_past) &&                                 \
        requested_extent <= (e) && address - (b) <= (e) - requested_extent) {{ \
      ++count; domain = (d); object = (o); generation = (g);            \
      base = (b); extent = (e);                                         \
    }}                                                                  \
  }} while (0)
  SPX_CONSIDER_ORIGIN(1U, 1U, 1U, context->image_base, context->image_size);
  SPX_CONSIDER_ORIGIN(
      2U, 1U, context->invocation_generation,
      context->stack_low, context->stack_high - context->stack_low);
  if (context->owner_fs_base != 0U)
    SPX_CONSIDER_ORIGIN(
        4U, 1U, context->invocation_generation,
        context->owner_fs_base, SPX_NATIVE_THREAD_ENVIRONMENT_BYTES);
  for (i = 0U; i < context->external_range_count; ++i)
    SPX_CONSIDER_ORIGIN(
        3U, context->external_ranges[i].object_id,
        context->external_ranges[i].generation,
        context->external_ranges[i].start,
        context->external_ranges[i].size);
#undef SPX_CONSIDER_ORIGIN
  if (count == 0U) return SPX_BOUNDARY_MEMORY_FAULT;
  if (count != 1U) return SPX_BOUNDARY_TYPE_MISMATCH;
  result->domain = domain;
  result->object = object;
  result->generation = generation;
  result->offset = address - base;
  result->extent = extent;
  result->permissions = permissions;
  return SPX_BOUNDARY_OK;
}}

static spx_boundary_status spx_native_realize_reference(
    void *opaque, const spx_machine_reference_v1 *reference,
    uint32_t permissions, uint32_t nullable, uint32_t allow_one_past,
    uint32_t *address) {{
  spx_native_context *context = (spx_native_context *)opaque;
  uint32_t base = 0U, extent = 0U, generation = 0U, found = 0U, i;
  if (context == 0 || reference == 0 || address == 0)
    return SPX_BOUNDARY_UNSUPPORTED;
  if (reference->domain == 0U && reference->object == 0U) {{
    if (nullable == 0U || reference->generation != 0U ||
        reference->offset != 0U || reference->extent != 0U ||
        reference->permissions != 0U)
      return SPX_BOUNDARY_MEMORY_FAULT;
    *address = 0U;
    return SPX_BOUNDARY_OK;
  }}
  if (reference->domain == 1U && reference->object == 1U) {{
    base = context->image_base; extent = context->image_size;
    generation = 1U; found = 1U;
  }} else if (reference->domain == 2U && reference->object == 1U) {{
    base = context->stack_low; extent = context->stack_high - context->stack_low;
    generation = context->invocation_generation; found = 1U;
  }} else if (reference->domain == 4U && reference->object == 1U &&
             context->owner_fs_base != 0U) {{
    base = context->owner_fs_base; extent = SPX_NATIVE_THREAD_ENVIRONMENT_BYTES;
    generation = context->invocation_generation; found = 1U;
  }} else if (reference->domain == 3U) {{
    for (i = 0U; i < context->external_range_count; ++i)
      if (context->external_ranges[i].object_id == reference->object) {{
        base = context->external_ranges[i].start;
        extent = context->external_ranges[i].size;
        generation = context->external_ranges[i].generation;
        ++found;
      }}
  }}
  if (found != 1U) return SPX_BOUNDARY_TYPE_MISMATCH;
  if (reference->generation != generation) return SPX_BOUNDARY_EXPIRED;
  if (reference->extent != extent || reference->offset > extent ||
      (reference->offset == extent && allow_one_past == 0U) ||
      (reference->permissions & permissions) != permissions ||
      reference->offset > 0xffffffffU - base)
    return SPX_BOUNDARY_MEMORY_FAULT;
  *address = base + (uint32_t)reference->offset;
  return SPX_BOUNDARY_OK;
}}

spx_runtime spx_native_runtime_instance = {{
  .context = {runtime_context_initializer},
  .read = spx_native_flat_read,
  .write = spx_native_flat_write,
  .atomic_compare_exchange = spx_native_atomic_compare_exchange,
  .atomic_exchange = spx_native_atomic_exchange,
  .resolve_reference = spx_native_resolve_reference,
  .realize_reference = spx_native_realize_reference,
  .undefined_value = spx_native_undefined_value,
  .external_call_fallback = spx_dispatch_external_call,
'''
