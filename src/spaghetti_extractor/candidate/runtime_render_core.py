"""Core native runtime C template rendering."""

from __future__ import annotations

from .runtime_memory_access import access_predicates_source
from .runtime_model import SharedModuleRuntimePlan
from ..transfer.reference_namespace import reference_namespace_source
from .runtime_allocation_lifetime import allocation_lifetime_source
from .runtime_range_release import range_release_source
from .runtime_range_ownership import range_allocation_result_source


def _native_runtime_source_core(plan: SharedModuleRuntimePlan) -> str:
    runtime_context_initializer = "0"
    ingress_checks = (
        " &&\n      ".join(
            f"spx_behavioral_has_unit(0x{int(row['target_rva']):08x}U)"
            for row in plan.ingress_descriptors
        )
        or "0U"
    )
    return f"""  return {ingress_checks};
}}

uint32_t spx_native_machine_fallback_allowed(uint32_t rva) {{
  const spx_region_override *override =
      spx_region_override_lookup == 0
      ? (const spx_region_override *)0
      : spx_region_override_lookup(rva);
  return override == 0 || override->fallback_on_unimplemented != 0U;
}}

{access_predicates_source()}static uint32_t spx_native_state_register(
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

static const spx_native_interface_method *spx_native_interface_method_for(
    uint32_t tagged_index) {{
  uint32_t index;
  if ((tagged_index & SPX_NATIVE_INTERFACE_TARGET_TAG) == 0U)
    return (const spx_native_interface_method *)0;
  index = tagged_index & ~SPX_NATIVE_INTERFACE_TARGET_TAG;
  if (index == 0U || index > spx_native_interface_method_count)
    return (const spx_native_interface_method *)0;
  return &spx_native_interface_methods[index - 1U];
}}

static uint32_t spx_native_interface_method_target_matches(
    uint32_t target_word, uint32_t tagged_index,
    uint32_t receiver_word, uint32_t receiver_known) {{
  const spx_native_interface_method *method =
      spx_native_interface_method_for(tagged_index);
  const spx_native_context *context = &spx_native_context_value;
  uint32_t i, matches = 0U;
  if (method == 0 || target_word == 0U ||
      method->slot > 0x3fffffffU)
    return 0U;
  for (i = 0U; i < context->interface_instance_count; ++i) {{
    const spx_native_interface_instance *instance =
        &context->interface_instances[i];
    uint32_t offset = method->slot * 4U;
    uint32_t cell;
    if (instance->generation == 0U ||
        instance->class_index != method->class_index ||
        (receiver_known != 0U && instance->object != receiver_word) ||
        instance->vtable > 0xffffffffU - offset)
      continue;
    cell = instance->vtable + offset;
    if (!spx_native_read_allowed(cell, 4U) ||
        spx_native_u32(cell) != target_word)
      continue;
    if (receiver_known == 0U) return 1U;
    ++matches;
  }}
  return matches == 1U;
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

static uint32_t spx_native_ascii_fold(uint32_t value) {{
  return value >= (uint32_t)'A' && value <= (uint32_t)'Z'
      ? value + ((uint32_t)'a' - (uint32_t)'A') : value;
}}

static uint32_t spx_native_ascii_text_matches(
    const char *observed, const char *expected, uint32_t fold) {{
  uint32_t index;
  if (observed == 0 || expected == 0) return 0U;
  for (index = 0U; index < 4096U; ++index) {{
    uint32_t left = (uint32_t)(uint8_t)observed[index];
    uint32_t right = (uint32_t)(uint8_t)expected[index];
    if (fold != 0U) {{
      left = spx_native_ascii_fold(left);
      right = spx_native_ascii_fold(right);
    }}
    if (left != right) return 0U;
    if (left == 0U) return 1U;
  }}
  return 0U;
}}

static uint32_t spx_native_guest_module_name_matches(
    uint32_t address, const char *expected, uint32_t wide) {{
  uint32_t index;
  if (address == 0U || expected == 0) return 0U;
  for (index = 0U; index < 260U; ++index) {{
    uint32_t observed, wanted = (uint32_t)(uint8_t)expected[index];
    uint32_t current = address + index * (wide != 0U ? 2U : 1U);
    if (current < address ||
        !spx_native_read_allowed(current, wide != 0U ? 2U : 1U))
      return 0U;
    observed = wide != 0U
        ? (uint32_t)*(volatile const uint16_t *)(uintptr_t)current
        : (uint32_t)*(volatile const uint8_t *)(uintptr_t)current;
    if (observed > 0x7fU) return 0U;
    if (observed == 0U) {{
      return wanted == 0U ||
          (expected[index] == '.' && expected[index + 1U] == 'd' &&
           expected[index + 2U] == 'l' && expected[index + 3U] == 'l' &&
           expected[index + 4U] == '\\0');
    }}
    if (wanted == 0U ||
        spx_native_ascii_fold(observed) != spx_native_ascii_fold(wanted))
      return 0U;
  }}
  return 0U;
}}

static uint32_t spx_native_guest_export_name_matches(
    uint32_t address, const char *expected) {{
  uint32_t index;
  if (address == 0U || address <= 0xffffU || expected == 0) return 0U;
  for (index = 0U; index < 4096U; ++index) {{
    uint32_t current = address + index;
    uint32_t observed, wanted;
    if (current < address || !spx_native_read_allowed(current, 1U)) return 0U;
    observed = (uint32_t)*(volatile const uint8_t *)(uintptr_t)current;
    wanted = (uint32_t)(uint8_t)expected[index];
    if (observed != wanted) return 0U;
    if (observed == 0U) return 1U;
  }}
  return 0U;
}}

static uint32_t spx_native_loader_argument(
    const spx_external_call_snapshot *snapshot, uint32_t base_offset,
    uint32_t argument, uint32_t *value) {{
  if (snapshot == 0 || value == 0 ||
      snapshot->argument_base_offset != base_offset ||
      argument >= snapshot->argument_count ||
      argument >= SPX_MAX_EXTERNAL_ARGUMENTS)
    return 0U;
  *value = snapshot->arguments[argument];
  return 1U;
}}

uint32_t spx_native_loader_code_target_matches(
    uint32_t target_word, uint32_t iat_rva,
    uint32_t loader_target_index) {{
  const spx_native_context *context = &spx_native_context_value;
  uint32_t i, iat_address;
  if (target_word == 0U) return 0U;
  if (iat_rva != 0U) {{
    if (iat_rva > context->image_size || context->image_size - iat_rva < 4U ||
        context->image_base > 0xffffffffU - iat_rva)
      return 0U;
    iat_address = context->image_base + iat_rva;
    if (spx_native_u32(iat_address) == target_word) return 1U;
  }}
  if (loader_target_index != 0U) {{
    if (loader_target_index > spx_native_loader_target_count) return 0U;
    return __atomic_load_n(
        &spx_native_loader_target_words[loader_target_index - 1U],
        __ATOMIC_ACQUIRE) == target_word;
  }}
  for (i = 0U; i < spx_native_loader_target_count; ++i)
    if (spx_native_loader_targets[i].iat_rva == iat_rva &&
        __atomic_load_n(&spx_native_loader_target_words[i],
                        __ATOMIC_ACQUIRE) == target_word)
      return 1U;
  return 0U;
}}

uint32_t spx_native_external_code_target_matches(
    uint32_t target_word, uint32_t iat_rva,
    uint32_t target_catalog_index) {{
  if ((target_catalog_index & SPX_NATIVE_INTERFACE_TARGET_TAG) != 0U)
    return iat_rva == 0U &&
        spx_native_interface_method_target_matches(
            target_word, target_catalog_index, 0U, 0U);
  return spx_native_loader_code_target_matches(
      target_word, iat_rva, target_catalog_index);
}}

spx_call_status spx_native_runtime_record_loader_service(
    uint32_t kind, uint32_t argument_base_offset,
    uint32_t argument_0, uint32_t argument_1, uint32_t nullable,
    const spx_external_call_snapshot *snapshot,
    const spx_machine_state *output) {{
  uint32_t first, second = 0U, i;
  if (kind == 0U) return SPX_CALL_OK;
  if (snapshot == 0 || output == 0 ||
      !spx_native_loader_argument(
          snapshot, argument_base_offset, argument_0, &first))
    return SPX_CALL_UNIMPLEMENTED;
  if (kind == 1U || kind == 2U) {{
    uint32_t matched = 0xffffffffU;
    if (first == 0U)
      return nullable != 0U ? SPX_CALL_OK : SPX_CALL_UNIMPLEMENTED;
    for (i = 0U; i < spx_native_loader_module_count; ++i) {{
      if (!spx_native_guest_module_name_matches(
              first, spx_native_loader_modules[i].dll, kind == 2U))
        continue;
      if (matched != 0xffffffffU) return SPX_CALL_UNIMPLEMENTED;
      matched = i;
    }}
    if (output->eax == 0U || matched == 0xffffffffU) return SPX_CALL_OK;
    {{
      uint32_t expected = 0U;
      if (!__atomic_compare_exchange_n(
              &spx_native_loader_module_handles[matched], &expected,
              output->eax, 0, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE) &&
          expected != output->eax)
        return SPX_CALL_UNIMPLEMENTED;
    }}
    return SPX_CALL_OK;
  }}
  if (kind == 3U) {{
    uint32_t module = 0xffffffffU, matches = 0U;
    if (!spx_native_loader_argument(
            snapshot, argument_base_offset, argument_1, &second))
      return SPX_CALL_UNIMPLEMENTED;
    for (i = 0U; i < spx_native_loader_module_count; ++i)
      if (__atomic_load_n(&spx_native_loader_module_handles[i],
                          __ATOMIC_ACQUIRE) == first) {{
        if (module != 0xffffffffU) return SPX_CALL_UNIMPLEMENTED;
        module = i;
      }}
    if (output->eax == 0U || module == 0xffffffffU) return SPX_CALL_OK;
    for (i = 0U; i < spx_native_loader_target_count; ++i) {{
      const spx_native_loader_target *target = &spx_native_loader_targets[i];
      uint32_t identity_matches;
      if (target->module_index != module) continue;
      identity_matches = second <= 0xffffU
          ? target->has_ordinal != 0U && target->ordinal == second
          : target->has_ordinal == 0U &&
              spx_native_guest_export_name_matches(second, target->symbol);
      if (identity_matches != 0U) ++matches;
    }}
    if (matches == 0U) return SPX_CALL_OK;
    for (i = 0U; i < spx_native_loader_target_count; ++i) {{
      const spx_native_loader_target *target = &spx_native_loader_targets[i];
      uint32_t identity_matches, expected = 0U;
      if (target->module_index != module) continue;
      identity_matches = second <= 0xffffU
          ? target->has_ordinal != 0U && target->ordinal == second
          : target->has_ordinal == 0U &&
              spx_native_guest_export_name_matches(second, target->symbol);
      if (identity_matches == 0U) continue;
      if (!__atomic_compare_exchange_n(
              &spx_native_loader_target_words[i], &expected, output->eax, 0,
              __ATOMIC_RELEASE, __ATOMIC_ACQUIRE) && expected != output->eax)
        return SPX_CALL_UNIMPLEMENTED;
    }}
    return SPX_CALL_OK;
  }}
  return SPX_CALL_UNIMPLEMENTED;
}}

static uint32_t spx_native_external_range_rule_matches(
    const spx_native_external_range_rule *rule,
    const spx_call_event *event) {{
  const spx_native_loader_target *narrowed_target;
  const spx_native_loader_module *narrowed_module;
  if (rule == 0 || event == 0 ||
      rule->instruction_rva != event->instruction_rva)
    return 0U;
  if (event->kind == SPX_CALL_INDIRECT && event->dll != 0) {{
    if (rule->target_catalog_index == 0U ||
        (rule->target_catalog_index & SPX_NATIVE_INTERFACE_TARGET_TAG) != 0U ||
        rule->target_catalog_index > spx_native_loader_target_count)
      return 0U;
    narrowed_target =
        &spx_native_loader_targets[rule->target_catalog_index - 1U];
    if (narrowed_target->module_index >= spx_native_loader_module_count)
      return 0U;
    narrowed_module =
        &spx_native_loader_modules[narrowed_target->module_index];
    if (!spx_native_ascii_text_matches(
            event->dll, narrowed_module->dll, UINT32_C(1)) ||
        event->has_ordinal != narrowed_target->has_ordinal)
      return 0U;
    if (event->has_ordinal != 0U) {{
      if (event->symbol != 0 || event->ordinal != narrowed_target->ordinal)
        return 0U;
    }} else if (event->symbol == 0 ||
               !spx_native_ascii_text_matches(
                   event->symbol, narrowed_target->symbol, UINT32_C(0))) {{
      return 0U;
    }}
  }}
  if (rule->target_iat_rva == 0U && rule->target_catalog_index == 0U)
    return 1U;
  if (event->kind != SPX_CALL_INDIRECT) return 0U;
  if ((rule->target_catalog_index & SPX_NATIVE_INTERFACE_TARGET_TAG) != 0U)
    return rule->target_iat_rva == 0U &&
        spx_native_interface_method_target_matches(
            event->target_rva, rule->target_catalog_index, 0U, 0U);
  return spx_native_loader_code_target_matches(
      event->target_rva, rule->target_iat_rva,
      rule->target_catalog_index);
}}

{range_release_source()}

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
  uint32_t i, found = 0U, exact_target_seen = 0U;
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
  snapshot->target_catalog_index = 0U;
  snapshot->argument_base_offset = 0U;
  snapshot->argument_count = 0U;
  /* A direct imported call has only its checked wildcard frame row.  An
   * indirect callable domain can also contain such a row beside exact
   * loader/interface target rows.  Once the observed target matches an exact
   * selector, the wildcard is not a competing target identity. */
  for (i = 0U; i < spx_native_external_range_rule_count; ++i) {{
    const spx_native_external_range_rule *rule =
        &spx_native_external_range_rules[i];
    if (rule->instruction_rva != event->instruction_rva ||
        (rule->target_iat_rva == 0U &&
         rule->target_catalog_index == 0U))
      continue;
    if (spx_native_external_range_rule_matches(rule, event)) {{
      exact_target_seen = 1U;
      break;
    }}
  }}
  for (i = 0U; i < spx_native_external_range_rule_count; ++i) {{
    const spx_native_external_range_rule *rule =
        &spx_native_external_range_rules[i];
    if (exact_target_seen != 0U && rule->target_iat_rva == 0U &&
        rule->target_catalog_index == 0U)
      continue;
    if (!spx_native_external_range_rule_matches(rule, event)) continue;
    if (found != 0U &&
        (snapshot->target_iat_rva != rule->target_iat_rva ||
         snapshot->target_catalog_index != rule->target_catalog_index)) {{
      spx_native_diagnostic_reason = 0x2008U;
      spx_native_diagnostic_value = event->target_rva;
      spx_native_diagnostic_aux = snapshot->target_iat_rva;
      spx_native_diagnostic_detail = rule->target_catalog_index;
      return SPX_CALL_UNIMPLEMENTED;
    }}
    snapshot->target_iat_rva = rule->target_iat_rva;
    snapshot->target_catalog_index = rule->target_catalog_index;
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
  if ((snapshot->target_catalog_index &
       SPX_NATIVE_INTERFACE_TARGET_TAG) != 0U) {{
    const spx_native_interface_method *method =
        spx_native_interface_method_for(snapshot->target_catalog_index);
    if (method == 0 || method->receiver_argument >= snapshot->argument_count ||
        !spx_native_interface_method_target_matches(
            event->target_rva, snapshot->target_catalog_index,
            snapshot->arguments[method->receiver_argument], 1U)) {{
      spx_native_diagnostic_reason = 0x200cU;
      spx_native_diagnostic_value = event->target_rva;
      spx_native_diagnostic_aux = method == 0
          ? 0U : method->receiver_argument;
      return SPX_CALL_UNIMPLEMENTED;
    }}
  }}
  return spx_native_validate_release_calls(event, snapshot);
}}

static uint32_t spx_native_external_argument(
    const spx_native_external_range_rule *rule,
    const spx_call_event *event,
    const spx_external_call_snapshot *snapshot,
    uint32_t index, uint32_t *value) {{
  if (rule == 0 || event == 0 || snapshot == 0 || value == 0 ||
      snapshot->instruction_rva != event->instruction_rva ||
      snapshot->target_iat_rva != rule->target_iat_rva ||
      snapshot->target_catalog_index != rule->target_catalog_index ||
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

{range_allocation_result_source()}
{allocation_lifetime_source()}static spx_call_status spx_native_add_external_range_for_rule(
    const spx_native_external_range_rule *rule,
    uint32_t start, uint32_t size) {{
  uint32_t external_range_rule_selector;
  uint64_t object_id = 0U;
  if (rule == 0 || rule < spx_native_external_range_rules ||
      rule >= spx_native_external_range_rules +
          spx_native_external_range_rule_count)
    return SPX_CALL_UNIMPLEMENTED;
  external_range_rule_selector =
      (uint32_t)(rule - spx_native_external_range_rules) + 1U;
  if (rule->object_rule_selector != 0U) {{
    const spx_native_object_authority_rule *object_rule;
    if (rule->object_rule_selector > spx_native_object_authority_rule_count)
      return SPX_CALL_UNIMPLEMENTED;
    object_rule = &spx_native_object_authority_rules[
        rule->object_rule_selector - 1U];
    if ((object_rule->locator_kind != 5U &&
         object_rule->locator_kind != 6U) ||
        rule->allocation_group_selector == 0U ||
        rule->allocation_group_selector > spx_native_external_range_rule_count ||
        object_rule->locator_subject_rva != rule->allocation_group_selector)
      return SPX_CALL_UNIMPLEMENTED;
    external_range_rule_selector = rule->allocation_group_selector;
    object_id = object_rule->object_id;
  }}
  return spx_native_add_external_range(
      start, size, rule->instruction_rva, rule->action,
      external_range_rule_selector, object_id);
}}

static spx_call_status spx_native_release_external_range(
    uint32_t start, uint32_t instruction_rva);

static const spx_native_external_range *spx_native_exact_external_range(
    uint32_t start) {{
  const spx_native_context *context = &spx_native_context_value;
  uint32_t i;
  for (i = 0U; i < context->external_range_count; ++i)
    if (context->external_ranges[i].start == start)
      return &context->external_ranges[i];
  return (const spx_native_external_range *)0;
}}

uint32_t spx_native_runtime_bind_interface_callback_argument(
    const char *profile_sha256, const char *interface_id,
    uint32_t object, uint32_t generation) {{
  spx_native_context *context = &spx_native_context_value;
  const spx_native_interface_class *class_contract = 0;
  const spx_native_external_range *range;
  uint32_t binding_kind = 2U, class_index, vtable, i;
  spx_call_status status;
  if (profile_sha256 == 0 || interface_id == 0 || object == 0U ||
      generation == 0U)
    return 0U;
  for (class_index = 0U;
       class_index < spx_native_interface_class_count; ++class_index) {{
    const spx_native_interface_class *candidate =
        &spx_native_interface_classes[class_index];
    if (spx_native_string_equal(
            candidate->profile_sha256, profile_sha256) &&
        spx_native_string_equal(candidate->interface_id, interface_id)) {{
      if (class_contract != 0) return 0U;
      class_contract = candidate;
    }}
  }}
  if (class_contract == 0 || class_contract->class_index == 0U ||
      class_contract->vtable_bytes == 0U)
    return 0U;
  for (i = 0U; i < context->interface_instance_count; ++i) {{
    const spx_native_interface_instance *instance =
        &context->interface_instances[i];
    if (instance->object != object) continue;
    return instance->class_index == class_contract->class_index ? 1U : 0U;
  }}
  range = spx_native_exact_external_range(object);
  if (range != 0) {{
    if (range->size < 4U) return 0U;
  }} else {{
    status = spx_native_add_external_range(object, 4U, 0U, 7U, 0U, 0U);
    if (status != SPX_CALL_OK) return 0U;
    binding_kind |= 4U;
  }}
  vtable = spx_native_u32(object);
  if (vtable == 0U) {{
    if ((binding_kind & 4U) != 0U)
      (void)spx_native_release_external_range(object, 0U);
    return 0U;
  }}
  range = spx_native_exact_external_range(vtable);
  if (range != 0) {{
    if (range->size < class_contract->vtable_bytes) {{
      if ((binding_kind & 4U) != 0U)
        (void)spx_native_release_external_range(object, 0U);
      return 0U;
    }}
  }} else {{
    status = spx_native_add_external_range(
        vtable, class_contract->vtable_bytes, 0U, 7U, 0U, 0U);
    if (status != SPX_CALL_OK) {{
      if ((binding_kind & 4U) != 0U)
        (void)spx_native_release_external_range(object, 0U);
      return 0U;
    }}
    binding_kind |= 8U;
  }}
  if (context->interface_instance_count ==
      SPX_NATIVE_MAX_INTERFACE_INSTANCES) {{
    if ((binding_kind & 8U) != 0U)
      (void)spx_native_release_external_range(vtable, 0U);
    if ((binding_kind & 4U) != 0U)
      (void)spx_native_release_external_range(object, 0U);
    return 0U;
  }}
  context->interface_instances[context->interface_instance_count].class_index =
      class_contract->class_index;
  context->interface_instances[context->interface_instance_count].object = object;
  context->interface_instances[context->interface_instance_count].vtable = vtable;
  context->interface_instances[
      context->interface_instance_count].generation = generation;
  ++context->interface_instance_count;
  return binding_kind;
}}

uint32_t spx_native_runtime_unbind_interface_callback_argument(
    const char *profile_sha256, const char *interface_id,
    uint32_t object, uint32_t generation, uint32_t binding_kind) {{
  spx_native_context *context = &spx_native_context_value;
  const spx_native_interface_class *class_contract = 0;
  uint32_t class_index, i, vtable;
  spx_call_status status = SPX_CALL_OK;
  if (binding_kind == 1U) return 1U;
  if ((binding_kind & 3U) != 2U || (binding_kind & ~15U) != 0U ||
      profile_sha256 == 0 || interface_id == 0 || object == 0U ||
      generation == 0U)
    return 0U;
  for (class_index = 0U;
       class_index < spx_native_interface_class_count; ++class_index) {{
    const spx_native_interface_class *candidate =
        &spx_native_interface_classes[class_index];
    if (spx_native_string_equal(
            candidate->profile_sha256, profile_sha256) &&
        spx_native_string_equal(candidate->interface_id, interface_id)) {{
      if (class_contract != 0) return 0U;
      class_contract = candidate;
    }}
  }}
  if (class_contract == 0) return 0U;
  for (i = 0U; i < context->interface_instance_count; ++i) {{
    spx_native_interface_instance *instance =
        &context->interface_instances[i];
    if (instance->object != object || instance->generation != generation ||
        instance->class_index != class_contract->class_index)
      continue;
    vtable = instance->vtable;
    --context->interface_instance_count;
    context->interface_instances[i] =
        context->interface_instances[context->interface_instance_count];
    if ((binding_kind & 8U) != 0U)
      status = spx_native_release_external_range(vtable, 0U);
    if ((binding_kind & 4U) != 0U &&
        spx_native_release_external_range(object, 0U) != SPX_CALL_OK)
      status = SPX_CALL_UNIMPLEMENTED;
    return status == SPX_CALL_OK ? 1U : 0U;
  }}
  return 0U;
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
      return spx_native_add_external_range_for_rule(
          rule, vector, (index + 1U) * 4U);
    }}
    if (!spx_native_terminated_extent(
            element, rule->element_unit_bytes, rule->element_max_units,
            &extent))
      return SPX_CALL_UNIMPLEMENTED;
    status = spx_native_add_external_range_for_rule(
        rule, element, extent);
    if (status != SPX_CALL_OK) return status;
  }}
  return SPX_CALL_UNIMPLEMENTED;
}}

static spx_call_status spx_native_add_external_interface_ranges(
    const spx_native_external_range_rule *rule, uint32_t cell) {{
  spx_native_context *context = &spx_native_context_value;
  uint32_t object, vtable, i, generation;
  spx_call_status status;
  if (rule == 0 || cell == 0U ||
      cell > 0xffffffffU - rule->pointee_offset)
    return SPX_CALL_UNIMPLEMENTED;
  object = spx_native_u32(cell + rule->pointee_offset);
  if (object == 0U)
    return rule->nullable != 0U
        ? SPX_CALL_OK : SPX_CALL_UNIMPLEMENTED;
  status = spx_native_add_external_range_for_rule(
      rule, object, rule->minimum_size);
  if (status != SPX_CALL_OK) return status;
  vtable = spx_native_u32(object);
  if (vtable == 0U) return SPX_CALL_UNIMPLEMENTED;
  status = spx_native_add_external_range_for_rule(
      rule, vtable, rule->size_value);
  if (status != SPX_CALL_OK || rule->interface_class_index == 0U)
    return status;
  if (rule->interface_class_index > spx_native_interface_class_count ||
      spx_native_interface_classes[
          rule->interface_class_index - 1U].class_index !=
              rule->interface_class_index)
    return SPX_CALL_UNIMPLEMENTED;
  generation = context->external_lifecycle_sequence;
  if (generation == 0U) generation = 1U;
  for (i = 0U; i < context->interface_instance_count; ++i) {{
    spx_native_interface_instance *instance =
        &context->interface_instances[i];
    if (instance->object != object) continue;
    if (instance->class_index != rule->interface_class_index ||
        instance->vtable != vtable)
      return SPX_CALL_UNIMPLEMENTED;
    instance->generation = generation;
    return SPX_CALL_OK;
  }}
  if (context->interface_instance_count ==
      SPX_NATIVE_MAX_INTERFACE_INSTANCES)
    return SPX_CALL_UNIMPLEMENTED;
  context->interface_instances[context->interface_instance_count].class_index =
      rule->interface_class_index;
  context->interface_instances[context->interface_instance_count].object = object;
  context->interface_instances[context->interface_instance_count].vtable = vtable;
  context->interface_instances[
      context->interface_instance_count].generation = generation;
  ++context->interface_instance_count;
  return SPX_CALL_OK;
}}

static spx_call_status spx_native_apply_interface_receiver_lifecycle(
    const spx_call_event *event,
    const spx_external_call_snapshot *snapshot,
    const spx_machine_state *output) {{
  spx_native_context *context = &spx_native_context_value;
  const spx_native_interface_method *method;
  uint32_t object, i;
  if ((snapshot->target_catalog_index &
       SPX_NATIVE_INTERFACE_TARGET_TAG) == 0U)
    return SPX_CALL_OK;
  method = spx_native_interface_method_for(snapshot->target_catalog_index);
  if (method == 0 || method->receiver_argument >= snapshot->argument_count)
    return SPX_CALL_UNIMPLEMENTED;
  if (method->lifecycle_effect == 0U ||
      (method->lifecycle_effect == 1U && output->eax != 0U))
    return SPX_CALL_OK;
  if (method->lifecycle_effect > 2U) return SPX_CALL_UNIMPLEMENTED;
  object = snapshot->arguments[method->receiver_argument];
  for (i = 0U; i < context->interface_instance_count; ++i) {{
    if (context->interface_instances[i].object != object ||
        context->interface_instances[i].class_index != method->class_index)
      continue;
    --context->interface_instance_count;
    context->interface_instances[i] =
        context->interface_instances[context->interface_instance_count];
    return spx_native_release_external_range(
        object, event->instruction_rva);
  }}
  return SPX_CALL_UNIMPLEMENTED;
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
  if (spx_native_apply_interface_receiver_lifecycle(
          event, snapshot, output) != SPX_CALL_OK) {{
    spx_native_diagnostic_reason = 0x200dU;
    return SPX_CALL_UNIMPLEMENTED;
  }}
  for (i = 0U; i < spx_native_external_range_rule_count; ++i) {{
    const spx_native_external_range_rule *rule =
        &spx_native_external_range_rules[i];
    spx_call_status status;
    uint32_t pointer = 0U;
    if (!spx_native_external_range_rule_matches(rule, event) ||
        rule->target_iat_rva != snapshot->target_iat_rva ||
        rule->target_catalog_index != snapshot->target_catalog_index)
      continue;
    if (rule->action == 0U) {{
      continue;
    }} else if (rule->action == 1U) {{
      status = spx_native_record_range_allocation(rule, event, snapshot, output);
    }} else if (rule->action == 2U) {{
      status = spx_native_apply_range_release(rule, event, snapshot, output);
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
      !spx_native_range_end(address, width, &end)) {{
    spx_native_diagnostic_reason = 0x3001U;
    spx_native_diagnostic_value = address;
    spx_native_diagnose_external_range(context, address);
    return 0U;
  }}
  if (context->owner_fs_base > 0xfffffffbU) {{
    spx_native_diagnostic_reason = 0x3004U;
    spx_native_diagnostic_value = context->owner_fs_base;
    return 0U;
  }}
  if (context->owner_fs_base != 0U &&
      address < context->owner_fs_base + 4U &&
      context->owner_fs_base < end) {{
    if (address == context->owner_fs_base && width == 4U) {{
      *fault = 0U;
      return context->guest_seh_head;
    }}
    spx_native_diagnostic_reason = 0x3004U;
    spx_native_diagnostic_value = address;
    return 0U;
  }}
  if (!spx_native_read_allowed(address, width)) {{
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
  uint32_t end, i;
  spx_native_context *context = (spx_native_context *)opaque;
  if (fault == 0) return;
  *fault = 1U;
  if (context == 0 || context->initialized == 0U ||
      (width != 1U && width != 2U && width != 4U) ||
      !spx_native_range_end(address, width, &end)) {{
    spx_native_diagnostic_reason = 0x3002U;
    spx_native_diagnostic_value = address;
    spx_native_diagnose_external_range(context, address);
    return;
  }}
  if (context->owner_fs_base > 0xfffffffbU) {{
    spx_native_diagnostic_reason = 0x3005U;
    spx_native_diagnostic_value = context->owner_fs_base;
    return;
  }}
  if (context->owner_fs_base != 0U &&
      address < context->owner_fs_base + 4U &&
      context->owner_fs_base < end) {{
    if (address == context->owner_fs_base && width == 4U) {{
      context->guest_seh_head = value;
      *fault = 0U;
      return;
    }}
    spx_native_diagnostic_reason = 0x3005U;
    spx_native_diagnostic_value = address;
    return;
  }}
  if (!spx_native_write_allowed(address, width)) {{
    spx_native_diagnostic_reason = 0x3002U;
    spx_native_diagnostic_value = address;
    spx_native_diagnose_external_range(context, address);
    return;
  }}
  p = (volatile uint8_t *)(uintptr_t)address;
  for (i = 0U; i < width; ++i) p[i] = (uint8_t)(value >> (i * 8U));
  *fault = 0U;
}}

static uint32_t spx_native_record_access_violation(
    void *opaque, uint32_t operation, uint32_t address) {{
  spx_native_context *context = (spx_native_context *)opaque;
  if (context == 0 || context->initialized == 0U ||
      (operation != 0U && operation != 1U && operation != 8U))
    return 0U;
  spx_native_diagnostic_reason = 0x3003U;
  spx_native_diagnostic_value = address;
  spx_native_diagnostic_aux = operation;
  spx_native_diagnostic_detail = 0U;
  return 1U;
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
    spx_runtime *runtime, spx_code_site_kind site_kind,
    uint32_t source_rva, uint32_t instruction_rva, uint32_t event_index,
    uint32_t target_word, uint32_t *target_rva) {{
  spx_native_context *context;
  uint32_t rva, site_index;
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
  for (site_index = 0U;
       site_index < spx_native_guest_dispatch_site_count; ++site_index) {{
    const spx_native_guest_dispatch_site *site =
        &spx_native_guest_dispatch_sites[site_index];
    uint32_t low, high;
    if (site->kind != (uint32_t)site_kind ||
        site->source_rva != source_rva ||
        site->instruction_rva != instruction_rva ||
        site->event_index != event_index ||
        site->target_offset > spx_native_guest_dispatch_target_count ||
        site->target_count >
            spx_native_guest_dispatch_target_count - site->target_offset)
      continue;
    low = site->target_offset;
    high = low + site->target_count;
    while (low < high) {{
      uint32_t middle = low + (high - low) / 2U;
      if (spx_native_guest_dispatch_targets[middle] < rva)
        low = middle + 1U;
      else
        high = middle;
    }}
    if (low < site->target_offset + site->target_count &&
        spx_native_guest_dispatch_targets[low] == rva &&
        spx_behavioral_has_unit(rva)) {{
      *target_rva = rva;
      return 0U;
    }}
    return 1U;
  }}
  return 1U;
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
  spx_native_context *context = &spx_native_context_value;
  uint32_t site_index;
  if (runtime == 0 || runtime->context != context ||
      context->initialized == 0U || input == 0 || output == 0)
    return SPX_CALL_UNIMPLEMENTED;
  for (site_index = 0U;
       site_index < spx_native_guest_dispatch_site_count; ++site_index) {{
    const spx_native_guest_dispatch_site *site =
        &spx_native_guest_dispatch_sites[site_index];
    spx_call_event event = {{0}};
    uint32_t target_index, matched = 0U;
    if (site->kind != (uint32_t)SPX_CODE_SITE_INDIRECT_JUMP ||
        site->source_rva != source_rva)
      continue;
    if (site->external_target_offset >
            spx_native_guest_dispatch_external_iat_count ||
        site->external_target_count >
            spx_native_guest_dispatch_external_iat_count -
                site->external_target_offset ||
        site->external_target_offset >
            spx_native_guest_dispatch_external_catalog_index_count ||
        site->external_target_count >
            spx_native_guest_dispatch_external_catalog_index_count -
                site->external_target_offset)
      return SPX_CALL_UNIMPLEMENTED;
    for (target_index = 0U;
         target_index < site->external_target_count; ++target_index) {{
      const uint32_t iat_rva = spx_native_guest_dispatch_external_iats[
          site->external_target_offset + target_index];
      const uint32_t loader_target_index =
          spx_native_guest_dispatch_external_catalog_indexes[
              site->external_target_offset + target_index];
      if ((iat_rva != 0U && iat_rva > context->image_size) ||
          (iat_rva != 0U && context->image_size - iat_rva < 4U) ||
          (iat_rva != 0U && context->image_base > 0xffffffffU - iat_rva) ||
          loader_target_index == 0U)
        return SPX_CALL_UNIMPLEMENTED;
      if ((loader_target_index & SPX_NATIVE_INTERFACE_TARGET_TAG) != 0U) {{
        if (iat_rva != 0U) return SPX_CALL_UNIMPLEMENTED;
        if (spx_native_interface_method_target_matches(
                target_word, loader_target_index, 0U, 0U))
          matched = 1U;
      }} else if (spx_native_loader_code_target_matches(
                     target_word, iat_rva, loader_target_index)) {{
        matched = 1U;
      }}
    }}
    if (matched == 0U) return SPX_CALL_UNIMPLEMENTED;
    event.kind = SPX_CALL_INDIRECT;
    event.source_rva = source_rva;
    event.instruction_rva = site->instruction_rva;
    event.call_index = site->event_index;
    event.target_rva = target_word;
    *output = *input;
    return spx_dispatch_external_call(runtime, &event, input, output);
  }}
  return SPX_CALL_UNIMPLEMENTED;
}}

static uint32_t spx_native_object_rule_base(
    const spx_native_context *context,
    const spx_native_object_authority_rule *rule, uint32_t *base,
    uint64_t *generation) {{
  uint32_t candidate, available, dynamic_generation;
  if (context == 0 || rule == 0 || base == 0 || generation == 0 ||
      rule->extent == 0U)
    return 0U;
  if (rule->locator_kind == 1U) {{
    if (rule->locator_offset > context->image_size ||
        rule->extent > context->image_size - rule->locator_offset ||
        context->image_base > 0xffffffffU - rule->locator_offset)
      return 0U;
    candidate = context->image_base + rule->locator_offset;
  }} else if (rule->locator_kind == 2U) {{
    uint8_t *tls = (uint8_t *)spx_native_module_tls_base_current();
    if (tls == 0 || rule->locator_offset > spx_native_tls_total_bytes ||
        rule->extent > spx_native_tls_total_bytes - rule->locator_offset)
      return 0U;
    candidate = (uint32_t)(uintptr_t)tls;
    if (candidate > 0xffffffffU - rule->locator_offset) return 0U;
    candidate += rule->locator_offset;
  }} else if (rule->locator_kind == 3U) {{
    uint32_t iat_address;
    if (rule->locator_subject_rva == 0U || context->image_size < 4U ||
        rule->locator_subject_rva > context->image_size - 4U ||
        context->image_base > 0xffffffffU - rule->locator_subject_rva)
      return 0U;
    iat_address = context->image_base + rule->locator_subject_rva;
    candidate = spx_native_u32(iat_address);
    if (candidate == 0U || candidate > 0xffffffffU - rule->locator_offset)
      return 0U;
    candidate += rule->locator_offset;
  }} else if (rule->locator_kind == 4U) {{
    if (!spx_native_captured_stack_rule_base(
            rule->locator_subject_rva, rule->locator_offset, rule->extent,
            &candidate, &dynamic_generation))
      return 0U;
  }} else {{
    return 0U;
  }}
  available = 0xffffffffU - candidate;
  if (rule->extent > available) return 0U;
  *base = candidate;
  *generation = rule->locator_kind == 4U
      ? (uint64_t)dynamic_generation : rule->generation;
  return 1U;
}}

{reference_namespace_source()}static const spx_native_interface_class *spx_native_exact_interface_class(
    const char *profile_sha256, const char *interface_id) {{
  const spx_native_interface_class *result = 0;
  uint32_t i;
  if (profile_sha256 == 0 || interface_id == 0) return 0;
  for (i = 0U; i < spx_native_interface_class_count; ++i) {{
    const spx_native_interface_class *candidate =
        &spx_native_interface_classes[i];
    if (!spx_native_string_equal(candidate->profile_sha256, profile_sha256) ||
        !spx_native_string_equal(candidate->interface_id, interface_id))
      continue;
    if (result != 0) return 0;
    result = candidate;
  }}
  return result;
}}

static spx_boundary_status spx_native_resolve_interface_resource(
    void *opaque, const char *profile_sha256, const char *interface_id,
    uint32_t physical_word, uint32_t nullable,
    spx_machine_resource_v1 *result) {{
  spx_native_context *context = (spx_native_context *)opaque;
  const spx_native_interface_class *class_contract;
  const spx_native_interface_instance *selected = 0;
  uint32_t i, count = 0U;
  if (context == 0 || result == 0) return SPX_BOUNDARY_UNSUPPORTED;
  if (physical_word == 0U) {{
    if (nullable == 0U) return SPX_BOUNDARY_MEMORY_FAULT;
    result->type_tag = result->generation = 0U;
    result->identity = 0U;
    return SPX_BOUNDARY_OK;
  }}
  class_contract = spx_native_exact_interface_class(
      profile_sha256, interface_id);
  if (class_contract == 0) return SPX_BOUNDARY_TYPE_MISMATCH;
  for (i = 0U; i < context->interface_instance_count; ++i) {{
    const spx_native_interface_instance *instance =
        &context->interface_instances[i];
    if (instance->class_index != class_contract->class_index ||
        instance->object != physical_word || instance->generation == 0U)
      continue;
    ++count;
    selected = instance;
  }}
  if (count == 0U) return SPX_BOUNDARY_EXPIRED;
  if (count != 1U) return SPX_BOUNDARY_TYPE_MISMATCH;
  result->type_tag = selected->class_index;
  result->generation = selected->generation;
  result->identity = selected->object;
  return SPX_BOUNDARY_OK;
}}

static spx_boundary_status spx_native_realize_interface_resource(
    void *opaque, const char *profile_sha256, const char *interface_id,
    const spx_machine_resource_v1 *resource, uint32_t nullable,
    uint32_t *physical_word) {{
  spx_native_context *context = (spx_native_context *)opaque;
  const spx_native_interface_class *class_contract;
  uint32_t i, count = 0U;
  if (context == 0 || resource == 0 || physical_word == 0)
    return SPX_BOUNDARY_UNSUPPORTED;
  if (resource->identity == 0U) {{
    if (nullable == 0U || resource->type_tag != 0U ||
        resource->generation != 0U)
      return SPX_BOUNDARY_MEMORY_FAULT;
    *physical_word = 0U;
    return SPX_BOUNDARY_OK;
  }}
  if (resource->identity > UINT32_MAX)
    return SPX_BOUNDARY_TYPE_MISMATCH;
  class_contract = spx_native_exact_interface_class(
      profile_sha256, interface_id);
  if (class_contract == 0 || resource->type_tag != class_contract->class_index)
    return SPX_BOUNDARY_TYPE_MISMATCH;
  for (i = 0U; i < context->interface_instance_count; ++i) {{
    const spx_native_interface_instance *instance =
        &context->interface_instances[i];
    if (instance->class_index != class_contract->class_index ||
        instance->object != (uint32_t)resource->identity ||
        instance->generation != resource->generation ||
        instance->generation == 0U)
      continue;
    ++count;
  }}
  if (count == 0U) return SPX_BOUNDARY_EXPIRED;
  if (count != 1U) return SPX_BOUNDARY_TYPE_MISMATCH;
  *physical_word = (uint32_t)resource->identity;
  return SPX_BOUNDARY_OK;
}}

/* One bounded transaction for the closed Win32 EXCEPTION_POINTERS view.
 * The root is read-only; the EXCEPTION_RECORD chain and x86 CONTEXT are
 * read/write referents for exactly the duration of the checked host call. */
#define SPX_NATIVE_EXCEPTION_SNAPSHOT_MAGIC 0x53505845U
typedef struct spx_native_exception_snapshot {{
  uint32_t magic, root, record_count, context;
  uint32_t record_addresses[SPX_NATIVE_EXCEPTION_RECORD_LIMIT];
  uint8_t record_bytes[SPX_NATIVE_EXCEPTION_RECORD_LIMIT]
      [SPX_NATIVE_EXCEPTION_RECORD_BYTES];
  uint8_t context_bytes[SPX_NATIVE_X86_CONTEXT_BYTES];
}} spx_native_exception_snapshot;

_Static_assert(sizeof(spx_native_exception_snapshot) <=
    SPX_NATIVE_EXCEPTION_OBJECT_SNAPSHOT_BYTES,
    "checked exception-object snapshot capacity is stale");

static void spx_native_copy_from_volatile(
    uint8_t *target, uint32_t source, uint32_t count) {{
  const volatile uint8_t *bytes =
      (const volatile uint8_t *)(uintptr_t)source;
  uint32_t index;
  for (index = 0U; index < count; ++index) target[index] = bytes[index];
}}

static void spx_native_copy_to_volatile(
    uint32_t target, const uint8_t *source, uint32_t count) {{
  volatile uint8_t *bytes = (volatile uint8_t *)(uintptr_t)target;
  uint32_t index;
  for (index = 0U; index < count; ++index) bytes[index] = source[index];
}}

static spx_call_status spx_native_inspect_exception_object(
    uint32_t root, uint32_t *record_addresses, uint32_t *record_count,
    uint32_t *context_address) {{
  uint32_t record, context, count = 0U, index;
  if (root == 0U || (root & 3U) != 0U || record_addresses == 0 ||
      record_count == 0 || context_address == 0 ||
      !spx_native_read_allowed(root, 8U))
    return SPX_CALL_MEMORY_FAULT;
  record = spx_native_u32(root);
  context = spx_native_u32(root + 4U);
  if (record == 0U || context == 0U || (record & 3U) != 0U ||
      (context & 3U) != 0U ||
      !spx_native_read_allowed(context, SPX_NATIVE_X86_CONTEXT_BYTES) ||
      !spx_native_write_allowed(context, SPX_NATIVE_X86_CONTEXT_BYTES))
    return SPX_CALL_MEMORY_FAULT;
  while (record != 0U) {{
    if (count >= SPX_NATIVE_EXCEPTION_RECORD_LIMIT ||
        !spx_native_read_allowed(record, SPX_NATIVE_EXCEPTION_RECORD_BYTES) ||
        !spx_native_write_allowed(record, SPX_NATIVE_EXCEPTION_RECORD_BYTES) ||
        spx_native_u32(record + 16U) > 15U)
      return SPX_CALL_MEMORY_FAULT;
    for (index = 0U; index < count; ++index)
      if (record_addresses[index] == record)
        return SPX_CALL_UNIMPLEMENTED;
    record_addresses[count++] = record;
    record = spx_native_u32(record + 8U);
  }}
  *record_count = count;
  *context_address = context;
  return SPX_CALL_OK;
}}

static spx_call_status spx_native_restore_exception_object(
    spx_native_exception_snapshot *snapshot) {{
  uint32_t index;
  if (snapshot == 0 || snapshot->magic != SPX_NATIVE_EXCEPTION_SNAPSHOT_MAGIC ||
      snapshot->record_count == 0U ||
      snapshot->record_count > SPX_NATIVE_EXCEPTION_RECORD_LIMIT ||
      !spx_native_write_allowed(
          snapshot->context, SPX_NATIVE_X86_CONTEXT_BYTES))
    return SPX_CALL_MEMORY_FAULT;
  for (index = 0U; index < snapshot->record_count; ++index)
    if (!spx_native_write_allowed(
            snapshot->record_addresses[index],
            SPX_NATIVE_EXCEPTION_RECORD_BYTES))
      return SPX_CALL_MEMORY_FAULT;
  for (index = 0U; index < snapshot->record_count; ++index)
    spx_native_copy_to_volatile(
        snapshot->record_addresses[index], snapshot->record_bytes[index],
        SPX_NATIVE_EXCEPTION_RECORD_BYTES);
  spx_native_copy_to_volatile(
      snapshot->context, snapshot->context_bytes,
      SPX_NATIVE_X86_CONTEXT_BYTES);
  snapshot->magic = 0U;
  return SPX_CALL_OK;
}}

spx_call_status spx_native_runtime_begin_exception_object(
    uint32_t exception_pointers, void *snapshot_value, uint32_t capacity,
    uint32_t *snapshot_size) {{
  spx_native_exception_snapshot *snapshot =
      (spx_native_exception_snapshot *)snapshot_value;
  spx_native_context *context = &spx_native_context_value;
  spx_call_status status;
  uint32_t index;
  if (snapshot == 0 || snapshot_size == 0 ||
      capacity < sizeof(*snapshot) || context->exception_service_active != 0U)
    return SPX_CALL_UNIMPLEMENTED;
  snapshot->magic = 0U;
  snapshot->root = exception_pointers;
  status = spx_native_inspect_exception_object(
      exception_pointers, snapshot->record_addresses,
      &snapshot->record_count, &snapshot->context);
  if (status != SPX_CALL_OK) return status;
  for (index = 0U; index < snapshot->record_count; ++index)
    spx_native_copy_from_volatile(
        snapshot->record_bytes[index], snapshot->record_addresses[index],
        SPX_NATIVE_EXCEPTION_RECORD_BYTES);
  spx_native_copy_from_volatile(
      snapshot->context_bytes, snapshot->context,
      SPX_NATIVE_X86_CONTEXT_BYTES);
  context->exception_service_root = snapshot->root;
  context->exception_service_record_count = snapshot->record_count;
  for (index = 0U; index < snapshot->record_count; ++index)
    context->exception_service_records[index] = snapshot->record_addresses[index];
  context->exception_service_context = snapshot->context;
  context->exception_callback_bound = 0U;
  context->exception_callback_root = 0U;
  context->exception_service_active = 1U;
  snapshot->magic = SPX_NATIVE_EXCEPTION_SNAPSHOT_MAGIC;
  *snapshot_size = (uint32_t)sizeof(*snapshot);
  return SPX_CALL_OK;
}}

spx_call_status spx_native_runtime_finish_exception_object(
    uint32_t exception_pointers, void *snapshot_value,
    uint32_t snapshot_size, uint32_t commit) {{
  spx_native_exception_snapshot *snapshot =
      (spx_native_exception_snapshot *)snapshot_value;
  spx_native_context *native_context = &spx_native_context_value;
  uint32_t records[SPX_NATIVE_EXCEPTION_RECORD_LIMIT];
  uint32_t count = 0U, context = 0U, index;
  spx_call_status status;
  if (native_context->exception_service_active == 0U ||
      native_context->exception_service_root != exception_pointers)
    return SPX_CALL_UNIMPLEMENTED;
  if (snapshot == 0 || snapshot_size != sizeof(*snapshot) ||
      snapshot->magic != SPX_NATIVE_EXCEPTION_SNAPSHOT_MAGIC ||
      snapshot->root != exception_pointers || commit > 1U) {{
    native_context->exception_service_active = 0U;
    native_context->exception_callback_bound = 0U;
    return SPX_CALL_UNIMPLEMENTED;
  }}
  if (commit == 0U) {{
    status = spx_native_restore_exception_object(snapshot);
    native_context->exception_service_active = 0U;
    native_context->exception_callback_bound = 0U;
    return status;
  }}
  status = spx_native_inspect_exception_object(
      exception_pointers, records, &count, &context);
  if (status == SPX_CALL_OK && count == snapshot->record_count &&
      context == snapshot->context) {{
    for (index = 0U; index < count; ++index)
      if (records[index] != snapshot->record_addresses[index]) break;
    if (index == count) {{
      snapshot->magic = 0U;
      native_context->exception_service_active = 0U;
      native_context->exception_callback_bound = 0U;
      return SPX_CALL_OK;
    }}
  }}
  (void)spx_native_restore_exception_object(snapshot);
  native_context->exception_service_active = 0U;
  native_context->exception_callback_bound = 0U;
  return status == SPX_CALL_OK ? SPX_CALL_UNIMPLEMENTED : status;
}}

spx_call_status spx_native_runtime_bind_exception_filter_callback(
    uint32_t exception_pointers) {{
  spx_native_context *context = &spx_native_context_value;
  uint32_t record, x86_context;
  if (context->exception_service_active == 0U ||
      context->exception_callback_bound != 0U ||
      context->exception_service_record_count == 0U ||
      exception_pointers == 0U || (exception_pointers & 3U) != 0U)
    return SPX_CALL_UNIMPLEMENTED;
  /* Physical stack validation and the native SEH gateway protect this exact
   * two-word import before semantic memory authority admits it. */
  record = spx_native_u32(exception_pointers);
  x86_context = spx_native_u32(exception_pointers + 4U);
  if (record != context->exception_service_records[0] ||
      x86_context != context->exception_service_context)
    return SPX_CALL_EXTERNAL_FAULT;
  context->exception_callback_root = exception_pointers;
  context->exception_callback_bound = 1U;
  return SPX_CALL_OK;
}}

uint32_t spx_native_runtime_exception_filter_callback_expected(void) {{
  return spx_native_context_value.exception_service_active != 0U ? 1U : 0U;
}}

void spx_native_runtime_reset_guest_seh_chain(void) {{
  spx_native_context_value.guest_seh_head = 0xffffffffU;
}}

uint32_t spx_native_runtime_guest_seh_chain_head(uint32_t *head) {{
  if (head == 0) return 0U;
  *head = spx_native_context_value.guest_seh_head;
  return 1U;
}}

uint32_t spx_native_runtime_set_guest_seh_chain_head(uint32_t head) {{
  spx_native_context_value.guest_seh_head = head;
  return 1U;
}}

spx_call_status spx_native_runtime_unbind_exception_filter_callback(
    uint32_t exception_pointers) {{
  spx_native_context *context = &spx_native_context_value;
  if (context->exception_service_active == 0U ||
      context->exception_callback_bound == 0U ||
      context->exception_callback_root != exception_pointers)
    return SPX_CALL_UNIMPLEMENTED;
  context->exception_callback_bound = 0U;
  context->exception_callback_root = 0U;
  return SPX_CALL_OK;
}}

spx_call_status spx_native_runtime_bind_unwind_handler_objects(
    uint32_t record_base, uint32_t record_count,
    uint32_t context_value, uint32_t handler_frame) {{
  spx_native_context *context = &spx_native_context_value;
  uint32_t record_bytes;
  if (context->initialized == 0U || context->unwind_service_active == 0U ||
      context->unwind_handler_bound != 0U || record_base == 0U ||
      context_value == 0U || handler_frame == 0U ||
      record_count == 0U ||
      record_count > SPX_NATIVE_EXCEPTION_RECORD_LIMIT)
    return SPX_CALL_UNIMPLEMENTED;
  record_bytes = record_count * SPX_NATIVE_EXCEPTION_RECORD_BYTES;
  if (record_base > 0xffffffffU - record_bytes ||
      context_value > 0xffffffffU - SPX_NATIVE_X86_CONTEXT_BYTES ||
      handler_frame > 0xffffffffU - 20U)
    return SPX_CALL_UNIMPLEMENTED;
  context->unwind_handler_record_base = record_base;
  context->unwind_handler_record_count = record_count;
  context->unwind_handler_context = context_value;
  context->unwind_handler_frame = handler_frame;
  context->unwind_handler_bound = 1U;
  return SPX_CALL_OK;
}}

spx_call_status spx_native_runtime_unbind_unwind_handler_objects(
    uint32_t record_base, uint32_t record_count,
    uint32_t context_value, uint32_t handler_frame) {{
  spx_native_context *context = &spx_native_context_value;
  if (context->unwind_handler_bound == 0U ||
      context->unwind_handler_record_base != record_base ||
      context->unwind_handler_record_count != record_count ||
      context->unwind_handler_context != context_value ||
      context->unwind_handler_frame != handler_frame)
    return SPX_CALL_UNIMPLEMENTED;
  context->unwind_handler_bound = 0U;
  context->unwind_handler_record_base = 0U;
  context->unwind_handler_record_count = 0U;
  context->unwind_handler_context = 0U;
  context->unwind_handler_frame = 0U;
  return SPX_CALL_OK;
}}

spx_call_status spx_native_runtime_begin_checked_unwind(
    uint32_t source_rva, uint32_t target_frame,
    uint32_t target_instruction, uint32_t exception_record,
    uint32_t return_value, const spx_machine_state *input,
    spx_machine_state *output) {{
  spx_native_context *context = &spx_native_context_value;
  uint32_t target_rva, target_owner, current, depth, prior;
  uint32_t visited[SPX_NATIVE_EXCEPTION_RECORD_LIMIT];
  if (context->initialized == 0U || context->nonlocal_active != 0U ||
      context->unwind_service_active != 0U || input == 0 || output == 0 ||
      context->image_base == 0U || target_instruction < context->image_base)
    return SPX_CALL_UNIMPLEMENTED;
  target_rva = target_instruction - context->image_base;
  if (!spx_behavioral_function_owner(target_rva, &target_owner) ||
      !spx_native_checked_unwind_inspect(
          target_frame, &context->unwind_snapshot))
    return SPX_CALL_UNIMPLEMENTED;
  context->unwind_exception_record_count = 0U;
  if (exception_record == 0U) {{
    for (prior = 0U; prior < 20U; ++prior)
      context->unwind_exception_records[0][prior] = 0U;
    context->unwind_exception_records[0][0] = 0xc0000027U;
    context->unwind_exception_records[0][3] = target_instruction;
    context->unwind_exception_record_count = 1U;
  }} else {{
    current = exception_record;
    for (depth = 0U; depth < SPX_NATIVE_EXCEPTION_RECORD_LIMIT; ++depth) {{
      if (current == 0U || (current & 3U) != 0U ||
          !spx_native_read_allowed(
              current, SPX_NATIVE_EXCEPTION_RECORD_BYTES))
        return SPX_CALL_MEMORY_FAULT;
      for (prior = 0U; prior < depth; ++prior)
        if (visited[prior] == current)
          return SPX_CALL_UNIMPLEMENTED;
      visited[depth] = current;
      spx_native_copy_from_volatile(
          (uint8_t *)(void *)context->unwind_exception_records[depth], current,
          SPX_NATIVE_EXCEPTION_RECORD_BYTES);
      current = context->unwind_exception_records[depth][2];
      ++context->unwind_exception_record_count;
      if (current == 0U) break;
    }}
    if (current != 0U) return SPX_CALL_UNIMPLEMENTED;
  }}
  if (input->esp > 0xffffffffU - 16U)
    return SPX_CALL_UNIMPLEMENTED;
  *output = *input;
  output->eax = return_value;
  output->esp = input->esp + 16U;
  context->nonlocal_active = 1U;
  context->nonlocal_source_rva = source_rva;
  context->nonlocal_target_rva = target_rva;
  context->nonlocal_value = return_value;
  context->nonlocal_target_function_entry_rva = target_owner;
  context->unwind_service_active = 1U;
  return SPX_CALL_NONLOCAL;
}}

static uint32_t spx_native_route_nonlocal(
    spx_runtime *runtime, uint32_t observed_source_rva,
    uint32_t target_rva, uint32_t value,
    uint32_t current_function_entry_rva, spx_machine_state *state,
    uint32_t *resume_rva) {{
  spx_native_context *context;
  uint32_t index, found = 0U, target_function_entry_rva = 0U;
  uint32_t current_function_owner = 0U;
  if (runtime == 0 || runtime->context == 0 || state == 0 || resume_rva == 0)
    return 2U;
  context = (spx_native_context *)runtime->context;
  if (context->initialized == 0U) return 2U;
  if (context->nonlocal_active == 0U) {{
    if (target_rva == 0U) return 2U;
    for (index = 0U; index < spx_native_nonlocal_transition_count; ++index) {{
      const spx_native_nonlocal_transition *transition =
          &spx_native_nonlocal_transitions[index];
      uint32_t transition_function_owner = 0U;
      if (transition->source_rva != observed_source_rva ||
          transition->target_rva != target_rva)
        continue;
      if (!spx_behavioral_function_owner(
              transition->target_function_entry_rva,
              &transition_function_owner))
        return 2U;
      if (found != 0U && target_function_entry_rva !=
          transition_function_owner)
        return 2U;
      ++found;
      target_function_entry_rva = transition_function_owner;
    }}
    if (found == 0U) return 2U;
    context->nonlocal_active = 1U;
    context->nonlocal_source_rva = observed_source_rva;
    context->nonlocal_target_rva = target_rva;
    context->nonlocal_value = value;
    context->nonlocal_target_function_entry_rva =
        target_function_entry_rva;
  }} else if (
      (target_rva != 0U &&
       (target_rva != context->nonlocal_target_rva ||
        value != context->nonlocal_value))) {{
    return 2U;
  }}
  if (!spx_behavioral_function_owner(
          current_function_entry_rva, &current_function_owner))
    return 2U;
  if (current_function_owner != context->nonlocal_target_function_entry_rva)
    return 1U;
  if (context->unwind_service_active != 0U) {{
    spx_call_status unwind_status = spx_native_checked_unwind_commit(
        &context->unwind_snapshot,
        context->unwind_exception_record_count,
        context->unwind_exception_records,
        runtime, state);
    if (unwind_status != SPX_CALL_OK) return 2U;
    context->unwind_service_active = 0U;
    context->unwind_exception_record_count = 0U;
  }}
  *resume_rva = context->nonlocal_target_rva;
  context->nonlocal_active = 0U;
  context->nonlocal_source_rva = 0U;
  context->nonlocal_target_rva = 0U;
  context->nonlocal_value = 0U;
  context->nonlocal_target_function_entry_rva = 0U;
  return 0U;
}}

spx_runtime spx_native_runtime_instance = {{
  .context = {runtime_context_initializer},
  .image_base = 0U,
  .read = spx_native_flat_read,
  .write = spx_native_flat_write,
  .atomic_compare_exchange = spx_native_atomic_compare_exchange,
  .atomic_exchange = spx_native_atomic_exchange,
  .resolve_reference = spx_native_resolve_reference,
  .realize_reference = spx_native_realize_reference,
  .resolve_interface_resource = spx_native_resolve_interface_resource,
  .realize_interface_resource = spx_native_realize_interface_resource,
  .undefined_value = spx_native_undefined_value,
  .external_call_fallback = spx_dispatch_external_call,
"""
