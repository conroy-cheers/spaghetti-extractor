"""Native runtime entry and terminal-control C rendering."""

from __future__ import annotations

from .runtime_model import NativeRuntimePlan


def _native_runtime_source_entry(plan: NativeRuntimePlan) -> str:
    x87_initializer = (
        ",\n  .execute_typed_x87_operation = "
        "stage_b_native_execute_typed_x87_operation"
        if plan.has_typed_x87_handler
        else ""
    )
    return f'''  .resolve_code_target = stage_b_native_resolve_code_target{x87_initializer}
  , .invoke_callable_external_jump =
      stage_b_native_invoke_callable_external_jump
}};

static void stage_b_native_unpack_flags(stage_b_machine_state *state) {{
  uint32_t flags = state->eflags;
  state->cf = (flags >> 0) & 1U;
  state->pf = (flags >> 2) & 1U;
  state->zf = (flags >> 6) & 1U;
  state->sf = (flags >> 7) & 1U;
  state->df = (flags >> 10) & 1U;
  state->of = (flags >> 11) & 1U;
}}

static stage_b_native_terminal_kind stage_b_native_terminal_for(
    stage_b_call_status status, uint32_t undefined_fault) {{
  if (undefined_fault != 0U)
    return STAGE_B_NATIVE_TERMINAL_UNDEFINED_VALUE;
  if (status == STAGE_B_CALL_OK) return STAGE_B_NATIVE_TERMINAL_RETURNED;
  if (status == STAGE_B_CALL_DIVIDE_ERROR)
    return STAGE_B_NATIVE_TERMINAL_DIVIDE_ERROR;
  if (status == STAGE_B_CALL_MEMORY_FAULT)
    return STAGE_B_NATIVE_TERMINAL_MEMORY_FAULT;
  if (status == STAGE_B_CALL_EXTERNAL_FAULT)
    return STAGE_B_NATIVE_TERMINAL_EXTERNAL_FAULT;
  return STAGE_B_NATIVE_TERMINAL_UNIMPLEMENTED;
}}

static uint32_t stage_b_native_has_transfer(uint32_t rva) {{
  uint32_t low = 0U, high = stage_b_native_transfer_count;
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
    return 0U;
  while (low < high) {{
    uint32_t middle = low + (high - low) / 2U;
    if (stage_b_native_transfer_rvas[middle] < rva) low = middle + 1U;
    else high = middle;
  }}
  return low != stage_b_native_transfer_count &&
      stage_b_native_transfer_rvas[low] == rva && stage_b_program_lookup(rva) != 0;
}}

static uint32_t stage_b_native_callback_matches(
    uint32_t rva, uint32_t stack_cleanup_bytes) {{
  uint32_t i;
  for (i = 0U; i < stage_b_native_callback_abi_count; ++i)
    if (stage_b_native_callback_abis[i].rva == rva &&
        stage_b_native_callback_abis[i].stack_cleanup_bytes == stack_cleanup_bytes)
      return 1U;
  return 0U;
}}

static stage_b_call_status stage_b_native_run_initialized(
    uint32_t entry_rva, const stage_b_machine_state *input,
    stage_b_machine_state *output) {{
  stage_b_call_status status;
  stage_b_native_context *context = &stage_b_native_context_value;
  if (input == 0 || output == 0 || context->initialized == 0U ||
      !stage_b_native_has_transfer(entry_rva))
    return STAGE_B_CALL_UNIMPLEMENTED;
  *output = *input;
  stage_b_native_unpack_flags(output);
  output->original_rva = entry_rva;
  status = stage_b_run_function(
      &stage_b_native_runtime_instance, entry_rva, output, output);
  if (context->undefined_fault != 0U) {{
    stage_b_native_diagnostic_reason = 0x5001U;
    stage_b_native_diagnostic_value = context->undefined_fault_slot;
    stage_b_native_diagnostic_aux = context->undefined_fault_rva;
    stage_b_native_diagnostic_detail = entry_rva;
    return STAGE_B_CALL_UNIMPLEMENTED;
  }}
  return status;
}}

stage_b_call_status stage_b_native_runtime_run_at_rva(
    uint32_t entry_rva, const stage_b_machine_state *input,
    stage_b_machine_state *output) {{
  stage_b_call_status status = STAGE_B_CALL_UNIMPLEMENTED;
  stage_b_native_context *context = &stage_b_native_context_value;
  uint32_t i;
  if (input == 0 || output == 0) return STAGE_B_CALL_UNIMPLEMENTED;
  *output = *input;
  if (__sync_lock_test_and_set(&context->active, 1U) != 0U) {{
    return STAGE_B_CALL_UNIMPLEMENTED;
  }}
  context->initialized = 0U;
  context->undefined_fault = 0U;
  context->undefined_fault_slot = 0U;
  context->undefined_fault_rva = 0U;
  context->last_undefined_fault = 0U;
  context->nested_depth = 0U;
  if (!stage_b_native_validate_image(context) ||
      !stage_b_native_validate_stack(context, input) ||
      !stage_b_native_transfer_table_valid() || !stage_b_native_has_transfer(entry_rva))
    goto release;
  if (context->process_world_initialized == 0U) {{
    context->external_range_count = 0U;
    context->external_lifecycle_count = 0U;
    context->external_lifecycle_next = 0U;
    context->external_lifecycle_sequence = 0U;
    context->external_trace_count = 0U;
    context->external_trace_next = 0U;
    context->external_trace_sequence = 0U;
    context->transfer_trace_count = 0U;
    context->transfer_trace_next = 0U;
    context->transfer_trace_sequence = 0U;
    for (i = 0U; i < stage_b_native_callable_binding_count; ++i) {{
      context->callable_bindings[i].capability_id =
          stage_b_native_callable_binding_capabilities[i];
      context->callable_bindings[i].target_word = 0U;
      context->callable_bindings[i].bound = 0U;
    }}
    context->process_world_initialized = 1U;
  }}
  context->owner_fs_base = input->fs_base;
  context->initialized = 1U;
  status = stage_b_native_run_initialized(entry_rva, input, output);
release:
  context->last_undefined_fault = context->undefined_fault;
  context->owner_fs_base = 0U;
  context->nested_depth = 0U;
  context->initialized = 0U;
  __sync_lock_release(&context->active);
  return status;
}}

stage_b_call_status stage_b_native_runtime_run_nested_callback(
    uint32_t callback_rva, uint32_t stack_cleanup_bytes,
    const stage_b_machine_state *input, stage_b_machine_state *output) {{
  stage_b_call_status status;
  stage_b_native_context *context = &stage_b_native_context_value;
  if (input == 0 || output == 0 || context->active != 1U ||
      context->initialized == 0U || input->fs_base != context->owner_fs_base ||
      context->nested_depth == 0xffffffffU ||
      !stage_b_native_callback_matches(callback_rva, stack_cleanup_bytes))
    return STAGE_B_CALL_UNIMPLEMENTED;
  ++context->nested_depth;
  status = stage_b_native_run_initialized(callback_rva, input, output);
  --context->nested_depth;
  if (status == STAGE_B_CALL_OK &&
      output->esp != input->esp + 4U + stack_cleanup_bytes)
    return STAGE_B_CALL_UNIMPLEMENTED;
  return status;
}}

stage_b_call_status stage_b_native_runtime_run_captured(
    const stage_b_machine_state *captured, stage_b_machine_state *output) {{
  stage_b_native_context *context = &stage_b_native_context_value;
  stage_b_call_status status;
  stage_b_native_terminal_call_status = STAGE_B_CALL_UNIMPLEMENTED;
  stage_b_native_terminal_status = STAGE_B_NATIVE_TERMINAL_UNIMPLEMENTED;
  if (captured == 0 || output == 0) return STAGE_B_CALL_UNIMPLEMENTED;
  status = stage_b_native_runtime_run_at_rva(
      0x{plan.entry_rva:08x}U, captured, output);
  stage_b_native_terminal_call_status = status;
  stage_b_native_terminal_status = stage_b_native_terminal_for(
      status, context->last_undefined_fault);
  stage_b_native_terminal_state = *output;
  return status;
}}

void stage_b_native_runtime_coordinate(
    const stage_b_machine_state *captured) {{
  stage_b_machine_state output;
  stage_b_call_status status =
      stage_b_native_runtime_run_captured(captured, &output);
  stage_b_native_terminal_call_status = status;
  if (captured != 0) stage_b_native_terminal_state = output;
  stage_b_native_terminate(stage_b_native_terminal_status);
}}
'''
