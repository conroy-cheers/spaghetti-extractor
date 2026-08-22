"""Native runtime entry and terminal-control C rendering."""

from __future__ import annotations

from .runtime_model import NativeRuntimePlan


def _native_runtime_source_entry(plan: NativeRuntimePlan) -> str:
    x87_initializer = (
        ",\n  .execute_typed_x87_operation = "
        "spx_native_execute_typed_x87_operation"
        if plan.has_typed_x87_handler
        else ""
    )
    return f'''  .resolve_code_target = spx_native_resolve_code_target{x87_initializer}
  , .invoke_callable_external_jump =
      spx_native_invoke_callable_external_jump
}};

static void spx_native_unpack_flags(spx_machine_state *state) {{
  uint32_t flags = state->eflags;
  state->cf = (flags >> 0) & 1U;
  state->pf = (flags >> 2) & 1U;
  state->zf = (flags >> 6) & 1U;
  state->sf = (flags >> 7) & 1U;
  state->df = (flags >> 10) & 1U;
  state->of = (flags >> 11) & 1U;
}}

static spx_native_terminal_kind spx_native_terminal_for(
    spx_call_status status, uint32_t undefined_fault) {{
  if (undefined_fault != 0U)
    return SPX_NATIVE_TERMINAL_UNDEFINED_VALUE;
  if (status == SPX_CALL_OK) return SPX_NATIVE_TERMINAL_RETURNED;
  if (status == SPX_CALL_DIVIDE_ERROR)
    return SPX_NATIVE_TERMINAL_DIVIDE_ERROR;
  if (status == SPX_CALL_MEMORY_FAULT)
    return SPX_NATIVE_TERMINAL_MEMORY_FAULT;
  if (status == SPX_CALL_EXTERNAL_FAULT)
    return SPX_NATIVE_TERMINAL_EXTERNAL_FAULT;
  return SPX_NATIVE_TERMINAL_UNIMPLEMENTED;
}}

static uint32_t spx_native_has_transfer(uint32_t rva) {{
  uint32_t low = 0U, high = spx_native_transfer_count;
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
    return 0U;
  while (low < high) {{
    uint32_t middle = low + (high - low) / 2U;
    if (spx_native_transfer_rvas[middle] < rva) low = middle + 1U;
    else high = middle;
  }}
  return low != spx_native_transfer_count &&
      spx_native_transfer_rvas[low] == rva && spx_program_lookup(rva) != 0;
}}

static uint32_t spx_native_callback_matches(
    uint32_t rva, uint32_t stack_cleanup_bytes) {{
  uint32_t i;
  for (i = 0U; i < spx_native_callback_abi_count; ++i)
    if (spx_native_callback_abis[i].rva == rva &&
        spx_native_callback_abis[i].stack_cleanup_bytes == stack_cleanup_bytes)
      return 1U;
  return 0U;
}}

static spx_call_status spx_native_run_initialized(
    uint32_t entry_rva, const spx_machine_state *input,
    spx_machine_state *output) {{
  spx_call_status status;
  spx_native_context *context = &spx_native_context_value;
  if (input == 0 || output == 0 || context->initialized == 0U ||
      !spx_native_has_transfer(entry_rva))
    return SPX_CALL_UNIMPLEMENTED;
  *output = *input;
  spx_native_unpack_flags(output);
  output->original_rva = entry_rva;
  status = spx_run_function(
      &spx_native_runtime_instance, entry_rva, output, output);
  if (context->undefined_fault != 0U) {{
    spx_native_diagnostic_reason = 0x5001U;
    spx_native_diagnostic_value = context->undefined_fault_slot;
    spx_native_diagnostic_aux = context->undefined_fault_rva;
    spx_native_diagnostic_detail = entry_rva;
    return SPX_CALL_UNIMPLEMENTED;
  }}
  return status;
}}

spx_call_status spx_native_runtime_run_at_rva(
    uint32_t entry_rva, const spx_machine_state *input,
    spx_machine_state *output) {{
  spx_call_status status = SPX_CALL_UNIMPLEMENTED;
  spx_native_context *context = &spx_native_context_value;
  uint32_t i;
  if (input == 0 || output == 0) return SPX_CALL_UNIMPLEMENTED;
  *output = *input;
  if (__sync_lock_test_and_set(&context->active, 1U) != 0U) {{
    return SPX_CALL_UNIMPLEMENTED;
  }}
  context->initialized = 0U;
  context->undefined_fault = 0U;
  context->undefined_fault_slot = 0U;
  context->undefined_fault_rva = 0U;
  context->last_undefined_fault = 0U;
  context->nested_depth = 0U;
  if (!spx_native_validate_image(context) ||
      !spx_native_validate_stack(context, input) ||
      !spx_native_transfer_table_valid() || !spx_native_has_transfer(entry_rva))
    goto release;
  if (context->process_world_initialized == 0U) {{
    context->external_range_count = 0U;
    context->external_lifecycle_count = 0U;
    context->external_lifecycle_next = 0U;
    context->external_lifecycle_sequence = 0U;
    for (i = 0U; i < spx_native_callable_binding_count; ++i) {{
      context->callable_bindings[i].capability_id =
          spx_native_callable_binding_capabilities[i];
      context->callable_bindings[i].target_word = 0U;
      context->callable_bindings[i].bound = 0U;
    }}
    context->process_world_initialized = 1U;
  }}
  context->owner_fs_base = input->fs_base;
  if (context->invocation_generation != 0xffffffffU)
    ++context->invocation_generation;
  context->initialized = 1U;
  status = spx_native_run_initialized(entry_rva, input, output);
release:
  context->last_undefined_fault = context->undefined_fault;
  context->owner_fs_base = 0U;
  context->nested_depth = 0U;
  context->initialized = 0U;
  __sync_lock_release(&context->active);
  return status;
}}

spx_call_status spx_native_runtime_run_nested_callback(
    uint32_t callback_rva, uint32_t stack_cleanup_bytes,
    const spx_machine_state *input, spx_machine_state *output) {{
  spx_call_status status;
  spx_native_context *context = &spx_native_context_value;
  if (input == 0 || output == 0 || context->active != 1U ||
      context->initialized == 0U || input->fs_base != context->owner_fs_base ||
      context->nested_depth == 0xffffffffU ||
      !spx_native_callback_matches(callback_rva, stack_cleanup_bytes))
    return SPX_CALL_UNIMPLEMENTED;
  ++context->nested_depth;
  status = spx_native_run_initialized(callback_rva, input, output);
  --context->nested_depth;
  if (status == SPX_CALL_OK &&
      output->esp != input->esp + 4U + stack_cleanup_bytes)
    return SPX_CALL_UNIMPLEMENTED;
  return status;
}}

spx_call_status spx_native_runtime_run_captured(
    const spx_machine_state *captured, spx_machine_state *output) {{
  spx_native_context *context = &spx_native_context_value;
  spx_call_status status;
  spx_native_terminal_call_status = SPX_CALL_UNIMPLEMENTED;
  spx_native_terminal_status = SPX_NATIVE_TERMINAL_UNIMPLEMENTED;
  if (captured == 0 || output == 0) return SPX_CALL_UNIMPLEMENTED;
  status = spx_native_runtime_run_at_rva(
      0x{plan.entry_rva:08x}U, captured, output);
  spx_native_terminal_call_status = status;
  spx_native_terminal_status = spx_native_terminal_for(
      status, context->last_undefined_fault);
  spx_native_terminal_state = *output;
  return status;
}}

void spx_native_runtime_coordinate(
    const spx_machine_state *captured) {{
  spx_machine_state output;
  spx_call_status status =
      spx_native_runtime_run_captured(captured, &output);
  spx_native_terminal_call_status = status;
  if (captured != 0) spx_native_terminal_state = output;
  spx_native_terminate(spx_native_terminal_status);
}}
'''
