#include "behavioral-c.h"

extern const spx_region_override *spx_region_override_lookup(
    uint32_t entry_rva) __attribute__((weak));
extern uint32_t spx_native_machine_fallback_allowed(
    uint32_t source_rva) __attribute__((weak));

const uint32_t spx_behavioral_transfer_count = 44U;

static uint32_t spx_behavioral_override_result_valid(spx_step_result result) {
  if (result.kind > SPX_NONLOCAL) return 0U;
  if (result.kind <= SPX_BRANCH)
    return result.target_rva != 0U && result.value == 0U;
  if (result.kind == SPX_RETURN) return result.target_rva == 0U;
  if (result.kind == SPX_INDIRECT_JUMP)
    return result.target_rva == 0U && result.value != 0U;
  if (result.kind == SPX_NONLOCAL)
    return result.target_rva != 0U;
  if (result.kind == SPX_UNIMPLEMENTED) return result.value == 0U;
  return result.target_rva == 0U && result.value == 0U;
}

uint32_t spx_behavioral_has_unit(uint32_t source_rva) {
  switch (source_rva) {
    case 0x00001284U: return 1U;
    case 0x0000128dU: return 1U;
    case 0x0000129cU: return 1U;
    case 0x000012a2U: return 1U;
    case 0x000055b7U: return 1U;
    case 0x000055beU: return 1U;
    case 0x000055c8U: return 1U;
    case 0x000055cdU: return 1U;
    case 0x000055d7U: return 1U;
    case 0x000055ddU: return 1U;
    case 0x000055e9U: return 1U;
    case 0x000055efU: return 1U;
    case 0x000055f6U: return 1U;
    case 0x000055f8U: return 1U;
    case 0x000055faU: return 1U;
    case 0x00005601U: return 1U;
    case 0x00005605U: return 1U;
    case 0x00005606U: return 1U;
    case 0x0000560dU: return 1U;
    case 0x00005614U: return 1U;
    case 0x00005619U: return 1U;
    case 0x00005620U: return 1U;
    case 0x00005623U: return 1U;
    case 0x0000562aU: return 1U;
    case 0x00005632U: return 1U;
    case 0x00005639U: return 1U;
    case 0x0000563eU: return 1U;
    case 0x00005646U: return 1U;
    case 0x00005654U: return 1U;
    case 0x00005662U: return 1U;
    case 0x0000566eU: return 1U;
    case 0x00005674U: return 1U;
    case 0x00005675U: return 1U;
    case 0x00005679U: return 1U;
    case 0x00005684U: return 1U;
    case 0x00005693U: return 1U;
    case 0x0000569bU: return 1U;
    case 0x000056a4U: return 1U;
    case 0x000056adU: return 1U;
    case 0x0000b18eU: return 1U;
    case 0x0000b195U: return 1U;
    case 0x0000b19cU: return 1U;
    case 0x0000b1a1U: return 1U;
    case 0x0000b1afU: return 1U;
    default: return 0U;
  }
}

uint32_t spx_behavioral_function_owner(
    uint32_t source_rva, uint32_t *owner_rva) {
  if (owner_rva == 0) return 0U;
  switch (source_rva) {
    case 0x00001284U: *owner_rva = 0x00001284U; return 1U;
    case 0x0000128dU: *owner_rva = 0x00001284U; return 1U;
    case 0x0000129cU: *owner_rva = 0x00001284U; return 1U;
    case 0x000012a2U: *owner_rva = 0x00001284U; return 1U;
    case 0x000055b7U: *owner_rva = 0x000055b7U; return 1U;
    case 0x000055beU: *owner_rva = 0x000055b7U; return 1U;
    case 0x000055c8U: *owner_rva = 0x000055b7U; return 1U;
    case 0x000055cdU: *owner_rva = 0x000055b7U; return 1U;
    case 0x000055d7U: *owner_rva = 0x000055b7U; return 1U;
    case 0x000055ddU: *owner_rva = 0x000055b7U; return 1U;
    case 0x000055e9U: *owner_rva = 0x000055b7U; return 1U;
    case 0x000055efU: *owner_rva = 0x000055b7U; return 1U;
    case 0x000055f6U: *owner_rva = 0x000055b7U; return 1U;
    case 0x000055f8U: *owner_rva = 0x000055b7U; return 1U;
    case 0x000055faU: *owner_rva = 0x000055b7U; return 1U;
    case 0x00005601U: *owner_rva = 0x000055b7U; return 1U;
    case 0x00005605U: *owner_rva = 0x000055b7U; return 1U;
    case 0x00005606U: *owner_rva = 0x000055b7U; return 1U;
    case 0x0000560dU: *owner_rva = 0x000055b7U; return 1U;
    case 0x00005614U: *owner_rva = 0x000055b7U; return 1U;
    case 0x00005619U: *owner_rva = 0x000055b7U; return 1U;
    case 0x00005620U: *owner_rva = 0x000055b7U; return 1U;
    case 0x00005623U: *owner_rva = 0x000055b7U; return 1U;
    case 0x0000562aU: *owner_rva = 0x000055b7U; return 1U;
    case 0x00005632U: *owner_rva = 0x000055b7U; return 1U;
    case 0x00005639U: *owner_rva = 0x000055b7U; return 1U;
    case 0x0000563eU: *owner_rva = 0x000055b7U; return 1U;
    case 0x00005646U: *owner_rva = 0x000055b7U; return 1U;
    case 0x00005654U: *owner_rva = 0x000055b7U; return 1U;
    case 0x00005662U: *owner_rva = 0x000055b7U; return 1U;
    case 0x0000566eU: *owner_rva = 0x000055b7U; return 1U;
    case 0x00005674U: *owner_rva = 0x000055b7U; return 1U;
    case 0x00005675U: *owner_rva = 0x000055b7U; return 1U;
    case 0x00005679U: *owner_rva = 0x000055b7U; return 1U;
    case 0x00005684U: *owner_rva = 0x000055b7U; return 1U;
    case 0x00005693U: *owner_rva = 0x000055b7U; return 1U;
    case 0x0000569bU: *owner_rva = 0x000055b7U; return 1U;
    case 0x000056a4U: *owner_rva = 0x000055b7U; return 1U;
    case 0x000056adU: *owner_rva = 0x000055b7U; return 1U;
    case 0x0000b18eU: *owner_rva = 0x0000b18eU; return 1U;
    case 0x0000b195U: *owner_rva = 0x0000b18eU; return 1U;
    case 0x0000b19cU: *owner_rva = 0x0000b18eU; return 1U;
    case 0x0000b1a1U: *owner_rva = 0x0000b18eU; return 1U;
    case 0x0000b1afU: *owner_rva = 0x0000b18eU; return 1U;
    default: return 0U;
  }
}

spx_step_result spx_behavioral_step(
    spx_runtime *rt, spx_machine_state *state, uint32_t source_rva) {
  if (state == 0)
    return (spx_step_result){ SPX_UNIMPLEMENTED, source_rva, 0U };
  const spx_region_override *override =
      spx_region_override_lookup == 0 ? 0 : spx_region_override_lookup(source_rva);
  if (override != 0) {
    spx_machine_state overridden = *state;
    spx_step_result result;
    if (override->entry_rva != source_rva || override->function == 0)
      return (spx_step_result){ SPX_UNIMPLEMENTED, source_rva, 0U };
    result = override->function(rt, &overridden);
    if (!spx_behavioral_override_result_valid(result))
      return (spx_step_result){ SPX_UNIMPLEMENTED, source_rva, 0U };
    if (!(result.kind == SPX_UNIMPLEMENTED &&
          override->fallback_on_unimplemented != 0U)) {
      *state = overridden;
      return result;
    }
  }
  if (spx_native_machine_fallback_allowed != 0 &&
      !spx_native_machine_fallback_allowed(source_rva))
    return (spx_step_result){ SPX_UNIMPLEMENTED, source_rva, 0U };
  switch (source_rva) {
    case 0x00001284U: return spx_sub_00001284(rt, state, source_rva);
    case 0x0000128dU: return spx_sub_00001284(rt, state, source_rva);
    case 0x0000129cU: return spx_sub_00001284(rt, state, source_rva);
    case 0x000012a2U: return spx_sub_00001284(rt, state, source_rva);
    case 0x000055b7U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x000055beU: return spx_sub_000055b7(rt, state, source_rva);
    case 0x000055c8U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x000055cdU: return spx_sub_000055b7(rt, state, source_rva);
    case 0x000055d7U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x000055ddU: return spx_sub_000055b7(rt, state, source_rva);
    case 0x000055e9U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x000055efU: return spx_sub_000055b7(rt, state, source_rva);
    case 0x000055f6U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x000055f8U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x000055faU: return spx_sub_000055b7(rt, state, source_rva);
    case 0x00005601U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x00005605U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x00005606U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x0000560dU: return spx_sub_000055b7(rt, state, source_rva);
    case 0x00005614U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x00005619U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x00005620U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x00005623U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x0000562aU: return spx_sub_000055b7(rt, state, source_rva);
    case 0x00005632U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x00005639U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x0000563eU: return spx_sub_000055b7(rt, state, source_rva);
    case 0x00005646U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x00005654U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x00005662U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x0000566eU: return spx_sub_000055b7(rt, state, source_rva);
    case 0x00005674U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x00005675U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x00005679U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x00005684U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x00005693U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x0000569bU: return spx_sub_000055b7(rt, state, source_rva);
    case 0x000056a4U: return spx_sub_000055b7(rt, state, source_rva);
    case 0x000056adU: return spx_sub_000055b7(rt, state, source_rva);
    case 0x0000b18eU: return spx_sub_0000b18e(rt, state, source_rva);
    case 0x0000b195U: return spx_sub_0000b18e(rt, state, source_rva);
    case 0x0000b19cU: return spx_sub_0000b18e(rt, state, source_rva);
    case 0x0000b1a1U: return spx_sub_0000b18e(rt, state, source_rva);
    case 0x0000b1afU: return spx_sub_0000b18e(rt, state, source_rva);
    default: return (spx_step_result){ SPX_UNIMPLEMENTED, source_rva, 0U };
  }
}

spx_call_status spx_behavioral_run(
    spx_runtime *rt, uint32_t entry_rva,
    const spx_machine_state *input, spx_machine_state *output) {
  spx_machine_state state;
  uint32_t rva = entry_rva;
  if (input == 0 || output == 0) return SPX_CALL_UNIMPLEMENTED;
  state = *input;
  for (;;) {
    state.original_rva = rva;
    spx_step_result result = spx_behavioral_step(rt, &state, rva);
    const uint32_t source_rva =
        result.kind == SPX_NONLOCAL && result.target_rva == 0U
        ? rva : state.original_rva;
    if (result.kind <= SPX_BRANCH) { rva = result.target_rva; continue; }
    if (result.kind == SPX_INDIRECT_JUMP) {
      uint32_t next_rva;
      if (rt != 0 && rt->resolve_code_target != 0 &&
          rt->resolve_code_target(
              rt, SPX_CODE_SITE_INDIRECT_JUMP, source_rva, source_rva, 0U,
              result.value, &next_rva) == 0U) {
        rva = next_rva;
        continue;
      }
      if (rt != 0 && rt->invoke_callable_external_jump != 0) {
        spx_machine_state external_output = state;
        spx_call_status status = rt->invoke_callable_external_jump(
            rt, source_rva, result.value, &state, &external_output);
        if (status == SPX_CALL_OK) { *output = external_output; return status; }
        *output = state; output->original_rva = source_rva; return status;
      }
    }
    if (result.kind == SPX_NONLOCAL) {
      uint32_t resume_rva = 0U, route = 2U;
      if (rt != 0 && rt->route_nonlocal != 0)
        route = rt->route_nonlocal(
            rt, source_rva, result.target_rva, result.value,
            entry_rva, &state, &resume_rva);
      if (route == 0U) { rva = resume_rva; continue; }
      *output = state; output->original_rva = source_rva;
      return route == 1U ? SPX_CALL_NONLOCAL : SPX_CALL_UNIMPLEMENTED;
    }
    *output = state;
    output->original_rva =
        result.target_rva != 0U ? result.target_rva : source_rva;
    if (result.kind == SPX_RETURN) {
      return SPX_CALL_OK;
    }
    if (result.kind == SPX_EXTERNAL_JUMP) return SPX_CALL_OK;
    if (result.kind == SPX_DIVIDE_ERROR) return SPX_CALL_DIVIDE_ERROR;
    if (result.kind == SPX_MEMORY_FAULT) return SPX_CALL_MEMORY_FAULT;
    if (result.kind == SPX_EXTERNAL_FAULT) return SPX_CALL_EXTERNAL_FAULT;
    return SPX_CALL_UNIMPLEMENTED;
  }
}

spx_call_status spx_invoke_call(
    spx_runtime *rt, const spx_call_event *event,
    const spx_machine_state *input, spx_machine_state *output) {
  uint32_t target_rva;
  spx_machine_state call_input;
  spx_call_status status;
  uint32_t return_address, fault = 0U;
  if (event == 0 || input == 0 || output == 0)
    return SPX_CALL_UNIMPLEMENTED;
  if (event->kind == SPX_CALL_INTERNAL_DIRECT ||
      (event->kind == SPX_CALL_INDIRECT && rt != 0 &&
       rt->resolve_code_target != 0 &&
       rt->resolve_code_target(
           rt, SPX_CODE_SITE_INDIRECT_CALL, event->source_rva,
           event->instruction_rva, event->call_index,
           event->target_rva, &target_rva) == 0U)) {
    if (rt == 0 || rt->write == 0 || input->esp < 4U ||
        event->return_rva == 0U ||
        rt->image_base > 0xffffffffU - event->return_rva) {
      *output = *input;
      return SPX_CALL_UNIMPLEMENTED;
    }
    return_address = rt->image_base + event->return_rva;
    call_input = *input;
    call_input.esp -= 4U;
    rt->write(rt->context, call_input.esp, 4U, return_address, &fault);
    if (fault != 0U) {
      *output = call_input;
      return SPX_CALL_MEMORY_FAULT;
    }
    status = spx_behavioral_run(rt,
        event->kind == SPX_CALL_INTERNAL_DIRECT
            ? event->target_rva : target_rva,
        &call_input, output);
    if (status == SPX_CALL_NONLOCAL)
      output->esp = input->esp;
    return status;
  }
  if (event->kind == SPX_CALL_EXTERNAL_IMPORT ||
      event->kind == SPX_CALL_INDIRECT)
    return spx_dispatch_external_call(rt, event, input, output);
  return SPX_CALL_UNIMPLEMENTED;
}
