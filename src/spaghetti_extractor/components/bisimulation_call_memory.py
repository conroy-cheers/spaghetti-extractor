"""Call-time memory observations for the shared sparse proof world."""

from __future__ import annotations


def call_memory_fragments() -> dict[str, str]:
    """Observe all public memory, conservatively, without copying the world.

    The fresh address is a universally checked witness, never a program input
    or a response constraint. Store its public byte before the exact call so
    later writes cannot change that observation. A private address has no byte
    observation here; keep that inactive field zero without reading its history.
    An independent allocation-index
    witness retains call-time lifetime state without copying an allocation table
    into every call. Private arguments retain their local-cell contracts; these
    observations alone do not admit allocator APIs or caller lifetime assumptions.
    """
    return {
        "fields": """  uint32_t memory_address, memory_private; uint8_t memory_byte;
  uint32_t allocation_count, allocation_index;
  spx_proof_allocation allocation_snapshot;""",
        "declarations": """
static void spx_proof_record_call_memory(spx_proof_call *call);
static uint32_t spx_proof_replay_call_memory(const spx_proof_call *call);
""",
        "helpers": """
static void spx_proof_record_call_allocations(spx_proof_call *call) {
  call->allocation_count = spx_exact_world.allocation_count;
  call->allocation_index = spx_nondet_u32();
  call->allocation_snapshot = (spx_proof_allocation){0};
  if (call->allocation_index < call->allocation_count)
    call->allocation_snapshot = spx_exact_world.allocations[call->allocation_index];
}

static uint32_t spx_proof_replay_call_allocations(const spx_proof_call *call) {
  if (call->allocation_count != spx_source_world.allocation_count) return UINT32_C(0);
  if (call->allocation_index >= call->allocation_count) return UINT32_C(1);
  return spx_proof_allocation_instance_equal(&call->allocation_snapshot,
      &spx_source_world.allocations[call->allocation_index]);
}

static void spx_proof_record_call_memory(spx_proof_call *call) {
  uint32_t address = spx_nondet_u32();
  spx_proof_record_call_allocations(call);
  call->memory_address = address;
  call->memory_private = spx_proof_is_private(&spx_exact_world, address);
  call->memory_byte = call->memory_private ? UINT8_C(0) : spx_proof_exact_byte(address);
}

static uint32_t spx_proof_replay_call_memory(const spx_proof_call *call) {
  uint32_t address = call->memory_address;
  if (!spx_proof_replay_call_allocations(call)) return UINT32_C(0);
  if (call->memory_private != UINT32_C(0) ||
      spx_proof_is_private(&spx_source_world, address) != UINT32_C(0))
    return UINT32_C(1);
  return call->memory_byte == spx_proof_source_byte(address);
}
""",
    }


def event_stack_input_cases(capacity: int) -> str:
    """Read a retained sparse event argument before falling back to the stack."""
    return "\n".join(
        "  if (event != 0 && event->stack_inputs != 0 &&\n"
        f"      event->stack_input_count > UINT32_C({index}) &&\n"
        f"      event->stack_inputs[{index}].offset == offset) {{\n"
        f"    if (event->stack_inputs[{index}].width != UINT32_C(4)) {{\n"
        "      *fault = UINT32_C(1);\n"
        "      return UINT32_C(0);\n"
        "    }\n"
        f"    return event->stack_inputs[{index}].value;\n"
        "  }"
        for index in range(max(1, capacity))
    )
