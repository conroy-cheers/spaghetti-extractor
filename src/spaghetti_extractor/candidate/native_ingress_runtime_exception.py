"""C template fragments for checked native-ingress exception objects."""

from __future__ import annotations

from typing import Any, Mapping, Sequence


def process_termination_branch_source_v1(
    seh_protocols: Sequence[Mapping[str, Any]],
) -> str:
    if not any(
        row.get("handler_rva") is None
        and row.get("escape_disposition") == "terminate_process_root"
        for row in seh_protocols
    ):
        return ""
    return r'''  if (seh->escape_disposition == 1U) {
    spx_native_terminal_kind terminal =
        seh->code == 0xc0000094U ? SPX_NATIVE_TERMINAL_DIVIDE_ERROR :
        seh->code == 0xc0000005U ? SPX_NATIVE_TERMINAL_MEMORY_FAULT :
        SPX_NATIVE_TERMINAL_EXTERNAL_FAULT;
    spx_native_terminal_status = terminal;
    spx_native_terminal_call_status = SPX_CALL_EXTERNAL_FAULT;
    spx_native_terminal_state = *frame->output;
    header->exceptional = 0U;
    spx_native_terminate(terminal);
  }
'''


def exception_memory_access_source_v1() -> str:
    """Render field-granular access checks for active handler objects."""

    return r'''static uint32_t spx_native_ranges_overlap(
    uint32_t left, uint32_t left_size,
    uint32_t right, uint32_t right_size) {
  uint64_t left_end = (uint64_t)left + left_size;
  uint64_t right_end = (uint64_t)right + right_size;
  return left_size != 0U && right_size != 0U &&
      left_end <= 0x100000000ULL && right_end <= 0x100000000ULL &&
      (uint64_t)left < right_end && (uint64_t)right < left_end;
}

static uint32_t spx_native_context_projection_bit(uint32_t offset) {
  switch (offset) {
    case 0U: return 0x001U; /* ContextFlags */
    case 156U: return 0x002U; /* Edi */
    case 160U: return 0x004U; /* Esi */
    case 164U: return 0x008U; /* Ebx */
    case 168U: return 0x010U; /* Edx */
    case 172U: return 0x020U; /* Ecx */
    case 176U: return 0x040U; /* Eax */
    case 180U: return 0x080U; /* Ebp */
    case 184U: return 0x400U; /* Eip */
    case 192U: return 0x100U; /* EFlags */
    case 196U: return 0x200U; /* Esp */
    default: return 0U;
  }
}

uint32_t spx_native_exception_memory_access(
    uint32_t address, uint32_t width, uint32_t write_access) {
  uint8_t *base = spx_native_thread_base();
  spx_native_thread_header *header;
  uint32_t index;
  if (base == 0 || width == 0U) return 0U;
  header = (spx_native_thread_header *)(void *)base;
  for (index = header->depth; index != 0U; --index) {
    const spx_native_ingress_frame *frame = spx_native_frame_at(base, index - 1U);
    const spx_native_seh_descriptor *seh;
    uint32_t offset, bit;
    if (frame->exception_active == 0U ||
        frame->exception_seh_index >= spx_native_seh_descriptor_count)
      continue;
    seh = &spx_native_seh_descriptors[frame->exception_seh_index];
    if (seh->exception_record_count == 0U ||
        seh->exception_record_count > SPX_EXCEPTION_RECORD_CHAIN_CAPACITY)
      return 2U;
    if (spx_native_ranges_overlap(
            address, width, frame->exception_record,
            80U * seh->exception_record_count)) {
      uint32_t record_index, record_offset, projection_mask;
      if (write_access != 0U || width != 4U ||
          address < frame->exception_record)
        return 2U;
      offset = address - frame->exception_record;
      record_index = offset / 80U;
      record_offset = offset % 80U;
      if ((record_offset & 3U) != 0U || record_offset >= 80U)
        return 2U;
      bit = 1U << (record_offset / 4U);
      projection_mask = record_index == 0U
          ? seh->exception_record_projection_mask
          : seh->nested_exception_record_projection_masks[record_index - 1U];
      return (projection_mask & bit) != 0U ? 1U : 2U;
    }
    if (spx_native_ranges_overlap(address, width, frame->exception_context, 200U)) {
      if (width != 4U || address < frame->exception_context) return 2U;
      offset = address - frame->exception_context;
      if ((offset & 3U) != 0U || offset >= 200U) return 2U;
      bit = spx_native_context_projection_bit(offset);
      if (bit == 0U || (seh->context_projection_mask & bit) == 0U)
        return 2U;
      if (write_access != 0U && bit == 0x001U) return 2U;
      return 1U;
    }
    if (spx_native_ranges_overlap(
            address, width, frame->exception_handler_frame, 20U)) {
      if (write_access != 0U || width != 4U ||
          address < frame->exception_handler_frame)
        return 2U;
      offset = address - frame->exception_handler_frame;
      return offset == 4U || offset == 12U ? 1U : 2U;
    }
  }
  return 0U;
}

uint32_t spx_native_exception_stack_pointer_authorized(uint32_t address) {
  uint8_t *base = spx_native_thread_base();
  spx_native_thread_header *header;
  uint32_t index;
  if (base == 0 || address == 0U) return 0U;
  header = (spx_native_thread_header *)(void *)base;
  for (index = header->depth; index != 0U; --index) {
    const spx_native_ingress_frame *frame = spx_native_frame_at(base, index - 1U);
    if (frame->exception_active != 0U &&
        frame->exception_seh_index < spx_native_seh_descriptor_count &&
        frame->exception_handler_frame == address)
      return 1U;
  }
  return 0U;
}'''


def exception_object_helpers_source_v1() -> str:
    """Render checked materialization and selected CONTEXT writeback."""

    return r'''static uint32_t spx_native_checked_exception_address(
    const spx_native_seh_descriptor *seh, uint32_t rva) {
  uint64_t address;
  if (seh == 0) return 0U;
  if (seh->pinned_address_projection == 0U) {
    if (rva != seh->source_rva || seh->portal == 0) return 0U;
    return (uint32_t)(uintptr_t)seh->portal;
  }
  if (spx_native_module_base_pointer == 0 ||
      spx_native_module_base_pointer == (uint8_t *)(uintptr_t)1U)
    return 0U;
  address = (uint64_t)(uint32_t)(uintptr_t)spx_native_module_base_pointer + rva;
  return address <= 0xffffffffULL ? (uint32_t)address : 0U;
}

static uint32_t *spx_native_exception_chain_scratch(
    uint8_t *base, const spx_native_ingress_frame *frame) {
  if (base == 0 || frame == 0) return 0;
  return (uint32_t *)(void *)(
      base + SPX_PRIVATE_STACK_OFFSET + frame->stack_mark);
}

static uint32_t spx_native_copy_exception_chain(
    uint8_t *base, const spx_native_ingress_frame *frame,
    const spx_native_seh_descriptor *seh, const uint32_t *primary) {
  const uint32_t *source = primary;
  const uint32_t *visited[SPX_EXCEPTION_RECORD_CHAIN_CAPACITY];
  uint32_t *target = spx_native_exception_chain_scratch(base, frame);
  uint32_t depth, word, prior;
  if (target == 0 || source == 0 || seh == 0 ||
      seh->exception_record_count < 2U ||
      seh->exception_record_count > SPX_EXCEPTION_RECORD_CHAIN_CAPACITY)
    return 0U;
  for (depth = 0U; depth < seh->exception_record_count; ++depth) {
    if (source == 0) return 0U;
    for (prior = 0U; prior < depth; ++prior)
      if (visited[prior] == source) return 0U;
    visited[depth] = source;
    for (word = 0U; word < 20U; ++word)
      target[depth * 20U + word] = source[word];
    source = (const uint32_t *)(uintptr_t)source[2];
    if (depth + 1U == seh->exception_record_count)
      return source == 0 ? 1U : 0U;
  }
  return 0U;
}

static uint32_t spx_native_materialize_exception_objects(
    const spx_native_thread_header *header,
    const spx_native_seh_descriptor *seh,
    spx_native_ingress_frame *frame,
    uint32_t records[SPX_EXCEPTION_RECORD_CHAIN_CAPACITY][20],
    uint32_t context[50],
    uint32_t handler_frame[5]) {
  uint8_t *base = spx_native_thread_base();
  uint32_t *scratch;
  uint32_t depth, index;
  if (header == 0 || seh == 0 || frame == 0 || base == 0 ||
      seh->exception_record_count == 0U ||
      seh->exception_record_count > SPX_EXCEPTION_RECORD_CHAIN_CAPACITY)
    return 0U;
  for (depth = 0U; depth < SPX_EXCEPTION_RECORD_CHAIN_CAPACITY; ++depth)
    for (index = 0U; index < 20U; ++index) records[depth][index] = 0U;
  if (seh->exception_record_count > 1U) {
    if (header->exceptional != 1U) return 0U;
    scratch = spx_native_exception_chain_scratch(base, frame);
    if (scratch == 0) return 0U;
    for (depth = 0U; depth < seh->exception_record_count; ++depth)
      for (index = 0U; index < 20U; ++index)
        records[depth][index] = scratch[depth * 20U + index];
  }
  for (index = 0U; index < 50U; ++index) context[index] = 0U;
  for (index = 0U; index < 5U; ++index) handler_frame[index] = 0U;
  records[0][0] = header->exception_code;
  records[0][1] = header->exception_flags;
  records[0][3] = header->exception_address;
  records[0][4] = header->exception_parameter_count;
  for (index = 0U;
       index < header->exception_parameter_count && index < 15U;
       ++index)
    records[0][5U + index] = header->exception_parameters[index];
  for (depth = 0U; depth < seh->exception_record_count; ++depth)
    records[depth][2] = depth + 1U < seh->exception_record_count
        ? (uint32_t)(uintptr_t)&records[depth + 1U][0] : 0U;
  context[0] = 0x00010003U;
  context[39] = frame->output->edi;
  context[40] = frame->output->esi;
  context[41] = frame->output->ebx;
  context[42] = frame->output->edx;
  context[43] = frame->output->ecx;
  context[44] = frame->output->eax;
  context[45] = frame->output->ebp;
  context[46] = header->exception_address;
  context[48] = frame->output->eflags;
  context[49] = frame->output->esp;
  handler_frame[1] = (uint32_t)(uintptr_t)&records[0][0];
  handler_frame[3] = (uint32_t)(uintptr_t)context;
  frame->exception_seh_index = (uint32_t)(seh - spx_native_seh_descriptors);
  frame->exception_record = (uint32_t)(uintptr_t)&records[0][0];
  frame->exception_context = (uint32_t)(uintptr_t)context;
  frame->exception_handler_frame = (uint32_t)(uintptr_t)handler_frame;
  frame->output->esp = frame->exception_handler_frame;
  __atomic_store_n(&frame->exception_active, 1U, __ATOMIC_RELEASE);
  return 1U;
}

static uint32_t spx_native_apply_exception_context(
    const spx_native_seh_descriptor *seh,
    const uint32_t context[50], spx_machine_state *output,
    uint32_t *continuation_rva) {
  uint32_t mask = seh->context_projection_mask;
  if (continuation_rva == 0) return 0U;
  *continuation_rva = seh->resumption_rva;
  if ((mask & 0x400U) != 0U) {
    uint32_t source_address, resumption_address;
    source_address = spx_native_checked_exception_address(
        seh, seh->source_rva);
    resumption_address = spx_native_checked_exception_address(
        seh, seh->resumption_rva);
    if (source_address == 0U || resumption_address == 0U) return 0U;
    if (context[46] == source_address)
      *continuation_rva = seh->source_rva;
    else if (context[46] == resumption_address)
      *continuation_rva = seh->resumption_rva;
    else
      return 0U;
  }
  if ((mask & 0x002U) != 0U) output->edi = context[39];
  if ((mask & 0x004U) != 0U) output->esi = context[40];
  if ((mask & 0x008U) != 0U) output->ebx = context[41];
  if ((mask & 0x010U) != 0U) output->edx = context[42];
  if ((mask & 0x020U) != 0U) output->ecx = context[43];
  if ((mask & 0x040U) != 0U) output->eax = context[44];
  if ((mask & 0x080U) != 0U) output->ebp = context[45];
  if ((mask & 0x100U) != 0U) output->eflags = context[48];
  if ((mask & 0x200U) != 0U) output->esp = context[49];
  return 1U;
}'''


def exception_recovery_source_v1() -> str:
    """Render checked unwind, handler dispatch, and authorized resumption."""

    return r'''uint32_t spx_native_ingress_recover_exception(void) {
  uint8_t *base = spx_native_thread_base();
  spx_native_thread_header *header;
  spx_native_ingress_frame *frame;
  const spx_native_seh_descriptor *seh;
  const spx_native_ingress_descriptor *descriptor;
  spx_call_status status;
  spx_machine_state resumption_state;
  uint32_t exception_records[SPX_EXCEPTION_RECORD_CHAIN_CAPACITY][20];
  uint32_t exception_context[50], handler_frame[5];
  uint32_t continuation_rva, materialized;
  if (base == 0) return (uint32_t)SPX_CALL_UNIMPLEMENTED;
  header = (spx_native_thread_header *)(void *)base;
  if (header->depth == 0U || header->exceptional == 0U ||
      header->seh_descriptor_index >= spx_native_seh_descriptor_count ||
      header->exception_frame_index >= header->depth)
    return (uint32_t)SPX_CALL_UNIMPLEMENTED;
  if (spx_native_abandon_frames_above(
          base, header, header->exception_frame_index) == 0U)
    return (uint32_t)SPX_CALL_UNIMPLEMENTED;
  frame = spx_native_frame_at(base, header->exception_frame_index);
  if (frame->bridge_index >= spx_native_ingress_descriptor_count)
    return (uint32_t)SPX_CALL_UNIMPLEMENTED;
  descriptor = &spx_native_ingress_descriptors[frame->bridge_index];
  seh = &spx_native_seh_descriptors[header->seh_descriptor_index];
  if (seh->handler_rva == 0U) return (uint32_t)SPX_CALL_UNIMPLEMENTED;
  if (spx_native_runtime_restore_execution(
          frame->runtime_initialized_mark,
          frame->runtime_nested_depth_mark,
          frame->outgoing_mark, frame->x87_mark) == 0U)
    return (uint32_t)SPX_CALL_UNIMPLEMENTED;
  status = spx_native_apply_checked_unwind(seh, frame);
  if (status != SPX_CALL_OK) return (uint32_t)status;
  materialized = seh->exception_record_projection_mask != 0U ||
      seh->context_projection_mask != 0U;
  continuation_rva = seh->resumption_rva;
  if (materialized != 0U) {
    if (seh->resumption_rva == 0U) return (uint32_t)SPX_CALL_UNIMPLEMENTED;
    resumption_state = *frame->output;
    if (spx_native_materialize_exception_objects(
            header, seh, frame, exception_records, exception_context,
            handler_frame) == 0U)
      return (uint32_t)SPX_CALL_UNIMPLEMENTED;
  }
  status = spx_native_runtime_run_at_rva(
      seh->handler_rva, frame->output, frame->output);
  if (materialized != 0U) {
    __atomic_store_n(&frame->exception_active, 0U, __ATOMIC_RELEASE);
    if (status == SPX_CALL_OK) {
      *frame->output = resumption_state;
      if (spx_native_apply_exception_context(
              seh, exception_context, frame->output,
              &continuation_rva) == 0U)
        status = SPX_CALL_UNIMPLEMENTED;
    }
  }
  if (status == SPX_CALL_OK && continuation_rva != 0U)
    status = spx_native_runtime_run_at_rva(
        continuation_rva, frame->output, frame->output);
  if (status == SPX_CALL_OK &&
      !spx_native_materialize_normal_return_frame(descriptor, frame))
    status = SPX_CALL_UNIMPLEMENTED;
  if (status == SPX_CALL_OK &&
      !spx_native_output_frame_valid(descriptor, frame))
    status = SPX_CALL_UNIMPLEMENTED;
  frame->outcome = status == SPX_CALL_OK
      ? (header->exceptional == 1U ? 4U : 1U) : 0U;
  header->exceptional = 0U;
  return (uint32_t)status;
}'''


__all__ = [
    "exception_memory_access_source_v1",
    "exception_object_helpers_source_v1",
    "exception_recovery_source_v1",
]
