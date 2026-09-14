"""Native address-admission predicates shared with contextual proof experiments.

These are the runtime predicates, not a memory map or a checked summary.
Consumers must supply the native context, section contents and priority access
handlers. An absent handler or external range is a premise requiring discharge;
allocation provenance alone cannot establish the complement of mapped storage.
"""


def range_predicates_source() -> str:
    return r'''static uint32_t spx_native_range_end(
    uint32_t start, uint32_t width, uint32_t *end) {
  if (width == 0U || start > 0xffffffffU - width) return 0U;
  *end = start + width;
  return 1U;
}

static uint32_t spx_native_inside(
    uint32_t start, uint32_t end, uint32_t region_start, uint32_t region_size) {
  uint32_t region_end;
  if (region_size == 0U ||
      !spx_native_range_end(region_start, region_size, &region_end))
    return 0U;
  return start >= region_start && end <= region_end;
}

static uint32_t spx_native_inside_external_range(
    const spx_native_context *context, uint32_t start, uint32_t end) {
  uint32_t i;
  for (i = 0U; i < context->external_range_count; ++i)
    if (spx_native_inside(
            start, end, context->external_ranges[i].start,
            context->external_ranges[i].size))
      return 1U;
  return 0U;
}

'''


def thread_environment_predicate_source() -> str:
    return r'''static uint32_t spx_native_inside_thread_environment(
    const spx_native_context *context, uint32_t start, uint32_t end) {
  uint32_t teb_end;
  return context->owner_fs_base != 0U &&
      spx_native_range_end(
          context->owner_fs_base,
          SPX_NATIVE_THREAD_ENVIRONMENT_BYTES,
          &teb_end) &&
      start >= context->owner_fs_base && end <= teb_end;
}

'''


def access_predicates_source() -> str:
    return r'''static uint32_t spx_native_write_allowed(uint32_t address, uint32_t width) {
  spx_native_context *context = &spx_native_context_value;
  uint32_t end, image_end, i, matched = 0U;
  uint32_t physical_frame_access = spx_native_physical_frame_memory_access(
      address, width, 1U);
  uint32_t captured_stack_access = spx_native_captured_stack_memory_access(
      address, width, 1U);
  uint32_t unwind_access = spx_native_unwind_service_memory_access(
      address, width, 1U);
  uint32_t service_access = spx_native_exception_service_memory_access(
      address, width, 1U);
  uint32_t exception_access = spx_native_exception_memory_access(
      address, width, 1U);
  if (physical_frame_access != 0U) return physical_frame_access == 1U;
  if (captured_stack_access != 0U) return captured_stack_access == 1U;
  if (unwind_access != 0U) return unwind_access == 1U;
  if (service_access != 0U) return service_access == 1U;
  if (exception_access != 0U) return exception_access == 1U;
  if (!spx_native_range_end(address, width, &end) ||
      !spx_native_range_end(context->image_base, context->image_size, &image_end))
    return 0U;
  if (spx_native_inside_external_range(context, address, end)) return 1U;
  if (spx_native_inside_thread_environment(context, address, end)) return 1U;
  if (end <= context->image_base || address >= image_end)
    return address >= context->stack_low && end <= context->stack_high;
  for (i = 0U; i < context->section_count; ++i) {
    uint32_t section = context->section_table + i * 40U;
    uint32_t virtual_size = spx_native_u32(section + 8U);
    uint32_t raw_size = spx_native_u32(section + 16U);
    uint32_t rva = spx_native_u32(section + 12U);
    uint32_t size = virtual_size > raw_size ? virtual_size : raw_size;
    uint32_t section_start;
    if (rva > 0xffffffffU - context->image_base) return 0U;
    section_start = context->image_base + rva;
    if (spx_native_inside(address, end, section_start, size)) {
      if ((spx_native_u32(section + 36U) &
          SPX_NATIVE_IMAGE_SCN_MEM_EXECUTE) != 0U)
        return 0U;
      matched = 1U;
    }
  }
  return matched;
}

static uint32_t spx_native_read_allowed(uint32_t address, uint32_t width) {
  spx_native_context *context = &spx_native_context_value;
  uint32_t end, image_end, i;
  uint32_t physical_frame_access = spx_native_physical_frame_memory_access(
      address, width, 0U);
  uint32_t captured_stack_access = spx_native_captured_stack_memory_access(
      address, width, 0U);
  uint32_t unwind_access = spx_native_unwind_service_memory_access(
      address, width, 0U);
  uint32_t service_access = spx_native_exception_service_memory_access(
      address, width, 0U);
  uint32_t exception_access = spx_native_exception_memory_access(
      address, width, 0U);
  if (physical_frame_access != 0U) return physical_frame_access == 1U;
  if (captured_stack_access != 0U) return captured_stack_access == 1U;
  if (unwind_access != 0U) return unwind_access == 1U;
  if (service_access != 0U) return service_access == 1U;
  if (exception_access != 0U) return exception_access == 1U;
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
  for (i = 0U; i < context->section_count; ++i) {
    uint32_t section = context->section_table + i * 40U;
    uint32_t virtual_size = spx_native_u32(section + 8U);
    uint32_t raw_size = spx_native_u32(section + 16U);
    uint32_t rva = spx_native_u32(section + 12U);
    uint32_t size = virtual_size > raw_size ? virtual_size : raw_size;
    uint32_t section_start;
    if (rva > 0xffffffffU - context->image_base) return 0U;
    section_start = context->image_base + rva;
    if (spx_native_inside(address, end, section_start, size)) return 1U;
  }
  return 0U;
}

'''
