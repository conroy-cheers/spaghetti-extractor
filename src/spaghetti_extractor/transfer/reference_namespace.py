"""Shared native/proof C resolution of the canonical object-authority rules.

Instance realization is supplied by the owning runtime. Selection, ambiguity,
metadata validation and pointer policy have one implementation.
"""


def reference_namespace_source(prefix: str = "spx_native", *, include_realization: bool = True,
                               include_resolution: bool = True) -> str:
    if type(include_realization) is not bool or type(include_resolution) is not bool:
        raise ValueError("reference lookup selection must be boolean")
    return (_reference_identity_source(prefix)
            + (_reference_dynamic_source(prefix) if include_resolution or include_realization else "")
            + (_reference_resolution_source(prefix) if include_resolution else "")
            + (_reference_realization_source(prefix) if include_realization else ""))


def _reference_identity_source(prefix: str) -> str:
    return r"""static uint32_t spx_native_object_rule_identity_equal(
    const char *left, const char *right) {
  uint32_t index = 0U;
  if (left == 0 || right == 0) return 0U;
  while (left[index] != 0 && left[index] == right[index]) ++index;
  return left[index] == right[index];
}

""".replace("spx_native", prefix)


def _reference_dynamic_source(prefix: str) -> str:
    return r"""static uint32_t spx_native_dynamic_external_object_instance(
    const spx_native_object_authority_rule *rule,
    const spx_native_external_range *range,
    uint32_t *base, uint64_t *generation, uint32_t *extent) {
  uint32_t candidate, available;
  if (rule == 0 || range == 0 || base == 0 || generation == 0 || extent == 0 ||
      rule->extent_mode > 1U || range->generation == 0U ||
      (rule->locator_kind != 5U && rule->locator_kind != 6U) ||
      rule->locator_subject_rva == 0U ||
      range->external_range_rule_selector != rule->locator_subject_rva ||
      range->object_id != rule->object_id ||
      rule->locator_offset > range->size ||
      rule->extent > range->size - rule->locator_offset ||
      range->start > 0xffffffffU - rule->locator_offset)
    return 0U;
  candidate = range->start + rule->locator_offset;
  available = rule->extent_mode == 1U ? range->size - rule->locator_offset : rule->extent;
  if (candidate > 0xffffffffU - available) return 0U;
  *base = candidate;
  *generation = range->generation;
  *extent = available;
  return 1U;
}

""".replace("spx_native", prefix)


def _reference_resolution_source(prefix: str) -> str:
    return r"""static spx_boundary_status spx_native_resolve_reference(
    void *opaque, uint32_t address, uint32_t requested_extent,
    uint32_t permissions, const char *authority_selector,
    uint32_t nullable, uint32_t allow_one_past,
    spx_machine_reference_v1 *result) {
  spx_native_context *context = (spx_native_context *)opaque;
  const spx_native_object_authority_rule *selected = 0;
  uint32_t count = 0U, selected_base = 0U, selected_extent = 0U, selector_known, i;
  uint64_t selected_generation = 0U;
  if (context == 0 || result == 0) return SPX_BOUNDARY_UNSUPPORTED;
  selector_known = authority_selector == 0;
  if (address == 0U) {
    if (nullable == 0U) return SPX_BOUNDARY_MEMORY_FAULT;
    result->domain = result->object = result->generation = 0U;
    result->offset = result->extent = 0U;
    result->permissions = 0U;
    return SPX_BOUNDARY_OK;
  }
  for (i = 0U; i < spx_native_object_authority_rule_count; ++i) {
    const spx_native_object_authority_rule *rule =
        &spx_native_object_authority_rules[i];
    uint32_t base, end, offset, inside, one_past;
    uint64_t generation;
    if (authority_selector != 0 &&
        !spx_native_object_rule_identity_equal(
            authority_selector, rule->identity))
      continue;
    selector_known = 1U;
    if (rule->locator_kind == 5U || rule->locator_kind == 6U) {
      uint32_t range_index;
      for (range_index = 0U; range_index < context->external_range_count;
           ++range_index) {
        uint32_t dynamic_base, dynamic_end, dynamic_offset, dynamic_extent;
        uint32_t dynamic_inside, dynamic_one_past;
        uint64_t dynamic_generation;
        if (!spx_native_dynamic_external_object_instance(
                rule, &context->external_ranges[range_index],
                &dynamic_base, &dynamic_generation, &dynamic_extent) ||
            dynamic_base > 0xffffffffU - dynamic_extent)
          continue;
        /* Empty live instances have an end identity, but no interior address.
           Ordinary memory-span validation still rejects zero-width access. */
        dynamic_end = dynamic_base + dynamic_extent;
        dynamic_inside = address >= dynamic_base && address < dynamic_end;
        dynamic_one_past = allow_one_past != 0U &&
            rule->interior_pointers != 0U && address == dynamic_end;
        if (!dynamic_inside && !dynamic_one_past) continue;
        dynamic_offset = address - dynamic_base;
        if ((dynamic_offset != 0U && rule->interior_pointers == 0U) ||
            requested_extent > dynamic_extent - dynamic_offset ||
            (rule->permissions & permissions) != permissions)
          continue;
        ++count; selected = rule; selected_base = dynamic_base;
        selected_generation = dynamic_generation; selected_extent = dynamic_extent;
      }
      continue;
    }
    if (!spx_native_object_rule_base(context, rule, &base, &generation) ||
        !spx_native_range_end(base, rule->extent, &end))
      continue;
    inside = address >= base && address < end;
    one_past = allow_one_past != 0U &&
        rule->interior_pointers != 0U && address == end;
    if (!inside && !one_past) continue;
    offset = address - base;
    if ((offset != 0U && rule->interior_pointers == 0U) ||
        requested_extent > rule->extent - offset ||
        (rule->permissions & permissions) != permissions)
      continue;
    ++count; selected = rule; selected_base = base;
    selected_generation = generation; selected_extent = rule->extent;
  }
  if (selector_known == 0U) return SPX_BOUNDARY_TYPE_MISMATCH;
  if (count == 0U) return SPX_BOUNDARY_MEMORY_FAULT;
  if (count != 1U) return SPX_BOUNDARY_TYPE_MISMATCH;
  result->domain = selected->domain;
  result->object = selected->object_id;
  result->generation = selected_generation;
  result->offset = address - selected_base;
  result->extent = selected_extent;
  result->permissions = selected->permissions;
  return SPX_BOUNDARY_OK;
}

""".replace("spx_native", prefix)


def _reference_realization_source(prefix: str) -> str:
    return r"""static spx_boundary_status spx_native_realize_reference(
    void *opaque, const spx_machine_reference_v1 *reference,
    uint32_t permissions, uint32_t nullable, uint32_t allow_one_past,
    uint32_t *address) {
  spx_native_context *context = (spx_native_context *)opaque;
  const spx_native_object_authority_rule *selected = 0;
  uint32_t base = 0U, selected_extent = 0U, found = 0U, dynamic_domain_seen = 0U, i;
  uint64_t selected_generation = 0U;
  if (context == 0 || reference == 0 || address == 0)
    return SPX_BOUNDARY_UNSUPPORTED;
  if (reference->domain == 0U && reference->object == 0U) {
    if (nullable == 0U || reference->generation != 0U ||
        reference->offset != 0U || reference->extent != 0U ||
        reference->permissions != 0U)
      return SPX_BOUNDARY_MEMORY_FAULT;
    *address = 0U;
    return SPX_BOUNDARY_OK;
  }
  for (i = 0U; i < spx_native_object_authority_rule_count; ++i) {
    const spx_native_object_authority_rule *rule =
        &spx_native_object_authority_rules[i];
    uint32_t candidate_base, candidate_extent;
    uint64_t candidate_generation;
    if (rule->domain != reference->domain) continue;
    if (rule->locator_kind == 5U || rule->locator_kind == 6U) {
      uint32_t range_index;
      dynamic_domain_seen = 1U;
      if (rule->object_id != reference->object) continue;
      for (range_index = 0U; range_index < context->external_range_count;
           ++range_index) {
        if (!spx_native_dynamic_external_object_instance(
                rule, &context->external_ranges[range_index],
                &candidate_base, &candidate_generation, &candidate_extent) ||
            candidate_generation != reference->generation)
          continue;
        ++found; selected = rule; base = candidate_base;
        selected_generation = candidate_generation; selected_extent = candidate_extent;
      }
      continue;
    }
    if (rule->object_id != reference->object ||
        !spx_native_object_rule_base(
            context, rule, &candidate_base, &candidate_generation))
      continue;
    ++found; selected = rule; base = candidate_base;
    selected_generation = candidate_generation; selected_extent = rule->extent;
  }
  if (found == 0U && dynamic_domain_seen != 0U)
    return SPX_BOUNDARY_EXPIRED;
  if (found != 1U) return SPX_BOUNDARY_TYPE_MISMATCH;
  if (reference->generation != selected_generation)
    return SPX_BOUNDARY_EXPIRED;
  if (reference->extent != selected_extent ||
      reference->permissions != selected->permissions ||
      reference->offset > selected_extent ||
      (reference->offset != 0U && selected->interior_pointers == 0U) ||
      (reference->offset == selected_extent &&
       (allow_one_past == 0U || selected->interior_pointers == 0U)) ||
      (selected->permissions & permissions) != permissions ||
      reference->offset > 0xffffffffU - base)
    return SPX_BOUNDARY_MEMORY_FAULT;
  *address = base + (uint32_t)reference->offset;
  return SPX_BOUNDARY_OK;
}

""".replace("spx_native", prefix)
