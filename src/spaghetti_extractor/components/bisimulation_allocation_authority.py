"""Project bound local allocation lifetimes into the native reference namespace.

The correspondence does not qualify a producer or a complete incoming runtime
inventory. Runtime admission additionally checks origin from allocating calls.
"""


def allocation_runtime_admission_source(*, capacity, authority, admitted_classes):
    """Check every represented instance against its checked class provenance.

    Classes come from validated requirements or native correspondence. The
    provenance tag is set by a checked allocating transition, or transported
    through an incoming constructor whose predecessor owes the same tag.
    Generic allocation and authority binding leave it unset. Class declarations
    alone therefore cannot qualify an instance. Empty classes may reach the native resolver
    and receive its ordinary missing-instance result. Tombstones keep their birth
    evidence so the same resolver can report expiry after release or reuse.
    """
    cases = []
    for selector, rule in enumerate(authority.rules, 1):
        if rule.locator.kind != 'external_allocation' or rule.identity not in admitted_classes:
            continue
        accepted = f'allocation->birth_class_selector == UINT32_C({selector})'
        rows = [f'  if (selector == UINT32_C({selector})) {{']
        for index in range(capacity):
            rows += [f'    if (world->allocation_count > UINT32_C({index})) {{',
                     f'      const spx_proof_allocation *allocation = &world->allocations[{index}];',
                     f'      if (allocation->native_rule_selector == selector && !({accepted})) return UINT32_C(0);',
                     '    }']
        rows += ['    return UINT32_C(1);', '  }']
        cases.extend(rows)
    return '''
static uint32_t spx_proof_allocation_class_locally_born(const spx_proof_world *world, uint32_t selector) {
''' + '\n'.join(cases) + '''
  return UINT32_C(0);
}
'''


def allocation_authority_source(*, prefix, capacity, rule_count, image_size, producers, include_context=True):
    """Use allocation tombstones for expiry and separate native generation IDs.

    Records retain local authority selectors. The namespace is supplied explicitly, either from checked native
    correspondence or conditional local classes; caller admission is separate.
    """
    producer_rows = ',\n'.join(
        '  {0U, 0U, 0U}' if row is None else
        f'  {{{row["selector"]}U, {row["family"]}U, {row["proof_family"]}U}}'
        for row in producers) or '  {0U, 0U, 0U}'
    lookup = '\n'.join(f'''
  if (producer_selector == UINT32_C({row["selector"]}) &&
      native_object == {prefix}_object_authority_rules[{index}].object_id) {{
    rule_selector = UINT32_C({index + 1});
  }}''' for index, row in enumerate(producers) if row is not None)
    unique = '\n'.join(f'''
  if (world->allocation_count > UINT32_C({i}) &&
      world->allocations[{i}].native_generation == native_generation &&
      &world->allocations[{i}] != allocation)
    return SPX_BOUNDARY_TYPE_MISMATCH;''' for i in range(capacity))
    return f'''
typedef struct {{ uint32_t namespace_selector, namespace_family, proof_family; }} spx_proof_allocation_producer;
static const spx_proof_allocation_producer spx_proof_allocation_producers[] = {{
{producer_rows}
}};
static spx_boundary_status spx_proof_bind_allocation_authority(
    spx_proof_world *world, uint32_t base, uint32_t size, uint32_t family, uint32_t owner,
    uint32_t producer_selector, uint64_t native_object, uint32_t native_generation) {{
  uint32_t index, rule_selector = UINT32_C(0);
  spx_proof_allocation *allocation;
  const {prefix}_object_authority_rule *rule;
  const spx_proof_allocation_producer *producer;
{lookup}
  if (spx_proof_origins_for(world) == 0 || rule_selector == UINT32_C(0) ||
      rule_selector > UINT32_C({rule_count}) || native_generation == UINT32_C(0))
    return SPX_BOUNDARY_TYPE_MISMATCH;
  rule = &{prefix}_object_authority_rules[rule_selector - 1U];
  producer = &spx_proof_allocation_producers[rule_selector - 1U];
  if (rule->locator_kind != UINT32_C(5) || producer->namespace_selector == UINT32_C(0) ||
      rule->locator_subject_rva != producer_selector || family != producer->namespace_family ||
      rule->object_id != native_object)
    return SPX_BOUNDARY_TYPE_MISMATCH;
  index = spx_proof_allocation_at(world, base);
  if (index == UINT32_MAX) return SPX_BOUNDARY_MEMORY_FAULT;
  allocation = &world->allocations[index];
  if (!allocation->live) return SPX_BOUNDARY_EXPIRED;
  if (allocation->base != base || allocation->size != size ||
      allocation->family != producer->proof_family || allocation->owner != owner ||
      base > UINT32_MAX - size)
    return SPX_BOUNDARY_MEMORY_FAULT;
  if (allocation->native_rule_selector != UINT32_C(0))
    return allocation->native_rule_selector == rule_selector &&
        allocation->native_generation == native_generation ? SPX_BOUNDARY_OK : SPX_BOUNDARY_TYPE_MISMATCH;
{unique}
  allocation->native_rule_selector = rule_selector;
  allocation->native_generation = native_generation;
  return SPX_BOUNDARY_OK;
}}
''' + (_allocation_context_source(prefix=prefix, capacity=capacity, rule_count=rule_count,
        image_size=image_size) if include_context else '')


def _allocation_context_source(*, prefix, capacity, rule_count, image_size):
    def store(index):
        # The unaliased local count starts at zero and each preceding record
        # emits at most one range. At row index it is therefore in [0, index].
        # Every generated slot is within capacity, including the final case.
        # Keep the constructor's history bound and early error outcomes below.
        branches = [f'      if (range_count == UINT32_C({i})) context->external_ranges[{i}] = range;\n      else'
                    for i in range(index)]
        return '\n'.join([*branches, f'      context->external_ranges[{index}] = range;'])
    # Immutable metadata needs no pointer identity. Constant-index value loads
    # avoid carrying selector-dependent pointer alternatives through each field
    # access in the native context projection. Keep the checked selector domain
    # and the same ordered error/partial-output behavior.
    select_rule = '\n'.join(
        f'      case {index + 1}U: rule = {prefix}_object_authority_rules[{index}]; '
        f'producer = spx_proof_allocation_producers[{index}]; break;'
        for index in range(rule_count))
    rows = '\n'.join(f'''
  if (world->allocation_count > UINT32_C({i})) {{
    const spx_proof_allocation *allocation = &world->allocations[{i}];
    if ((allocation->native_rule_selector == UINT32_C(0)) !=
        (allocation->native_generation == UINT32_C(0))) return SPX_BOUNDARY_TYPE_MISMATCH;
    if (allocation->live && allocation->native_rule_selector != UINT32_C(0)) {{
      uint32_t selector = allocation->native_rule_selector;
      if (selector > UINT32_C({rule_count}) || allocation->native_generation == UINT32_C(0))
        return SPX_BOUNDARY_TYPE_MISMATCH;
      {prefix}_object_authority_rule rule;
      spx_proof_allocation_producer producer;
      switch (selector) {{
{select_rule}
      default: return SPX_BOUNDARY_TYPE_MISMATCH;
      }}
      if (rule.locator_kind != UINT32_C(5) || producer.namespace_selector == UINT32_C(0) ||
          rule.locator_subject_rva != producer.namespace_selector ||
          allocation->family != producer.proof_family)
        return SPX_BOUNDARY_TYPE_MISMATCH;
      const {prefix}_external_range range = {{
        allocation->base, allocation->size, allocation->native_generation, producer.namespace_selector, rule.object_id
      }};
{store(i)}
      context->external_range_count = ++range_count;
    }}
  }}''' for i in range(capacity))
    return f'''
static spx_boundary_status spx_proof_allocation_authority_context(
    const spx_proof_world *world, {prefix}_context *context) {{
  if (spx_proof_origins_for((void *)world) == 0 || context == 0)
    return SPX_BOUNDARY_UNSUPPORTED;
  *context = ({prefix}_context){{SPX_PROOF_IMAGE_BASE, UINT32_C({image_size}), 0U, {{{{0}}}}}};
  uint32_t range_count = UINT32_C(0);
  if (world->allocation_count > UINT32_C({capacity})) return SPX_BOUNDARY_MEMORY_FAULT;
{rows}
  return SPX_BOUNDARY_OK;
}}
'''
