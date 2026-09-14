"""Allocation instances in the existing paired sparse proof world.

These primitives do not admit an external allocator contract by themselves.
Call admission remains separate from the lifecycle and memory implementation.
"""

from .bisimulation_support import BisimulationRefinementError


def allocation_fragments(*, capacity, reference_capacity, private_ranges, immutable_bytes, image_size=None):
    if type(capacity) is not int or not 0 < capacity < 0xffffffff:
        raise BisimulationRefinementError("proof allocation capacity is malformed")
    if image_size is not None and (type(image_size) is not int or not 0 < image_size <= 0xffffffff):
        raise BisimulationRefinementError("proof allocation image extent is malformed")
    # The mapped image is already live before any logical view is borrowed.
    # Protect its complete extent, including bytes without an object-rule view.
    image = f'''
  if (spx_proof_allocation_overlap(base, size, SPX_PROOF_IMAGE_BASE, UINT64_C({image_size})))
    return SPX_BOUNDARY_MEMORY_FAULT;''' if image_size is not None else ""
    lookup = '\n'.join(f'''
  if (world->allocation_count > UINT32_C({i}) &&
      (address == world->allocations[{i}].base ||
       (address > world->allocations[{i}].base &&
        (uint64_t)address - world->allocations[{i}].base < world->allocations[{i}].size)))
    return UINT32_C({i});''' for i in reversed(range(capacity)))
    one_past = '\n'.join(f'''
    if (world->allocation_count > UINT32_C({i}) &&
        (uint64_t)address == (uint64_t)world->allocations[{i}].base + world->allocations[{i}].size) {{
      index = UINT32_C({i});
      break;
    }}''' for i in reversed(range(capacity)))
    # A single-pass do block allows the generated alternatives to select one
    # row without a symbolic traversal loop or an increased unwind budget.
    overlaps = '\n'.join(f'''
  if (world->allocation_count > UINT32_C({i}) && world->allocations[{i}].live &&
      spx_proof_allocation_overlap(base, size, world->allocations[{i}].base,
                                   world->allocations[{i}].size))
    return SPX_BOUNDARY_MEMORY_FAULT;''' for i in range(capacity))
    borrowed = '\n'.join(f'''
  if (origins->count > UINT32_C({i}) && origins->entries[{i}].lifetime_generation == UINT64_C(1) &&
      spx_proof_allocation_overlap(base, size, origins->entries[{i}].base,
                                   origins->entries[{i}].extent))
    return SPX_BOUNDARY_MEMORY_FAULT;''' for i in range(reference_capacity))
    protected = '\n'.join(f'''
  if (spx_proof_allocation_overlap(base, size, UINT64_C({base}), UINT64_C({size})))
    return SPX_BOUNDARY_MEMORY_FAULT;''' for base, size in
        (*private_ranges, *((address, 1) for address, _ in immutable_bytes)))
    release = '\n'.join(f'''
  if (world->allocation_count > UINT32_C({i}) && world->allocations[{i}].base == base) {{
    spx_proof_allocation *allocation = &world->allocations[{i}];
    if (!allocation->live) return SPX_BOUNDARY_EXPIRED;
    if (allocation->family != family || allocation->owner != owner)
      return SPX_BOUNDARY_TYPE_MISMATCH;
    if (succeeded) allocation->live = UINT32_C(0);
    return SPX_BOUNDARY_OK;
  }}''' for i in reversed(range(capacity)))
    spanning = '\n'.join(f'''
  if (world->allocation_count > UINT32_C({i}) &&
      spx_proof_allocation_overlap(address, extent, world->allocations[{i}].base,
                                   world->allocations[{i}].size)) return UINT32_C(0);'''
        for i in range(capacity))
    equality = '\n'.join(f'''
  if (spx_exact_world.allocation_count > UINT32_C({i})) {{
    const spx_proof_allocation *left = &spx_exact_world.allocations[{i}];
    const spx_proof_allocation *right = &spx_source_world.allocations[{i}];
    if (!spx_proof_allocation_instance_equal(left, right)) return UINT32_C(0);
  }}''' for i in range(capacity))
    live_reference = '\n'.join(f'''
  if (world->allocation_count > UINT32_C({i}) &&
      world->allocations[{i}].generation == generation) {{
    const spx_proof_allocation *allocation = &world->allocations[{i}];
    return allocation->live && address >= allocation->base &&
        (uint64_t)address - allocation->base <= allocation->size &&
        extent <= allocation->size - ((uint64_t)address - allocation->base);
  }}''' for i in range(capacity))
    return {
        'declarations': '''typedef struct spx_proof_allocation {
  uint32_t base, size, family, owner, generation, live, zero_initialized;
  uint32_t write_floor, shadow_floor;
  uint32_t native_rule_selector, native_generation, birth_class_selector;
} spx_proof_allocation;''',
        'world_fields': f'''  uint32_t allocation_count, input_allocation_count;
  spx_proof_allocation allocations[{capacity}];''',
        'helpers': f'''
static uint8_t spx_proof_initial_byte(uint32_t);
uint8_t __CPROVER_uninterpreted_spx_allocation_byte(uint32_t generation, uint32_t offset);

static uint32_t spx_proof_allocation_overlap(
    uint64_t base, uint64_t size, uint64_t other, uint64_t other_size) {{
  return base == other || (base < other + other_size && other < base + size);
}}

static uint32_t spx_proof_allocation_at(const spx_proof_world *world, uint32_t address) {{
{lookup}
  return UINT32_MAX;
}}

static spx_proof_allocation spx_proof_allocation_snapshot(
    const spx_proof_world *world, uint32_t index) {{
  /* Selection observes one record without retaining a symbolic pointer into
     the whole history. Every arm uses a statically bounded array element. */
{chr(10).join(f'  if (index == UINT32_C({i})) return world->allocations[{i}];' for i in range(capacity))}
  __CPROVER_assert(0, "spx-bisimulation-allocation-selection");
  return (spx_proof_allocation){{0}};
}}

static spx_boundary_status spx_proof_allocate(
    spx_proof_world *world, uint32_t base, uint32_t size,
    uint32_t family, uint32_t owner, uint32_t zero_initialized) {{
  spx_proof_origins *origins = spx_proof_origins_for(world);
  uint32_t position;
  if (origins == 0 || family == UINT32_C(0) || zero_initialized > UINT32_C(1))
    return SPX_BOUNDARY_TYPE_MISMATCH;
  if (base == UINT32_C(0)) return SPX_BOUNDARY_OK;
  if ((uint64_t)base + size > UINT64_C(4294967296) ||
      (base >= world->private_low && base < world->private_high) ||
      ((uint64_t)base < world->private_high &&
       (uint64_t)world->private_low < (uint64_t)base + size))
    return SPX_BOUNDARY_MEMORY_FAULT;
  position = world->allocation_count;
  if (position >= UINT32_C({capacity})) return SPX_BOUNDARY_MEMORY_FAULT;
{image}
{protected}
{overlaps}
{borrowed}
  world->allocations[position] = (spx_proof_allocation){{
    base, size, family, owner, position + UINT32_C(2), UINT32_C(1), zero_initialized,
    world->write_count, world->shadow_count, UINT32_C(0), UINT32_C(0), UINT32_C(0)
  }};
  world->allocation_count = position + UINT32_C(1);
  return SPX_BOUNDARY_OK;
}}

static spx_boundary_status spx_proof_release_allocation(
    spx_proof_world *world, uint32_t base, uint32_t family, uint32_t owner,
    uint32_t succeeded) {{
  if (spx_proof_origins_for(world) == 0 || family == UINT32_C(0) || succeeded > UINT32_C(1))
    return SPX_BOUNDARY_TYPE_MISMATCH;
  if (base == UINT32_C(0)) return SPX_BOUNDARY_OK;
{release}
  return SPX_BOUNDARY_MEMORY_FAULT;
}}

static spx_boundary_status spx_proof_allocation_input_admitted(
    const spx_proof_allocation *history, uint32_t count,
    uint32_t private_low, uint32_t private_high, const spx_proof_origins *origins,
    const spx_proof_allocation *input) {{
  /* One metadata predicate for construction and predecessor admission. An
     empty incoming origin registry is represented by origins == 0. */
  if (input == 0 || (count != UINT32_C(0) && history == 0) ||
      input->base == UINT32_C(0) || input->family == UINT32_C(0) ||
      input->live > UINT32_C(1) || input->zero_initialized > UINT32_C(1) ||
      ((input->native_rule_selector == UINT32_C(0)) !=
       (input->native_generation == UINT32_C(0))))
    return SPX_BOUNDARY_TYPE_MISMATCH;
  if (count >= UINT32_C({capacity})) return SPX_BOUNDARY_MEMORY_FAULT;
  if (input->generation != count + UINT32_C(2)) return SPX_BOUNDARY_TYPE_MISMATCH;
  const uint32_t base = input->base, size = input->size;
  if ((uint64_t)base + size > UINT64_C(4294967296) ||
      (base >= private_low && base < private_high) ||
      ((uint64_t)base < private_high && (uint64_t)private_low < (uint64_t)base + size) ||
      (input->native_rule_selector != UINT32_C(0) && base > UINT32_MAX - size))
    return SPX_BOUNDARY_MEMORY_FAULT;
{image}
{protected}
{overlaps.replace('world->allocation_count', 'count').replace('world->allocations', 'history')}
  if (origins != 0) {{
{borrowed}
  }}
{chr(10).join(f'''  if (count > UINT32_C({i}) && input->native_generation != UINT32_C(0) &&
      history[{i}].native_generation == input->native_generation)
    return SPX_BOUNDARY_TYPE_MISMATCH;''' for i in range(capacity))}
  return SPX_BOUNDARY_OK;
}}

static spx_boundary_status spx_proof_restore_allocation_input(
    spx_proof_world *world, const spx_proof_allocation *input) {{
  /* Constructor for a region's incoming lifetime state, not an allocating
     service or authority grant. Its caller owes the predecessor relation.
     Restore histories before decoding views or executing any region effects. */
  if (spx_proof_origins_for(world) == 0 || input == 0 ||
      world->allocation_count != world->input_allocation_count ||
      world->write_count != UINT32_C(0) || world->shadow_count != UINT32_C(0) ||
      world->private_write_count != UINT32_C(0) || world->call_count != UINT32_C(0) ||
      world->atomic_count != UINT32_C(0))
    return SPX_BOUNDARY_TYPE_MISMATCH;
  spx_boundary_status status = spx_proof_allocation_input_admitted(world->allocations,
      world->allocation_count, world->private_low, world->private_high,
      spx_proof_origins_for(world), input);
  if (status != SPX_BOUNDARY_OK) return status;
  const spx_proof_allocation saved = *input;
  status = spx_proof_allocate(world, saved.base, saved.size,
      saved.family, saved.owner, saved.zero_initialized);
  if (status != SPX_BOUNDARY_OK) return status;
  spx_proof_allocation *restored = &world->allocations[world->allocation_count - UINT32_C(1)];
  *restored = saved;
  restored->write_floor = UINT32_C(0);
  restored->shadow_floor = UINT32_C(0);
  world->input_allocation_count = world->allocation_count;
  return SPX_BOUNDARY_OK;
}}

static uint32_t spx_proof_allocation_reference_generation(
    const spx_proof_world *world, uint32_t address, uint64_t extent,
    uint32_t one_past, uint64_t *generation) {{
  uint32_t index = spx_proof_allocation_at(world, address);
  if (index == UINT32_MAX && extent == UINT64_C(0) && one_past) {{
    do {{
{one_past}
    }} while (0);
  }}
  if (index != UINT32_MAX) {{
    const spx_proof_allocation snapshot = spx_proof_allocation_snapshot(world, index);
    const spx_proof_allocation *allocation = &snapshot;
    if (!allocation->live || address < allocation->base ||
        (uint64_t)address - allocation->base > allocation->size ||
        extent > allocation->size - ((uint64_t)address - allocation->base))
      return UINT32_C(0);
    *generation = allocation->generation;
    return UINT32_C(1);
  }}
{spanning}
  *generation = UINT64_C(1);
  return UINT32_C(1);
}}

static uint32_t spx_proof_allocation_access(
    const spx_proof_world *world, uint32_t address, uint32_t width) {{
  uint64_t generation;
  /* Validate the whole span: adjacent live objects do not form one object. */
  return spx_proof_allocation_reference_generation(world, address, width, UINT32_C(0),
                                                   &generation);
}}

static uint32_t spx_proof_allocation_reference_live(
    const spx_proof_world *world, uint32_t address, uint64_t extent,
    uint64_t generation, uint32_t one_past) {{
  if (generation == UINT64_C(1)) {{
    uint64_t current;
    return spx_proof_allocation_reference_generation(world, address, extent, one_past, &current) &&
        current == UINT64_C(1);
  }}
{live_reference}
  return UINT32_C(0);
}}

static uint32_t spx_proof_allocation_history_visible(
    const spx_proof_world *world, uint32_t position, uint32_t address, uint32_t shadow) {{
  uint32_t index = spx_proof_allocation_at(world, address);
  if (index == UINT32_MAX) return UINT32_C(1);
  const spx_proof_allocation snapshot = spx_proof_allocation_snapshot(world, index);
  const spx_proof_allocation *allocation = &snapshot;
  return allocation->live && position >= (shadow ? allocation->shadow_floor : allocation->write_floor);
}}

static uint8_t spx_proof_allocation_initial_byte(
    const spx_proof_world *world, uint32_t address) {{
  uint32_t index = spx_proof_allocation_at(world, address);
  if (index == UINT32_MAX) return spx_proof_initial_byte(address);
  const spx_proof_allocation snapshot = spx_proof_allocation_snapshot(world, index);
  const spx_proof_allocation *allocation = &snapshot;
  if (!allocation->live) return UINT8_C(0);
  /* Initialization describes the birth event. Imported live storage contains
     arbitrary current input bytes, including writes made before the cut. */
  if (index < world->input_allocation_count) return spx_proof_initial_byte(address);
  if (allocation->zero_initialized) return UINT8_C(0);
  return __CPROVER_uninterpreted_spx_allocation_byte(allocation->generation, address - allocation->base);
}}

static uint32_t spx_proof_allocation_instance_equal(
    const spx_proof_allocation *left, const spx_proof_allocation *right) {{
  /* Write/shadow floors locate history; equivalent write widths can differ. */
  return left->base == right->base && left->size == right->size &&
      left->family == right->family && left->owner == right->owner &&
      left->generation == right->generation && left->live == right->live &&
      left->zero_initialized == right->zero_initialized &&
      left->native_rule_selector == right->native_rule_selector &&
      left->native_generation == right->native_generation &&
      left->birth_class_selector == right->birth_class_selector;
}}

static uint32_t spx_proof_allocation_states_equal(void) {{
  if (spx_exact_world.allocation_count != spx_source_world.allocation_count) return UINT32_C(0);
{equality}
  return UINT32_C(1);
}}

uint32_t spx_proof_world_allocation_cut_admitted(void) {{
  /* Resumed regions currently start with empty allocation histories. Equality
     of two nonempty histories at the predecessor cannot justify that reset.
     Retired instances matter too: dropping them can revive stale references.
     Replace this admission rule only with checked incoming lifetime transport. */
  return spx_exact_world.allocation_count == UINT32_C(0) &&
      spx_source_world.allocation_count == UINT32_C(0);
}}
''',
    }


def allocation_configuration(*, specs, max_calls, maximum_inputs, max_nul_views,
                             reference_capacity, authority_payload, inventory,
                             requirements, private_ranges, immutable_bytes, image_size,
                             runtime_assurance=None):
    """Bind one capacity to lifetime storage, native adapters and frame checks."""
    from .bisimulation_call_allocation import allocation_call_fragments
    from .bisimulation_reference_authority import checked_reference_authority, reference_authority_source
    from .bisimulation_reference_origins import checked_capacity

    if type(maximum_inputs) is not int or not 0 <= maximum_inputs < 0xffffffff:
        raise BisimulationRefinementError("incoming allocation capacity is malformed")
    capacity = max_calls + maximum_inputs
    if type(capacity) is not int or not 0 < capacity < 0xffffffff:
        raise BisimulationRefinementError("combined allocation capacity is malformed")
    authority = checked_reference_authority(authority_payload)
    origin_capacity = checked_capacity(reference_capacity,
        4 + 2 * capacity + max_nul_views + (len(authority.rules) if authority is not None else 0))
    calls = allocation_call_fragments(specs=specs, authority=authority,
        inventory=inventory, capacity=capacity, requirements=requirements)
    native = reference_authority_source(authority_payload, image_size=image_size,
        allocation_capacity=capacity, runtime_inventory=inventory,
        allocation_requirements=requirements, runtime_assurance=runtime_assurance,
        reference_capacity=origin_capacity)
    allocations = allocation_fragments(capacity=capacity, reference_capacity=origin_capacity,
        private_ranges=private_ranges, immutable_bytes=immutable_bytes, image_size=image_size)
    return calls, native, allocations, origin_capacity, capacity
