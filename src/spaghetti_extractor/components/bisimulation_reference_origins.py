"""Issued logical origins and their physical storage/lifetime correspondence."""

from typing import Mapping
from .bisimulation_support import BisimulationRefinementError


def parse_capacity(value):
    if type(value) is not int or not 1 <= value <= 0xffffffff:
        raise ValueError("reference origin capacity must be a positive uint32")
    return value


def checked_capacity(requested, default):
    """Tighten proof storage without removing its overflow assertions."""
    if requested is None:
        return default
    from .bisimulation_support import BisimulationRefinementError
    try:
        capacity = parse_capacity(requested)
        if capacity > default:
            raise ValueError(f"reference origin capacity exceeds the derived bound {default}")
    except ValueError as error:
        raise BisimulationRefinementError(str(error)) from error
    return capacity


def capacity_description(value=None):
    return "spx-bisimulation-reference-capacity" + ("" if value is None else f":{parse_capacity(value)}")


def validate_capacity_binding(operation, planned):
    field = "reference_origin_capacity"
    present = field in operation
    capacity = parse_capacity(operation[field]) if present else None
    for row in [planned, *operation["obligation_models"]]:
        if (field in row) != present or (present and parse_capacity(row[field]) != capacity):
            raise ValueError("reference origin capacity differs between plan, operation and segment")
    if present and any(capacity_description(capacity) not in model["required_assertion_descriptions"]
                       for model in operation["obligation_models"]):
        raise ValueError("reference origin capacity lacks its required overflow assertion")


def origin_declarations(capacity: int) -> str:
    return f"""typedef struct spx_proof_origin {{
  uint64_t domain, object, generation, extent, lifetime_generation;
  uint32_t base, permissions;
}} spx_proof_origin;
typedef struct spx_proof_origins {{
  uint32_t count;
  spx_proof_origin entries[{capacity}];
}} spx_proof_origins;"""


def reference_source(*, reference_capacity, nul_extent_cases, reference_private_check, capacity_claim=None):
    # The existing capacity assertion and failure return dominate these stores.
    # Keep indices constant so symbolic counts do not select an entire record
    # array in the solver. The count advances once, after the selected append.
    append_cases = []
    for i in range(reference_capacity):
        prefix = '  '
        if reference_capacity != 1:
            prefix += (f'{"if" if i == 0 else "else if"} (origins->count == UINT32_C({i})) '
                       if i < reference_capacity - 1 else 'else ')
        append_cases.append(prefix + f'origins->entries[{i}] = incoming;')
    append_cases = '\n'.join(append_cases)
    record_cases = '\n'.join(f'''
  if (origins->count > UINT32_C({i})) {{
    const spx_proof_origin *existing = &origins->entries[{i}];
    if (existing->domain == reference->domain && existing->object == reference->object &&
        existing->generation == reference->generation) {{
      /* One logical identity cannot move or revive after its lifetime ended. */
      if (existing->base != address || existing->lifetime_generation != lifetime_generation)
        return SPX_BOUNDARY_TYPE_MISMATCH;
      if (existing->extent == extent && existing->permissions == reference->permissions)
        return SPX_BOUNDARY_OK;
    }}
  }}''' for i in range(reference_capacity))
    lookup_cases = '\n'.join(f'''
  if (origins->count > UINT32_C({i})) {{
    const spx_proof_origin *candidate = &origins->entries[{i}];
    if (candidate->domain == reference->domain) {{
      known_domain = UINT32_C(1);
      if (candidate->object == reference->object) {{
        known_object = UINT32_C(1);
        if (candidate->generation == reference->generation) {{
          known_generation = UINT32_C(1);
          if (candidate->extent == reference->extent && candidate->permissions == reference->permissions) {{
            selected = *candidate;
            selected_valid = UINT32_C(1);
          }}
        }}
      }}
    }}
  }}''' for i in range(reference_capacity))
    return f"""
static spx_boundary_status spx_proof_record_reference_origin(
    spx_proof_world *world, uint32_t physical_address,
    const spx_machine_reference_v1 *reference, uint32_t one_past) {{
  spx_proof_origins *origins = spx_proof_origins_for(world);
  uint32_t address;
  uint64_t extent, lifetime_generation;
  if (origins == 0 || reference == 0 || reference->domain == UINT64_C(0) ||
      reference->object == UINT64_C(0) || reference->generation == UINT64_C(0))
    return SPX_BOUNDARY_TYPE_MISMATCH;
  if (reference->offset > physical_address || reference->offset > reference->extent)
    return SPX_BOUNDARY_MEMORY_FAULT;
  address = physical_address - (uint32_t)reference->offset;
  extent = reference->extent;
  if (address == UINT32_C(0) || extent > UINT64_C(4294967296) - address)
    return SPX_BOUNDARY_MEMORY_FAULT;
{reference_private_check}
    return SPX_BOUNDARY_MEMORY_FAULT;
  if (!spx_proof_allocation_reference_generation(world, address, extent, one_past, &lifetime_generation))
    return SPX_BOUNDARY_EXPIRED;
{record_cases}
  __CPROVER_assert(origins->count < UINT32_C({reference_capacity}),
      "{capacity_description(capacity_claim)}");
  if (origins->count >= UINT32_C({reference_capacity})) return SPX_BOUNDARY_MEMORY_FAULT;
  const spx_proof_origin incoming = {{
    reference->domain, reference->object, reference->generation, extent, lifetime_generation,
    address, reference->permissions
  }};
{append_cases}
  ++origins->count;
  return SPX_BOUNDARY_OK;
}}

static spx_boundary_status spx_proof_resolve_reference(
    void *opaque, uint32_t address, uint32_t requested, uint32_t permissions,
    const char *selector, uint32_t nullable, uint32_t one_past,
    spx_machine_reference_v1 *result) {{
  spx_proof_world *world = (spx_proof_world *)opaque;
  uint64_t extent = (uint64_t)requested;
  uint64_t generation;
  (void)selector;
  if (spx_proof_origins_for(opaque) == 0 || result == 0 || (address == 0U && nullable == 0U))
    return SPX_BOUNDARY_MEMORY_FAULT;
  if (address == 0U) {{
    *result = (spx_machine_reference_v1){{0}};
    return SPX_BOUNDARY_OK;
  }}
{nul_extent_cases}
  if ((uint64_t)address + extent > UINT64_C(4294967296))
    return SPX_BOUNDARY_MEMORY_FAULT;
  if (!spx_proof_allocation_reference_generation(world, address, extent, one_past, &generation))
    return SPX_BOUNDARY_EXPIRED;
  *result = (spx_machine_reference_v1){{
    UINT64_C(1), address, generation, UINT64_C(0), extent, permissions
  }};
  return spx_proof_record_reference_origin(world, address, result, one_past);
}}

static spx_boundary_status spx_proof_realize_reference(
    void *opaque, const spx_machine_reference_v1 *reference,
    uint32_t permissions, uint32_t nullable, uint32_t one_past,
    uint32_t *address) {{
  spx_proof_origins *origins = spx_proof_origins_for(opaque);
  /* Selection reads the registry without modifying it. Copy the record so the
     subsequent scalar checks do not retain a symbolic pointer into the table.
     Lifetime is still checked against the current world after selection. */
  spx_proof_origin selected = {{0}};
  uint32_t selected_valid = UINT32_C(0);
  uint32_t known_domain = UINT32_C(0), known_object = UINT32_C(0), known_generation = UINT32_C(0);
  if (origins == 0 || reference == 0 || address == 0)
    return SPX_BOUNDARY_MEMORY_FAULT;
  if (reference->domain == UINT64_C(0) && reference->object == UINT64_C(0)) {{
    if (nullable == 0U || reference->generation != UINT64_C(0) ||
        reference->offset != UINT64_C(0) || reference->extent != UINT64_C(0) ||
        reference->permissions != UINT32_C(0))
      return SPX_BOUNDARY_MEMORY_FAULT;
    *address = UINT32_C(0);
    return SPX_BOUNDARY_OK;
  }}
{lookup_cases}
  if (known_domain == UINT32_C(0)) return SPX_BOUNDARY_TYPE_MISMATCH;
  if (known_object != UINT32_C(0) && known_generation == UINT32_C(0)) return SPX_BOUNDARY_EXPIRED;
  if (selected_valid == UINT32_C(0)) return SPX_BOUNDARY_MEMORY_FAULT;
  if (!spx_proof_allocation_reference_live((spx_proof_world *)opaque,
          selected.base, selected.extent, selected.lifetime_generation, one_past))
    return SPX_BOUNDARY_EXPIRED;
  if ((reference->permissions & permissions) != permissions ||
      reference->offset > reference->extent ||
      (reference->offset == reference->extent && one_past == 0U) ||
      reference->extent > UINT64_C(4294967296) - selected.base ||
      reference->offset > UINT32_MAX - selected.base)
    return SPX_BOUNDARY_MEMORY_FAULT;
  *address = selected.base + (uint32_t)reference->offset;
  return SPX_BOUNDARY_OK;
}}
"""


def logical_argument_physical_index(service_id: str, input_index: object, *, service_bindings) -> int:
    if (
        not isinstance(input_index, int)
        or isinstance(input_index, bool)
        or input_index < 0
    ):
        raise BisimulationRefinementError(
            "proof-world reference-result origin argument is malformed"
        )
    bindings = [
        binding
        for binding in service_bindings
        if binding.get("service_id") == service_id
        and binding.get("provider_kind") != "component_operation"
    ]
    physical_indices: set[int] = set()
    for binding in bindings:
        transducers = binding.get("argument_transducers")
        if transducers is None:
            physical_indices.add(int(input_index))
            continue
        for physical_index, transducer in enumerate(transducers):
            if (
                isinstance(transducer, Mapping)
                and transducer.get("kind") == "logical_argument"
                and transducer.get("parameter_index") == input_index
            ):
                physical_indices.add(physical_index)
    if (
        not bindings
        or len(physical_indices) != 1
    ):
        raise BisimulationRefinementError(
            "proof-world reference-result origin has no unique raw argument"
        )
    return next(iter(physical_indices))
