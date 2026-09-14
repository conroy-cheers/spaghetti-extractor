"""Native object authority in the existing contextual proof world.

Resolution uses the native runtime implementation. Image locators have the
same checked realization; local allocations require checked allocating calls.
Incoming runtime/caller locators still require qualified lifetime evidence.
"""

import json
from collections.abc import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..semantic_objects.object_authority import MachineObjectAuthorityV2, MachineObjectAuthorityError
from ..transfer.reference_namespace import reference_namespace_source
from .bisimulation_support import BisimulationRefinementError
from .bisimulation_allocation_authority import allocation_authority_source, allocation_runtime_admission_source
from .bisimulation_allocation_namespace import allocation_namespace_producers
from .bisimulation_allocation_classes import checked_allocation_requirements


PREFIX = "spx_proof_authority"
LOCATOR_CODES = {"image_rva": 1, "tls_offset": 2, "resolved_data_import": 3,
                 "captured_stack": 4, "external_allocation": 5, "resource": 6}


def checked_reference_authority(value):
    if value is None:
        return None
    try:
        authority = MachineObjectAuthorityV2.parse(value)
    except MachineObjectAuthorityError as exc:
        raise BisimulationRefinementError(f"proof reference authority: {exc}") from exc
    if any(rule.permissions > 0xffffffff for rule in authority.rules):
        raise BisimulationRefinementError("proof reference authority permissions exceed the runtime ABI")
    return authority


def reference_authority_unwind_arguments(value, *, allocation_capacity=1):
    if type(allocation_capacity) is not int or not 0 < allocation_capacity < 0xffffffff:
        raise BisimulationRefinementError("proof reference authority allocation capacity is malformed")
    authority = checked_reference_authority(value)
    if authority is None or not authority.rules:
        return []
    bounds = {
        f"{PREFIX}_object_rule_identity_equal.0": max((len(r.identity.encode('utf-8'))
                                                      for r in authority.rules), default=0) + 1,
        # CBMC numbers the nested external-range loop before the rule loop.
        # Keep the former rule-count floor for unchanged small worlds, but
        # admit every represented instance even when they share one class.
        **{f"{PREFIX}_{function}.{index}": max(len(authority.rules),
                allocation_capacity if index == 0 else 1) + 1
           for function in ("resolve_reference", "realize_reference") for index in (0, 1)},
    }
    return ["--unwindset", ','.join(f'{key}:{value}' for key, value in sorted(bounds.items()))]


def reference_authority_bound(models, world):
    authority = checked_reference_authority(models.get("reference_authority"))
    requirements = checked_allocation_requirements(authority, models.get('reference_allocation_requirements'))
    if models.get('reference_allocation_requirements_sha256') != (
            None if requirements is None else canonical_sha256_v3(requirements)):
        return False
    bindings = world.get("bindings", {})
    return (authority is not None and isinstance(bindings, Mapping) and
            authority.authority_sha256 == bindings.get("machine_object_authority_sha256"))


def reference_authority_source(value, *, image_size, allocation_capacity=1, runtime_inventory=None,
                               allocation_requirements=None, runtime_assurance=None,
                               reference_capacity=None):
    from .bisimulation_assurance import runtime_contract_selected
    issued = runtime_contract_selected(runtime_assurance, "issued-reference-access")
    projected = runtime_contract_selected(runtime_assurance, "world-reference-summary")
    authority = checked_reference_authority(value)
    if authority is None:
        if issued or projected:
            raise BisimulationRefinementError('conditional access needs checked reference authority')
        if allocation_requirements is not None:
            raise BisimulationRefinementError('allocation requirements need their canonical object authority')
        return ""
    if type(image_size) is not int or not 0 < image_size <= 0xffffffff:
        raise BisimulationRefinementError("proof reference authority requires its checked image extent")
    if type(allocation_capacity) is not int or not 0 < allocation_capacity < 0xffffffff:
        raise BisimulationRefinementError("proof reference authority allocation capacity is malformed")
    producers = allocation_namespace_producers(authority, inventory=runtime_inventory, requirements=allocation_requirements)
    rows = []
    resolve_guards, realize_guards = [], []
    for selector, rule in enumerate(authority.rules, 1):
        producer = producers[selector - 1]
        allocation_selector = 0 if producer is None else producer["selector"]
        rows.append('  {' + ', '.join((json.dumps(rule.identity), f'UINT64_C({rule.domain})',
            f'UINT64_C({rule.object_id})', f'UINT64_C({rule.generation})',
            f'UINT32_C({rule.extent})', f'UINT32_C({rule.permissions})',
            f'UINT32_C({LOCATOR_CODES[rule.locator.kind]})', f'UINT32_C({rule.locator.offset})',
            f'UINT32_C({allocation_selector})',
            f'UINT32_C({int(rule.interior_pointers)})',
            f'UINT32_C({int(rule.extent_mode == "instance_remainder")})')) + '}')
        if rule.locator.kind != "image_rva":
            qualified = (f'spx_proof_allocation_class_locally_born((spx_proof_world *)opaque, UINT32_C({selector}))'
                         if rule.locator.kind == 'external_allocation' else '0U')
            resolve_guards.append(f'''  if (address != 0U && (selector == 0 ||
      {PREFIX}_object_rule_identity_equal(selector, {json.dumps(rule.identity)})))
    spx_proof_reference_locator_qualified({qualified});''')
            realize_guards.append(f'''  if (reference != 0 && reference->domain == UINT64_C({rule.domain}) &&
      reference->object == UINT64_C({rule.object_id}))
    spx_proof_reference_locator_qualified({qualified});''')
    declarations = f'''
typedef struct {{
  const char *identity;
  uint64_t domain, object_id, generation;
  uint32_t extent, permissions, locator_kind, locator_offset;
  uint32_t locator_subject_rva, interior_pointers, extent_mode;
}} {PREFIX}_object_authority_rule;
typedef struct {{
  uint32_t start, size, generation, external_range_rule_selector;
  uint64_t object_id;
}} {PREFIX}_external_range;
typedef struct {{
  uint32_t image_base, image_size, external_range_count;
  {PREFIX}_external_range external_ranges[{allocation_capacity}];
}} {PREFIX}_context;
static const {PREFIX}_object_authority_rule {PREFIX}_object_authority_rules[] = {{
{','.join(rows) if rows else '  {0}'}
}};
static const uint32_t {PREFIX}_object_authority_rule_count = UINT32_C({len(rows)});

static void spx_proof_reference_locator_qualified(uint32_t qualified) {{
  __CPROVER_assert(qualified, "spx-bisimulation-reference-locator-qualified");
  __CPROVER_assume(qualified);
}}
'''
    if not projected:
        declarations += _native_reference_helpers()
    context_setup = (f'spx_boundary_status status = {PREFIX}_world_context_status((spx_proof_world *)opaque);'
        if projected else f'{PREFIX}_context context;\n  spx_boundary_status status = spx_proof_allocation_authority_context((spx_proof_world *)opaque, &context);')
    lookup_prefix = PREFIX + ('_world' if projected else '')
    lookup_context = 'opaque' if projected else '&context'
    wrappers = f'''
static spx_boundary_status spx_proof_authority_runtime_resolve(
    void *opaque, uint32_t address, uint32_t requested, uint32_t permissions,
    const char *selector, uint32_t nullable, uint32_t one_past,
    spx_machine_reference_v1 *result) {{
  if (spx_proof_origins_for(opaque) == 0 || result == 0) return SPX_BOUNDARY_UNSUPPORTED;
  {context_setup}
  if (status != SPX_BOUNDARY_OK) return status;
{chr(10).join(resolve_guards)}
  status = {lookup_prefix}_resolve_reference({lookup_context}, address, requested,
      permissions, selector, nullable, one_past, result);
  if (status != SPX_BOUNDARY_OK || address == 0U) return status;
  return spx_proof_record_reference_origin((spx_proof_world *)opaque, address, result, one_past);
}}
'''
    if issued:
        from .bisimulation_issued_access import issued_access_realization_source
        wrappers += issued_access_realization_source(authority=authority,
            reference_capacity=reference_capacity, realize_guards=realize_guards,
            assurance=runtime_assurance)
    else:
        wrappers += f'''static spx_boundary_status spx_proof_authority_runtime_realize(
    void *opaque, const spx_machine_reference_v1 *reference,
    uint32_t permissions, uint32_t nullable, uint32_t one_past, uint32_t *address) {{
  if (spx_proof_origins_for(opaque) == 0 || reference == 0 || address == 0)
    return SPX_BOUNDARY_UNSUPPORTED;
  {context_setup}
  if (status != SPX_BOUNDARY_OK) return status;
{chr(10).join(realize_guards)}
  status = {lookup_prefix}_realize_reference({lookup_context}, reference,
      permissions, nullable, one_past, address);
  if (status != SPX_BOUNDARY_OK || *address == 0U) return status;
  status = spx_proof_record_reference_origin((spx_proof_world *)opaque, *address, reference, one_past);
  if (status != SPX_BOUNDARY_OK) return status;
  return spx_proof_realize_reference(opaque, reference, permissions, nullable, one_past, address);
}}
'''
    projection = ""
    if projected:
        from .bisimulation_world_namespace import world_reference_source
        projection = world_reference_source(authority=authority, capacity=allocation_capacity,
            image_size=image_size, prefix=PREFIX, assurance=runtime_assurance,
            include_realization=not issued)
    inventory_identity = canonical_sha256_v3(runtime_inventory)
    namespace = (f"Supplied runtime allocation inventory: {inventory_identity}" if allocation_requirements is None else
                 f"Local allocation class namespace: {canonical_sha256_v3(allocation_requirements)}; native correspondence pending")
    return (f"/* {namespace}; instances require checked birth or transported class provenance. */\n" +
            declarations + reference_namespace_source(PREFIX, include_realization=not (issued or projected),
                include_resolution=not projected) +
            allocation_authority_source(prefix=PREFIX, capacity=allocation_capacity,
                rule_count=len(authority.rules), image_size=image_size, producers=producers,
                include_context=not projected) + projection +
            allocation_runtime_admission_source(capacity=allocation_capacity, authority=authority,
                admitted_classes={rule.identity for rule, producer in zip(authority.rules, producers)
                                  if producer is not None}) + wrappers)


def _native_reference_helpers():
    return f'''static uint32_t {PREFIX}_range_end(uint32_t start, uint32_t width, uint32_t *end) {{
  if (width == 0U || start > UINT32_MAX - width) return 0U;
  *end = start + width; return 1U;
}}
static uint32_t {PREFIX}_object_rule_base(
    const {PREFIX}_context *context, const {PREFIX}_object_authority_rule *rule,
    uint32_t *base, uint64_t *generation) {{
  uint32_t candidate;
  if (context == 0 || rule == 0 || base == 0 || generation == 0 || rule->extent == 0U)
    return 0U;
  spx_proof_reference_locator_qualified(rule->locator_kind == 1U);
  if (rule->locator_offset > context->image_size ||
      rule->extent > context->image_size - rule->locator_offset ||
      context->image_base > UINT32_MAX - rule->locator_offset)
    return 0U;
  candidate = context->image_base + rule->locator_offset;
  if (rule->extent > UINT32_MAX - candidate) return 0U;
  *base = candidate; *generation = rule->generation; return 1U;
}}
'''
