"""Explicit conditional projection of world allocation metadata into references."""

import re

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_assurance import runtime_contract_selected
from .bisimulation_support import BisimulationRefinementError


def world_reference_contract():
    return {
        "id": "world-reference-summary", "revision": 2,
        "authority_backends": ["x86-pe32", "x86-pe32-loader-relative-v2"],
        "locators": ["image_rva", "external_allocation"],
        "semantics": [
            "Use the checked image namespace and allocation-producer mapping.",
            "Validate allocation count, selector/generation pairing and live producer/family correspondence before lookup.",
            "Resolve against image rules and current live native allocation instances without constructing a context table.",
            "Preserve unknown-selector, ambiguity, missing-instance and expired-generation outcomes.",
            "Preserve native identity, extent, permissions, null, interior-pointer, one-past and PE32 overflow rules.",
            "Context checks and pure lookups neither issue origins nor change bytes, lifetimes or observable effects.",
            "Runtime wrappers retain class qualification and origin issuance; memory-fact observers use pure lookup.",
        ],
        "authority": "Explicitly conditional namespace projection; no native activation.",
    }


def world_reference_assurance():
    contract = world_reference_contract()
    return {"kind": "conditional-runtime-contracts", "contracts": [{
        "id": contract["id"], "revision": contract["revision"],
        "contract_sha256": canonical_sha256_v3(contract),
    }]}


def world_reference_source(*, authority, capacity, image_size, prefix, assurance,
                           include_realization=True):
    contract = world_reference_contract()
    if not runtime_contract_selected(assurance, contract["id"]):
        raise BisimulationRefinementError("world reference projection requires its implemented contract")
    if (authority is None or authority.machine_backend not in contract["authority_backends"]
            or any(rule.locator.kind not in contract["locators"] for rule in authority.rules)):
        raise BisimulationRefinementError("world reference projection requires image/allocation PE32 authority")
    if (type(capacity) is not int or not 0 < capacity < 0xffffffff
            or len(authority.rules) * capacity >= 0xffffffff
            or type(image_size) is not int or not 0 < image_size <= 0xffffffff
            or type(include_realization) is not bool):
        raise BisimulationRefinementError("world reference projection bounds are unsupported")
    if not isinstance(prefix, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", prefix):
        raise BisimulationRefinementError("world reference projection prefix is malformed")
    dynamic = [i for i, rule in enumerate(authority.rules) if rule.locator.kind == 'external_allocation']
    digest = world_reference_assurance()['contracts'][0]['contract_sha256']
    lines = [f'#ifndef SPX_CONDITIONAL_RUNTIME_CONTRACT_{digest}',
             '#error "world reference projection requires explicitly conditional obligation execution"', '#endif',
             f'static spx_boundary_status {prefix}_world_context_status(const spx_proof_world *world) {{',
             '  if (spx_proof_origins_for((void *)world) == 0) return SPX_BOUNDARY_UNSUPPORTED;',
             f'  if (world->allocation_count > {capacity}U) return SPX_BOUNDARY_MEMORY_FAULT;']
    for slot in range(capacity):
        row = f'world->allocations[{slot}]'
        accepted = ' || '.join(
            f'({row}.native_rule_selector == {i+1}U && spx_proof_allocation_producers[{i}].namespace_selector != 0U && '
            f'{prefix}_object_authority_rules[{i}].locator_subject_rva == spx_proof_allocation_producers[{i}].namespace_selector && '
            f'{row}.family == spx_proof_allocation_producers[{i}].proof_family)' for i in dynamic) or '0U'
        lines += [f'  if (world->allocation_count > {slot}U) {{',
                  f'    if (({row}.native_rule_selector == 0U) != ({row}.native_generation == 0U))',
                  '      return SPX_BOUNDARY_TYPE_MISMATCH;',
                  f'    if ({row}.live && {row}.native_rule_selector != 0U && !({accepted}))',
                  '      return SPX_BOUNDARY_TYPE_MISMATCH;', '  }']
    lines += ['  return SPX_BOUNDARY_OK;', '}']
    candidates = []
    for i in range(len(authority.rules)):
        rule = f'{prefix}_object_authority_rules[{i}]'
        for slot in range(capacity) if i in dynamic else (None,):
            tag = f'{i}_{slot}' if slot is not None else str(i)
            if slot is None:
                base, size, generation = f'(SPX_PROOF_IMAGE_BASE + {rule}.locator_offset)', f'{rule}.extent', f'{rule}.generation'
                terms = [f'{size} != 0U', f'{rule}.locator_offset <= UINT32_C({image_size})',
                    f'{size} <= UINT32_C({image_size}) - {rule}.locator_offset',
                    f'SPX_PROOF_IMAGE_BASE <= UINT32_MAX - {rule}.locator_offset', f'{size} <= UINT32_MAX - {base}']
            else:
                row = f'world->allocations[{slot}]'
                base = f'({row}.base + {rule}.locator_offset)'
                size = f'({rule}.extent_mode == 1U ? {row}.size - {rule}.locator_offset : {rule}.extent)'
                generation = f'{row}.native_generation'
                object_id = '(' + ''.join(f'{row}.native_rule_selector == {k+1}U ? {prefix}_object_authority_rules[{k}].object_id : ' for k in dynamic) + '0U)'
                selector = '(' + ''.join(f'{row}.native_rule_selector == {k+1}U ? spx_proof_allocation_producers[{k}].namespace_selector : ' for k in dynamic) + '0U)'
                terms = [f'world->allocation_count > {slot}U', f'{row}.live', f'{row}.native_rule_selector != 0U',
                    f'{rule}.extent_mode <= 1U', f'{generation} != 0U', f'{rule}.locator_subject_rva != 0U',
                    f'{selector} == {rule}.locator_subject_rva', f'{object_id} == {rule}.object_id',
                    f'{rule}.locator_offset <= {row}.size', f'{rule}.extent <= {row}.size - {rule}.locator_offset',
                    f'{row}.base <= UINT32_MAX - {rule}.locator_offset', f'{base} <= UINT32_MAX - {size}']
            candidates.append((i, tag, rule, base, size, generation, terms))
    lines += [f'static spx_boundary_status {prefix}_world_resolve_reference(',
        '    void *opaque, uint32_t address, uint32_t requested_extent, uint32_t permissions,',
        '    const char *authority_selector, uint32_t nullable, uint32_t allow_one_past, spx_machine_reference_v1 *result) {',
        '  const spx_proof_world *world = (const spx_proof_world *)opaque;',
        '  if (spx_proof_origins_for((void *)world) == 0 || result == 0) return SPX_BOUNDARY_UNSUPPORTED;',
        '  if (address == 0U) {', '    if (nullable == 0U) return SPX_BOUNDARY_MEMORY_FAULT;',
        '    result->domain = result->object = result->generation = 0U;',
        '    result->offset = result->extent = 0U; result->permissions = 0U;', '    return SPX_BOUNDARY_OK;', '  }',
        '  uint32_t known = authority_selector == 0, count = 0U, base = 0U, extent = 0U, allowed = 0U;',
        '  uint64_t domain = 0U, object = 0U, generation = 0U;']
    for i in range(len(authority.rules)):
        lines += [f'  uint32_t selected_{i} = authority_selector == 0 || {prefix}_object_rule_identity_equal(authority_selector, {prefix}_object_authority_rules[{i}].identity);',
                  f'  known |= selected_{i};']
    for i, tag, rule, base, size, generation, terms in candidates:
        offset, end = f'(address - {base})', f'({base} + {size})'
        predicates = [f'selected_{i}', *terms,
            f'((address >= {base} && address < {end}) || (allow_one_past != 0U && {rule}.interior_pointers != 0U && address == {end}))',
            f'({offset} == 0U || {rule}.interior_pointers != 0U)', f'requested_extent <= {size} - {offset}',
            f'({rule}.permissions & permissions) == permissions']
        lines += [f'  uint32_t match_{tag} = ' + ' && '.join('('+term+')' for term in predicates) + ';', f'  count += match_{tag};']
        lines += [f'  {name} |= match_{tag} ? {value} : 0U;' for name, value in (
            ('base', base), ('extent', size), ('generation', generation), ('allowed', f'{rule}.permissions'),
            ('domain', f'{rule}.domain'), ('object', f'{rule}.object_id'))]
    lines += ['  if (!known) return SPX_BOUNDARY_TYPE_MISMATCH;', '  if (count == 0U) return SPX_BOUNDARY_MEMORY_FAULT;',
        '  if (count != 1U) return SPX_BOUNDARY_TYPE_MISMATCH;',
        '  result->domain = domain; result->object = object; result->generation = generation;',
        '  result->offset = address - base; result->extent = extent; result->permissions = allowed;',
        '  return SPX_BOUNDARY_OK;', '}']
    if include_realization:
        lines += [f'static spx_boundary_status {prefix}_world_realize_reference(',
            '    void *opaque, const spx_machine_reference_v1 *reference, uint32_t permissions,',
            '    uint32_t nullable, uint32_t allow_one_past, uint32_t *address) {',
            '  const spx_proof_world *world = (const spx_proof_world *)opaque;',
            '  if (spx_proof_origins_for((void *)world) == 0 || reference == 0 || address == 0) return SPX_BOUNDARY_UNSUPPORTED;',
            '  if (reference->domain == 0U && reference->object == 0U) {',
            '    if (nullable == 0U || reference->generation != 0U || reference->offset != 0U ||',
            '        reference->extent != 0U || reference->permissions != 0U) return SPX_BOUNDARY_MEMORY_FAULT;',
            '    *address = 0U; return SPX_BOUNDARY_OK;', '  }',
            '  uint32_t found = 0U, dynamic_seen = 0U, base = 0U, extent = 0U, allowed = 0U, interior = 0U;',
            '  uint64_t generation = 0U;']
        for i in dynamic:
            lines.append(f'  dynamic_seen |= {prefix}_object_authority_rules[{i}].domain == reference->domain;')
        for i, tag, rule, base, size, generation, terms in candidates:
            predicates = [f'{rule}.domain == reference->domain && {rule}.object_id == reference->object', *terms]
            if i in dynamic:
                predicates.append(f'{generation} == reference->generation')
            lines += [f'  uint32_t match_{tag} = ' + ' && '.join('('+term+')' for term in predicates) + ';', f'  found += match_{tag};']
            lines += [f'  {name} |= match_{tag} ? {value} : 0U;' for name, value in (
                ('base', base), ('extent', size), ('generation', generation), ('allowed', f'{rule}.permissions'), ('interior', f'{rule}.interior_pointers'))]
        lines += ['  if (found == 0U && dynamic_seen != 0U) return SPX_BOUNDARY_EXPIRED;',
            '  if (found != 1U) return SPX_BOUNDARY_TYPE_MISMATCH;', '  if (reference->generation != generation) return SPX_BOUNDARY_EXPIRED;',
            '  if (reference->extent != extent || reference->permissions != allowed ||',
            '      reference->offset > extent || (reference->offset != 0U && interior == 0U) ||',
            '      (reference->offset == extent && (allow_one_past == 0U || interior == 0U)) ||',
            '      (allowed & permissions) != permissions || reference->offset > UINT32_MAX - base)',
            '    return SPX_BOUNDARY_MEMORY_FAULT;', '  *address = base + (uint32_t)reference->offset;',
            '  return SPX_BOUNDARY_OK;', '}']
    return '\n'.join(lines)+'\n'
