"""Find allocation premises used by a selected, proof-bound operation overlay.

Declarations alone are not dependencies. Calls and named object decoders select
classes; unresolved classes fail instead of silently losing a native premise.
"""

from collections.abc import Mapping

from .bisimulation_allocation_classes import checked_allocation_requirements
from .bisimulation_lifetime_namespace import checked_lifetime_call
from .bisimulation_reference_authority import checked_reference_authority
from .bisimulation_shared_composition import allocation_preserving_dependencies
from .bisimulation_support import BisimulationRefinementError
from .bisimulation_typed_services import _proof_call_specs


def allocation_dependencies(models, overlay):
    authority = checked_reference_authority(models.get('reference_authority'))
    requirements = checked_allocation_requirements(authority, models.get('reference_allocation_requirements')) or []
    if requirements and not allocation_preserving_dependencies(models):
        # Stateful callees can hide allocation and release sites. Their checked
        # transitive premises must be composed before this local projection can
        # establish the complete native requirements of the parent. A checked
        # framed image leaf preserves that history and contributes no classes.
        raise BisimulationRefinementError('connected allocation dependencies require transitive proof premises')
    classes = {row['authority']['id']: row for row in requirements}
    selectors = overlay.get('object_authority_selectors', {})
    if not isinstance(selectors, Mapping) or any(not isinstance(value, str) for value in selectors.values()):
        raise BisimulationRefinementError('allocation dependency selectors are malformed')
    allocation_ids = set() if authority is None else {
        rule.identity for rule in authority.rules if rule.locator.kind == 'external_allocation'}
    used = set(selectors.values()) & allocation_ids
    services = overlay.get('service_bindings', [])
    if not isinstance(services, list) or any(not isinstance(row, Mapping) for row in services):
        raise BisimulationRefinementError('allocation dependency service bindings are malformed')
    bindings = [row for row in services
                if isinstance(row.get('external_effect_contract'), Mapping) and
                row['external_effect_contract'].get('world_effect') in {'dynamicRanges', 'dynamicRangeRelease'}]
    specs = _proof_call_specs(bindings, allow_lifetime_effects=True)
    for spec in specs:
        effect = checked_lifetime_call(spec, inventory=None)
        if effect['action'] == 'add_result_range':
            matched = [row['authority']['id'] for row in requirements
                       if row['contract_identity_sha256'] == spec['external_contract_identity_sha256']]
            if len(matched) != 1:
                raise BisimulationRefinementError('allocation call has no unique required class')
        else:
            matched = [row['authority']['id'] for row in requirements
                       if row['effect']['ownership']['family'] == effect['ownership']['family']]
            if not matched:
                raise BisimulationRefinementError('release call has no required allocation family')
        used.update(matched)
    if used - set(classes):
        raise BisimulationRefinementError('selected allocation decoder lacks its class requirement')
    if not used:
        return None
    return {'reference_authority': authority.to_payload(),
            'requirements': [classes[identity] for identity in sorted(used)], 'call_specs': specs}
