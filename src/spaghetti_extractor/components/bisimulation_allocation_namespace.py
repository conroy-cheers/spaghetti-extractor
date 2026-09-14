"""Lower allocation classes into the proof's explicitly chosen namespace.

Local class ordinals are never advertised as final native selectors. Supplied
native inventories retain their existing numeric correspondence path; both use
the shared resolver and the same independent caller-qualification barriers.
"""

from .bisimulation_allocation_classes import checked_allocation_requirements
from .bisimulation_allocation_producers import allocation_producer_correspondence
from .bisimulation_support import BisimulationRefinementError


def allocation_namespace_producers(authority, *, inventory=None, requirements=None):
    if inventory is not None and requirements is not None:
        raise BisimulationRefinementError('allocation namespace cannot mix local requirements and native inventory')
    if requirements is None:
        return [None if row is None else {
            'selector': row['native_producer_selector'], 'family': row['native_family_selector'],
            'proof_family': row['proof_family_selector'],
        } for row in allocation_producer_correspondence(authority, inventory)]
    requirements = checked_allocation_requirements(authority, requirements)
    families = {family: index for index, family in enumerate(sorted({
        row['effect']['ownership']['family'] for row in requirements}), 1)}
    classes = {row['authority']['id']: {
        'selector': index,
        'family': families[row['effect']['ownership']['family']],
        'proof_family': families[row['effect']['ownership']['family']],
    } for index, row in enumerate(requirements, 1)}
    return [classes.get(rule.identity) for rule in authority.rules]
