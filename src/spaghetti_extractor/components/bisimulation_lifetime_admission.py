"""Conditional local lifetime admission through the existing typed adapter path.

Declared classes are insufficient: each consumed transition needs its complete
checked site, physical frame and matching class. Runtime origin checks still
reject incoming objects without locally established lifetime evidence.
"""

from collections.abc import Mapping
from pathlib import Path

from .bisimulation_lifetime_namespace import checked_lifetime_transitions
from .bisimulation_reference_authority import checked_reference_authority


def uses_lifetime_services(bindings):
    return any(isinstance(row.get('external_effect_contract'), Mapping) and
               row['external_effect_contract'].get('world_effect') in {'dynamicRanges', 'dynamicRangeRelease'}
               for row in bindings)


def admitted_call_specs(bindings, *, reference_authority=None, allocation_requirements=None):
    from .bisimulation_typed_services import _proof_call_specs

    specs = _proof_call_specs(bindings, allow_lifetime_effects=allocation_requirements is not None)
    if uses_lifetime_services(bindings):
        checked_lifetime_transitions(specs, authority=checked_reference_authority(reference_authority),
                                     requirements=allocation_requirements)
    return specs


def lifetime_implementation_paths():
    """Bind the consumed admission, call/lifetime oracle and shared native resolver."""
    components = (
        'bisimulation_lifetime_admission.py', 'bisimulation_lifetime_namespace.py',
        'bisimulation_allocation_classes.py', 'bisimulation_allocation_namespace.py',
        'bisimulation_allocation_producers.py', 'bisimulation_allocation_authority.py',
        'bisimulation_allocation_lifetime.py', 'bisimulation_call_allocation.py',
        'bisimulation_call_memory.py', 'bisimulation_reference_authority.py',
        'bisimulation_reference_origins.py', 'bisimulation_world.py',
    )
    return [*(Path(__file__).with_name(name) for name in components),
            *(Path(__file__).parents[1] / 'external' / name for name in ('lifetime_effects.py', 'import_sites.py')),
            Path(__file__).parents[1] / 'semantic_objects' / 'object_authority.py',
            Path(__file__).parents[1] / 'transfer' / 'reference_namespace.py']
