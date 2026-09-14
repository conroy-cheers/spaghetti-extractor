"""Selector-independent requirements for an owned allocation class.

These descriptions bind semantics, not inventory completeness, live callers or
deployment permission. Numeric lowering stays in the existing native planner.
"""

import copy
import re
from collections.abc import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..external.lifetime_effects import checked_lifetime_effect
from .bisimulation_support import BisimulationRefinementError


ALLOCATION_EFFECT_FIELDS = (
    'action', 'register', 'ownership', 'allocation', 'size_kind', 'size_value',
    'size_argument', 'size_right_argument', 'minimum_size', 'nullable',
)


def allocation_class_requirement(rule, *, contract_identity_sha256, effect, argument_words):
    """Project a checked authority and effect; omit physical sites and selectors.

    The enclosing input retains authority evidence and module/environment bindings.
    This semantic projection intentionally does not replace those provenance checks.
    """
    if (rule.kind != 'external' or rule.lifetime != 'allocation' or
            rule.locator.kind != 'external_allocation'):
        raise BisimulationRefinementError('allocation class requires an external allocation authority')
    if (not isinstance(contract_identity_sha256, str) or
            re.fullmatch('[0-9a-f]{64}', contract_identity_sha256) is None or
            type(argument_words) is not int or not 0 <= argument_words <= 0xffffffff):
        raise BisimulationRefinementError('allocation class contract identity or arity is malformed')
    if (not isinstance(effect, Mapping) or set(effect) != set(ALLOCATION_EFFECT_FIELDS) or
            effect.get('action') != 'add_result_range' or effect.get('ownership') is None):
        raise BisimulationRefinementError('allocation class requires one normalized owned result effect')
    payload = {
        'authority': {
            'id': rule.identity, 'domain': rule.domain, 'object': rule.object_id,
            'generation': rule.generation, 'extent': rule.extent, 'permissions': rule.permissions,
            'lifetime': rule.lifetime, 'interior_pointers': rule.interior_pointers,
            'extent_mode': rule.extent_mode,
            'locator': {'kind': rule.locator.kind, 'identity': rule.locator.identity,
                        'offset': rule.locator.offset},
        },
        'contract_identity_sha256': contract_identity_sha256,
        'argument_words': argument_words, 'effect': copy.deepcopy(dict(effect)),
    }
    return {**payload, 'class_sha256': canonical_sha256_v3(payload)}


def require_allocation_class(required, actual):
    """Compare the entire derived requirement, including canonical scalar types.

    Callers must derive ``actual`` from their checked inputs. A matching digest alone
    does not establish the origin of either supplied class or its numeric inventory.
    """
    if canonical_sha256_v3(required) != canonical_sha256_v3(actual):
        raise BisimulationRefinementError('native allocation class disagrees with its local requirement')


def checked_allocation_requirements(authority, values):
    """Validate serialized conditional requirements against their object authority.

    Round-trip the normalized effect through the shared contract parser. This
    checks its supported domain without granting site, caller or link authority.
    """
    if values is None:
        return None
    if authority is None or not isinstance(values, list):
        raise BisimulationRefinementError('allocation requirements need their canonical object authority')
    rules = {rule.identity: rule for rule in authority.rules}
    checked, identities = [], []
    try:
        for value in values:
            identity = value['authority']['id']
            rule = rules[identity]
            effect, words = value['effect'], value['argument_words']
            expected = allocation_class_requirement(rule, effect=effect, argument_words=words,
                contract_identity_sha256=value['contract_identity_sha256'])
            require_allocation_class(value, expected)
            kind = effect['size_kind']
            size = {'kind': kind}
            if kind == 'fixed':
                size['byte_count'] = effect['size_value']
            elif kind == 'argument':
                size.update(argument=effect['size_argument'], scale=effect['size_value'])
            elif kind == 'product':
                size.update(left_argument=effect['size_argument'], right_argument=effect['size_right_argument'])
            payload = {'memory_effect': 'none', 'world_effect': 'dynamicRanges',
                'result_register_relations': [{'relation': 'dynamic_range_base',
                    'register': effect['register'], 'size': size, 'minimum_size': effect['minimum_size'],
                    'nullable': effect['nullable'], 'ownership': effect['ownership'], 'allocation': effect['allocation']}]}
            normalized = checked_lifetime_effect(payload, argument_words=words)
            if canonical_sha256_v3(normalized) != canonical_sha256_v3(effect):
                raise ValueError('allocation requirement effect is not canonical')
            identities.append(identity)
            checked.append(expected)
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise BisimulationRefinementError(f'allocation requirement is malformed: {exc}') from exc
    if identities != sorted(set(identities)):
        raise BisimulationRefinementError('allocation requirements are duplicated or not in authority identity order')
    return checked
