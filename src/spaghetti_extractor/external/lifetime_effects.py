"""Normalize the explicitly supported owned allocation and release effects.

This is a contract projection, not permission to execute a service or assume a
caller satisfies its domain. Proof and local preparation consume the same shape.
"""

from collections.abc import Mapping

from ..errors import ToolkitInputError
from .range_allocation import parse_range_allocation
from .range_ownership import parse_range_ownership
from .range_release import machine_range_release


class LifetimeEffectError(ToolkitInputError):
    """A lifetime effect is outside the supported contract shape."""


def checked_lifetime_effect(payload, *, argument_words):
    """Admit explicit owned EAX allocations or whole-instance releases only."""
    try:
        if (payload.get('memory_effect') != 'none' or payload.get('memory_footprints') or
                payload.get('out_pointer_relations') or payload.get('out_interface_relations') or
                payload.get('callback_effect', 'none') != 'none'):
            raise ValueError('lifetime transition has additional memory, output or callback effects')
        if payload.get('external_service_protocol') is not None:
            raise ValueError('lifetime transition has an additional service protocol')
        if payload.get('disposition', 'returns') != 'returns':
            raise ValueError('lifetime transition has an unsupported call outcome')
        release = machine_range_release(payload, argument_words=argument_words, context='proof lifetime call')
        relations = payload.get('result_register_relations', [])
        if release is not None:
            if (relations not in ([], [{'register': 'eax', 'relation': 'related_word'}]) or
                    release.ownership is None):
                raise ValueError('release requires ownership and only a related EAX result')
            return {'action': 'release_argument_range', 'argument': payload['world_effect_argument'],
                    'ownership': release.ownership.payload(), 'release': release.payload()}
        if payload.get('world_effect') != 'dynamicRanges' or len(relations) != 1:
            raise ValueError('allocation requires exactly one result relation')
        relation = relations[0]
        if (not isinstance(relation, Mapping) or relation.get('relation') != 'dynamic_range_base' or
                relation.get('register') != 'eax' or type(relation.get('nullable')) is not bool):
            raise ValueError('allocation requires an explicit owned EAX range result')
        ownership = parse_range_ownership(relation.get('ownership'), argument_words=argument_words,
                                          context='proof allocation')
        allocation = parse_range_allocation(relation.get('allocation'), argument_words=argument_words,
                                            context='proof allocation')
        if ownership is None or allocation is None:
            raise ValueError('allocation requires explicit ownership and initialization')
        size = relation.get('size', {})
        kind = size.get('kind')
        value, left, right = 0, None, None
        if kind == 'fixed' and set(size) == {'kind', 'byte_count'}:
            value = size['byte_count']
        elif kind == 'argument' and set(size) <= {'kind', 'argument', 'scale'}:
            left, value = size['argument'], size.get('scale', 1)
        elif kind == 'product' and set(size) == {'kind', 'left_argument', 'right_argument'}:
            left, right = size['left_argument'], size['right_argument']
        else:
            raise ValueError('allocation size is outside the checked fixed/argument/product domain')
        minimum = relation.get('minimum_size', 0)
        if any(type(item) is not int or not 0 <= item <= 0xffffffff for item in (minimum, value)):
            raise ValueError('allocation size and minimum must fit uint32')
        if any(index is not None and (type(index) is not int or not 0 <= index < argument_words)
               for index in (left, right)):
            raise ValueError('allocation size argument is outside its frame')
        return {'action': 'add_result_range', 'register': 'eax', 'ownership': ownership.payload(),
                'allocation': allocation.payload(), 'size_kind': kind, 'size_value': value,
                'size_argument': left, 'size_right_argument': right, 'minimum_size': minimum,
                'nullable': relation['nullable']}
    except (ValueError, TypeError, KeyError, AttributeError, ToolkitInputError) as exc:
        raise LifetimeEffectError(f'lifetime effect unsupported: {exc}') from exc
