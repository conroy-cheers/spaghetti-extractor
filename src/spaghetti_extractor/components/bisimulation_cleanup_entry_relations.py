"""Normalize the reviewed cleanup supplier's legacy entry predicates.

This compatibility reader recognizes a closed set of predicates emitted by the
existing checked supplier. It is not a C parser or an authoring interface. New
caller definitions use typed relation IR. Unrecognized legacy predicates fail
closed instead of being pasted into a generated caller model.
"""

import re

from .bisimulation_call_relations import (
    ScalarBinding, ViewBinding, constant, expression, lower_call_relation, parameter,
)
from .relation_ir import BOOL_SORT, RelationSortV1


U32 = RelationSortV1('bitvector', width=32)
U64 = RelationSortV1('bitvector', width=64)
MEMORY = RelationSortV1('view', type_id='bytes')
PARAMETERS = ('stack', 'text_address', 'text_extent', 'scratch_address',
              'scratch_extent', 'length', 'length_target')


def _known_predicates():
    values = {name: parameter(name, U32) for name in PARAMETERS}
    wide = lambda value: expression('zero_extend', U64, value)
    add = lambda left, right: expression('add', left.sort, left, right)
    sub = lambda left, right: expression('sub', left.sort, left, right)
    le = lambda left, right: expression('ule', BOOL_SORT, left, right)
    lt = lambda left, right: expression('ult', BOOL_SORT, left, right)
    eq = lambda left, right: expression('eq', BOOL_SORT, left, right)
    both = lambda left, right: expression('and', BOOL_SORT, left, right)
    either = lambda left, right: expression('or', BOOL_SORT, left, right)
    stack, text, extent, scratch, scratch_extent, length, target = (values[n] for n in PARAMETERS)
    high = add(wide(stack), constant(4, 64))
    text_end = add(wide(text), wide(extent))
    scratch_end = add(wide(scratch), wide(scratch_extent))
    end = constant(2**32, 64)
    predicates = {
        '(uint64_t)stack+4U<=4194304U || (uint64_t)stack-72U>=UINT64_C(4419584)':
            either(le(high, constant(4194304, 64)), le(constant(4419584, 64), sub(wide(stack), constant(72, 64)))),
        '(uint64_t)text_address+text_extent<=4194304U || text_address>=UINT64_C(4419584)':
            either(le(text_end, constant(4194304, 64)), le(constant(4419584, 64), wide(text))),
        'length_target!=0U': expression('not', BOOL_SORT, eq(target, constant(0))),
        'text_address>0U && text_extent>0U && (uint64_t)text_address+text_extent<=UINT64_C(4294967296) && length<text_extent':
            both(both(both(lt(constant(0), text), lt(constant(0), extent)), le(text_end, end)), lt(length, extent)),
        '__CPROVER_uninterpreted_readonly_byte(text_address+length)==0U':
            eq(expression('byte_read', RelationSortV1('bitvector', width=8),
                parameter('entry_memory', MEMORY), add(text, length)), constant(0, 8)),
        '(uint64_t)scratch_address+scratch_extent<=UINT64_C(4294967296)': le(scratch_end, end),
        '(uint64_t)text_address+text_extent<=scratch_address || (uint64_t)scratch_address+scratch_extent<=text_address':
            either(le(text_end, wide(scratch)), le(scratch_end, wide(text))),
    }
    for size in (40, 72):
        low = wide(sub(stack, constant(size)))
        predicates[f'stack>={size}U && (uint64_t)stack+4U<=UINT64_C(4294967296)'] = both(
            le(constant(size), stack), le(high, end))
        predicates[f'(uint64_t)stack+4U<=text_address || (uint64_t)text_address+text_extent<=stack-{size}U'] = either(
            le(high, wide(text)), le(text_end, low))
    predicates['(uint64_t)stack+4U<=scratch_address || (uint64_t)scratch_address+scratch_extent<=stack-40U'] = either(
        le(high, wide(scratch)), le(scratch_end, wide(sub(stack, constant(40)))))
    predicates['(uint64_t)stack+4U<=4251992U || stack-40U>=UINT64_C(4251996)'] = either(
        le(high, constant(4251992, 64)), le(constant(4251996, 64), wide(sub(stack, constant(40)))))
    for name, start, finish in [('text', text, text_end), ('scratch', scratch, scratch_end)]:
        predicates[f'(uint64_t){name}_address+{name}_extent<=4251992U || {name}_address>=UINT64_C(4251996)'] = either(
            le(finish, constant(4251992, 64)), le(constant(4251996, 64), wide(start)))
    return {re.sub(r'\s+', '', text): value for text, value in predicates.items()}


def normalized_cleanup_entry_relations(contract):
    """Preserve each supplied premise's identity and typed meaning.

    Full supplier validation and the surrounding supported-contract check remain
    mandatory. This reader grants no additional premise or runtime qualification.
    In particular its byte accessor denotes incoming contents, not pointer data.
    """
    incoming = contract['input_relation']
    callers = incoming['caller_requirements']
    entries = incoming['entry_admission']
    if (not isinstance(callers, dict) or not isinstance(entries, list)
            or any(not isinstance(key, str) for key in callers)):
        raise ValueError('cleanup entry relation inventory is malformed')
    named = [*sorted(callers.items()), *((f'entry-admission-{i}', p) for i, p in enumerate(entries))]
    if len({name for name, _ in named}) != len(named):
        raise ValueError('cleanup entry relation identities collide')
    known = _known_predicates()
    result = []
    for name, predicate in named:
        key = re.sub(r'\s+', '', predicate) if isinstance(predicate, str) else None
        if key not in known:
            raise ValueError('cleanup entry predicate needs a checked typed rule: ' + name)
        result.append({'id': name, 'expression': known[key].to_payload()})
    return result


def cleanup_entry_predicates(contract):
    bindings = {name: ScalarBinding(U32, name) for name in PARAMETERS}
    bindings['entry_memory'] = ViewBinding(MEMORY, '0U', 'UINT64_C(4294967296)',
                                          '__CPROVER_uninterpreted_readonly_byte')
    return [lower_call_relation(row['expression'], parameters=bindings).predicate()
            for row in normalized_cleanup_entry_relations(contract)]
