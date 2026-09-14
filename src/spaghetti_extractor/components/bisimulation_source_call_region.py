"""Bind a single service-call proof region to a complete compiled C component.

This projection proves only structural correspondence. The emitted fragment
still needs a functional comparison, incoming context admission and a checked
supplier contract. It is a proof model, never a new production component API.
"""

import re

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_cut_state import _symbol, _walk
from .bisimulation_entry_conformance import _payload, _semantic
from .bisimulation_region_context import _region
from .bisimulation_source_entry import _type_closure


def _require(condition, detail):
    if not condition:
        raise ValueError('source call region: ' + detail)


def _path(value):
    """Accept only plain typed parameter/member loads, retaining their types."""
    node = _semantic(value)
    kind, named, args = node.get('id'), node.get('namedSub', {}), node.get('sub', [])
    _require(set(node) <= {'id', 'namedSub', 'sub'} and 'type' in named,
             'unsupported call expression payload')
    if kind == 'symbol':
        _require(set(named) == {'type', 'identifier'} and not args, 'unsupported symbol load')
        return (_symbol(node),)
    if kind == 'dereference':
        _require(set(named) == {'type'} and len(args) == 1, 'unsupported dereference')
        return (*_path(args[0]), '*')
    if kind == 'member':
        _require(set(named) == {'type', 'component_name'} and len(args) == 1, 'unsupported member load')
        name = named['component_name'].get('id')
        _require(isinstance(name, str) and re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', name), 'invalid service member')
        return (*_path(args[0]), name)
    raise ValueError('source call region: unsupported call expression ' + str(kind))


def project_source_call_region(*, functions, symbols, function, entry, exits):
    """Project one unconditional view-returning service invocation and its live result.

    All region instructions are accounted for, including compiler return storage.
    Acyclic coverage and the absence of incoming edges into the region interior
    come from the existing cut engine. No source text is selected by substring
    as evidence of behavior; anchors have already passed compiled marker erasure.
    """
    start, owned, ports = _region(functions, function, entry, exits)
    _require(len(ports) == 1 and '@return' not in ports, 'one normal outgoing cut is required')
    rows = functions[function]['instructions']
    selected = sorted(owned)
    _require(selected == list(range(start + 1, next(iter(ports.values())))), 'nonlinear call region')
    instructions = [rows[i] for i in selected]
    _require([r['instructionId'] for r in instructions] == ['DECL', 'DECL', 'FUNCTION_CALL', 'ASSIGN', 'DEAD'],
             'region must initialize one fresh view from exactly one service call')
    _require(all(not r.get('targets') for r in instructions), 'branch inside call region')
    declared, temporary = [_symbol(row['code']['sub'][0]) for row in instructions[:2]]
    _require(declared and temporary and declared != temporary, 'ambiguous return storage')
    for identity in (declared, temporary):
        symbol = symbols.get(identity, {})
        _require(symbol.get('isStaticLifetime') is False and symbol.get('isParameter') is False
                 and symbol.get('location', {}).get('function') == function, 'result must use fresh automatic storage')
        _require(sum(r['instructionId'] == 'DECL' and _symbol(r['code']['sub'][0]) == identity for r in rows) == 1,
                 'result storage has another declaration')
        _require(not any(_symbol(n) == identity for r in rows[:start] for n in _walk(_payload(r))),
                 'result storage is referenced before entry')
    code = instructions[2]['code']
    _require(code.get('id') == 'code' and code.get('namedSub', {}).get('statement', {}).get('id') == 'function_call'
             and len(code.get('sub', [])) == 3, 'unsupported call instruction')
    lhs, callee, args = code['sub']
    _require(_symbol(lhs) == temporary and args.get('id') == 'arguments', 'call return storage differs')
    assignment = instructions[3]['code']['sub']
    _require(len(assignment) == 2 and [_symbol(v) for v in assignment] == [declared, temporary]
             and _symbol(instructions[4]['code']['sub'][0]) == temporary, 'result transport differs')
    target = _path(callee)
    parameters = functions[function]['parameterIdentifiers']
    _require(len(target) == 6 and target[0] in parameters and target[1:4] == ('*', 'services', '*')
             and target[5:] == ('*',), 'call is not a generated service invocation')
    context, service = target[0], target[-2]
    context_type = _semantic(symbols[context]['type'])
    pointee = context_type.get('sub', [{}])[0]
    context_name = pointee.get('namedSub', {}).get('#typedef', {}).get('id', '')
    _require(context_type.get('id') == 'pointer' and pointee.get('id') == 'struct_tag'
             and re.fullmatch('spx_[A-Za-z0-9_]+_context_v5', context_name)
             and pointee['namedSub'].get('identifier', {}).get('id') == 'tag-' + context_name,
             'call context is not a generated component context')
    arguments = args.get('sub', [])
    _require(arguments and _path(arguments[0]) == (context, '*', 'services', '*', 'context'),
             'service context comes from another object')
    values = []
    for arg in arguments[1:]:
        arg = _semantic(arg)
        typ = arg.get('namedSub', {}).get('type', {})
        _require(arg.get('id') == 'constant' and set(arg) == {'id', 'namedSub'}
                 and set(arg['namedSub']) == {'type', 'value'}
                 and typ.get('id') == 'unsignedbv' and typ.get('namedSub', {}).get('width', {}).get('id') == '32',
                 'service arguments require explicit uint32 constants in this projection')
        value = int(arg['namedSub']['value']['id'], 16)
        _require(0 <= value < 2**32, 'service argument exceeds uint32')
        values.append(value)
    def result_type(value):
        value = _semantic(value)
        return {**value, 'namedSub': {k: v for k, v in value.get('namedSub', {}).items() if k != '#typedef'}}

    typ = result_type(symbols[declared]['type'])
    _require(typ == result_type(symbols[temporary]['type']) == result_type(lhs['namedSub']['type'])
             == result_type(callee['namedSub']['type']['namedSub']['return_type'])
             and typ == {'id': 'struct_tag', 'namedSub': {'identifier': {'id': 'tag-spx_view_v1'}}},
             'service result is not an unchanged portable view')
    closure = _type_closure(symbols, {context: context, declared: declared, temporary: temporary})
    _require(not any({'#volatile', 'C_volatile', 'volatile', '#atomic'} & n.get('namedSub', {}).keys()
                     for n in _walk(closure)), 'volatile or atomic storage needs an observable-load rule')
    return {'status': 'projected-source-call-region', 'authorizing': False,
            'function': function, 'entry_marker': entry, 'exit': next(iter(ports)),
            'instruction_indices': selected, 'body_sha256': canonical_sha256_v3([_payload(r) for r in instructions]),
            'context_parameter': context, 'context_type': context_name, 'service_id': service, 'arguments': values,
            'result_local': declared, 'result_type': typ, 'type_closure_sha256': canonical_sha256_v3(closure),
            'fresh_result_storage': True, 'outside_storage_unchanged_except_service': True,
            'functional_correctness_checked': False, 'incoming_domain_checked': False,
            'supplier_contract_checked': False, 'activation_authorized': False}
