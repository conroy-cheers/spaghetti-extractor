"""Restricted compiler check for a closed, sequential observation family.

This establishes a dependency/frame boundary, not a replacement theorem. Safety,
value/effect congruence and the consuming program relation need separate evidence.
Only direct calls, forward control flow, pointer-free stored inputs and immutable
pointer parameters rooted in those inputs are supported. There is no heap model
inferred from an integer address or a declared footprint.
"""

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_cut_state import _symbol, _walk, _written_object
from spaghetti_extractor.components.bisimulation_entry_conformance import _function_payload
from spaghetti_extractor.components.bisimulation_source_entry import _type_closure


def _require(condition, message):
    if not condition:
        raise ValueError('observer family: ' + message)


def check_observer_family(*, functions, symbols, root, readable_globals, observation_bit):
    """Check explicit readable storage and a single write-only set-to-one effect.

    All bodies and declared storage types are bound in the result. This is not
    independent runtime qualification or permission to import a summary.
    """
    readable = set(readable_globals)
    _require(readable and observation_bit not in readable, 'ambiguous input/effect selection')
    closure = _type_closure(symbols, {name: name for name in readable | {observation_bit}})
    _require(not any(node.get('id') == 'pointer' or '#volatile' in node.get('namedSub', {})
                     for node in _walk(closure)), 'stored inputs must be pointer-free and nonvolatile')
    _require(all(symbols[name].get('isStaticLifetime') is True
                 and symbols[name].get('isVolatile') is False for name in readable | {observation_bit}),
             'selected storage must be stable global objects')
    _require(symbols[observation_bit]['type'].get('id') == 'unsignedbv', 'effect is not an unsigned scalar')
    active, done, reads, oracles, calls, writes = set(), set(), set(), set(), [], []

    def visit(name):
        _require(name not in active, 'recursive family requires a separate progress rule')
        if name in done:
            return
        _require(name in functions and functions[name].get('isBodyAvailable') is True,
                 'missing direct callee body: ' + name)
        active.add(name)
        body = functions[name]
        parameters = body.get('parameterIdentifiers', [])
        pointers = {p for p in parameters if symbols[p]['type'].get('id') == 'pointer'}
        _require(name != root or not pointers, 'root pointer arguments lack stored-input provenance')
        parameter_types = _type_closure(symbols, {p: p for p in parameters})
        _require(not any(v.get('id') == 'pointer' for v in _walk(parameter_types['tags']))
                 and not any('#volatile' in v.get('namedSub', {}) for v in _walk(parameter_types)),
                 'parameter contains pointers or volatile storage')
        rows = body['instructions']
        locations = {row['locationNumber']: i for i, row in enumerate(rows)}
        _require(len(locations) == len(rows), 'duplicate instruction locations')

        def expression(value):
            def null_pointer(node):
                return (node.get('id') == 'constant'
                        and node.get('namedSub', {}).get('type', {}).get('id') == 'pointer'
                        and node.get('namedSub', {}).get('value', {}).get('id') == 'NULL')

            for node in _walk(value):
                identity = _symbol(node)
                typ = node.get('namedSub', {}).get('type', {})
                _require(node.get('id') not in {'side_effect', 'nondet_symbol'}, 'hidden or nondeterministic effect')
                _require('#volatile' not in typ.get('namedSub', {}), 'volatile observation')
                if node.get('id') == 'dereference':
                    _require(len(node.get('sub', [])) == 1 and _symbol(node['sub'][0]) in pointers,
                             'dereference lacks immutable input provenance')
                operands = node.get('sub', [])
                null_test = (node.get('id') in {'equal', 'notequal', '=', '!='} and len(operands) == 2
                             and ((_symbol(operands[0]) in pointers and null_pointer(operands[1]))
                                  or (_symbol(operands[1]) in pointers and null_pointer(operands[0]))))
                _require(node.get('id') == 'dereference' or null_test or not any(
                    child.get('namedSub', {}).get('type', {}).get('id') == 'pointer'
                    for child in operands), 'pointer identity or arithmetic is outside the value key')
                if typ.get('id') == 'pointer':
                    rooted_address = (node.get('id') == 'address_of' and len(node.get('sub', [])) == 1
                                      and _symbol(node['sub'][0]) in readable)
                    _require(identity in pointers or rooted_address or null_pointer(node), 'pointer reconstruction or escape')
                if typ.get('id') == 'mathematical_function':
                    _require(identity is not None, 'unknown mathematical oracle')
                    _require(not any(v.get('id') == 'pointer' for v in _walk(typ)), 'oracle pointer input')
                    oracles.add(identity)
                if (identity in symbols and symbols[identity].get('isLvalue') is True
                        and typ.get('id') != 'mathematical_function'):
                    obj = symbols[identity]
                    _require(obj.get('isVolatile') is False, 'volatile storage')
                    if obj.get('isStaticLifetime'):
                        _require(identity in readable, 'undeclared readable global: ' + identity)
                        reads.add(identity)
                    else:
                        _require(obj.get('location', {}).get('function') == name, 'foreign automatic storage')

        def local_target(value):
            identity = _written_object(value)
            _require(identity in symbols and symbols[identity].get('isStaticLifetime') is False
                     and symbols[identity].get('location', {}).get('function') == name
                     and identity not in pointers, 'write escapes automatic storage')
            typ = _type_closure(symbols, {'target': identity})
            _require(not any(v.get('id') == 'pointer' or '#volatile' in v.get('namedSub', {})
                             for v in _walk(typ)), 'pointer or volatile local write')

        for index, row in enumerate(rows):
            kind = row['instructionId']
            _require(kind in {'GOTO', 'ASSERT', 'ASSIGN', 'FUNCTION_CALL', 'SET_RETURN_VALUE',
                             'DECL', 'DEAD', 'SKIP', 'LOCATION', 'END_FUNCTION'},
                     'unsupported control or effect: ' + kind)
            _require(all(target in locations and locations[target] > index for target in row.get('targets', [])),
                     'backward control requires a separate progress rule')
            if 'guard' in row:
                expression(row['guard'])
            operands = row.get('code', {}).get('sub', [])
            if kind == 'ASSIGN':
                _require(len(operands) == 2, 'malformed assignment')
                left, right = operands
                if _symbol(left) == observation_bit:
                    _require(right.get('id') == 'constant' and right['namedSub']['type']['id'] == 'unsignedbv'
                             and int(right['namedSub']['value']['id'], 16) == 1, 'effect must set the bit to one')
                    writes.append({'function': name, 'instruction_index': index})
                else:
                    local_target(left)
                    expression(left)
                expression(right)
            elif kind == 'FUNCTION_CALL':
                _require(len(operands) == 3, 'malformed direct call')
                target = _symbol(operands[1])
                _require(target is not None and target in functions, 'indirect or external call')
                if operands[0].get('id') != 'nil':
                    local_target(operands[0])
                    expression(operands[0])
                args = operands[2].get('sub', [])
                callee_parameters = functions[target].get('parameterIdentifiers', [])
                _require(len(args) == len(callee_parameters), 'call arity differs')
                for parameter, arg in zip(callee_parameters, args, strict=True):
                    expression(arg)
                    if symbols[parameter]['type'].get('id') == 'pointer':
                        _require(_symbol(arg) in pointers or (arg.get('id') == 'address_of'
                                 and len(arg.get('sub', [])) == 1 and _symbol(arg['sub'][0]) in readable),
                                 'callee pointer lacks stored-input provenance')
                calls.append({'caller': name, 'callee': target, 'instruction_index': index})
                visit(target)
            elif kind == 'SET_RETURN_VALUE':
                for operand in operands:
                    expression(operand)
                _require(not any(v.get('namedSub', {}).get('type', {}).get('id') == 'pointer'
                                 for v in operands), 'returned pointer escapes')
        active.remove(name)
        done.add(name)

    visit(root)
    _require(writes, 'declared observation effect has no implementation')
    return {'status': 'checked-closed-observer-family', 'authorizing': False, 'root': root,
            'readable_globals': sorted(readable), 'observed_global_reads': sorted(reads),
            'observation_bit': observation_bit, 'set_to_one_sites': writes, 'calls': calls,
            'mathematical_oracles': sorted(oracles), 'stored_types_sha256': canonical_sha256_v3(closure),
            'bodies_sha256': {name: canonical_sha256_v3(_function_payload(functions[name])) for name in sorted(done)},
            'safety_checked': False, 'value_congruence_checked': False, 'summary_consumption_checked': False}
