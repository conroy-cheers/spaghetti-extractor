"""Admit storage and service expressions for a fresh-buffer entry comparison.

This is a source footprint check, not a service summary or an execution proof.
The consuming proof must bind the prepared graph, cover every selected edge,
check each invocation and transport the actual outgoing state. In particular,
unused context fields and parameters must not become concrete proof premises.
"""
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_cut_state import _symbol, _walk
from spaghetti_extractor.components.bisimulation_entry_conformance import _payload
from spaghetti_extractor.components.bisimulation_source_call_region import _path
from spaghetti_extractor.components.bisimulation_source_entry import _type_closure
from spaghetti_extractor.components.bisimulation_source_region_transport import _integer


def check_fresh_buffer_entry_frame(*, functions, symbols, function, instruction_indices,
                                   context_parameter, text_parameter, scratch_local):
    """Check length/allocate calls and byte access through explicit view roles.

    Ordinary scalar control and automatic aggregate copies are allowed. Public
    storage is accessed only through the two service contracts and byte helpers;
    pointer aliases, direct descriptor accesses and additional services require
    another admission rule. No restriction on scalar logic establishes its
    correctness: wrong sizes, stores and invocation order still reach the solver.
    """
    def require(condition, detail):
        if not condition:
            raise ValueError('fresh buffer entry frame: ' + detail)

    body = functions[function]
    parameters = body['parameterIdentifiers']
    require(context_parameter in parameters and text_parameter in parameters
            and context_parameter != text_parameter, 'invalid parameter roles')
    indices = list(instruction_indices)
    rows = body['instructions']
    require(indices and len(set(indices)) == len(indices) and all(
        type(i) is int and 0 <= i < len(rows) for i in indices), 'invalid selected instructions')
    touched, calls = set(), []

    def automatic(identity):
        symbol = symbols.get(identity, {})
        require(symbol.get('isStaticLifetime') is False and symbol.get('isParameter') is False
                and symbol.get('location', {}).get('function') == function,
                'access is not automatic storage: ' + str(identity))
        touched.add(identity)

    automatic(scratch_local)

    def local_value(value):
        # All direct public loads and pointer construction are deliberately
        # excluded. The few legal pointer expressions are checked at call sites.
        require(value.get('id') not in {'address_of', 'dereference', 'index', 'side_effect'},
                'unmodeled pointer or effect expression')
        if value.get('id') == 'symbol':
            automatic(_symbol(value))
        typ = value.get('namedSub', {}).get('type', {})
        require(typ.get('id') not in {'pointer', 'array', 'union_tag'}, 'unmodeled pointer value')
        for child in value.get('sub', []):
            local_value(child)

    def local_target(value):
        while value.get('id') == 'member' and len(value.get('sub', [])) == 1:
            value = value['sub'][0]
        require(_symbol(value) is not None, 'write is not to automatic storage')
        automatic(_symbol(value))

    def address(value, identity=None, byte=False):
        require(value.get('id') == 'address_of' and len(value.get('sub', [])) == 1,
                'helper requires a direct automatic address')
        name = _symbol(value['sub'][0])
        automatic(name)
        require(identity is None or name == identity, 'helper uses another view')
        if byte:
            typ = symbols[name]['type']
            require(typ.get('id') == 'unsignedbv' and typ.get('namedSub', {}).get('width', {}).get('id') == '8',
                    'read result is not an automatic byte')

    for i in sorted(indices):
        row = rows[i]; kind = row['instructionId']; operands = row.get('code', {}).get('sub', [])
        if kind in {'DECL', 'DEAD'}:
            require(len(operands) == 1, 'malformed lifetime instruction')
            automatic(_symbol(operands[0]))
        elif kind == 'ASSIGN':
            require(len(operands) == 2, 'malformed assignment')
            local_target(operands[0]); local_value(operands[1])
        elif kind == 'FUNCTION_CALL':
            require(len(operands) == 3, 'malformed call')
            lhs, callee, arguments = operands
            require(arguments.get('id') == 'arguments', 'malformed call arguments')
            local_target(lhs)
            args = arguments.get('sub', [])
            name = _symbol(callee)
            if name in {'spx_view_read_u8', 'spx_view_write_u8'}:
                require(len(args) == 3, 'byte helper arity differs')
                if name == 'spx_view_read_u8':
                    require(_symbol(args[0]) == text_parameter, 'read uses another view')
                    address(args[2], byte=True)
                else:
                    address(args[0], scratch_local)
                    local_value(args[2])
                local_value(args[1])
            else:
                path = _path(callee)
                require(len(path) == 6 and path[:4] == (context_parameter, '*', 'services', '*')
                        and path[4] in {'length', 'allocate'} and path[5] == '*',
                        'call needs another service contract')
                name = path[4]
                require(len(args) == (2 if name == 'length' else 3)
                        and _path(args[0]) == (context_parameter, '*', 'services', '*', 'context'),
                        'service context or arity differs')
                if name == 'length':
                    require(_symbol(args[1]) == text_parameter, 'length uses another view')
                else:
                    for arg in args[1:]:
                        local_value(arg)
            calls.append({'instruction_index': i, 'dependency': name})
        elif kind == 'GOTO':
            local_value(row['guard'])
        elif kind == 'SET_RETURN_VALUE':
            require(len(operands) == 1 and _integer(operands[0]) == 0xffffffff,
                    'source return requires an explicit outcome contract')
        else:
            require(kind in {'SKIP', 'LOCATION'}, 'unsupported instruction ' + kind)
    closure = _type_closure(symbols, {name: name for name in [*touched, context_parameter, text_parameter]})
    require(not any({'#volatile', 'C_volatile', 'volatile', '#atomic'} & node.get('namedSub', {}).keys()
                    for node in _walk(closure)), 'volatile or atomic storage needs another effect contract')
    return {'status': 'checked-fresh-buffer-entry-footprint', 'authorizing': False,
            'instruction_indices': sorted(indices), 'calls': calls,
            'automatic_storage': sorted(touched), 'read_parameters': [context_parameter, text_parameter],
            'body_sha256': canonical_sha256_v3([_payload(rows[i]) for i in sorted(indices)]),
            'type_closure_sha256': canonical_sha256_v3(closure),
            'coverage_checked': False, 'service_contracts_checked': False,
            'runtime_compatibility_checked': False}
