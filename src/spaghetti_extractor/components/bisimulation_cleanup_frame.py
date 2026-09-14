"""Compiled source-effect admission for conditional cleanup-tail proofs.

This does not prove service behavior or graph coverage. The paired consumer must
check every actual call, complete descriptors, lifetime, returns and byte effects.
"""
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_cut_state import _symbol, _walk
from spaghetti_extractor.components.bisimulation_entry_conformance import _payload
from spaghetti_extractor.components.bisimulation_source_call_region import _path
from spaghetti_extractor.components.bisimulation_source_entry import _type_closure



def check_cleanup_tail_frame(*, functions, symbols, function, instruction_indices, parameters, scratch_local):
    def require(condition, detail):
        if not condition:
            raise ValueError('cleanup tail frame: ' + detail)

    roles = {'context', 'text', 'suppress_notice', 'main_window', 'edit_window', 'caption'}
    body = functions[function]; rows = body['instructions']
    require(set(parameters) == roles and set(parameters.values()) == set(body['parameterIdentifiers']),
            'parameter roles differ')
    indices = sorted(instruction_indices)
    require(indices and len(set(indices)) == len(indices) and all(
        type(i) is int and 0 <= i < len(rows) for i in indices), 'invalid selected instructions')
    touched, calls = set(), []

    def automatic(name):
        symbol = symbols.get(name, {})
        require(symbol.get('isStaticLifetime') is False and symbol.get('isParameter') is False
                and symbol.get('location', {}).get('function') == function,
                'access is not automatic storage: ' + str(name))
        touched.add(name)

    automatic(scratch_local)

    def local_value(value):
        require(value.get('id') not in {'address_of', 'dereference', 'index', 'side_effect'},
                'unmodeled pointer or effect expression')
        if value.get('id') == 'symbol':
            automatic(_symbol(value))
        require(value.get('namedSub', {}).get('type', {}).get('id') not in {'pointer', 'array', 'union_tag'},
                'unmodeled pointer value')
        for child in value.get('sub', []):
            local_value(child)

    def target(value):
        while value.get('id') == 'member' and len(value.get('sub', [])) == 1:
            value = value['sub'][0]
        require(_symbol(value) is not None, 'write is not to automatic storage')
        automatic(_symbol(value))

    def address(value, *, identity=None, width=None, view=False):
        require(value.get('id') == 'address_of' and len(value.get('sub', [])) == 1,
                'call requires a direct automatic address')
        name = _symbol(value['sub'][0]); automatic(name)
        require(identity is None or name == identity, 'call uses another automatic view')
        typ = symbols[name]['type']
        if width is not None:
            require(typ.get('id') == 'unsignedbv' and typ.get('namedSub', {}).get('width', {}).get('id') == str(width),
                    'read result representation differs')
        if view:
            require(typ.get('id') == 'struct_tag' and typ['namedSub']['identifier']['id'] == 'tag-spx_view_v1',
                    'call needs an automatic view')

    context = parameters['context']
    service_prefix = (context, '*', 'services', '*')
    for i in indices:
        row = rows[i]; kind = row['instructionId']; operands = row.get('code', {}).get('sub', [])
        if kind in {'DECL', 'DEAD'}:
            require(len(operands) == 1, 'malformed lifetime instruction'); automatic(_symbol(operands[0]))
        elif kind == 'ASSIGN':
            require(len(operands) == 2, 'malformed assignment'); target(operands[0]); local_value(operands[1])
        elif kind == 'FUNCTION_CALL':
            require(len(operands) == 3, 'malformed call')
            lhs, callee, arguments = operands
            require(arguments.get('id') == 'arguments', 'malformed call arguments')
            if lhs.get('id') != 'nil':
                target(lhs)
            args = arguments.get('sub', []); name = _symbol(callee)
            if name in {'spx_view_read_u8', 'spx_view_write_u8'}:
                require(len(args) == 3, 'byte helper arity differs')
                if name == 'spx_view_read_u8':
                    require(_symbol(args[0]) == parameters['text'], 'read uses another view')
                    address(args[2], width=8)
                else:
                    address(args[0], identity=scratch_local); local_value(args[2])
                local_value(args[1])
            else:
                path = _path(callee)
                if len(path) == 4 and path[1:] == ('*', 'read', '*'):
                    require(path[0] in {parameters[k] for k in ['suppress_notice', 'main_window', 'edit_window']},
                            'read needs another view contract')
                    require(len(args) == 5 and _path(args[0]) == (path[0], '*', 'access_context')
                            and _path(args[1]) == (path[0], '*', 'base'), 'read context or reference differs')
                    local_value(args[2]); local_value(args[3]); address(args[4], width=64)
                    name = 'read:' + next(k for k, v in parameters.items() if v == path[0])
                else:
                    require(len(path) == 6 and path[:4] == service_prefix and path[-1] == '*',
                            'call needs another service context')
                    name = path[4]
                    require(name in {'copy', 'release', 'resource_text', 'message', 'focus'},
                            'call needs another service contract')
                    arity = {'copy': 3, 'release': 2, 'resource_text': 2, 'message': 5, 'focus': 2}[name]
                    require(len(args) == arity and _path(args[0]) == (*service_prefix, 'context'),
                            'service context or arity differs')
                    if name == 'copy':
                        require(_symbol(args[1]) == parameters['text'], 'copy uses another destination')
                        address(args[2], identity=scratch_local)
                    elif name == 'release':
                        require(_path(args[1]) == (scratch_local, 'base'), 'release uses another reference')
                    elif name == 'message':
                        local_value(args[1]); address(args[2], view=True)
                        require(_symbol(args[3]) == parameters['caption'], 'message uses another caption')
                        local_value(args[4])
                    else:
                        local_value(args[1])
            calls.append({'instruction_index': i, 'dependency': name})
        elif kind == 'GOTO':
            local_value(row['guard'])
        elif kind == 'SET_RETURN_VALUE':
            require(len(operands) == 1, 'malformed return'); local_value(operands[0])
        else:
            require(kind in {'SKIP', 'LOCATION'}, 'unsupported instruction ' + kind)
    closure = _type_closure(symbols, {name: name for name in [*touched, *parameters.values()]})
    require(not any({'#volatile', 'C_volatile', 'volatile', '#atomic'} & n.get('namedSub', {}).keys()
                    for n in _walk(closure)), 'volatile or atomic storage needs another effect contract')
    return {'status': 'checked-cleanup-tail-footprint', 'authorizing': False,
            'instruction_indices': indices, 'calls': calls, 'automatic_storage': sorted(touched),
            'parameter_roles': parameters, 'body_sha256': canonical_sha256_v3([_payload(rows[i]) for i in indices]),
            'type_closure_sha256': canonical_sha256_v3(closure), 'coverage_checked': False,
            'service_contracts_checked': False, 'runtime_compatibility_checked': False}
