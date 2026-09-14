"""Check the actual cleanup source's uses before changing view representations.

This is a structural premise for composition, not a component-equivalence proof.
It consumes the owned compiler graph already covered by the regional proofs.
"""
from pathlib import Path

from .bisimulation_call_evidence import read_json
from .bisimulation_compaction_contract import require
from .bisimulation_compaction_inputs import read_inventory
from .bisimulation_cut_state import _symbol, _walk
from .bisimulation_entry_conformance import _payload, _truth
from .bisimulation_source_call_region import _path
from .bisimulation_source_region_transport import _integer, _known
from ..artifacts.artifact_set import canonical_sha256_v3

SCALARS = {'unsignedbv', 'signedbv', 'bool', 'c_bool'}
OPAQUE = {'tag-spx_view_v1', 'tag-spx_ref_v1'}


def _type(value):
    return value.get('namedSub', {}).get('type', {})


def _opaque(value):
    typ = _type(value)
    return typ.get('id') == 'struct_tag' and typ.get('namedSub', {}).get('identifier', {}).get('id') in OPAQUE


def _width(value):
    if value.get('id') == 'typecast' and len(value.get('sub', [])) == 1:
        child = value['sub'][0]
        if (_type(value) == {'id': 'unsignedbv', 'namedSub': {'width': {'id': '32'}}}
                and _type(child).get('id') in {'signedbv', 'unsignedbv'}
                and _type(child).get('namedSub', {}).get('width', {}).get('id') == '32'):
            value = child
    return _integer(value)


def _scalar(value):
    for node in _walk(value):
        if node.get('id') in {'member', 'dereference', 'address_of', 'index', 'side_effect'}:
            raise ValueError('cleanup representation use: descriptor observation or unmodeled address')
        if node.get('id') == 'symbol':
            require(_type(node).get('id') in SCALARS, 'cleanup scalar observes an opaque or pointer value')


def _fault_exit(rows, locations, index, status):
    """Require a finite, silent fault suffix independent of the output variable."""
    seen, trace, facts = set(), [], {status: True}
    while True:
        require(0 <= index < len(rows) and index not in seen, 'cleanup read fault has no finite silent exit')
        seen.add(index); trace.append(index); row = rows[index]; kind = row['instructionId']
        if kind == 'SET_RETURN_VALUE':
            args = row.get('code', {}).get('sub', [])
            require(len(args) == 1 and _integer(args[0]) == 0xffffffff,
                    'cleanup read fault observes a result or changes its outcome')
            return trace
        if kind == 'GOTO':
            known = _known(row['guard'], facts)
            require(known is not None, 'cleanup read fault branches on an unproved value')
            targets = row.get('targets', [])
            require(len(targets) == 1 and targets[0] in locations, 'cleanup read fault has invalid control')
            index = locations[targets[0]] if known else index+1
        else:
            require(kind in {'DEAD', 'SKIP', 'LOCATION'}, 'cleanup read fault has an observable continuation')
            if kind == 'DEAD':
                values = row.get('code', {}).get('sub', [])
                require(len(values) == 1, 'cleanup read fault has malformed lifetime end')
                facts.pop(_symbol(values[0]), None)
            index += 1


def checked_cleanup_source_use(body, *, parameters):
    rows = body['instructions']; locations = {r['locationNumber']: i for i, r in enumerate(rows)}
    require(rows and len(locations) == len(rows), 'cleanup source use has duplicate locations')
    roles = {'context', 'text', 'suppress_notice', 'main_window', 'edit_window', 'caption'}
    require(set(parameters) == roles and set(parameters.values()) == set(body['parameterIdentifiers']),
            'cleanup source use parameter roles differ')
    context = parameters['context']; prefix = (context, '*', 'services', '*')
    function = context.rsplit('::', 1)[0]
    opaque_locals, accesses, copies, calls, visited = set(), [], [], [], set()

    def local(value):
        name = _symbol(value)
        require(name is not None and name.startswith(function+'::') and name not in parameters.values(),
                'cleanup representation storage is not a direct local')
        require(_opaque(value) or _type(value).get('id') in SCALARS, 'cleanup local type needs another relation')
        if _opaque(value):
            opaque_locals.add(name)
        return name

    def view(value):
        if _symbol(value) in {parameters[k] for k in roles-{'context'}}:
            return
        args = value.get('sub', [])
        require(value.get('id') == 'address_of' and len(args) == 1 and _opaque(args[0]),
                'cleanup representation call needs a direct view')
        local(args[0])

    def read_output(value):
        args = value.get('sub', [])
        require(value.get('id') == 'address_of' and len(args) == 1 and _type(args[0]).get('id') in SCALARS,
                'cleanup read output must be a direct scalar local')
        return local(args[0])

    pending = [0]
    while pending:
        index = pending.pop()
        if index in visited:
            continue
        require(0 <= index < len(rows), 'cleanup representation use falls off its function')
        visited.add(index); row = rows[index]; kind = row['instructionId']
        operands = row.get('code', {}).get('sub', [])
        require(not row.get('targets') or kind == 'GOTO', 'cleanup source use target on non-branch')
        if kind in {'DECL', 'DEAD'}:
            require(len(operands) == 1, 'cleanup source use malformed lifetime instruction'); local(operands[0])
        elif kind == 'ASSIGN':
            require(len(operands) == 2, 'cleanup source use malformed assignment')
            lhs, rhs = operands; destination = local(lhs)
            if _opaque(lhs):
                require(_opaque(rhs) and _type(lhs) == _type(rhs), 'cleanup opaque assignment needs a checked constructor')
                source = local(rhs); copies.append({'instruction': index, 'source': source, 'destination': destination})
            else:
                _scalar(rhs)
        elif kind == 'FUNCTION_CALL':
            require(len(operands) == 3, 'cleanup source use malformed call')
            lhs, callee, args = operands; args = args.get('sub', [])
            name = _symbol(callee); path = () if name else _path(callee)
            if lhs.get('id') != 'nil':
                local(lhs)
            width, output = None, None
            if name in {'spx_view_read_u8', 'spx_view_write_u8'}:
                require(len(args) == 3, 'cleanup byte helper arity differs'); view(args[0]); _scalar(args[1]); width = 1
                if name == 'spx_view_read_u8':
                    output = read_output(args[2])
                else:
                    _scalar(args[2])
            elif len(path) == 4 and path[1:] == ('*', 'read', '*'):
                require(path[0] in {parameters[k] for k in ['suppress_notice', 'main_window', 'edit_window']}
                    and len(args) == 5 and _path(args[0]) == (path[0], '*', 'access_context')
                    and _path(args[1]) == (path[0], '*', 'base'), 'cleanup span read needs its own view')
                _scalar(args[2]); width = _width(args[3])
                require(width in {1, 2, 4}, 'cleanup span width is not supported by the actual adapter')
                output = read_output(args[4]); name = 'read-shared-view'
            else:
                require(len(path) == 6 and path[:4] == prefix and path[-1] == '*', 'cleanup source use unknown dependency')
                name = path[4]
                arities = {'length': 2, 'allocate': 3, 'copy': 3, 'release': 2, 'resource_text': 2, 'message': 5, 'focus': 2}
                require(name in arities and len(args) == arities[name] and _path(args[0]) == (*prefix, 'context'),
                        'cleanup service arguments or context differ')
                if name == 'length':
                    view(args[1])
                elif name == 'copy':
                    view(args[1]); view(args[2])
                elif name == 'release':
                    require(args[1].get('id') == 'member' and _path(args[1])[-1:] == ('base',)
                        and len(args[1].get('sub', [])) == 1 and _opaque(args[1]['sub'][0]), 'cleanup release needs an opaque reference')
                    local(args[1]['sub'][0])
                elif name == 'message':
                    _scalar(args[1]); view(args[2]); view(args[3]); _scalar(args[4])
                else:
                    for value in args[1:]:
                        _scalar(value)
            calls.append({'instruction': index, 'dependency': name})
            if width is not None:
                access = {'instruction': index, 'dependency': name, 'width': width}
                if output is not None:
                    status = _symbol(lhs)
                    require(status is not None and status != output and _type(lhs).get('id') in SCALARS,
                            'cleanup read has no separate scalar status')
                    access.update(output=output, fault_exit=_fault_exit(rows, locations, index+1, status))
                accesses.append(access)
        elif kind == 'GOTO':
            _scalar(row['guard'])
        elif kind == 'SET_RETURN_VALUE':
            require(len(operands) == 1, 'cleanup source use malformed return'); _scalar(operands[0]); continue
        else:
            require(kind in {'SKIP', 'LOCATION'}, 'cleanup source use unsupported instruction '+kind)
        if kind == 'GOTO':
            targets = row.get('targets', [])
            require(len(targets) == 1 and targets[0] in locations, 'cleanup source use invalid branch')
            known = _truth(row['guard'], {})
            pending += ([locations[targets[0]]] if known is not False else []) + ([index+1] if known is not True else [])
        else:
            pending.append(index+1)
    return {'status': 'checked-cleanup-source-representation-use', 'authorizing': False,
        'body_sha256': canonical_sha256_v3([_payload(row) for row in rows]),
        'reachable_instructions': len(visited), 'opaque_locals': sorted(opaque_locals),
        'opaque_copies': sorted(copies, key=lambda r: r['instruction']),
        'calls': sorted(calls, key=lambda r: r['instruction']), 'accesses': sorted(accesses, key=lambda r: r['instruction']),
        'reference_fields_observed': False, 'supported_widths': sorted({a['width'] for a in accesses}),
        'requires': ['Existing regional footprints establish owned nonescaping storage and admitted call roles.',
            'Dependency contracts relate views and references, successful values, outcomes and complete effects.',
            'The actual and regional accessors must satisfy the outcome-aware representation relation.'],
        'scope': 'Owned source does not inspect descriptor identities; read faults have finite silent constant exits. This does not qualify adapters, services, memory or whole-component equivalence.'}


def cleanup_source_representation_use(preparation, contracts, grant_protocol):
    preparation = Path(preparation)
    graphs = read_json(preparation/'compiler-checks.json')['source_region_graphs']
    # The already checked grant protocol binds the shared complete graph and body.
    require(set(contracts) == {'entry', 'loop', 'tail'} and len(grant_protocol['source_cover']) == 7,
            'cleanup representation use needs the complete imported graph')
    ordinary = read_inventory(preparation/'source-region-graph-models/0000-ordinary')
    context_name = contracts['entry']['parameter_roles']['context']
    candidates = [name for name, body in ordinary['functions'].items() if body.get('isBodyAvailable')
        and name+'::'+context_name in body['parameterIdentifiers']]
    require(len(candidates) == 1 and graphs, 'cleanup representation source function is ambiguous')
    function, = candidates
    result = checked_cleanup_source_use(ordinary['functions'][function],
        parameters={role: function+'::'+name for role, name in contracts['entry']['parameter_roles'].items()})
    require(result['body_sha256'] == grant_protocol['body_sha256'], 'cleanup representation source body differs')
    result['source_cover'] = dict(grant_protocol['source_cover'])
    return result
