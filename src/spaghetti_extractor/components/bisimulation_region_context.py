"""Check the unchanged compiled context around an explicitly marked proof region.

The region's behavior, frame, invocation contracts and incoming domain still need
separate proofs. This relation compares context; it never imports a local theorem.
Markers are empty proof-only calls, not additional production component APIs.
"""

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_cut_state import _symbol, _walk
from spaghetti_extractor.components.bisimulation_entry_conformance import (
    _function_payload, _payload, _symbol_payload, _truth,
)


def _require(condition, detail):
    if not condition:
        raise ValueError('region context transport: ' + detail)


def _private_scalar(identity, symbols, functions, function):
    """Only rename a single-declaration automatic scalar with no exposed address."""
    symbol = symbols.get(identity, {})
    _require(symbol.get('isStaticLifetime') is False and symbol.get('isParameter') is False
             and symbol.get('location', {}).get('function') == function
             and symbol.get('type', {}).get('id') in {'signedbv', 'unsignedbv', 'bool', 'c_bool'},
             'renamed local must be an automatic scalar')
    declarations = 0
    for name, body in functions.items():
        for row in body.get('instructions', []):
            payload = _payload(row)
            uses = [v for v in _walk(payload) if _symbol(v) == identity]
            _require(not uses or name == function, 'renamed local escapes its function')
            _require(not any(v.get('id') == 'address_of' and any(_symbol(n) == identity for n in _walk(v))
                             for v in _walk(payload)), 'renamed local exposes its address')
            if row['instructionId'] == 'DECL' and uses:
                declarations += 1
    _require(declarations == 1, 'renamed local needs one declaration')
    return _symbol_payload(symbol)


def _call(row):
    operands = row.get('code', {}).get('sub', [])
    return (_symbol(operands[1]) if row['instructionId'] == 'FUNCTION_CALL' and len(operands) == 3 else None)


def _normalized(body, removed=()):
    rows = list(body.get('instructions', []))
    locations = {row['locationNumber']: i for i, row in enumerate(rows)}
    _require(len(locations) == len(rows), 'duplicate location')
    removed = set(removed) | {i for i, row in enumerate(rows) if row['instructionId'] in {'SKIP', 'LOCATION'}}
    def target(location):
        _require(location in locations, 'foreign target')
        index = locations[location]
        while index in removed:
            index += 1
        _require(index < len(rows), 'removed terminal target')
        return rows[index]['locationNumber']
    # Ending a new private scalar's lifetime can make the compiler invert a
    # later unchanged break: IF g GOTO next; GOTO exit; next:. After lifetime
    # erasure, fold precisely that finite diamond to IF !g GOTO exit. The
    # intermediate jump must have no other incoming edge or semantic payload.
    # This changes only the comparison inventory, never a compiled model.
    while True:
        kept_indices = [i for i in range(len(rows)) if i not in removed]
        incoming = {target(v) for i in kept_indices for v in rows[i].get('targets', [])}
        folded = False
        for position in range(len(kept_indices) - 2):
            i, j, following = kept_indices[position:position + 3]
            branch, jump = rows[i], rows[j]
            guard = branch.get('guard', {})
            payload = _payload(jump)
            if (branch['instructionId'] != 'GOTO' or len(branch.get('targets', [])) != 1
                    or _truth(guard, {}) is not None or guard.get('namedSub', {}).get('type') != {'id': 'bool'}
                    or target(branch['targets'][0]) != rows[following]['locationNumber']
                    or jump['instructionId'] != 'GOTO' or len(jump.get('targets', [])) != 1
                    or _truth(jump.get('guard', {}), {}) is not True
                    or set(payload) != {'instructionId', 'guard', 'property'} or payload['property']
                    or rows[j]['locationNumber'] in incoming):
                continue
            inverse = (guard['sub'][0] if guard.get('id') == 'not' and len(guard.get('sub', [])) == 1 else
                       {'id': 'not', 'namedSub': {'type': {'id': 'bool'}}, 'sub': [guard]})
            rows[i] = {**branch, 'guard': inverse, 'targets': list(jump['targets'])}
            removed.add(j)
            folded = True
            break
        if not folded:
            break
    kept = [{**row, 'targets': [target(v) for v in row.get('targets', [])]}
            for i, row in enumerate(rows) if i not in removed]
    return _function_payload({**body, 'instructions': kept})


def _markers(functions, function, markers):
    # A terminal region needs only an entry marker: its real C returns are
    # already observable exits. Marker validation checks identity and inertia;
    # coverage and progress belong to the consuming region relation.
    _require(len(markers) >= 1 and len(set(markers)) == len(markers), 'ambiguous marker family')
    for name in markers:
        body = functions.get(name, {})
        _require(name != function and body.get('isBodyAvailable') is True
                 and body.get('parameterIdentifiers') == [] and body.get('instructions'), 'missing empty marker')
        _require(all(row['instructionId'] in {'SKIP', 'LOCATION', 'END_FUNCTION'} and not row.get('targets')
                     for row in body['instructions']), 'marker has behavior')
    sites = {}
    for owner, body in functions.items():
        for index, row in enumerate(body.get('instructions', [])):
            name = _call(row)
            if name not in markers:
                continue
            operands = row['code']['sub']
            _require(owner == function and name not in sites and operands[0].get('id') == 'nil'
                     and not operands[2].get('sub'), 'marker call is not unique and argument-free')
            sites[name] = index
    _require(set(sites) == set(markers), 'missing marker call')
    return sites


def check_inert_region_markers(*, original_functions, original_symbols, marked_functions, marked_symbols,
                              function, markers):
    """Require complete compiled correspondence after erasing only empty calls."""
    sites = _markers(marked_functions, function, markers)
    _require(set(marked_functions) - set(original_functions) == set(markers)
             and not set(original_functions) - set(marked_functions), 'marker function universe differs')
    _require(set(marked_symbols) - set(original_symbols) == set(markers)
             and not set(original_symbols) - set(marked_symbols), 'marker symbol universe differs')
    for name, symbol in original_symbols.items():
        _require(_symbol_payload(symbol) == _symbol_payload(marked_symbols[name]), 'marker changed storage: ' + name)
    for name, body in original_functions.items():
        _require(_normalized(body) == _normalized(marked_functions[name], sites.values() if name == function else ()),
                 'marker changed compiled function: ' + name)
    return {'status': 'matched-inert-region-markers', 'authorizing': False, 'marker_sites': sites,
            'original_function_sha256': canonical_sha256_v3(_normalized(original_functions[function])),
            'marked_function_sha256': canonical_sha256_v3(_normalized(marked_functions[function]))}


def _region(functions, function, entry, exits):
    markers = _markers(functions, function, [entry, *exits.values()])
    body = functions[function]
    rows = body['instructions']
    locations = {row['locationNumber']: i for i, row in enumerate(rows)}
    _require(len(locations) == len(rows), 'duplicate region location')
    ports = {index: name for name, marker in exits.items() for index in [markers[marker]]}
    # Shared compiler labels immediately before a cut belong to that exit, not
    # to the region. Other regions may also branch to these inert instructions.
    for index in range(len(rows) - 2, -1, -1):
        if rows[index]['instructionId'] in {'SKIP', 'LOCATION'} and index + 1 in ports:
            ports[index] = ports[index + 1]
    owned, colors, reached = set(), {}, {}
    pending = [(markers[entry] + 1, False)]
    def successors(index):
        row = rows[index]
        targets = row.get('targets', [])
        _require(not targets or row['instructionId'] == 'GOTO', 'target on a non-branch')
        if row['instructionId'] == 'END_FUNCTION':
            return []
        if row['instructionId'] == 'GOTO':
            _require(len(targets) == 1 and targets[0] in locations, 'invalid branch target')
            known = _truth(row['guard'], {})
            return ([locations[targets[0]]] if known is not False else []) + ([index + 1] if known is not True else [])
        return [index + 1]
    while pending:
        index, done = pending.pop()
        _require(0 <= index < len(rows), 'region falls off function')
        if done:
            colors[index] = 2
            continue
        if index in ports or rows[index]['instructionId'] == 'END_FUNCTION':
            port = ports.get(index, '@return')
            destination = markers[exits[port]] if port in exits else index
            _require(port not in reached or reached[port] == destination, 'ambiguous exit')
            reached[port] = destination
            continue
        if colors.get(index) == 2:
            continue
        _require(colors.get(index) != 1, 'internal cycle requires a progress rule')
        colors[index] = 1
        owned.add(index)
        _require(_call(rows[index]) not in [entry, *exits.values()], 'nested or repeated marker')
        pending.append((index, True))
        pending.extend((value, False) for value in reversed(successors(index)))
    _require(set(exits) <= set(reached), 'missing outgoing cut')
    # A caller may enter only through the declared entry. Even a currently
    # unreachable edge into the middle invalidates this structural boundary.
    for index in range(len(rows)):
        if index in owned:
            continue
        for following in successors(index):
            _require(following not in owned or index == markers[entry],
                     f'external edge bypasses region entry: {index} -> {following}')
    return markers[entry], owned, reached


def check_region_context_transport(*, original_functions, original_symbols, edited_functions, edited_symbols,
                                   function, entry, exits):
    """Compare complete contexts after replacing the selected regions by ports.

    A private automatic scalar may be introduced inside the region if no use
    other than ending its lifetime escapes it. Changed region behavior is
    deliberately not accepted or rejected here; separate local proofs decide it.
    """
    _require('@return' not in exits and entry not in exits.values(), 'reserved or repeated port')
    _require(set(original_functions) == set(edited_functions), 'context function universe differs')
    _require(not set(original_symbols) - set(edited_symbols), 'context storage removed')
    a = _region(original_functions, function, entry, exits)
    b = _region(edited_functions, function, entry, exits)
    _require(set(a[2]) == set(b[2]), 'exit port coverage differs')
    added = set(edited_symbols) - set(original_symbols)
    extra_dead = set()
    for name in added:
        _private_scalar(name, edited_symbols, edited_functions, function)
        _require(not any({'#volatile', 'C_volatile'} & node.get('namedSub', {}).keys()
                         for node in _walk(edited_symbols[name]['type'])), 'new private storage is volatile')
        for index, row in enumerate(edited_functions[function]['instructions']):
            if not any(_symbol(node) == name for node in _walk(_payload(row))):
                continue
            if index not in b[1]:
                _require(row['instructionId'] == 'DEAD' and _symbol(row['code']['sub'][0]) == name,
                         'new private storage escapes region')
                extra_dead.add(index)
    for name, symbol in original_symbols.items():
        _require(_symbol_payload(symbol) == _symbol_payload(edited_symbols[name]), 'context storage changed: ' + name)
    for name, body in original_functions.items():
        if name != function:
            _require(_normalized(body) == _normalized(edited_functions[name]), 'context helper changed: ' + name)
    def collapsed(functions, region, extra):
        start, owned, ports = region
        body = functions[function]
        rows = list(body['instructions'])
        rows[start] = {'instructionId': 'PROOF_REGION', 'locationNumber': rows[start]['locationNumber'],
                       'code': {'ports': sorted(ports)}, 'targets': [rows[ports[k]]['locationNumber'] for k in sorted(ports)]}
        return _normalized({**body, 'instructions': rows}, owned | set(extra))
    left, right = collapsed(original_functions, a, ()), collapsed(edited_functions, b, extra_dead)
    _require(left == right, 'compiled context outside region differs')
    return {'status': 'matched-compiled-region-context', 'authorizing': False,
            'context_sha256': canonical_sha256_v3(left), 'entry_marker': entry, 'exit_markers': exits,
            'original_region_indices': sorted(a[1]), 'edited_region_indices': sorted(b[1]),
            'ports': sorted(a[2]), 'new_private_scalars': sorted(added),
            'erased_private_lifetime_ends': sorted(extra_dead),
            'local_behavior_checked': False, 'frame_checked': False, 'incoming_domain_checked': False,
            'local_theorem_import_authorized': False}
