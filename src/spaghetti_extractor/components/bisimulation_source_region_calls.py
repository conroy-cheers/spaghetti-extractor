"""Compiled call obligations between explicit compiler-inventoried cuts.

Use only on the existing source-cut-locals inventory, with its exact marker
prelude and separately checked source profile. This inventories dependencies;
it proves neither call contracts, state transport, nor application equivalence.
"""

from spaghetti_extractor.components.bisimulation_cut_state import _symbol
from spaghetti_extractor.components.bisimulation_entry_conformance import _payload, _truth


def source_region_calls(*, functions, symbols, function, entry_sync, control_graph=False):
    """Follow both unknown branch arms, stopping at the next cut or C return.

The current admission profile requires an acyclic region and direct calls.
An internal loop needs a repeated-call/progress rule, not silent truncation.
The explicit control_graph mode inventories cycles and computed calls for typed
body correspondence only. Its consumer must prove complete execution, progress
and dependency contracts separately; it cannot reuse one invocation per site.
Marker labels alone are insufficient: require the compiler's private uint32
declaration, zero initializer and end-of-lifetime instruction.
"""
    def require(condition, detail):
        if not condition:
            raise ValueError('source region calls: ' + detail)

    def zero_initializer(value):
        # Zero remains zero under an integer-width conversion. Do not erase
        # casts on other values or extend this to arbitrary constant folding.
        typ = value.get('namedSub', {}).get('type', {})
        if typ.get('id') not in {'signedbv','unsignedbv'}:
            return False
        if value.get('id') == 'constant':
            return int(value['namedSub']['value']['id'], 16) == 0
        operands = value.get('sub', [])
        return value.get('id') == 'typecast' and len(operands) == 1 and zero_initializer(operands[0])

    require(type(control_graph) is bool, 'invalid control graph mode')
    body = functions.get(function, {})
    require(body.get('isBodyAvailable') is True, 'missing source body')
    rows = body.get('instructions', [])
    locations = {row['locationNumber']: i for i, row in enumerate(rows)}
    require(len(locations) == len(rows), 'duplicate instruction location')
    markers = {}
    for i, row in enumerate(rows):
        if row['instructionId'] != 'DECL':
            continue
        identity = _symbol(row['code']['sub'][0])
        symbol = symbols.get(identity, {})
        name = symbol.get('baseName', '')
        prefix = '__CPROVER_spx_local_sync_'
        if not name.startswith(prefix):
            continue
        sync = name[len(prefix):]
        require(sync and sync not in {v[0] for v in markers.values()}, 'duplicate cut marker')
        require(symbol.get('isStaticLifetime') is False and symbol.get('isParameter') is False
                and symbol.get('location', {}).get('function') == function
                and symbol.get('type', {}).get('id') == 'unsignedbv'
                and symbol['type'].get('namedSub', {}).get('width', {}).get('id') == '32'
                and not {'#volatile','C_volatile'} & symbol['type'].get('namedSub', {}).keys(),
                'cut marker is not private uint32 storage')
        require(i+2 < len(rows), 'truncated marker')
        assign, dead = rows[i+1:i+3]
        values = assign.get('code', {}).get('sub', [])
        require(assign['instructionId'] == 'ASSIGN' and len(values) == 2
                and _symbol(values[0]) == identity and zero_initializer(values[1])
                and dead['instructionId'] == 'DEAD' and _symbol(dead['code']['sub'][0]) == identity,
                'marker prelude shape differs')
        markers[i] = (sync, i+3)
    entries = [after for sync, after in markers.values() if sync == entry_sync]
    require(len(entries) == 1, 'entry marker is absent or ambiguous')
    colors, calls, exits, visited, repeated = {}, {}, set(), set(), set()

    pending = [(entries[0], False)]
    while pending:
        i, complete = pending.pop()
        require(0 <= i < len(rows), 'region falls off the function')
        if complete:
            colors[i] = 2
            continue
        if i in markers:
            exits.add(('cut', markers[i][0]))
            continue
        if colors.get(i) == 2:
            continue
        if colors.get(i) == 1:
            require(control_graph, 'internal cycle requires a repeated-call/progress rule')
            repeated.add(i)
            continue
        colors[i] = 1
        visited.add(i)
        row = rows[i]
        kind = row['instructionId']
        require(not row.get('targets') or kind == 'GOTO', 'target on a non-branch instruction')
        require(kind in {'DECL','DEAD','ASSIGN','FUNCTION_CALL','GOTO','SKIP','LOCATION',
                         'SET_RETURN_VALUE','END_FUNCTION'}, 'unsupported source instruction ' + kind)
        if kind == 'SET_RETURN_VALUE':
            exits.add(('return', str(i)))
            successors = []
        elif kind == 'END_FUNCTION':
            raise ValueError('source region calls: end without a C return value')
        elif kind == 'GOTO':
            targets = row.get('targets', [])
            require(len(targets) == 1 and targets[0] in locations, 'invalid branch target')
            known = _truth(row['guard'], {})
            successors = []
            if known is not False:
                successors.append(locations[targets[0]])
            if known is not True:
                successors.append(i+1)
        else:
            if kind == 'FUNCTION_CALL':
                operands = row.get('code', {}).get('sub', [])
                require(len(operands) == 3 and (control_graph or _symbol(operands[1]) is not None),
                        'indirect call requires an explicit target/contract rule')
                calls[i] = {'instruction_index': i, 'callee': _symbol(operands[1]),
                            'payload': _payload(row)}
            successors = [i+1]
        pending.append((i, True))
        pending.extend((successor, False) for successor in reversed(successors))

    require(exits, 'region has no exit')
    return {'status':'inventoried', 'authorizing':False, 'entry_sync':entry_sync,
            'calls':[calls[i] for i in sorted(calls)], 'exits':sorted(exits),
            'instruction_indices':sorted(visited), 'acyclic':not repeated,
            **({'control_graph_only':True, 'cycle_frontiers':sorted(repeated),
                'progress_checked':False, 'invocation_multiplicity_checked':False} if control_graph else {}),
            'call_contracts_checked':False, 'state_transport_checked':False}


def match_source_region_calls(region, *, prefix_calls):
    """Require an exact inventory of invocations supplied by a matched prefix.

    Consume each occurrence once: equal signatures or even equal instruction
    payloads do not authorize additional invocations. This is a dependency gate,
    not a proof that argument states satisfy the supplied contracts. The prefix
    relation and evidence bindings must be checked separately by its consumer.
    """
    if region.get('control_graph_only') or not region.get('acyclic') or any(call.get('callee') is None for call in region['calls']):
        raise ValueError('source region calls: graph sites cannot reuse single-invocation contracts')
    remaining = list(enumerate(prefix_calls))
    matches = []
    for call in region['calls']:
        candidates = [(i, pair) for i, pair in enumerate(remaining)
                      if pair[1] == call['payload']]
        if not candidates:
            raise ValueError('source region calls: missing invocation qualification for '
                             f"{call['callee']} at instruction {call['instruction_index']}")
        slot, (prefix_index, _) = candidates[0]
        remaining.pop(slot)
        matches.append({'instruction_index': call['instruction_index'],
                        'prefix_call_index': prefix_index})
    if remaining:
        raise ValueError('source region calls: unused prefix invocation qualification')
    return {'status': 'matched-invocation-dependencies', 'authorizing': False,
            'matches': matches, 'call_contracts_checked': False,
            'state_transport_checked': False}
