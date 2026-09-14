"""Compiler-bound manual proof-region graphs, without theorem or ownership authority."""

import re

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_cut_state import _symbol, _walk
from .bisimulation_entry_conformance import _payload, _symbol_payload, _truth
from .bisimulation_region_context import _markers
from .bisimulation_source_entry import _type_closure


def _require(condition, detail):
    if not condition:
        raise ValueError('source region graph: ' + detail)


def checked_graph_boundary(value, source):
    from .bisimulation_source_edit_check import checked_edit_boundary

    _require(isinstance(value, dict) and set(value) == {
        'operation_id', 'source', 'entry', 'exits', 'regions'}, 'boundary fields differ')
    boundary = checked_edit_boundary({k: v for k, v in value.items() if k != 'regions'}, source, minimum_exits=1)
    entries = value['regions']
    _require(isinstance(entries, list) and entries and all(isinstance(v, str) for v in entries)
             and len(set(entries)) == len(entries) and set(entries) <= {'entry', *boundary['exits']},
             'regions must select distinct declared cuts')
    return {**boundary, 'regions': list(entries)}


def project_source_region_graph(*, functions, symbols, function, cuts, entries):
    """Inventory all paths to the next cut or return, including inter-region cycles.

    An internal cycle requires another manual cut. Calls and memory effects remain
    explicit unqualified dependencies. Region digests exclude absolute instruction
    positions, so unrelated region growth need not change their semantic binding.
    No liveness, state transport, contract applicability or progress is inferred.
    """
    _require(isinstance(cuts, dict) and all(isinstance(k, str) and re.fullmatch(
        '[A-Za-z_][A-Za-z0-9_]*', k) for k in cuts), 'invalid cut names')
    _require(isinstance(entries, list) and entries and all(isinstance(v, str) for v in entries)
             and len(entries) == len(set(entries)) and set(entries) <= set(cuts), 'invalid region entries')
    sites = _markers(functions, function, list(cuts.values()))
    ports = {sites[marker]: name for name, marker in cuts.items()}
    rows = functions[function]['instructions']
    locations = {r['locationNumber']: i for i, r in enumerate(rows)}
    _require(len(locations) == len(rows), 'duplicate instruction location')

    def successors(index):
        _require(0 <= index < len(rows), 'region falls off function')
        row = rows[index]
        kind, targets = row['instructionId'], row.get('targets', [])
        _require(not targets or kind == 'GOTO', 'target on non-branch instruction')
        if kind in {'SET_RETURN_VALUE', 'END_FUNCTION'}:
            return []
        if kind != 'GOTO':
            return [index + 1]
        _require(len(targets) == 1 and targets[0] in locations, 'invalid branch target')
        known = _truth(row['guard'], {})
        return ([locations[targets[0]]] if known is not False else []) + ([index + 1] if known is not True else [])

    # Compiler join labels and constant routing immediately before a cut
    # belong to that port. They are shared by its incoming regions, not effects
    # owned by one predecessor. Only follow paths already known to reach a cut.
    while True:
        previous = len(ports)
        for index in range(len(rows) - 1, -1, -1):
            row = rows[index]
            routing = row['instructionId'] in {'SKIP', 'LOCATION'} or (
                row['instructionId'] == 'GOTO' and _truth(row.get('guard', {}), {}) is not None
                and row.get('code', {}).get('id', 'nil') == 'nil')
            if index not in ports and routing:
                targets = successors(index)
                if len(targets) == 1 and targets[0] in ports:
                    ports[index] = ports[targets[0]]
        if len(ports) == previous:
            break

    regions = []
    for entry in entries:
        start = sites[cuts[entry]]
        owned, colors, exits = set(), {}, set()
        pending = [(start + 1, False)]
        while pending:
            index, finished = pending.pop()
            _require(0 <= index < len(rows), 'region falls off function')
            if index in ports:
                exits.add(('cut', ports[index]))
                continue
            if finished:
                colors[index] = 2
                continue
            if colors.get(index) == 2:
                continue
            _require(colors.get(index) != 1, 'internal cycle requires another manual cut: ' + entry)
            colors[index] = 1
            owned.add(index)
            row = rows[index]
            kind = row['instructionId']
            _require(kind in {'DECL', 'DEAD', 'ASSIGN', 'FUNCTION_CALL', 'GOTO', 'SKIP',
                             'LOCATION', 'SET_RETURN_VALUE', 'END_FUNCTION'}, 'unsupported instruction ' + kind)
            if kind in {'SET_RETURN_VALUE', 'END_FUNCTION'}:
                exits.add(('return', kind))
            pending.append((index, True))
            pending.extend((target, False) for target in reversed(successors(index)))
        _require(exits, 'region has no exit')
        ordered = sorted(owned)
        ordinal = {index: i for i, index in enumerate(ordered)}

        def destination(index):
            if index in ports:
                return {'cut': ports[index]}
            _require(index in ordinal, 'uncovered successor')
            return {'instruction': ordinal[index]}

        body = [{**_payload(rows[i]), 'successors': [destination(j) for j in successors(i)]} for i in ordered]
        referenced = {_symbol(node) for item in body for node in _walk(item) if _symbol(node)}
        _require(referenced <= symbols.keys(), 'missing referenced symbol')
        storage = {name: _symbol_payload(symbols[name]) for name in sorted(referenced)
                   if symbols[name].get('type', {}).get('id') != 'code'}
        types = _type_closure(symbols, {name: name for name in referenced})
        calls = []
        for index in ordered:
            if rows[index]['instructionId'] == 'FUNCTION_CALL':
                args = rows[index].get('code', {}).get('sub', [])
                _require(len(args) == 3, 'malformed call')
                calls.append({'instruction': ordinal[index], 'direct_callee': _symbol(args[1]),
                              'payload': _payload(rows[index]), 'contract_checked': False})
        incoming = [{'source_instruction': i, 'target_instruction': j} for i in range(len(rows))
                    if i not in owned and i != start for j in successors(i) if j in owned]
        semantic = {'entry': entry, 'body': body, 'storage': storage, 'type_closure': types}
        regions.append({'entry': entry, 'instruction_indices': ordered, 'exits': [list(v) for v in sorted(exits)],
                        'calls': calls, 'referenced_storage': sorted(storage),
                        'external_interior_entries': incoming, 'acyclic_between_cuts': True,
                        'semantic_sha256': canonical_sha256_v3(semantic),
                        'body_sha256': canonical_sha256_v3(body),
                        'storage_sha256': canonical_sha256_v3({'storage': storage, 'types': types})})
    edges = [{'source': r['entry'], 'target': name} for r in regions for kind, name in r['exits'] if kind == 'cut']
    covered = {i for r in regions for i in r['instruction_indices']}
    # Count actual control reachability separately from the compiler's trailing
    # routing/lifetime records after a C return. This uses the same terminal
    # outcome convention as each region above; it is not a lifetime theorem.
    reachable, pending = set(), [0]
    while pending:
        index = pending.pop()
        if index in reachable:
            continue
        _require(0 <= index < len(rows), 'operation falls off function')
        reachable.add(index)
        pending.extend(successors(index))
    return {'status': 'projected-source-region-graph', 'authorizing': False,
            'function': function, 'cut_sites': {name: sites[marker] for name, marker in cuts.items()},
            'regions': regions, 'edges': edges,
            'unselected_cut_regions': sorted(set(cuts) - set(entries)),
            'uncovered_instruction_count': len(set(range(len(rows))) - covered - set(ports)),
            'reachable_instruction_count': len(reachable),
            'uncovered_reachable_instruction_count': len(reachable - covered - set(ports)),
            'whole_component_complete': False, 'state_transport_checked': False,
            'functional_correctness_checked': False, 'progress_checked': False,
            'memory_contracts_checked': False, 'activation_authorized': False}
