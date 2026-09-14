"""Compiled cut-body relation with explicit entry and exit storage.

This checks entry restoration and body/control correspondence. Runtime contracts,
the input harness domain, and correspondence of public memory remain separate.
The consumer must separately bind and check the complete local theorem.
"""

from spaghetti_extractor.components.bisimulation_cut_state import _symbol, _walk
from spaghetti_extractor.components.bisimulation_entry_conformance import (
    _advance, _payload, _truth, _function_payload, _symbol_payload,
)
from spaghetti_extractor.components.bisimulation_source_entry import _type_closure
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_source_region_calls import source_region_calls
from spaghetti_extractor.components.bisimulation_region_context import _private_scalar


def _require(condition, message):
    if not condition:
        raise ValueError('source region transport: ' + message)


def _integer(value):
    if value.get('id') == 'typecast' and len(value.get('sub', [])) == 1:
        # Only use casts for zero, whose truth and value are width independent.
        return 0 if _integer(value['sub'][0]) == 0 else None
    if value.get('id') == 'constant':
        named = value.get('namedSub', {})
        if named.get('type', {}).get('id') in {'unsignedbv', 'signedbv'}:
            return int(named['value']['id'], 16)
    return None


def _known(expression, facts):
    result = _truth(expression, facts)
    if result is not None:
        return result
    args = expression.get('sub', [])
    if expression.get('id') == 'not' and len(args) == 1:
        result = _known(args[0], facts)
        return None if result is None else not result
    if expression.get('id') in {'equal', 'notequal'} and len(args) == 2:
        if _integer(args[1]) == 0 and _symbol(args[0]) in facts:
            result = facts[_symbol(args[0])]
            return result if expression['id'] == 'notequal' else not result
    return None


def _rename_symbols(value, mapping):
    if isinstance(value, list):
        return [_rename_symbols(v, mapping) for v in value]
    if not isinstance(value, dict):
        return value
    result = {key: _rename_symbols(v, mapping) for key, v in value.items()}
    if value.get('id') == 'symbol':
        identity = _symbol(value)
        if identity in mapping:
            result['namedSub']['identifier'] = {'id': mapping[identity]}
    return result



def check_source_region_transport(*, original_functions, original_symbols,
                                  local_functions, local_symbols, function,
                                  entry_sync, restored_locals, cut_results, control_graph=False):
    """Relate an ordinary marker inventory to a proof-only cut/return model.

    restored_locals maps exact automatic identities to members of spx_cut. Cut
    ordinals are supplied by the bound experiment. Conditional callees must be
    qualified separately; this matcher preserves call payloads, not their bodies.
    """
    ordinary = source_region_calls(functions=original_functions, symbols=original_symbols,
                                   function=function, entry_sync=entry_sync, control_graph=control_graph)
    _require(all(type(v) is int for v in cut_results.values())
             and len(set(cut_results.values())) == len(cut_results), 'ambiguous cut ordinals')
    left = original_functions[function]['instructions']
    right = local_functions[function]['instructions']
    maps = [{r['locationNumber']: i for i, r in enumerate(rows)} for rows in (left, right)]
    _require(all(len(m) == len(r) for m, r in zip(maps, (left, right))), 'duplicate locations')
    for rows, locations in zip((left, right), maps):
        for row in rows:
            _require(all(t in locations for t in row.get('targets', [])), 'foreign branch target')
            _require(not row.get('targets') or row['instructionId'] == 'GOTO', 'target on non-branch')
    cuts = {}
    for i, row in enumerate(left):
        if row['instructionId'] == 'DECL':
            symbol = original_symbols.get(_symbol(row['code']['sub'][0]), {})
            name = symbol.get('baseName', '')
            if name.startswith('__CPROVER_spx_local_sync_'):
                cuts[i] = name.removeprefix('__CPROVER_spx_local_sync_')
    starts = [i+3 for i, name in cuts.items() if name == entry_sync]
    _require(len(starts) == 1, 'ambiguous entry')
    parameters = original_functions[function]['parameterIdentifiers']
    _require(parameters == local_functions[function]['parameterIdentifiers'], 'parameter identities differ')
    selected = {identity: identity for identity in [*parameters, *restored_locals]}
    _require(_type_closure(original_symbols, selected) == _type_closure(local_symbols, selected),
             'incoming storage type closure differs')

    # Follow the generated BEGIN jump, including the compiler's declaration
    # guards. No source call, assume, arbitrary write, or unknown branch can be
    # hidden before the restore frontier.
    i = 0
    visited, facts, restores, declared = set(), {}, [], set()
    while True:
        _require(i not in visited and 0 <= i < len(right), 'entry cycle or fallthrough')
        visited.add(i)
        row = right[i]
        kind = row['instructionId']
        if kind == 'ASSERT' and row.get('sourceLocation', {}).get('comment') == 'source-cut-invariant':
            _require(_truth(row['guard'], {}) is True, 'entry invariant requires separate admission')
            break
        if kind in {'DECL', 'SKIP', 'LOCATION'}:
            if kind == 'DECL':
                declared.add(_symbol(row['code']['sub'][0]))
            i += 1
            continue
        if kind == 'GOTO':
            value = _known(row['guard'], facts)
            _require(value is not None and len(row.get('targets', [])) == 1, 'unknown entry branch')
            i = maps[1][row['targets'][0]] if value else i+1
            continue
        _require(kind == 'ASSIGN', 'effect or assumption before restore frontier')
        lhs, rhs = row['code']['sub']
        identity = _symbol(lhs)
        if identity in restored_locals:
            _require(identity in declared and local_symbols[identity].get('isStaticLifetime') is False
                     and local_symbols[identity].get('isParameter') is False,
                     'restore lacks fresh automatic storage')
            _require(rhs.get('id') == 'member' and len(rhs.get('sub', [])) == 1
                     and _symbol(rhs['sub'][0]) == 'spx_cut'
                     and rhs.get('namedSub', {}).get('component_name', {}).get('id') == restored_locals[identity],
                     'local restore differs: ' + identity)
            _require(lhs['namedSub']['type'] == rhs['namedSub']['type'], 'restore changes type')
            restores.append(identity)
        else:
            symbol = local_symbols.get(identity, {})
            private_flag = (symbol.get('baseName') == 'spx_local_entered'
                            and symbol.get('location', {}).get('function') == function
                            and symbol.get('isStaticLifetime') is False
                            and symbol.get('isParameter') is False
                            and not any({'#volatile', 'C_volatile'} & node.get('namedSub', {}).keys()
                                        for node in _walk(symbol.get('type', {}))))
            compiler_flag = (identity and identity.startswith('__CPROVER_going_to::')
                             and symbol.get('isAuxiliary') is True
                             and symbol.get('isStaticLifetime') is False
                             and symbol.get('type', {}).get('id') == 'bool'
                             and symbol.get('location', {}).get('function') == function)
            _require(compiler_flag or private_flag,
                     'unexpected entry assignment')
            value = _truth(rhs, {})
            if value is None and _integer(rhs) == 0:
                value = False
            _require(value is not None and (_integer(rhs) in {0, 1} or rhs['namedSub']['type']['id'] == 'bool'),
                     'entry flag assignment is not boolean')
            facts[identity] = value
        i += 1
    _require(len(restores) == len(set(restores)) and set(restores) == set(restored_locals),
             'missing or duplicate incoming restore')
    local_start = i+1

    def epilogue(rows, locations, start, symbols):
        seen = set()
        while True:
            _require(0 <= start < len(rows) and start not in seen, 'return epilogue cycle')
            seen.add(start)
            row = rows[start]
            if row['instructionId'] == 'END_FUNCTION':
                return
            if row['instructionId'] == 'DEAD':
                symbol = symbols.get(_symbol(row['code']['sub'][0]), {})
                _require(symbol.get('isStaticLifetime') is False
                         and symbol.get('location', {}).get('function') == function,
                         'return ends nonlocal lifetime')
            elif row['instructionId'] == 'GOTO':
                _require(_truth(row['guard'], {}) is True and len(row.get('targets', [])) == 1,
                         'conditional return epilogue')
                start = locations[row['targets'][0]]
                continue
            else:
                _require(row['instructionId'] in {'SKIP', 'LOCATION'}, 'effect after return value')
            start += 1

    pending = [(starts[0], local_start)]
    pairs, exits, local_renaming = set(), set(), {}
    while pending:
        a, b = pending.pop()
        a = _advance(left, maps[0], a, {}, set())
        b = _advance(right, maps[1], b, {}, set())
        if (a, b) in pairs:
            continue
        if a in cuts:
            name = cuts[a]
            _require(name in cut_results, 'missing exit mapping')
            marker = right[b]
            _require(marker['instructionId'] == 'ASSERT'
                     and marker.get('sourceLocation', {}).get('comment') == 'source-cut-invariant:'+name
                     and _truth(marker['guard'], {}) is True, 'cut identity or invariant differs')
            _require(b+1 < len(right) and right[b+1]['instructionId'] == 'SET_RETURN_VALUE'
                     and _integer(right[b+1]['code']['sub'][0]) == cut_results[name], 'cut result differs')
            epilogue(right, maps[1], b+2, local_symbols)
            exits.add(('cut', name))
            pairs.add((a, b))
            continue
        if left[a]['instructionId'] == right[b]['instructionId'] == 'DECL':
            lhs, rhs = [_symbol(row['code']['sub'][0]) for row in (left[a], right[b])]
            if lhs != rhs:
                _require(lhs not in selected and rhs not in selected and rhs not in local_renaming
                         and lhs not in local_renaming.values() and lhs not in local_symbols
                         and rhs not in original_symbols, 'ambiguous local renaming')
                original = _private_scalar(lhs, original_symbols, original_functions, function)
                local = _private_scalar(rhs, local_symbols, local_functions, function)
                _require(original == {**local, 'name': lhs}, 'renamed local storage differs')
                local_renaming[rhs] = lhs
        _require(_payload(left[a]) == _rename_symbols(_payload(right[b]), local_renaming),
                 f'body instruction differs at {a}/{b}')
        pairs.add((a, b))
        kind = left[a]['instructionId']
        if kind == 'SET_RETURN_VALUE':
            result = _integer(left[a]['code']['sub'][0])
            # Synthetic cut ordinals share the return channel in cut models.
            # A terminal-only model has no such ordinals: retain its checked
            # return expression and let the paired theorem check its value.
            _require(not cut_results or (result is not None and result not in cut_results.values()),
                     'return needs a separately tagged outcome')
            epilogue(left, maps[0], a+1, original_symbols)
            epilogue(right, maps[1], b+1, local_symbols)
            exits.add(('return', str(a)))
            continue
        _require(kind in {'DECL', 'DEAD', 'ASSIGN', 'FUNCTION_CALL', 'GOTO'}, 'unsupported body effect')
        if kind == 'GOTO':
            _require(len(left[a]['targets']) == len(right[b]['targets']) == 1, 'ambiguous body branch')
            pending.append((maps[0][left[a]['targets'][0]], maps[1][right[b]['targets'][0]]))
        pending.append((a+1, b+1))
    _require(exits == set(ordinary['exits']), 'exit coverage differs')
    # Identical operand spelling does not preserve storage duration or the
    # layouts behind struct tags. In particular an unrestored automatic can
    # overapproximate entry state, whereas a newly static object initialized at
    # startup could silently restrict it. Check every referenced shared symbol;
    # renamed private scalars already pass the stricter nonescape rule above.
    referenced = {_symbol(node) for a, _ in pairs if a not in cuts
                  for node in _walk(_payload(left[a])) if _symbol(node)}
    storage = {}
    for identity in sorted(referenced - set(local_renaming.values())):
        _require(identity in original_symbols and identity in local_symbols,
                 'body operand storage is absent: ' + identity)
        original, local = original_symbols[identity], local_symbols[identity]
        if original.get('type', {}).get('id') == 'code':
            continue  # Callee bodies remain separate contracts.
        _require(_symbol_payload(original) == _symbol_payload(local),
                 'body operand storage differs: ' + identity)
        storage[identity] = identity
    _require(_type_closure(original_symbols, storage) == _type_closure(local_symbols, storage),
             'body operand type closure differs')
    return {'status': 'matched-source-region-transport', 'authorizing': False,
            **({'control_graph_only':True, 'execution_obligations_checked':False,
                'dependency_inventory':ordinary} if control_graph else {}),
            'restored_locals': restored_locals, 'entry_path': sorted(visited),
            'private_scalar_renaming': local_renaming,
            'instruction_pairs': sorted(pairs), 'exits': sorted(exits),
            'checked_body_storage': sorted(storage),
            'runtime_contracts_checked': False, 'input_harness_domain_checked': False,
            'paired_cut_observer_transport_checked': False,
            'public_memory_correspondence_checked': False}


def check_source_region_observer_transport(*, original_functions, original_symbols,
                                         local_functions, local_symbols, function,
                                         entry_sync, restored_locals, cut_results,
                                         observer, observer_arguments, parameter_arguments=(),
                                         captured_locals=(), control_graph=False):
    """Check exact cut arguments to a proof-only, assertion-only observer.

    observer_arguments lists (automatic symbol, address_of) pairs after the cut
    ordinal. Parameter values require explicit parameter_arguments and must each
    occur once. Strip only the checked calls, then use the ordinary body/restore/exit
    relation. The observer predicates and application domain are separate proof
    obligations; this does not import the actual paired application's codecs.
    """
    _require(observer in local_functions and observer != function, 'cut observer is absent')
    body = local_functions[observer]
    _require(body.get('isBodyAvailable') is True and body.get('instructions'), 'cut observer lacks a body')
    _require(all(row['instructionId'] in {'ASSERT', 'SKIP', 'LOCATION', 'END_FUNCTION'}
                 and not row.get('targets') for row in body['instructions']),
             'cut observer must contain only assertions')
    _require(any(row['instructionId'] == 'ASSERT' for row in body['instructions']), 'cut observer has no predicates')
    _require(not any(node.get('id') in {'side_effect', 'nondet_symbol'}
                     for row in body['instructions'] for node in _walk(row.get('guard', {}))),
             'cut observer guard has an effect')
    parameters = original_functions[function].get('parameterIdentifiers', [])
    _require(len(set(parameter_arguments)) == len(parameter_arguments)
             and set(parameter_arguments) <= set(parameters), 'unknown or duplicate parameter capture')
    _require(len(set(captured_locals)) == len(captured_locals), 'duplicate outgoing local capture')
    for identity in captured_locals:
        original = original_symbols.get(identity, {})
        local = local_symbols.get(identity, {})
        _require(original.get('isStaticLifetime') is False and original.get('isParameter') is False
                 and original.get('location', {}).get('function') == function
                 and _symbol_payload(original) == _symbol_payload(local), 'outgoing capture is not matching automatic storage')
    _require(_type_closure(original_symbols, {k:k for k in captured_locals})
             == _type_closure(local_symbols, {k:k for k in captured_locals}), 'outgoing capture type closure differs')
    allowed = set(restored_locals) | set(parameter_arguments) | set(captured_locals)
    _require(observer_arguments and all(identity in allowed and type(address) is bool
                                        for identity, address in observer_arguments),
             'cut observer argument is not a selected automatic')
    _require(all(not address for identity, address in observer_arguments if identity in parameter_arguments),
             'parameter capture requires its value')
    _require(sorted(identity for identity, _ in observer_arguments if identity in parameters)
             == sorted(parameter_arguments), 'parameter capture inventory differs')
    _require(len(body.get('parameterIdentifiers', [])) == len(observer_arguments)+1,
             'cut observer parameter count differs')
    rows = local_functions[function]['instructions']
    removed, seen, bindings = set(), set(), []
    for index, row in enumerate(rows):
        operands = row.get('code', {}).get('sub', [])
        if row['instructionId'] != 'FUNCTION_CALL' or len(operands) != 3 or _symbol(operands[1]) != observer:
            continue
        _require(index > 0 and operands[0].get('id') == 'nil', 'cut observer must return no value')
        marker = rows[index-1]
        description = marker.get('sourceLocation', {}).get('comment', '')
        name = description.removeprefix('source-cut-invariant:')
        _require(marker['instructionId'] == 'ASSERT' and name in cut_results
                 and description == 'source-cut-invariant:'+name and name not in seen,
                 'cut observer is not uniquely adjacent to its marker')
        args = operands[2].get('sub', [])
        _require(len(args) == len(observer_arguments)+1 and _integer(args[0]) == cut_results[name],
                 'cut observer ordinal or arity differs')
        for arg, (identity, address) in zip(args[1:], observer_arguments, strict=True):
            if address:
                _require(arg.get('id') == 'address_of' and len(arg.get('sub', [])) == 1,
                         'cut observer requires the live automatic address')
                arg = arg['sub'][0]
            _require(_symbol(arg) == identity, 'cut observer transports a different local')
        _require(not any(row['locationNumber'] in other.get('targets', []) for other in rows),
                 'control flow bypasses the cut marker')
        removed.add(index)
        seen.add(name)
        bindings.append({'cut': name, 'instruction_index': index, 'call_sha256': canonical_sha256_v3(_payload(row))})
    _require(seen == set(cut_results), 'missing cut observer')
    reduced = {**local_functions, function: {**local_functions[function],
               'instructions': [row for i, row in enumerate(rows) if i not in removed]}}
    relation = check_source_region_transport(original_functions=original_functions, original_symbols=original_symbols,
        local_functions=reduced, local_symbols=local_symbols, function=function, entry_sync=entry_sync,
        restored_locals=restored_locals, cut_results=cut_results, control_graph=control_graph)
    return {**relation, 'local_cut_observer_arguments_checked': True,
            'observer_function': observer, 'observer_calls': bindings,
            'parameter_capture_arguments': list(parameter_arguments),
            'observer_body_sha256': canonical_sha256_v3(_function_payload(body)),
            'observer_predicates_checked': False}
