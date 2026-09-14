"""Compiled assertion-only cut observers using the shared body and context rules."""
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_region_context import (
    _require, _markers, _normalized, _region,
    check_inert_region_markers, check_region_context_transport,
)
from .bisimulation_source_region_transport import check_source_region_observer_transport, check_source_region_transport

def _marked_inventory(marked_functions, marked_symbols, function, markers):
    """Convert checked inert calls to private inventory tokens, never executable C."""
    sites = _markers(marked_functions, function, list(markers.values()))
    rows = marked_functions[function]['instructions']
    by_index = {sites[marker]: sync for sync, marker in markers.items()}
    symbols = dict(marked_symbols)
    converted = []
    next_location = max(row['locationNumber'] for row in rows) + 1
    for index, row in enumerate(rows):
        if index not in by_index:
            converted.append(row)
            continue
        sync = by_index[index]
        identity = function + '::__spx_inventory_marker_' + sync
        _require(identity not in symbols, 'inventory marker collision')
        typ = {'id': 'unsignedbv', 'namedSub': {'width': {'id': '32'}}}
        operand = {'id': 'symbol', 'namedSub': {'identifier': {'id': identity}, 'type': typ}}
        symbols[identity] = {'name': identity, 'baseName': '__CPROVER_spx_local_sync_' + sync,
            'isStaticLifetime': False, 'isParameter': False, 'type': typ, 'location': {'function': function}}
        zero = {'id': 'constant', 'namedSub': {'type': typ, 'value': {'id': '0'}}}
        for kind, statement, args, location in [('DECL', 'decl', [operand], row['locationNumber']),
                ('ASSIGN', 'assign', [operand, zero], next_location), ('DEAD', 'dead', [operand], next_location + 1)]:
            converted.append({'instructionId': kind, 'locationNumber': location,
                'code': {'id': 'code', 'namedSub': {'statement': {'id': statement}, 'type': {'id': 'empty'}}, 'sub': args}})
        next_location += 2
    functions = {**marked_functions, function: {**marked_functions[function], 'instructions': converted}}
    return functions, symbols, sites


def check_marked_region_observer_transport(*, marked_functions, marked_symbols, local_functions, local_symbols,
                                         function, entry_sync, markers, restored_locals, cut_results,
                                         observer, observer_arguments, parameter_arguments=(),
                                         captured_locals=(), control_graph=False):
    """Use the existing body/observer matcher at real, checked empty-call cuts.

    Marker triplets below are inventory tokens for the existing matcher. They
    are never compiled, executed or substituted into a proof model. The actual
    marker erasure and caller-context correspondence are separate bound checks.
    """
    _require(set(markers) == {entry_sync, *cut_results}, 'marker/cut inventory differs')
    functions, symbols, sites = _marked_inventory(marked_functions, marked_symbols, function, markers)
    relation = check_source_region_observer_transport(original_functions=functions, original_symbols=symbols,
        local_functions=local_functions, local_symbols=local_symbols, function=function, entry_sync=entry_sync,
        restored_locals=restored_locals, cut_results=cut_results, observer=observer,
        observer_arguments=observer_arguments, parameter_arguments=parameter_arguments,
        captured_locals=captured_locals, control_graph=control_graph)
    return {**relation, 'actual_marker_sites': sites,
            'actual_marked_function_sha256': canonical_sha256_v3(_normalized(marked_functions[function])),
            'inventory_tokens_executed': False}


def check_marked_region_transport(*, marked_functions, marked_symbols, local_functions, local_symbols,
                                  function, entry_sync, markers, restored_locals, cut_results,
                                  control_graph=False):
    """Match a terminal region's real C returns without synthetic cut observers.

    The consuming proof checks its actual result and post-state. This relation
    retains every source return expression, effect, dependency and control edge;
    it cannot turn correspondence into a functional or runtime qualification.
    """
    _require(set(markers) == {entry_sync, *cut_results}, 'marker/cut inventory differs')
    functions, symbols, sites = _marked_inventory(marked_functions, marked_symbols, function, markers)
    relation = check_source_region_transport(original_functions=functions, original_symbols=symbols,
        local_functions=local_functions, local_symbols=local_symbols, function=function, entry_sync=entry_sync,
        restored_locals=restored_locals, cut_results=cut_results, control_graph=control_graph)
    return {**relation, 'actual_marker_sites': sites,
            'actual_marked_function_sha256': canonical_sha256_v3(_normalized(marked_functions[function])),
            'inventory_tokens_executed': False}
