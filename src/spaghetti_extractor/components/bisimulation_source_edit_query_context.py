"""Preserve query properties and unwind counters across a pure source edit.

This relation operates on CBMC's processed inventories, including generated
safety assertions. It supplements the raw-model/source correspondence; it does
not itself prove properties or change the scope of retained query results.
"""

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_region_context import _markers, _normalized, _region
from .bisimulation_source_edit import prepare_pure_region_comparison


def _require(condition, message):
    if not condition:
        raise ValueError('source edit query context: ' + message)


def summarize_processed_query_context(functions, loops, *, function, markers):
    """Bind complete helpers while retaining only the editable function in memory.

    CBMC 6.9 numbers backwards GOTOs in instruction order within each function.
    Check that reconstructed numbering agrees with its independent loop listing.
    Include those IDs and actual property IDs in the semantic comparison, so a
    numerically identical unwindset or property selection cannot change meaning.
    """
    bodies = {row['name']: row for row in functions}
    _require(len(bodies) == len(functions) and function in bodies, 'ambiguous function inventory')
    present = set(markers.values()) & set(bodies)
    _require(not present or present == set(markers.values()), 'partial marker family')
    sites = _markers(bodies, function, list(markers.values())) if present else {}
    properties, reconstructed_loops, digests = {}, {}, {}
    local = {}
    for name, body in bodies.items():
        rows = body.get('instructions', [])
        locations = {row['locationNumber']: index for index, row in enumerate(rows)}
        _require(len(locations) == len(rows), 'duplicate instruction location')
        loop_number = 0
        tagged = []
        for index, row in enumerate(rows):
            _require(not {'queryLoopId', 'queryPropertyId'} & row.keys(), 'reserved query annotation')
            item = dict(row)
            if row['instructionId'] == 'ASSERT':
                identity = row.get('sourceLocation', {}).get('propertyId')
                _require(isinstance(identity, str) and identity and identity not in properties,
                         'missing or duplicate property ID')
                item['queryPropertyId'] = identity
                properties[identity] = {'function': name, 'index': index}
            if row['instructionId'] == 'GOTO':
                targets = row.get('targets', [])
                _require(targets and all(v in locations for v in targets), 'invalid query branch')
                if any(locations[v] <= index for v in targets):
                    identity = name + '.' + str(loop_number)
                    loop_number += 1
                    item['queryLoopId'] = identity
                    reconstructed_loops[identity] = row.get('sourceLocation', {})
            tagged.append(item)
        annotated = {**body, **({'instructions': tagged} if 'instructions' in body else {})}
        if name in present:
            local[name] = annotated
            continue
        digests[name] = canonical_sha256_v3(_normalized(annotated, sites.values() if name == function else ()))
        if name == function:
            local[name] = annotated
    listed = {row['name']: row['sourceLocation'] for row in loops}
    _require(len(listed) == len(loops) and listed == reconstructed_loops,
             'processed loop sites differ from checker inventory')
    if present:
        _, owned, _ = _region(local, function, markers['entry'], {k:v for k,v in markers.items() if k != 'entry'})
        _require(not any('queryLoopId' in local[function]['instructions'][i] for i in owned),
                 'local edit crosses a bounded backward GOTO')
    return {'functions': digests, 'properties': properties, 'loop_ids': sorted(listed),
            'local_functions': local}


def compare_processed_query_context(models, symbols, *, function, markers, checked_source):
    """Check both marker erasures and the complete instrumented context.

    Unchanged property IDs are deliberately required in this first transport
    rule. A future renumbering rule must bind each new ID to its actual predicate
    and site, rather than relying on its spelling or source line.
    """
    _require(set(models) == {'baseline', 'baseline-marked', 'edited', 'edited-marked'},
             'processed model coverage differs')
    for side in ('baseline', 'edited'):
        before, marked = models[side], models[side + '-marked']
        _require(before['functions'] == marked['functions'], 'processed marker erasure differs: ' + side)
        _require(before['properties'].keys() == marked['properties'].keys()
                 and before['loop_ids'] == marked['loop_ids'], 'marker changed property or loop coverage')
    a, b = models['baseline-marked'], models['edited-marked']
    _require({k:v for k,v in a['functions'].items() if k != function}
             == {k:v for k,v in b['functions'].items() if k != function}, 'processed helper context differs')
    _require(a['properties'].keys() == b['properties'].keys() and a['loop_ids'] == b['loop_ids'],
             'processed property or loop coverage differs')
    comparison = prepare_pure_region_comparison(original_functions=a['local_functions'],
        original_symbols=symbols['baseline-marked'], edited_functions=b['local_functions'],
        edited_symbols=symbols['edited-marked'], function=function, entry=markers['entry'],
        exits={k:v for k,v in markers.items() if k != 'entry'})
    _require(comparison['source'] == checked_source, 'processed local query differs from satisfied local query')
    return {'status': 'matched-processed-query-context', 'authorizing': False,
            'comparison': {k:v for k,v in comparison.items() if k != 'source'},
            'property_ids': sorted(a['properties']), 'loop_ids': a['loop_ids'],
            'model_context_sha256': {side: canonical_sha256_v3({k:v for k,v in row.items() if k != 'local_functions'})
                                    for side, row in models.items()}}
