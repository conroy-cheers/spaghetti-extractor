"""Bind a public entry graph, exact original prefix and compiled source footprint."""
from pathlib import Path
import re

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file
from .bisimulation_call_evidence import read_json
from .bisimulation_compaction_inputs import read_inventory, coarsen_inert_cuts
from .bisimulation_fresh_buffer_contract import checked_fresh_buffer_contract, require
from .bisimulation_fresh_buffer_frame import check_fresh_buffer_entry_frame
from .bisimulation_source_call_check import checked_source_region_graphs
from .bisimulation_source_edit_check import _marked_source
from .bisimulation_source_entry import _type_closure
from .formats import COMPONENT_EXACT_C_SLICE_V1_FORMAT


def load_fresh_buffer_inputs(preparation, exact, contract, dependencies):
    contract = checked_fresh_buffer_contract(contract)
    require(dependencies is None or dependencies == {}, 'entry services need runtime qualification, not unconsumed dependency receipts')
    preparation, exact = Path(preparation), Path(exact)
    feedback = read_json(preparation/'compiler-checks.json')
    require(read_json(preparation/'source-check.json')['status'] == 'complete'
            and feedback['source_profile']['status'] == 'satisfied', 'source preparation is incomplete')
    source = feedback['source_region_graphs']
    graphs = checked_source_region_graphs(source, artifacts=preparation/'source-region-graph-models')
    index = contract['graph_index']; require(index < len(graphs), 'graph index is absent')
    graph, boundary = graphs[index], source['boundaries'][index]
    require(graph['cut_sites'].get(contract['entry_cut']) == 0 and contract['exit_cut'] in graph['cut_sites'],
            'entry prefix has an unproved predecessor or missing exit')
    nodes = {r['entry']: r for r in graph['regions']}
    pending, reached = [contract['entry_cut']], set()
    while pending:
        name = pending.pop()
        if name in reached:
            continue
        require(name in nodes, 'prefix contains an unprepared cut')
        reached.add(name)
        for kind, target in nodes[name]['exits']:
            require(kind in {'cut', 'return'}, 'unsupported prefix exit')
            if kind == 'cut' and target != contract['exit_cut']:
                pending.append(target)
    require(reached == set(contract['regions']), 'selected regions differ from entry closure')
    selected = {i for name in reached for i in nodes[name]['instruction_indices']}
    cut_sites = {graph['cut_sites'][name] for name in reached}
    require(all(edge['source_instruction'] in selected | cut_sites for name in reached
                for edge in nodes[name]['external_interior_entries']), 'entry prefix has an unproved predecessor')
    ordinary_root = preparation/f'source-region-graph-models/{index:04d}-ordinary'
    ordinary = read_inventory(ordinary_root)
    marked = read_inventory(preparation/f'source-region-graph-models/{index:04d}-marked')
    function, symbols = graph['function'], ordinary['symbols']
    parameters = ordinary['functions'][function]['parameterIdentifiers']
    names = {symbols[n]['baseName']: n for n in parameters}
    require(len(names) == len(parameters) and set(names) == set(contract['parameter_roles'].values()), 'source parameters differ')
    roles = {role: names[name] for role, name in contract['parameter_roles'].items()}
    result_type = symbols[function]['type']['namedSub']['return_type']
    require(result_type['id'] == 'unsignedbv' and result_type['namedSub']['width']['id'] == '32', 'result must be uint32')
    captures = {}
    for role in ['input', 'output', 'removed', 'scratch']:
        name = contract['source_locals'][role]
        matches = [n for n, row in symbols.items() if row.get('baseName') == name
                   and row.get('location', {}).get('function') == function and row.get('isStaticLifetime') is False
                   and row.get('isParameter') is False and not row.get('isAuxiliary')]
        require(len(matches) == 1, 'ambiguous outgoing role ' + role)
        identity = matches[0]; typ = symbols[identity]['type']
        require((typ['id'] == 'struct_tag' and typ['namedSub']['identifier']['id'] == 'tag-spx_view_v1') if role == 'scratch' else
                (typ['id'] == 'unsignedbv' and typ['namedSub']['width']['id'] == '32'), 'outgoing role type differs')
        captures[identity] = role
    footprint = check_fresh_buffer_entry_frame(**marked, function=function, instruction_indices=selected,
        context_parameter=roles['context'], text_parameter=roles['text'],
        scratch_local=next(n for n, role in captures.items() if role == 'scratch'))
    package = source['source_package']
    require(len(package['files']) == 1 and package['files'][0]['path'] == boundary['source']
            and not package['shared_inputs'], 'entry requires one prepared C translation unit')
    text = (ordinary_root/'inputs'/boundary['source']).read_text()
    _, markers = _marked_source(text, boundary)
    kept = {contract['entry_cut'], contract['exit_cut']}
    merged = coarsen_inert_cuts(marked, function=function, markers=markers, keep=kept)
    manifest = read_json(exact/'component-exact-c-slice-v1.json')
    require(manifest['format'] == COMPONENT_EXACT_C_SLICE_V1_FORMAT and manifest['slice_sha256'] == canonical_sha256_v3(
        {k: v for k, v in manifest.items() if k != 'slice_sha256'}) and manifest['component_id'] == package['lift_unit_id']
        and manifest['root_entry_rvas'] == [contract['entry_rva']] and not manifest['dependency_components']
        and len(manifest['functions']) == 1 and not manifest['internal_direct_call_closure']['call_edges']
        and set(manifest['forced_label_rvas']) == {contract['exit_rva']}, 'original entry slice differs')
    files = {}
    for row in manifest['files']:
        path = exact/row['path']
        require(path.resolve().is_relative_to(exact.resolve()) and row['path'] not in files
                and sha256_file(path) == row['sha256'], 'stale original entry file')
        files[row['path']] = row['sha256']
    require(files.get('state-machine-runtime.h') == sha256_file(ordinary_root/'include/state-machine-runtime.h'), 'original ABI differs')
    original_function = manifest['functions'][0]['symbol']
    require(all(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', n) for n in [function, *names, original_function]), 'invalid compiled identifier')
    return {'contract': contract, 'text': text, 'graph': graph, 'boundary': boundary,
        'source_function': function, 'original_function': original_function, 'parameters': list(names),
        'captures': captures, 'restores': {}, 'markers': {k: v for k, v in markers.items() if k in kept},
        'marked': merged, 'include': ordinary_root/'include', 'original_files': files, 'footprint': footprint,
        'binding': {'contract': contract, 'interface_intent': source['interface_intent'],
            'regions': {n: nodes[n]['semantic_sha256'] for n in sorted(reached)},
            'original_slice_sha256': manifest['slice_sha256'], 'source_function': function,
            'source_parameter_types': _type_closure(symbols, {n: n for n in parameters})}}
