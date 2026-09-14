"""Bind a terminal source graph to original behavior and an independently proved supplier."""
import re
from pathlib import Path

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file
from .bisimulation_call_evidence import read_json
from .bisimulation_call_domain import checked_call_domain
from .bisimulation_cleanup_contract import checked_cleanup_contract, require
from .bisimulation_cleanup_frame import check_cleanup_tail_frame
from .bisimulation_compaction_inputs import read_inventory, coarsen_inert_cuts
from .bisimulation_source_call_check import checked_source_region_graphs
from .bisimulation_source_edit_check import _marked_source
from .bisimulation_shared_original_check import checked_shared_original_transition
from .bisimulation_source_entry import _type_closure
from .formats import COMPONENT_EXACT_C_SLICE_V1_FORMAT


def load_cleanup_inputs(preparation, exact, contract, dependencies):
    contract = checked_cleanup_contract(contract)
    require(isinstance(dependencies, dict) and set(dependencies) == {'resource_text'}, 'one checked resource supplier is required')
    preparation, exact = Path(preparation), Path(exact)
    supplier = Path(dependencies['resource_text'])
    feedback = read_json(preparation/'compiler-checks.json')
    require(read_json(preparation/'source-check.json')['status'] == 'complete'
            and feedback['source_profile']['status'] == 'satisfied', 'source preparation is incomplete')
    source = feedback['source_region_graphs']
    graphs = checked_source_region_graphs(source, artifacts=preparation/'source-region-graph-models')
    index = contract['graph_index']; require(index < len(graphs), 'graph index is absent')
    graph, boundary = graphs[index], source['boundaries'][index]
    nodes = {r['entry']: r for r in graph['regions']}
    pending, reached = [contract['entry_cut']], set()
    while pending:
        name = pending.pop()
        if name in reached:
            continue
        require(name in nodes, 'terminal proof has an unprepared cut')
        reached.add(name)
        for kind, target in nodes[name]['exits']:
            if kind == 'cut':
                pending.append(target)
            else:
                require(kind == 'return', 'terminal proof has an unsupported exit')
    require(reached == set(contract['regions']), 'selected regions differ from terminal closure')
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
    restores = {}
    for role, name in contract['source_locals'].items():
        matches = [n for n, row in symbols.items() if row.get('baseName') == name
                   and row.get('location', {}).get('function') == function
                   and row.get('isStaticLifetime') is False and row.get('isParameter') is False and not row.get('isAuxiliary')]
        require(len(matches) == 1, 'ambiguous automatic role ' + role)
        identity = matches[0]; typ = symbols[identity]['type']
        require((typ['id'] == 'struct_tag' and typ['namedSub']['identifier']['id'] == 'tag-spx_view_v1') if role == 'scratch' else
                (typ['id'] == 'unsignedbv' and typ['namedSub']['width']['id'] == '32'), 'source role type differs')
        restores[identity] = role
    selected = {i for name in reached for i in nodes[name]['instruction_indices']}
    cut_sites = {graph['cut_sites'][name] for name in reached}
    require(all(edge['source_instruction'] in selected | cut_sites for name in reached
                for edge in nodes[name]['external_interior_entries']), 'undeclared interior predecessor')
    scratch = next(n for n, role in restores.items() if role == 'scratch')
    footprint = check_cleanup_tail_frame(**marked, function=function, instruction_indices=selected,
                                        parameters=roles, scratch_local=scratch)
    package = source['source_package']
    require(len(package['files']) == 1 and package['files'][0]['path'] == boundary['source']
            and not package['shared_inputs'], 'tail requires one prepared C translation unit')
    text = (ordinary_root/'inputs'/boundary['source']).read_text()
    _, markers = _marked_source(text, boundary)
    kept = {contract['entry_cut']}
    merged = coarsen_inert_cuts(marked, function=function, markers=markers, keep=kept)
    comparison = read_json(supplier/'original-comparison/result.json')
    transition = checked_shared_original_transition(comparison, artifacts=supplier/'original-comparison',
        certificate=read_json(supplier/'local-contract.json'), source_artifacts=supplier/'local-contract-models')
    # The complete source body and footprint, not a fabricated single-call
    # execution summary, bind these possibly conditional invocation sites.
    resource_sites = [r for r in footprint['calls'] if r['dependency'] == 'resource_text']
    require(resource_sites, 'source has no resource consumer')
    projection = {'service_id': 'resource_text', 'arguments': [{'kind': 'word-checked-by-paired-trace'}]}
    domain = checked_call_domain(transition, projection, contract['supplier_call'])
    require(domain['stack_delta'] == -12 and domain['low'] == -44 and domain['high'] == 4
            and domain['image_base'] == contract['image_base'] and domain['image_size'] == contract['image_size']
            and set(domain['views']) == {'buffer', 'module'} and domain['views']['module'][0:2] == (4, 1)
            and domain['views']['buffer'] == (domain['result_extent'], 3, domain['result_address']), 'supplier needs another adapter domain')
    require(transition['domain']['machine_domain']['private_writes'] == [{'offset': -28, 'bytes': 28}], 'supplier private writes need another adapter')
    site = contract['calls']['resource_text']
    require(site == {k: domain[v] for k, v in [('entry', 'entry'), ('instruction', 'instruction'), ('successor', 'successor')]}, 'supplier call site differs')
    original = read_json(exact/'component-exact-c-slice-v1.json')
    require(original['format'] == COMPONENT_EXACT_C_SLICE_V1_FORMAT and original['slice_sha256'] == canonical_sha256_v3(
        {k: v for k, v in original.items() if k != 'slice_sha256'}) and original['component_id'] == package['lift_unit_id']
        and original['root_entry_rvas'] == [contract['entry_rva']] and original['root_unit_ids'] == original['root_context_unit_ids']
        and not original['forced_label_rvas'] and not original['dependency_components'], 'original terminal slice differs')
    files = {r['path']: r['sha256'] for r in original['files']}
    require(len(files) == len(original['files']), 'duplicate original file')
    for name, digest in files.items():
        require((exact/name).resolve().is_relative_to(exact.resolve()) and sha256_file(exact/name) == digest, 'stale original file')
    child = comparison['bindings']['exact_c_slice']; child_file = f'behavioral-fn-{domain["callee"]:08x}.c'
    require(files.get(child_file) == next(r['sha256'] for r in child['files'] if r['path'] == child_file), 'callee original behavior differs')
    edges = original['internal_direct_call_closure']['call_edges']
    require(len(edges) == 1 and all(edges[0][k] == v for k, v in {
        'source_rva': domain['entry'], 'instruction_rva': domain['instruction'], 'return_rva': domain['successor'],
        'target_rva': domain['callee'], 'call_index': 0}.items()), 'original dependency edge differs')
    original_function = f'spx_sub_{contract["entry_rva"]:08x}'
    function_row, = [r for r in original['functions'] if r['symbol'] == original_function]
    owned_rvas = {r['rva'] for r in original['source_map'] if r['unit_id'] in original['root_unit_ids']}
    require(set(function_row['unit_rvas']) == owned_rvas and all(s['entry'] in owned_rvas for s in contract['calls'].values()), 'original region omits or adds owned transfers')
    copied = ['behavioral-c.h', 'state-machine-runtime.h', 'behavioral-support.c', f'behavioral-fn-{contract["entry_rva"]:08x}.c']
    require(all(n in files for n in copied) and files['state-machine-runtime.h'] == sha256_file(ordinary_root/'include/state-machine-runtime.h'), 'original ABI or root source differs')
    require(all(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', n) for n in [function, *names, original_function]), 'invalid compiled identifier')
    return {'contract': contract, 'text': text, 'boundary': boundary, 'source_function': function,
        'original_function': original_function, 'parameters': list(names), 'restores': restores,
        'markers': {k: v for k, v in markers.items() if k in kept}, 'marked': merged, 'include': ordinary_root/'include',
        'original_files': {n: files[n] for n in copied}, 'domain': domain, 'footprint': footprint,
        'dependency_evidence': {'resource_text': transition},
        'binding': {'contract': contract, 'interface_intent': source['interface_intent'],
            'regions': {n: nodes[n]['semantic_sha256'] for n in sorted(reached)},
            'original_slice_sha256': original['slice_sha256'], 'source_function': function,
            'source_parameter_types': _type_closure(symbols, {n: n for n in parameters}),
            'supplier_domain': transition['domain'], 'supplier_domain_sha256': transition['domain_sha256']}}
