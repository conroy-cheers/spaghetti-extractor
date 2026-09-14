"""Bind a public source graph, explicit local contract and exact original slice."""
import json
import re
from pathlib import Path

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file
from .bisimulation_compaction_contract import checked_compaction_contract, require
from .bisimulation_source_call_check import checked_source_region_graphs
from .bisimulation_source_edit_check import _marked_source
from .bisimulation_region_context import _markers
from .formats import COMPONENT_EXACT_C_SLICE_V1_FORMAT
from .bisimulation_cut_state import _walk
from .bisimulation_source_entry import _type_closure
from .bisimulation_source_region_transport import _integer


def read_inventory(root):
    result = {}
    for key, field in [('functions','functions'), ('symbols','symbolTable')]:
        rows = [r[field] for r in json.loads((Path(root)/(key+'.stdout')).read_text()) if field in r]
        require(len(rows) == 1, 'ambiguous compiler inventory')
        result[key] = {r['name']:r for r in rows[0]} if key == 'functions' else rows[0]
    return result


def coarsen_inert_cuts(inventory, *, function, markers, keep):
    """Erase only already-checked empty marker calls, preserving every real edge."""
    sites = _markers(inventory['functions'], function, list(markers.values()))
    removed_symbols = {marker for name,marker in markers.items() if name not in keep}
    removed = {sites[name] for name in removed_symbols}
    rows = inventory['functions'][function]['instructions']
    locations = {r['locationNumber']:i for i,r in enumerate(rows)}
    def destination(target):
        require(target in locations, 'foreign branch during cut merge')
        index = locations[target]
        while index in removed:
            index += 1
        require(index < len(rows), 'cut merge removes terminal target')
        return rows[index]['locationNumber']
    functions = {k:v for k,v in inventory['functions'].items() if k not in removed_symbols}
    functions[function] = {**functions[function], 'instructions':[
        {**row, 'targets':[destination(v) for v in row.get('targets',[])]}
        for i,row in enumerate(rows) if i not in removed]}
    return {'functions':functions,'symbols':{k:v for k,v in inventory['symbols'].items() if k not in removed_symbols}}


def load_compaction_inputs(preparation, exact, contract, dependencies=None):
    if isinstance(contract, dict) and contract.get('profile') == 'local-text-cleanup-entry-v1':
        from .bisimulation_fresh_buffer_inputs import load_fresh_buffer_inputs
        return load_fresh_buffer_inputs(preparation, exact, contract, dependencies)
    if isinstance(contract, dict) and contract.get('profile') == 'local-text-cleanup-tail-v1':
        from .bisimulation_cleanup_inputs import load_cleanup_inputs
        return load_cleanup_inputs(preparation, exact, contract, dependencies)
    require(dependencies is None or dependencies == {}, 'loop profile has no service dependencies')
    contract = checked_compaction_contract(contract)
    preparation, exact = Path(preparation), Path(exact)
    feedback = json.loads((preparation/'compiler-checks.json').read_text())
    require(json.loads((preparation/'source-check.json').read_text())['status']=='complete'
            and feedback['source_profile']['status']=='satisfied', 'source preparation is incomplete')
    result = feedback['source_region_graphs']
    graphs = checked_source_region_graphs(result, artifacts=preparation/'source-region-graph-models')
    index = contract['graph_index']; require(index < len(graphs), 'graph index is absent')
    graph, boundary = graphs[index], result['boundaries'][index]
    require(contract['entry_cut'] in graph['cut_sites'] and contract['exit_cut'] in graph['cut_sites'], 'unknown cut')
    nodes = {r['entry']:r for r in graph['regions']}
    pending, reached = [contract['entry_cut']], set()
    while pending:
        name = pending.pop()
        if name in reached:
            continue
        require(name in nodes, 'selected proof has an unprepared region')
        reached.add(name)
        require(not nodes[name]['external_interior_entries'], 'region has an undeclared interior entry')
        for kind,target in nodes[name]['exits']:
            if kind=='cut' and target not in {contract['entry_cut'],contract['exit_cut']}:
                pending.append(target)
    require(reached==set(contract['regions']), 'selected regions differ from cut closure')
    original_root = preparation/f'source-region-graph-models/{index:04d}-ordinary'
    marked = read_inventory(preparation/f'source-region-graph-models/{index:04d}-marked')
    ordinary = read_inventory(original_root)
    function = graph['function']; symbols = ordinary['symbols']
    for name in reached:
        for index_ in nodes[name]['instruction_indices']:
            row=marked['functions'][function]['instructions'][index_]
            require(row['instructionId']!='END_FUNCTION', 'untagged source fallthrough outcome')
            if row['instructionId']=='SET_RETURN_VALUE':
                require(_integer(row['code']['sub'][0])==0xffffffff, 'source return requires an explicit outcome contract')
    parameters = ordinary['functions'][function]['parameterIdentifiers']
    names = [symbols[p]['baseName'] for p in parameters]
    require(len(set(names))==len(names) and contract['text_parameter'] in names, 'ambiguous source parameters')
    require(all(symbols[p]['type']['id'] in {'pointer','signedbv','unsignedbv'} for p in parameters), 'unsupported parameter representation')
    return_type = symbols[function]['type']['namedSub']['return_type']
    require(return_type['id']=='unsignedbv' and return_type['namedSub']['width']['id']=='32', 'source result must be uint32')
    used = {v for name in reached for v in nodes[name]['referenced_storage']}
    require(set(parameters)&used <= {parameters[names.index(contract['text_parameter'])]}, 'region reads an unsupported parameter')
    require(all(call['direct_callee'] in {'spx_view_read_u8','spx_view_write_u8'}
        for name in reached for call in nodes[name]['calls']), 'region needs another dependency contract')
    restores = {}
    for role in ('input','output','removed','scratch'):
        name = contract['source_locals'][role]
        matches = [k for k,v in symbols.items() if v.get('baseName')==name and v.get('location',{}).get('function')==function
                   and v.get('isStaticLifetime') is False and v.get('isParameter') is False and not v.get('isAuxiliary')]
        require(len(matches)==1, 'ambiguous automatic role '+role)
        identity = matches[0]; typ=symbols[identity]['type']
        require((typ['id']=='struct_tag' and typ['namedSub']['identifier']['id']=='tag-spx_view_v1') if role=='scratch' else
                (typ['id']=='unsignedbv' and typ['namedSub']['width']['id']=='32'), 'source role type differs')
        restores[identity] = role
    closure = _type_closure(symbols, {k:k for k in [*parameters,*restores]})
    require(not any({'#volatile','C_volatile','volatile','#atomic'} & n.get('namedSub',{}).keys() for n in _walk(closure)), 'volatile or atomic cut storage is unsupported')
    source = result['source_package']
    require(len(source['files'])==1 and source['files'][0]['path']==boundary['source'] and not source['shared_inputs'],
            'local compaction currently needs one ordinary C translation unit')
    text = (original_root/'inputs'/boundary['source']).read_text()
    _,markers = _marked_source(text,boundary)
    kept = {contract['entry_cut'],contract['exit_cut']}
    merged = coarsen_inert_cuts(marked,function=function,markers=markers,keep=kept)
    manifest = json.loads((exact/'component-exact-c-slice-v1.json').read_text())
    require(manifest['format']==COMPONENT_EXACT_C_SLICE_V1_FORMAT and manifest['slice_sha256']==canonical_sha256_v3({k:v for k,v in manifest.items() if k!='slice_sha256'})
            and manifest['component_id']==source['lift_unit_id'] and manifest['root_entry_rvas']==[contract['entry_rva']]
            and not manifest['dependency_components'] and len(manifest['functions'])==1
            and not manifest['internal_direct_call_closure']['call_edges']
            and set(manifest['forced_label_rvas'])=={contract['entry_rva'],contract['exit_rva']}, 'exact slice does not match the local boundary')
    require(all(isinstance(name,str) and re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',name)
        for name in [function,*names,manifest['functions'][0]['symbol']]), 'invalid compiled function or parameter identifier')
    files = {}
    for row in manifest['files']:
        file=exact/row['path']
        require(file.resolve().is_relative_to(exact.resolve()) and row['path'] not in files and sha256_file(file)==row['sha256'], 'stale or escaping original file')
        files[row['path']]=row['sha256']
    require(files.get('state-machine-runtime.h')==sha256_file(original_root/'include/state-machine-runtime.h'), 'original runtime ABI differs')
    return {'contract':contract,'graph':graph,'boundary':boundary,'ordinary':ordinary,'marked':merged,
        'markers':{k:v for k,v in markers.items() if k in kept},'restores':restores,'text':text,
        'source_function':function,'parameters':names,'original_function':manifest['functions'][0]['symbol'],
        'include':original_root/'include','manifest':manifest,'original_files':files,
        'binding':{'contract':contract,'interface_intent':result['interface_intent'],
            'regions':{name:nodes[name]['semantic_sha256'] for name in sorted(reached)},
            'original_slice_sha256':manifest['slice_sha256'], 'source_function':function,
            'source_parameter_types':_type_closure(symbols,{p:p for p in parameters})}}
