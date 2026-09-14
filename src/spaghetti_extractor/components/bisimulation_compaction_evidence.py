"""Validate conditional region evidence and current compiled state transport."""
import json
from pathlib import Path

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file
from .bisimulation_call_evidence import read_json, producer_binding, checker_options
from .bisimulation_compaction_contract import require, compaction_runtime_contract
from .bisimulation_compaction_inputs import read_inventory
from .bisimulation_region_observer import check_marked_region_observer_transport, check_marked_region_transport
from .cbmc_backend import _output_sha256, _property_statuses, validate_smt_solver_binding

POLICY = 'conditional-source-byte-compaction-region-v1'
ENTRY = 'check_iteration'


def region_checker_options(unwind, solver):
    """Both backends discharge the same complete safety and unwinding obligations."""
    return checker_options(unwind, solver) + ([] if solver is not None else ['--no-array-field-sensitivity'])


def compaction_producers():
    return producer_binding({__name__, 'spaghetti_extractor.components.bisimulation_compaction_check'})


def source_transport(data, proof):
    """Recheck against current preparation without regenerating the proved model."""
    local = read_inventory(proof)
    contract = data['contract']
    if contract['profile'] == 'local-text-cleanup-entry-v1':
        captures = data['captures']
        transport = check_marked_region_observer_transport(
            marked_functions=data['marked']['functions'], marked_symbols=data['marked']['symbols'],
            local_functions=local['functions'], local_symbols=local['symbols'], function=data['source_function'],
            entry_sync=contract['entry_cut'], markers=data['markers'], restored_locals={},
            cut_results={contract['exit_cut']: contract['exit_rva']}, observer='observe_entry',
            observer_arguments=[(name, role == 'scratch') for name, role in captures.items()],
            captured_locals=list(captures), control_graph=True)
        for name in ['spx_view_read_u8', 'spx_view_write_u8']:
            require(not data['marked']['functions'][name]['isBodyAvailable'] and local['functions'][name]['isBodyAvailable'],
                    'entry byte helper is not an external source dependency')
        return json.loads(json.dumps(transport))
    if contract['profile'] == 'local-text-cleanup-tail-v1':
        transport = check_marked_region_transport(
            marked_functions=data['marked']['functions'], marked_symbols=data['marked']['symbols'],
            local_functions=local['functions'], local_symbols=local['symbols'],
            function=data['source_function'], entry_sync=contract['entry_cut'], markers=data['markers'],
            restored_locals=data['restores'], cut_results={}, control_graph=True)
        return json.loads(json.dumps(transport))
    transport = check_marked_region_observer_transport(
        marked_functions=data['marked']['functions'], marked_symbols=data['marked']['symbols'],
        local_functions=local['functions'], local_symbols=local['symbols'],
        function=data['source_function'], entry_sync=contract['entry_cut'], markers=data['markers'],
        restored_locals=data['restores'],
        cut_results={contract['entry_cut']:contract['entry_rva'], contract['exit_cut']:contract['exit_rva']},
        observer='observe_loop', observer_arguments=[(key, role=='scratch') for key,role in data['restores'].items()])
    return json.loads(json.dumps(transport))


def compiled_sources(bindings):
    return ['pair.c', *sorted(name for name in bindings['original_files'] if name.startswith('behavioral-fn-')),
            'behavioral-support.c']


def check_compaction_evidence(result, root):
    root = Path(root); proof = root/'proof'
    require(result.get('policy')==POLICY and result.get('status')=='satisfied'
        and result.get('authorizing') is False and result.get('activation_authorized') is False
        and result.get('whole_component_complete') is False and result.get('runtime_compatibility')=='unverified'
        and result.get('receipt_sha256')==canonical_sha256_v3({k:v for k,v in result.items() if k!='receipt_sha256'}),
        'stale or incomplete region receipt')
    key = result['proof_key']; files = result['proof_files']
    require(result['proof_key_sha256']==canonical_sha256_v3(key), 'region proof key differs')
    require(key['bindings']['runtime_contract']==compaction_runtime_contract(key['bindings']['contract']), 'runtime contract differs')
    solver = result['solver']
    if solver is not None:
        validate_smt_solver_binding(solver)
    require(key['options'] == region_checker_options(int(key['options'][2]), solver),
            'region checker options omit or change required obligations')
    for name,digest in files.items():
        path = proof/name
        require(path.resolve().is_relative_to(proof.resolve()) and sha256_file(path)==digest, 'region proof file changed')
    directories = list((proof/'query-evidence').glob('*/query.json'))
    require(len(directories)==1, 'region needs one complete query')
    record = read_json(directories[0]); directory = directories[0].parent; binding = record['binding']
    require(record['returncode']==0 and directory.name==canonical_sha256_v3(binding)
        and binding['goto_model_sha256']==files['model.goto']
        and binding['arguments']==['$GOTO_MODEL','--function',ENTRY,*key['options']], 'region query/model/options differ')
    compiler = read_json(proof/'compiler-command.json')
    require(compiler['returncode']==0 and compiler['command']==[
        binding['tools']['compiler'],'--i386-win32','-nostdinc','-I','.',
        *compiled_sources(key['bindings']),'--function',ENTRY,'-o','model.goto'], 'region compiler command differs')
    expected = {'pair.c','authored.c',*key['bindings']['original_files'],*key['bindings']['headers']}
    require(set(compiler['inputs'])==expected and all(files[name]==digest for name,digest in compiler['inputs'].items()),
        'region compiled input inventory differs')
    host = read_json(proof/'host-typecheck.json')
    require(host['returncode'] == 0 and host['inputs'] == compiler['inputs']
        and host['command'][1:] == ['-m32','-fsyntax-only','-nostdinc','-I','.',
            '-Werror=incompatible-pointer-types','-Wno-implicit-function-declaration','pair.c']
        and sha256_file(Path(host['command'][0])) == key['tools']['host_cc'],
        'region model lacks bound C callback type conformance')
    require(all(files[name]==digest for name,digest in {
        **key['bindings']['original_files'],**key['bindings']['headers']}.items()), 'region original or header bytes differ')
    proof_tools = [('compiler','goto_cc'),('checker','cbmc')]
    if solver is not None:
        proof_tools.append(('external_smt2_solver','smt_solver'))
        require(binding['tools']['external_smt2_solver'] == solver['executable']
                and key['tools']['smt_solver'] == solver['sha256'], 'region solver binding differs')
    else:
        require('smt_solver' not in key['tools'] and 'external_smt2_solver' not in binding['tools'],
                'SAT region has an unexpected external solver')
    for name,value in proof_tools:
        tool = binding['tools']
        require(sha256_file(Path(tool[name]))==tool[name+'_sha256']==key['tools'][value], 'region proof tool changed')
    inventory = read_json(proof/'inventory-commands.json')
    require(set(inventory)=={'functions','symbols'}, 'missing region compiler inventories')
    for name,flag in [('functions','--show-goto-functions'),('symbols','--show-symbol-table')]:
        row=inventory[name]
        require(row['returncode']==0 and row['command']==[row['command'][0],flag,'--json-ui','model.goto']
            and sha256_file(Path(row['command'][0]))==key['tools']['goto_instrument']
            and row['model_sha256']==files['model.goto']
            and row['stdout_sha256']==files[name+'.stdout'] and row['stderr_sha256']==files[name+'.stderr'],
            'region inventory differs from compiled model')
    stdout,stderr = (directory/'stdout').read_text(),(directory/'stderr').read_text()
    require(sha256_file(directory/'stdout')==record['stdout_sha256'] and sha256_file(directory/'stderr')==record['stderr_sha256'],
        'region query output changed')
    statuses = _property_statuses(json.loads(stdout))
    require(statuses and set(statuses.values())=={'SUCCESS'} and sorted(statuses)==result['query']['property_ids']
        and len(statuses)==result['query']['properties'] and _output_sha256(stdout,stderr)==result['query']['output_sha256'],
        'region lacks complete successful properties')
