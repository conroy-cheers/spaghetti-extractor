"""Exact input and process bindings for conditional source-bound caller proofs."""

import json
from pathlib import Path
import sys

from ..artifacts.artifact_set import canonical_sha256_v3
from ..build_support.python_module_index import _local_imports
from ..util import sha256_file
from .bisimulation_call_domain import require, checked_call_domain
from .bisimulation_call_model import ENTRY
from .bisimulation_shared_original_check import checked_shared_original_transition
from .bisimulation_source_call_check import checked_source_call_regions
from .cbmc_backend import _output_sha256, _property_statuses, solver_arguments
from .formats import COMPONENT_EXACT_C_SLICE_V1_FORMAT

POLICY = 'conditional-source-bound-call-region-v1'


def producer_binding(roots=None):
    """Use the existing static import graph without constructing a consumer model.

    This is deliberately conservative across proof-engine edits. Authored
    application implementations are separate inputs and never enter this graph.
    """
    root = Path(__file__).resolve().parents[2]
    pending = set(roots) if roots is not None else {__name__, 'spaghetti_extractor.components.bisimulation_call_check'}
    result = {}
    while pending:
        module = pending.pop()
        if module in result:
            continue
        path = root.joinpath(*module.split('.')).with_suffix('.py')
        if not path.is_file():
            path = root.joinpath(*module.split('.'), '__init__.py')
        require(path.is_file(), 'missing model producer ' + module)
        result[module] = sha256_file(path)
        pending.update(_local_imports(module=module, path=path) - result.keys())
    return {'python': sys.version, 'modules': dict(sorted(result.items()))}


def read_json(path):
    return json.loads(Path(path).read_text())


def load_call_inputs(*, preparation, exact, supplier, contract):
    preparation, exact, supplier = map(Path, (preparation, exact, supplier))
    feedback = read_json(preparation/'compiler-checks.json')
    require(read_json(preparation/'source-check.json')['status'] == 'complete'
            and feedback['source_profile']['status'] == 'satisfied', 'source preparation is incomplete')
    source = feedback['source_call_regions']
    projections = checked_source_call_regions(source, artifacts=preparation/'source-call-region-models')
    index = contract['region_index']
    require(type(index) is int and 0 <= index < len(projections), 'unknown source region')
    transition = checked_shared_original_transition(read_json(supplier/'original-comparison/result.json'),
        artifacts=supplier/'original-comparison', certificate=read_json(supplier/'local-contract.json'),
        source_artifacts=supplier/'local-contract-models')
    domain = checked_call_domain(transition, projections[index], contract)
    original = read_json(exact/'component-exact-c-slice-v1.json')
    require(original['format'] == COMPONENT_EXACT_C_SLICE_V1_FORMAT
            and original['slice_sha256'] == canonical_sha256_v3({k:v for k,v in original.items() if k!='slice_sha256'})
            and original['component_id'] == source['source_package']['lift_unit_id']
            and original['root_entry_rvas'] == [domain['entry']]
            and len(original['root_unit_ids']) == 1
            and original['root_unit_ids'] == original['root_context_unit_ids']
            and not original['forced_label_rvas'] and not original['dependency_components'], 'original region slice differs')
    rows = original['files']
    files = {r['path']:r['sha256'] for r in rows}
    require(len(rows) == len(files), 'duplicate original file')
    for name, digest in files.items():
        require((exact/name).resolve().is_relative_to(exact.resolve()) and sha256_file(exact/name) == digest, 'stale original file')
    child = read_json(supplier/'original-comparison/result.json')['bindings']['exact_c_slice']
    child_file = f'behavioral-fn-{domain["callee"]:08x}.c'
    require(files.get(child_file) == next(r['sha256'] for r in child['files'] if r['path']==child_file),
            'original call target does not match checked supplier behavior')
    edges = original['internal_direct_call_closure']['call_edges']
    require(len(edges) == 1 and all(edges[0][key] == value for key,value in {
        'source_rva':domain['entry'], 'instruction_rva':domain['instruction'], 'return_rva':domain['successor'],
        'target_rva':domain['callee'], 'call_index':0}.items()), 'original dependency edge differs')
    function = next(row for row in original['functions'] if row['symbol']==f'spx_sub_{domain["entry"]:08x}')
    require(function['unit_rvas'] == [domain['entry']], 'original region includes unselected transfers')
    # The slice may retain the original dependency for provenance, but neither
    # its C nor its authored object is copied or compiled in the consumer model.
    copied = ['behavioral-c.h','state-machine-runtime.h','behavioral-support.c',f'behavioral-fn-{domain["entry"]:08x}.c']
    require(all(name in files for name in copied), 'original region lacks runtime or source')
    require(files['state-machine-runtime.h'] == sha256_file(preparation/f'source-call-region-models/{index:04d}-ordinary/include/state-machine-runtime.h'),
            'source and original runtime headers differ')
    return domain, transition, {'source_preparation_sha256':source['receipt_sha256'],
        'source_projection':projections[index], 'original_slice_sha256':original['slice_sha256'],
        'original_files':{name:files[name] for name in copied}, 'contract':contract,
        'supplier_domain_sha256':transition['domain_sha256'], 'runtime_contract':domain['runtime_contract']}


def checker_options(unwind, solver):
    require(type(unwind) is int and unwind >= 2, 'invalid unwind budget')
    return ['--json-ui','--unwind',str(unwind),'--unwinding-assertions','--bounds-check','--pointer-check',
        '--signed-overflow-check','--undefined-shift-check','--div-by-zero-check','--object-bits','12',
        '--no-self-loops-to-assumptions',*solver_arguments(solver),'--reachability-slice-fb','--slice-formula',
        '--verbosity','8','--timestamp','monotonic']


def check_call_evidence(result, root):
    """Validate an unchanged successful process/model/input envelope for reuse.

    Current caller inputs and the entire producer graph must separately match
    the old proof key. This does not regenerate the consumer C model.
    """
    root = Path(root)
    require(result.get('policy') == POLICY and result.get('status') == 'satisfied'
            and result.get('authorizing') is False and result.get('activation_authorized') is False
            and result.get('receipt_sha256') == canonical_sha256_v3({k:v for k,v in result.items() if k!='receipt_sha256'}),
            'stale or incomplete previous caller proof')
    require(result['proof_key_sha256'] == canonical_sha256_v3(result['proof_key']), 'caller proof key differs')
    for name,digest in result['proof_files'].items():
        path = root/'proof'/name
        require(path.resolve().is_relative_to((root/'proof').resolve()) and sha256_file(path) == digest, 'caller proof file changed')
    directories = list((root/'proof/query-evidence').glob('*/query.json'))
    require(len(directories)==1, 'caller needs one complete query')
    record = read_json(directories[0]); directory=directories[0].parent
    require(record['returncode']==0 and directory.name==canonical_sha256_v3(record['binding'])
            and record['binding']['goto_model_sha256']==result['proof_files']['model.goto']
            and record['binding']['arguments']==['$GOTO_MODEL','--function',ENTRY,*result['proof_key']['options']],
            'caller query/model/options differ')
    compiler = read_json(root/'proof/compiler-command.json')
    entry = result['proof_key']['bindings']['contract']['entry_rva']
    original = f'behavioral-fn-{entry:08x}.c'
    require(compiler['returncode']==0 and compiler['command']==[
        record['binding']['tools']['compiler'],'--i386-win32','-nostdinc','-I','.',
        'pair.c',original,'behavioral-support.c','--function',ENTRY,'-o','model.goto'], 'caller compiler command differs')
    expected = {'pair.c',original,'behavioral-support.c','behavioral-c.h','state-machine-runtime.h',
                'stdint.h','stddef.h','portable-component.h','portable-component-implementation.h'}
    require(set(compiler['inputs']) == expected and all(result['proof_files'][name]==digest
            for name,digest in compiler['inputs'].items()), 'caller compiled input inventory differs')
    require(all(result['proof_files'][name]==digest for name,digest
                in result['proof_key']['bindings']['original_files'].items()), 'caller original bytes differ')
    for name, value in (('compiler','goto_cc'),('checker','cbmc'),('external_smt2_solver','smt_solver')):
        tool=record['binding']['tools']
        require(sha256_file(Path(tool[name]))==tool[name+'_sha256']==result['proof_key']['tools'][value], 'caller proof tool changed')
    stdout, stderr=(directory/'stdout').read_text(),(directory/'stderr').read_text()
    require(sha256_file(directory/'stdout')==record['stdout_sha256'] and sha256_file(directory/'stderr')==record['stderr_sha256'], 'caller query outputs changed')
    statuses=_property_statuses(json.loads(stdout))
    require(statuses and set(statuses.values())=={'SUCCESS'} and sorted(statuses)==result['query']['property_ids']
            and len(statuses)==result['query']['properties']
            and _output_sha256(stdout,stderr)==result['query']['output_sha256'], 'caller lacks complete successful properties')
