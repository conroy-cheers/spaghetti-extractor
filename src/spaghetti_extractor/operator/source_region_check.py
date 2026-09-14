"""Public conditional region checks consume independently cached source preparation."""

from pathlib import Path
import shutil

from ..components.bisimulation_compaction_check import check_source_compaction
from ..components.bisimulation_call_evidence import read_json
from ..util import sha256_file, write_json
from .work_status import build_operator_work_status_v2, build_operator_blocker_detail_v1


def write_component_source_region_check(*, target_id, component_id, preparation, exact, contract,
                                      out, workspace, goto_cc, goto_instrument, cbmc, smt_solver, previous=None,
                                      unwind=16, timeout_seconds=60, timings=None, dependencies=None, host_cc=None):
    out, workspace = Path(out), Path(workspace)
    if workspace.resolve().is_relative_to(out.resolve()):
        raise ValueError('region proof workspace must be outside its artifact output')
    baseline = read_json(Path(preparation)/'source-check.json')
    if (baseline['target_id']!=target_id or baseline['scope']!='component-source'
            or len(baseline['subjects'])!=1 or baseline['subjects'][0]['subject']!='component:'+component_id):
        raise ValueError('region preparation identifies another component')
    result = check_source_compaction(preparation=preparation,exact=exact,contract=contract,
        output=workspace,goto_cc=goto_cc,goto_instrument=goto_instrument,cbmc=cbmc,smt_solver=smt_solver,
        previous=None if previous is None else Path(previous)/'region-comparison',
        unwind=unwind,timeout_seconds=timeout_seconds,timings=timings,dependencies=dependencies,host_cc=host_cc)
    out.mkdir(parents=True,exist_ok=True)
    shutil.copytree(workspace,out/'region-comparison')
    state={'satisfied':'complete','violated':'violated','incomplete':'incomplete'}[result['status']]
    blockers=[{'family':'source-region-comparison','status':row['status'],'code':row['code'],
               'diagnostic':row.get('detail') or 'Selected region remains unproved.'}
              for row in result['checks'] if row['status']!='satisfied']
    status=build_operator_work_status_v2(target_id=target_id,scope='component-source',subjects=[{
        'subject':'component:'+component_id,'kind':'component','state':state,'authority':'not-applicable',
        'stage':'source-compile-profile-and-local-contract','sources':baseline['subjects'][0]['sources'],
        'blockers':[{'family':r['family'],'code':r['code'],'location':None} for r in blockers],
        'next_action':('Discharge region entry, remaining regions/progress and runtime compatibility; this result cannot activate a component.'
            if state=='complete' else 'Inspect region-comparison/result.json and repair the source or region/dependency contract.')}])
    write_json(out/'source-check.json',status)
    write_json(out/'source-check-details.json',build_operator_blocker_detail_v1(target_id=target_id,
        subject='component:'+component_id,source_format=status['format'],source_sha256=sha256_file(out/'source-check.json'),
        blockers=blockers,family=None,code=None,limit=None))
    feedback=read_json(Path(preparation)/'compiler-checks.json')
    # Retain the validated source binding by reference. Its independent Nix
    # product remains unchanged when a supplier implementation is requalified.
    feedback.pop('source_call_regions',None)
    feedback.pop('source_region_graphs',None)
    feedback['local_contract']={'status':result['status'],'authorizing':False,'qualified_connected_summary':False,
        'path':'region-comparison/result.json','receipt_sha256':result['receipt_sha256'],
        'query_reuse':{'executed_queries':result['reuse']['solver_runs'],
                       'reused_queries':int(result['reuse']['status']=='reused')},
        'region_comparison':{'status':result['status'],'region':{'entry_cut':contract.get('entry_cut'),'exit_cut':contract.get('exit_cut'),'regions':contract.get('regions')},'reuse':result['reuse'],
            'runtime_compatibility':result['runtime_compatibility'],'whole_component_complete':False,
            'activation_authorized':False,'source_preparation':str(preparation),
            'runtime_contract':result.get('proof_key',{}).get('bindings',{}).get('runtime_contract'),
            **({'dependencies':result['dependency_evidence']} if result.get('dependency_evidence') else {})}}
    write_json(out/'compiler-checks.json',feedback)
    return status

def validate_component_source_region_feedback(root, local, status):
    """Public success requires current inputs and the complete local proof envelope."""
    from ..artifacts.artifact_set import canonical_sha256_v3
    from ..components.bisimulation_compaction_check import compaction_bindings
    from ..components.bisimulation_compaction_inputs import load_compaction_inputs
    from ..components.bisimulation_compaction_evidence import (
        POLICY, require, compaction_producers, check_compaction_evidence, source_transport,
    )
    root=Path(root); result=read_json(root/'region-comparison/result.json'); region=local['region_comparison']
    contract=result['inputs']['contract']
    require(result.get('policy')==POLICY and result.get('authorizing') is False
        and result.get('activation_authorized') is False and result.get('whole_component_complete') is False
        and result.get('runtime_compatibility')=='unverified'
        and result.get('receipt_sha256')==canonical_sha256_v3({k:v for k,v in result.items() if k!='receipt_sha256'})
        and local['receipt_sha256']==result['receipt_sha256'] and local['status']==result['status']
        and local['authorizing'] is False and local['qualified_connected_summary'] is False
        and local['path']=='region-comparison/result.json'
        and local['query_reuse']=={'executed_queries':result['reuse']['solver_runs'],'reused_queries':int(result['reuse']['status']=='reused')}
        and region=={'status':result['status'],'region':{k:contract.get(k) for k in ['entry_cut','exit_cut','regions']},
            'reuse':result['reuse'],'runtime_compatibility':'unverified','whole_component_complete':False,
            'activation_authorized':False,'source_preparation':result['inputs']['preparation'],
            'runtime_contract':result.get('proof_key',{}).get('bindings',{}).get('runtime_contract'),
            **({'dependencies':result['dependency_evidence']} if result.get('dependency_evidence') else {})}
        and status=={'satisfied':'complete','violated':'violated','incomplete':'incomplete'}[result['status']],
        'public region feedback differs from conditional evidence')
    if result['status']=='satisfied':
        data=load_compaction_inputs(**result['inputs'])
        require(result.get('dependency_evidence', {}) == data.get('dependency_evidence', {}),
                'region supplier evidence differs from current dependencies')
        require(compaction_bindings(data)==result['proof_key']['bindings']
            and compaction_producers()==result['proof_key']['producers'], 'region inputs or producers changed')
        check_compaction_evidence(result,root/'region-comparison')
        require(source_transport(data,root/'region-comparison/proof')==result['source_transport'], 'region transport differs')
