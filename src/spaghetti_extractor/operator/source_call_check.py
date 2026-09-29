"""Public conditional caller checks consume independently cached source preparation."""

from pathlib import Path
import shutil

from ..components.bisimulation_call_check import check_source_bound_call
from ..components.bisimulation_call_evidence import read_json
from ..util import sha256_file, write_json
from .work_status import build_operator_work_status_v2, build_operator_blocker_detail_v1


def write_component_source_call_check(*, target_id, component_id, preparation, exact, supplier, contract,
                                      out, workspace, goto_cc, cbmc, smt_solver, previous=None,
                                      unwind=16, timeout_seconds=30, timings=None,
                                      source_package=None, interface_package=None):
    out, workspace = Path(out), Path(workspace)
    if workspace.resolve().is_relative_to(out.resolve()):
        raise ValueError('caller proof workspace must be outside its artifact output')
    baseline = read_json(Path(preparation)/'source-check.json')
    if (baseline['target_id']!=target_id or baseline['scope']!='component-source'
            or len(baseline['subjects'])!=1 or baseline['subjects'][0]['subject']!='component:'+component_id):
        raise ValueError('caller preparation identifies another component')
    checker = check_source_bound_call
    extra = {'smt_solver': smt_solver}
    if contract.get('profile') == 'finite-paired-caller-v1':
        from .source_operation_call_check import check_operation_call
        checker = check_operation_call
        extra = {'source_package': source_package, 'interface_package': interface_package}
    elif source_package is not None or interface_package is not None:
        raise ValueError('complete operation inputs require a supported caller profile')
    result = checker(preparation=preparation,exact=exact,supplier=supplier,contract=contract,
        output=workspace,goto_cc=goto_cc,cbmc=cbmc,**extra,
        previous=None if previous is None else Path(previous)/'caller-comparison',
        unwind=unwind,timeout_seconds=timeout_seconds,timings=timings)
    out.mkdir(parents=True,exist_ok=True)
    shutil.copytree(workspace,out/'caller-comparison')
    state={'satisfied':'complete','violated':'violated','incomplete':'incomplete'}[result['status']]
    blockers=[{'family':'source-call-comparison','status':row['status'],'code':row['code'],
               'diagnostic':row.get('detail') or 'Caller region remains unproved.'}
              for row in result['checks'] if row['status']!='satisfied']
    status=build_operator_work_status_v2(target_id=target_id,scope='component-source',subjects=[{
        'subject':'component:'+component_id,'kind':'component','state':state,'authority':'not-applicable',
        'stage':'source-compile-profile-and-local-contract','sources':baseline['subjects'][0]['sources'],
        'blockers':[{'family':r['family'],'code':r['code'],'location':None} for r in blockers],
        'next_action':('Discharge caller entry, remaining regions/progress and runtime compatibility; this result cannot activate a component.'
            if state=='complete' else 'Inspect caller-comparison/result.json and repair the source or caller/dependency contract.')}])
    write_json(out/'source-check.json',status)
    write_json(out/'source-check-details.json',build_operator_blocker_detail_v1(target_id=target_id,
        subject='component:'+component_id,source_format=status['format'],source_sha256=sha256_file(out/'source-check.json'),
        blockers=blockers,family=None,code=None,limit=None))
    feedback=read_json(Path(preparation)/'compiler-checks.json')
    # Retain the validated source binding by reference. Its independent Nix
    # product remains unchanged when a supplier implementation is requalified.
    feedback.pop('source_call_regions',None)
    feedback['local_contract']={'status':result['status'],'authorizing':False,'qualified_connected_summary':False,
        'path':'caller-comparison/result.json','receipt_sha256':result['receipt_sha256'],
        'query_reuse':{'executed_queries':result['reuse']['solver_runs'],
                       'reused_queries':int(result['reuse']['status']=='reused')},
        'caller_comparison':{'status':result['status'],'region':result['region'],'reuse':result['reuse'],
            'runtime_compatibility':result['runtime_compatibility'],'whole_component_complete':False,
            'activation_authorized':False,'source_preparation':str(preparation),
            'runtime_contract':result.get('proof_key',{}).get('bindings',{}).get('runtime_contract'),
            'supplier_domain_sha256':result.get('supplier_transition',{}).get('domain_sha256'),
            'supplier_receipt_sha256':result.get('supplier_transition',{}).get('supplier_receipt_sha256')}}
    if 'dependency_contract' in result:
        feedback['local_contract']['caller_comparison']['dependency_contract'] = result['dependency_contract']
    if result.get('policy') == 'conditional-source-operation-call-v1':
        feedback['local_contract']['caller_comparison']['native_memory'] = result.get('proof_key',{}).get('bindings',{}).get('native_memory')
        feedback['local_contract']['caller_comparison']['native_calls'] = result.get('proof_key',{}).get('bindings',{}).get('native_calls')
        feedback['local_contract']['caller_comparison']['source_services'] = result.get('proof_key',{}).get('bindings',{}).get('source_services')
        feedback['local_contract']['caller_comparison']['boundary'] = result.get('proof_key',{}).get('bindings',{}).get('boundary')
        feedback['local_contract']['caller_comparison']['admission'] = result.get('admission')
    write_json(out/'compiler-checks.json',feedback)
    return status


def validate_component_source_call_feedback(root, local, status):
    """Keep displayed caller success bound to its actual conditional result."""
    from ..artifacts.artifact_set import canonical_sha256_v3
    from ..components.bisimulation_call_evidence import (
        POLICY, check_call_evidence, load_call_inputs, producer_binding, require,
    )

    root=Path(root)
    result=read_json(root/'caller-comparison/result.json')
    caller=local['caller_comparison']
    operation_profile = result.get('policy') == 'conditional-source-operation-call-v1'
    if operation_profile:
        require(caller.get('dependency_contract') == result.get('dependency_contract'),
                'displayed caller dependency requirements differ')
        require(caller.get('native_memory') == result.get('proof_key',{}).get('bindings',{}).get('native_memory'),
                'displayed native access definitions differ')
        require(caller.get('native_calls') == result.get('proof_key',{}).get('bindings',{}).get('native_calls'),
                'displayed native call definitions differ')
        require(caller.get('source_services') == result.get('proof_key',{}).get('bindings',{}).get('source_services'),
                'displayed source service definitions differ')
        require(caller.get('boundary') == result.get('proof_key',{}).get('bindings',{}).get('boundary'),
                'displayed caller boundary definition differs')
        require(caller.get('admission') == result.get('admission'), 'displayed caller entry admission differs')
    require((result.get('policy')==POLICY or operation_profile) and result.get('authorizing') is False
            and result.get('activation_authorized') is False and result.get('whole_component_complete') is False
            and result.get('receipt_sha256')==canonical_sha256_v3({k:v for k,v in result.items() if k!='receipt_sha256'})
            and local['receipt_sha256']==result['receipt_sha256'] and local['status']==result['status']
            and caller['status']==result['status'] and caller['reuse']==result['reuse']
            and caller['region']==result['region'] and caller['whole_component_complete'] is False
            and caller['activation_authorized'] is False and caller['runtime_compatibility']=='unverified'
            and status=={'satisfied':'complete','violated':'violated','incomplete':'incomplete'}[result['status']],
            'public caller feedback differs from its conditional evidence')
    if result['status']=='satisfied':
        if operation_profile:
            from .source_operation_call_check import validate_operation_call_result
            validate_operation_call_result(result, root/'caller-comparison')
            transition, bindings = result['supplier_transition'], result['proof_key']['bindings']
        else:
            _, transition, bindings=load_call_inputs(**result['inputs'])
            require(bindings==result['proof_key']['bindings'] and transition==result['supplier_transition']
                    and result['proof_key']['producers']==producer_binding(), 'caller proof inputs or producer changed')
        require(caller['supplier_domain_sha256']==transition['domain_sha256']
                and caller['supplier_receipt_sha256']==transition['supplier_receipt_sha256']
                and caller['runtime_contract']==bindings['runtime_contract'], 'displayed caller contract differs')
        if not operation_profile:
            check_call_evidence(result,root/'caller-comparison')
