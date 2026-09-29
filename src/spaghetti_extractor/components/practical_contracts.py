"""Optional existing memory-contract proofs alongside concrete comparisons.

These source frame/input-dependence obligations are not original/source
equivalence. The enclosing comparison retains their separate scope and costs.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
import shutil

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file
from .comparison_package import package_file
from .interface_package_v5 import compile_component_interface_v5
from .bisimulation_readonly_contracts import check_readonly_source_contracts,check_mutable_source_contracts,check_shared_source_contracts
from .bisimulation_readonly_evidence import validate_readonly_source_contracts,validate_mutable_source_contracts,validate_shared_source_contracts
from .bisimulation_readonly_model import fixed_mutable_summary_operations,fixed_readonly_summary_operations
from .bisimulation_shared_model import shared_source_shape
from .cbmc_backend import _parse_json,_failures,_output_sha256
from .machine_overlay_services_v5 import _c_identifier
from .bisimulation_object_model import object_source_shape
from .bisimulation_readonly_contracts import check_object_source_contracts
from .bisimulation_readonly_evidence import validate_object_source_contracts

CLAIM = 'source memory frame and input dependence; not original/source equivalence'


def checked_local_shared_contract(value, interface):
    """Select an existing conditional source theorem, not an activation premise."""
    if value is None:
        return None
    from .relation_v5 import ComponentRelationIntentV1
    from .bisimulation_mutable_memory import MAX_MUTABLE_MODEL_BYTES
    from .bisimulation_shared_services import shared_service_contract_index
    fields={'relation_intent','maximum_calls','maximum_memory_events'}
    if not isinstance(value,dict) or set(value)-{'service_contracts'}!=fields:
        raise ValueError('local shared contract requires an existing relation and explicit model capacities')
    for name,limit in [('maximum_calls',64),('maximum_memory_events',MAX_MUTABLE_MODEL_BYTES)]:
        if type(value[name]) is not int or not 0<value[name]<=limit:
            raise ValueError('local shared contract has invalid '+name)
    relation=ComponentRelationIntentV1.parse(value['relation_intent'])
    bundle=compile_component_interface_v5(interface)
    if (relation.component_id!=interface.component_id or relation.status!='ready_for_check'
            or {row['operation_id'] for row in relation.operations}!={op.identity for op in bundle.interface.operations}):
        raise ValueError('local shared contract relation differs from the selected interface')
    if 'service_contracts' in value:
        shared_service_contract_index(bundle,value['service_contracts'])
    return value


def _rule(plan, bundle):
    shared=checked_local_shared_contract(plan.get('local_shared_contract'),bundle.intent)
    if shared is not None:
        return ('shared-memory-service-contracts',check_shared_source_contracts,
                validate_shared_source_contracts,shared_source_shape(bundle),{'shared_contract':shared})
    mutable=fixed_mutable_summary_operations(bundle)
    if mutable is not None:
        return 'mutable-memory-contracts',check_mutable_source_contracts,validate_mutable_source_contracts,mutable,{}
    objects=object_source_shape(bundle)
    if objects is not None:
        return 'object-memory-contracts',check_object_source_contracts,validate_object_source_contracts,objects,{}
    return ('readonly-memory-contracts',check_readonly_source_contracts,validate_readonly_source_contracts,
            fixed_readonly_summary_operations(bundle),{})


def _binding(snapshot: Path, plan: dict, interface) -> dict:
    names=set(plan['sources'])
    for directory in plan['include_directories']:
        names.update(p.relative_to(snapshot).as_posix() for p in (snapshot/directory).rglob('*') if p.is_file())
    return {'interface_sha256':interface.intent_sha256,'operation_symbols':plan['operation_symbols'],
            'sources':{n:sha256_file(package_file(snapshot,n)) for n in sorted(names)},
            **({'local_shared_contract':plan['local_shared_contract']} if plan.get('local_shared_contract') is not None else {})}


def _classification(result: dict, root: Path) -> str:
    if result.get('status')=='satisfied':
        return 'proved'
    if str(result.get('code', '')).endswith('_source_profile_rejected'):
        return 'unavailable'
    if result.get('code') in {'readonly_summary_contract_shape_unsupported','mutable_summary_contract_shape_unsupported','shared_summary_contract_shape_unsupported','object_summary_contract_shape_unsupported'}:
        return 'unavailable'
    checks=result.get('checks',[])
    failed=False
    for row in checks:
        if row.get('status')!='violated':
            continue
        if row.get('code')=='cbmc_counterexample':
            name=_c_identifier(row['operation_id'])+'-'+row['kind']+'-check.stdout'
            payload=_parse_json(package_file(root,name).read_text())
            failures=_failures(payload) if payload is not None else []
            if not failures:
                raise ValueError('optional contract counterexample lacks failed properties')
            if all('.unwind.' in str(f.get('property','')) for f in failures):
                failed=True
                continue
        return 'disproved'
    if failed:
        return 'incomplete'  # Exhausting a loop bound is not a behavioral disproof.
    if checks and any(row.get('code')=='cbmc_timeout' for row in checks) and all(
            row.get('status')=='satisfied' or row.get('code')=='cbmc_timeout' for row in checks):
        return 'timeout'
    return 'incomplete'


def _files(root: Path) -> dict:
    return {p.relative_to(root).as_posix():sha256_file(p) for p in sorted(root.rglob('*')) if p.is_file()}


def check_practical_contracts(*, output: Path, plan: dict, interface, query_timeout: float = 30,
                              previous: Path | None = None) -> dict:
    if not math.isfinite(query_timeout) or query_timeout<=0:
        raise ValueError('optional contract query timeout must be finite and positive')
    bundle=compile_component_interface_v5(interface)
    kind,checker,_,_,options=_rule(plan,bundle)
    tools={name:Path(path) if (path:=shutil.which(name.replace('_','-'))) else None
           for name in ('cbmc','goto_cc','goto_instrument')}
    if any(path is None for path in tools.values()):
        raise ValueError('optional contracts require CBMC tools; enter the project development shell')
    timings=[]
    prior=None
    if previous is not None:
        from .comparison_run import load_comparison_result
        old=load_comparison_result(previous)
        if old['formal_check']['status']=='proved':
            prior=previous/'formal'
    result=checker(bundle=bundle,package=output/'source-packages'/plan['component_id'],
        output=output/'formal',**tools,timeout_seconds=60,query_timeout_seconds=query_timeout,
        previous_contract=prior,timings=timings,**options)
    value={'status':_classification(result,output/'formal'),'required_for_comparison':False,'claim':CLAIM,
        'kind':kind,
        'binding':_binding(output/'inputs',plan,interface),
        'tools':{name:{'path':str(path),'sha256':sha256_file(path)} for name,path in tools.items()},
        'result':result,'artifact_sha256s':_files(output/'formal'),'timings':timings,
        'query_timeout_seconds':query_timeout,
        'work_counts':{phase:sum(row['phase']==phase for row in timings) for phase in ('compiler','model','solver')},
        'reused_queries':sum(row.get('reused_queries',0) for row in timings)}
    validate_practical_contracts(output=output,plan=plan,interface=interface,value=value)
    return value


def validate_practical_contracts(*, output: Path, plan: dict, interface, value: dict) -> None:
    if value=={'status':'not-requested','required_for_comparison':False}:
        return
    fields={'status','required_for_comparison','claim','kind','binding','tools','result','artifact_sha256s',
            'timings','query_timeout_seconds','work_counts','reused_queries'}
    if not isinstance(value,dict) or set(value)!=fields or value['required_for_comparison'] is not False or value['claim']!=CLAIM:
        raise ValueError('optional contract evidence has unsupported fields or scope')
    if value['binding']!=_binding(output/'inputs',plan,interface):
        raise ValueError('optional contract checks another implementation or interface')
    if _files(output/'formal')!=value['artifact_sha256s']:
        raise ValueError('optional contract artifacts are stale')
    if set(value['tools'])!={'cbmc','goto_cc','goto_instrument'}:
        raise ValueError('optional contract tool inventory is incomplete')
    if value['work_counts']!={phase:sum(row['phase']==phase for row in value['timings']) for phase in ('compiler','model','solver')}:
        raise ValueError('optional contract work counts disagree with retained phases')
    for name,row in value['tools'].items():
        if name not in {'cbmc','goto_cc','goto_instrument'} or sha256_file(Path(row['path']))!=row['sha256']:
            raise ValueError('optional contract tool binding is stale')
    result=value['result']
    if _classification(result,output/'formal')!=value['status']:
        raise ValueError('optional contract outcome differs from checker evidence')
    bundle=compile_component_interface_v5(interface)
    kind,checker,validator,shape,options=_rule(plan,bundle)
    if value['kind']!=kind:
        raise ValueError('optional contract selects another proof rule')
    if value['status']=='unavailable':
        profile_rejected=str(result.get('code','')).endswith('_source_profile_rejected')
        if shape is not None and not profile_rejected:
            raise ValueError('optional contract rule is available for this interface')
        package=Path('/unused')
        if profile_rejected:
            from .source import load_component_source_package
            package=output/'source-packages'/plan['component_id']
            source=load_component_source_package(package)
            if {row['path']:row['sha256'] for row in source['files']}!={
                    name:sha256_file(package_file(output/'inputs',name)) for name in plan['sources']}:
                raise ValueError('optional formal eligibility checks different C inputs')
        observed=checker(bundle=bundle,package=package,output=Path('/unused'),
            goto_cc=None,goto_instrument=None,cbmc=None,**options)
        if result!=observed or value['artifact_sha256s']:
            raise ValueError('optional contract unavailability differs from current rule')
        return
    if result.get('receipt_sha256')!=canonical_sha256_v3({k:v for k,v in result.items() if k!='receipt_sha256'}):
        raise ValueError('optional contract receipt identity is stale')
    if result['interface_intent']!=interface.to_payload() or result['operation_symbols']!=plan['operation_symbols']:
        raise ValueError('optional contract has different source interface bindings')
    if result.get('shared_contract')!=options.get('shared_contract'):
        raise ValueError('optional contract checks another shared premise')
    files=result['source_package']['files']
    if {row['path']:row['sha256'] for row in files}!={name:sha256_file(package_file(output/'inputs',name)) for name in plan['sources']}:
        raise ValueError('optional contract proves another authored source')
    if result['tools']!={name:row['sha256'] for name,row in value['tools'].items()}:
        raise ValueError('optional contract checker binding differs')
    if value['status']=='proved':
        validator(result,artifacts=output/'formal')
    if value['status']=='timeout':
        for check in result['checks']:
            if check.get('code')!='cbmc_timeout':
                continue
            name=_c_identifier(check['operation_id'])+'-'+check['kind']
            attempts=list((output/'formal/query-evidence'/name/'failed-attempts').glob('*/attempt.json'))
            model=next(m for m in result['models'] if (m['operation_id'],m['kind'])==(check['operation_id'],check['kind']))
            matching=False
            for path in attempts:
                attempt=json.loads(path.read_text())
                stdout=package_file(path.parent,'stdout').read_bytes();stderr=package_file(path.parent,'stderr').read_bytes()
                matching |= (attempt['termination']=={'kind':'timeout','timeout_seconds':value['query_timeout_seconds']}
                    and attempt['authorizing'] is False and attempt['reusable'] is False
                    and attempt['binding']['goto_model_sha256']==model['checked_goto_sha256']
                    and attempt['binding']['tools']['checker_sha256']==result['tools']['cbmc']
                    and attempt['binding']['tools']['compiler_sha256']==result['tools']['goto_cc']
                    and attempt['stdout_sha256']==sha256_file(path.parent/'stdout')
                    and attempt['stderr_sha256']==sha256_file(path.parent/'stderr')
                    and check['output_sha256']==_output_sha256(stdout,stderr))
            if not matching:
                raise ValueError('optional contract timeout lacks a retained checker attempt')
