"""Checked selection policy for finite, explicitly experimental component runs."""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..artifacts.artifact_set import canonical_sha256_v3
from ..components.comparison_package import load_comparison_package,package_file
from ..components.comparison_run import load_comparison_result
from ..components.interface_package_v5 import ComponentInterfaceIntentV1
from ..util import sha256_file
from .formats import EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT,EXPERIMENTAL_COMPONENT_EXECUTION_V1_FORMAT


def load_experimental_policy(path: Path) -> dict:
    value=json.loads(path.read_text())
    fields={'format','target_id','configuration_id','scope','required_components','accepted_assumptions',
            'allowed_formal_statuses','allow_original_runtime_dependencies'}
    if not isinstance(value,dict) or set(value)-{'accepted_input_domains','accepted_representations','accepted_resource_checks','accepted_service_catalogs','required_component_checks'}!=fields or value['format']!=EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT:
        raise ValueError('unsupported experimental policy')
    if value['scope']!='component-network' or any(not isinstance(value[k],str) or not value[k] for k in ('target_id','configuration_id')):
        raise ValueError('experimental policy requires an explicit component-network identity')
    ids=value['required_components']
    if not isinstance(ids,list) or not ids or any(not isinstance(s,str) or not s for s in ids) or len(set(ids))!=len(ids):
        raise ValueError('experimental policy component selection is empty or repeated')
    if 'required_component_checks' in value:
        required=value['required_component_checks']
        if (not isinstance(required,list) or any(not isinstance(s,str) or s not in ids for s in required)
                or len(set(required))!=len(required)):
            raise ValueError('required component checks must be unique selected component IDs')
    assumptions=value['accepted_assumptions']
    if not isinstance(assumptions,dict) or set(assumptions)!=set(ids):
        raise ValueError('experimental policy must address every component assumption set')
    for rows in assumptions.values():
        if not isinstance(rows,list) or not rows or any(not isinstance(s,str) or not s for s in rows):
            raise ValueError('experimental assumptions must be explicit strings')
    statuses=value['allowed_formal_statuses']
    if not isinstance(statuses,list) or not statuses or any(not isinstance(s,str) or s not in {'not-requested','unavailable','timeout','proved'} for s in statuses):
        raise ValueError('experimental policy cannot accept a disproved or unknown formal status')
    if type(value['allow_original_runtime_dependencies']) is not bool:
        raise ValueError('experimental original-runtime policy must be explicit')
    if 'accepted_input_domains' in value:
        from ..components.comparison_domain import checked_input_domain
        domains=value['accepted_input_domains']
        if not isinstance(domains,dict) or set(domains)!=set(ids):
            raise ValueError('experimental policy must address every selected input domain')
        for domain in domains.values():
            checked_input_domain(domain)
    if 'accepted_service_catalogs' in value:
        accepted=value['accepted_service_catalogs']
        if not isinstance(accepted,dict) or set(accepted)!=set(value['required_components']) or any(d is not None and (not isinstance(d,str) or re.fullmatch(r'[0-9a-f]{64}',d) is None) for d in accepted.values()):
            raise ValueError('experimental service catalogs must explicitly address every component')
    if 'accepted_resource_checks' in value:
        accepted=value['accepted_resource_checks']
        if (not isinstance(accepted,dict) or set(accepted)!=set(ids) or any(
                digest is not None and (not isinstance(digest,str) or not re.fullmatch(r'[0-9a-f]{64}',digest))
                for digest in accepted.values())):
            raise ValueError('experimental policy must bind every resource-check declaration')
    if 'accepted_representations' in value:
        from ..components.lifting_intent import normalize_lifting_group
        accepted=value['accepted_representations']
        if not isinstance(accepted,dict) or set(accepted)!=set(ids):
            raise ValueError('experimental policy must address every component representation')
        for identity,row in accepted.items():
            if row is None:
                continue
            if not isinstance(row,dict) or set(row)!={'group','revision'} or not isinstance(row['revision'],str) or not row['revision']:
                raise ValueError('experimental representation policy is malformed')
            if identity not in normalize_lifting_group(row['group'],0)['members']:
                raise ValueError('experimental component is absent from its accepted replacement group')
    return value


def compiler_read_inputs(root: Path, result: dict):
    """Map compiler reads to retained inputs while preserving external paths."""
    keys=sorted(result['input_sha256s'],key=len,reverse=True)
    for name,digest in result['compiler_dependencies'].items():
        relative=next((key for key in keys if name.endswith('/inputs/'+key)),None)
        yield (root/'inputs'/relative if relative else Path(name)),digest


def selected_comparison(root: Path, policy: dict) -> tuple[dict,dict]:
    result=load_comparison_result(root)
    plan,_=load_comparison_package(root/'inputs')
    if result['target_id']!=policy['target_id'] or result['status']!='match' or result['case_selection'] is not None:
        raise ValueError('experimental execution requires a full matching comparison for the selected target')
    from ..components.comparison_resources import resource_applicability
    if resource_applicability(result) not in ('not-requested','satisfied'):
        raise ValueError('resource contract premises are violated or instrumentation is incomplete')
    if result['formal_check']['status'] not in policy['allowed_formal_statuses']:
        raise ValueError('formal result is outside experimental project policy')
    if result['source_profile']['status']!='satisfied' or any(p['status']!='satisfied' for p in result.get('source_profiles',{}).values()):
        raise ValueError('selected source does not satisfy its C profile')
    if plan['runtime_files'] and not policy['allow_original_runtime_dependencies']:
        raise ValueError('project policy does not permit these original runtime dependencies')
    for path,digest in compiler_read_inputs(root,result):
        if not path.is_file() or sha256_file(path)!=digest:
            raise ValueError('experimental compiler-read input is absent or stale')
    return result,plan


def component_binding(root: Path, row: dict, prefix: str = '') -> dict:
    snapshot=root/'inputs'
    interface=ComponentInterfaceIntentV1.parse(json.loads(package_file(snapshot,row['interface']).read_text()))
    names=set(row['sources'])
    for directory in row['include_directories']:
        names.update(p.relative_to(snapshot).as_posix() for p in (snapshot/directory).rglob('*') if p.is_file())
    from ..components.comparison_representation import representation_binding
    representation=representation_binding(snapshot,row)
    return {'interface_sha256':interface.intent_sha256,'operation_symbols':row['operation_symbols'],
        'sources':{name.removeprefix(prefix):sha256_file(package_file(snapshot,name)) for name in sorted(names)},
        'assumptions':row['assumptions'],
        **({'requirements':row['requirements']} if 'requirements' in row else {}),
        **({'recursion_groups':row['recursion_groups']} if 'recursion_groups' in row else {}),
        **({'service_bridge':row['service_bridge']} if 'service_bridge' in row else {}),
        **({'service_catalog':row['service_catalog']} if 'service_catalog' in row else {}),
        **({'resource_checks':row['resource_checks']} if 'resource_checks' in row else {}),**({'input_domain':row['input_domain']} if 'input_domain' in row else {}),
        **({'representation':representation} if representation is not None else {})}


def selected_component_check(root: Path, identity: str, binding: dict, policy: dict) -> dict:
    checked,plan=selected_comparison(root,policy)
    if checked['component_id']!=identity:
        raise ValueError('experimental component check belongs to another component')
    if component_binding(root,plan)!=binding:
        raise ValueError('component comparison checks a different selected implementation or contract')
    return checked


def validate_experimental_evidence(root: Path, policy: dict, checks: dict) -> dict:
    if not isinstance(checks,dict) or any(not isinstance(row,dict) or set(row)!={'path','receipt_sha256'}
            or any(not isinstance(row[k],str) or not row[k] for k in row) for row in checks.values()):
        raise ValueError('experimental component check bindings are malformed')
    graph,plan=selected_comparison(root/'comparison',policy)
    from ..components.comparison_representation import validate_representation_selection,representation_policy
    validate_representation_selection(root/'comparison/inputs',plan,complete=True)
    selected={plan['component_id']:component_binding(root/'comparison',plan)}
    for row in plan.get('dependencies',[]):
        selected[row['id']]=component_binding(root/'comparison',row,f"dependencies/{row['id']}/")
    required={plan['component_id'],*policy.get('required_component_checks',policy['required_components'])}
    if set(selected)!=set(policy['required_components']) or not required<=checks.keys() or not checks.keys()<=selected.keys():
        raise ValueError('experimental selection and required component checks differ')
    for identity,binding in selected.items():
        catalog=binding.get('service_catalog')
        if (catalog['catalog_sha256'] if catalog else None)!=policy.get('accepted_service_catalogs',{}).get(identity):
            raise ValueError(f'experimental service catalog has not been accepted for {identity}')
        resources=binding.get('resource_checks')
        digest=canonical_sha256_v3(resources) if resources is not None else None
        if digest!=policy.get('accepted_resource_checks',{}).get(identity):
            raise ValueError(f'experimental resource checks have not been accepted for {identity}')
        if representation_policy(binding.get('representation'))!=policy.get('accepted_representations',{}).get(identity):
            raise ValueError(f'experimental representation has not been accepted for {identity}')
        if binding['assumptions']!=policy['accepted_assumptions'][identity]:
            raise ValueError(f'experimental assumptions have not been accepted for {identity}')
        if binding.get('input_domain')!=policy.get('accepted_input_domains',{}).get(identity):
            raise ValueError(f'experimental input domain has not been accepted for {identity}')
        if identity not in checks:continue  # Explicit policy: selected network evidence only.
        path=checks[identity]['path']
        package_file(root,path+'/comparison-result.json')
        checked=selected_component_check(root/path,identity,binding,policy)
        if checked['receipt_sha256']!=checks[identity]['receipt_sha256']:
            raise ValueError('experimental component check identity is stale')
    from .experimental_program import program_binding
    return {'comparison_sha256':graph['receipt_sha256'],'candidate_sha256':graph['binary_sha256'],
        **program_binding(root/'comparison',plan),
        'components':selected,'tools':plan['tools'],
        'runtime_sha256s':{Path(name).name:sha256_file(package_file(root/'comparison/inputs',name)) for name in plan['runtime_files']}}


def load_experimental_manifest(root: Path, *, case_id: str | None = None) -> dict:
    payload=json.loads(package_file(root,'experimental-execution.json').read_text())
    fields={'format','authority','policy_sha256','configuration_id','target_id','scope','bindings',
            'component_checks','symbols','suite_sha256','case_ids','manifest_sha256'}
    if not isinstance(payload,dict) or set(payload)!=fields or payload['format']!=EXPERIMENTAL_COMPONENT_EXECUTION_V1_FORMAT:
        raise ValueError('unsupported experimental execution manifest')
    if payload['authority']!='experimental-execution-only' or payload['manifest_sha256']!=canonical_sha256_v3({k:v for k,v in payload.items() if k!='manifest_sha256'}):
        raise ValueError('experimental manifest authority or identity is invalid')
    policy=load_experimental_policy(package_file(root,'experimental-policy.json'))
    if payload['policy_sha256']!=sha256_file(root/'experimental-policy.json') or any(payload[k]!=policy[k] for k in ('configuration_id','target_id','scope')):
        raise ValueError('experimental project policy binding is stale')
    if payload['bindings']!=validate_experimental_evidence(root,policy,payload['component_checks']):
        raise ValueError('experimental implementation/runtime binding is stale')
    suite=package_file(root,'candidate-suite.json')
    if sha256_file(suite)!=payload['suite_sha256']:
        raise ValueError('experimental case suite binding is stale')
    from .experimental_build import comparison_suite,symbol_definitions
    graph=load_comparison_result(root/'comparison')
    suite_value=json.loads(suite.read_text())
    if suite_value!=comparison_suite(root,graph,policy):
        raise ValueError('experimental suite differs from its checked selected observations')
    cases=suite_value['cases']
    if [row['id'] for row in cases]!=payload['case_ids'] or not cases or (case_id is not None and case_id not in payload['case_ids']):
        raise ValueError('experimental case is absent from the admitted suite')
    symbols=payload['symbols']
    if sha256_file(package_file(root,'symbols.txt'))!=symbols['output_sha256']:
        raise ValueError('experimental symbol inventory is stale')
    from .experimental_program import authored_binary
    if (symbols['binary_sha256']!=authored_binary(payload['bindings'])[1]
            or symbols['definitions']!=symbol_definitions((root/'symbols.txt').read_text(),payload['bindings']['components'])
            or not Path(symbols['tool']['path']).is_file()
            or sha256_file(Path(symbols['tool']['path']))!=symbols['tool']['sha256']):
        raise ValueError('experimental symbol ownership or tool binding differs')
    for name,digest in payload['bindings']['runtime_sha256s'].items():
        program=payload['bindings'].get('program')
        source='comparison/inputs/'+program['runtime_files'][name] if program else 'comparison/build/'+name
        if sha256_file(package_file(root,source))!=digest:
            raise ValueError('experimental linked runtime differs from the checked input')
    return payload
