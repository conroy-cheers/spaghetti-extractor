"""Prepare the existing experimental policy and a review guide from retained checks."""
from __future__ import annotations

import json
from pathlib import Path
import shlex

from ..artifacts.artifact_set import canonical_sha256_v3
from ..components.comparison_representation import representation_policy, validate_representation_selection
from .experimental_manifest import component_binding, selected_comparison, selected_component_check, load_experimental_policy
from .formats import EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT


def _review(*, policy: dict, comparison: Path, graph: dict, plan: dict,
            bindings: dict, checks: dict, checked: dict, missing: list, command: list) -> str:
    main=plan['component_id']
    lines=['# Experimental policy review', '',
        'Review `experimental-policy.json` before passing it to `candidate build`. '
        'This command prepares policy and guidance; it does not build, run or qualify a replacement.', '',
        'Target: `'+policy['target_id']+'`; configuration: `'+policy['configuration_id']+'`.', '',
        'Program/network scope: '+graph['scope'], '',
        f"Main comparison: `{main}`, {len(graph['cases'])} concrete cases, formal status `"+
        graph['formal_check']['status']+'`. This is network evidence, not a separate local check for each selected unit.', '',
        'Observations: '+', '.join('`'+s+'`' for s in plan['observation_fields'])+'.',
        'Original runtime dependencies allowed: '+str(policy['allow_original_runtime_dependencies']).lower()+'.',
        'Allowed formal statuses: '+', '.join('`'+s+'`' for s in policy['allowed_formal_statuses'])+'.', '',
        'Known mismatches, stale inputs, disproved contracts and incomplete required resource observations still reject. '
        'Finite comparisons and declared assumptions do not establish strong qualification.', '',
        '## Selected evidence', '', '| Component | Evidence supplied | Required before build |', '|---|---|---|']
    required=set(policy.get('required_component_checks',policy['required_components']))|{main}
    for identity in bindings:
        evidence=('main network comparison' if identity==main else
            str(len(checked[identity]['cases']))+'-case component comparison; formal '+checked[identity]['formal_check']['status']
            if identity in checked else 'selected network cases only')
        requirement='main comparison' if identity==main else ('component receipt' if identity in required else 'network evidence accepted explicitly')
        lines.append(f'| `{identity}` | {evidence} | {requirement} |')
    if missing:
        lines+=['', 'Required component receipts still missing: '+', '.join('`'+s+'`' for s in missing)+'.',
            'Add matching `--component-comparison COMPONENT=DIR` arguments to the build command, '
            'or prepare a new policy explicitly naming those components with `--network-only COMPONENT`.']
    lines+=['', '## Build after review', '', '```sh', shlex.join(command), '```', '',
        'The build rechecks the selection and every supplied receipt. This guide is not admission evidence. '
        'Reuse this policy across compatible C edits; prepare a new one when accepted boundary declarations change.', '',
        '## Original inputs', '', '```json', json.dumps(plan['original'],indent=2,sort_keys=True), '```', '',
        '## Component assumptions and declarations', '',
        'Service and resource digests in the policy are generated from the declarations below. '
        'Review their meaning; no manual hash calculation is needed. Network evidence does not establish '
        'coverage of every operation. Read the retained case reports for the observed scope.', '']
    for identity,binding in bindings.items():
        unit=plan if identity==main else next(row for row in plan['dependencies'] if row['id']==identity)
        interface=comparison/'inputs'/unit['interface']
        source=checks.get(identity,comparison)
        lines+=['### '+identity, '', f'Interface: [{identity}](<{interface}>). ',
            f'Comparison: [retained result](<{source / "comparison-result.json"}>).', '',
            *['- '+s for s in binding['assumptions']], '', '<details>', '<summary>Accepted declarations and requirements</summary>', '',
            '```json',json.dumps({name:binding.get(name) for name in
                ('input_domain','requirements','service_catalog','resource_checks','representation')},indent=2,sort_keys=True),
            '```', '', '</details>', '']
    return '\n'.join(lines)


def prepare_experimental_policy(*, comparison: Path, component_checks: dict[str,Path], target_id: str,
                                configuration_id: str, output: Path, network_only: list[str]) -> dict:
    comparison=comparison.resolve();output=output.resolve()
    checks={identity:path.resolve() for identity,path in component_checks.items()}
    for path in [comparison,*checks.values()]:
        if output.is_relative_to(path) or path.is_relative_to(output):
            raise ValueError('policy output and retained comparisons must be separate')
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError('policy output must be a new or empty directory')
    policy=dict(format=EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT,target_id=target_id,
        configuration_id=configuration_id,scope='component-network',
        allowed_formal_statuses=['not-requested','unavailable','timeout','proved'],
        allow_original_runtime_dependencies=True)
    graph,plan=selected_comparison(comparison,policy)
    validate_representation_selection(comparison/'inputs',plan,complete=True)
    main=plan['component_id']
    bindings={main:component_binding(comparison,plan),**{
        unit['id']:component_binding(comparison,unit,'dependencies/'+unit['id']+'/') for unit in plan.get('dependencies',[])}}
    if main in checks or not checks.keys()<=bindings.keys():
        raise ValueError('component comparisons must name selected suppliers; the main comparison already supplies its root receipt')
    if (len(network_only)!=len(set(network_only)) or not set(network_only)<=bindings.keys() or main in network_only):
        raise ValueError('--network-only requires unique selected supplier IDs; the main comparison remains mandatory')
    checked={identity:selected_component_check(path,identity,bindings[identity],policy) for identity,path in checks.items()}
    policy.update(required_components=sorted(bindings),
        accepted_assumptions={k:v['assumptions'] for k,v in bindings.items()},
        accepted_input_domains={k:v.get('input_domain') for k,v in bindings.items()},
        accepted_service_catalogs={k:v['service_catalog']['catalog_sha256'] if v.get('service_catalog') else None for k,v in bindings.items()},
        accepted_resource_checks={k:canonical_sha256_v3(v['resource_checks']) if v.get('resource_checks') else None for k,v in bindings.items()},
        accepted_representations={k:representation_policy(v.get('representation')) for k,v in bindings.items()},
        allow_original_runtime_dependencies=bool(plan['runtime_files'] or any(
            json.loads((path/'inputs/comparison-plan.json').read_text())['runtime_files'] for path in checks.values())))
    if network_only:policy['required_component_checks']=sorted(bindings.keys()-set(network_only))
    required=set(policy.get('required_component_checks',policy['required_components']))
    missing=sorted(required-checks.keys()-{main})
    command=['spaghetti-extractor','candidate','build',target_id,'--experimental-comparison',str(comparison),
        '--experimental-policy',str(output/'experimental-policy.json')]
    for identity,path in sorted(checks.items()):command+=['--component-comparison',identity+'='+str(path)]
    command+=['--output',str(output.parent/(output.name+'-experiment'))]
    guide=_review(policy=policy,comparison=comparison,graph=graph,plan=plan,bindings=bindings,
        checks=checks,checked=checked,missing=missing,command=command)
    output.mkdir(parents=True,exist_ok=True)
    (output/'experimental-policy.json').write_text(json.dumps(policy,indent=2,sort_keys=True)+'\n')
    load_experimental_policy(output/'experimental-policy.json')
    (output/'README.md').write_text(guide)
    return dict(policy=policy,main_component=main,missing_checks=missing,build_command=command)
