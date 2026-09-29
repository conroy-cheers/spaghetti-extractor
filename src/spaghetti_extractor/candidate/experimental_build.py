"""Bind checked component selections to the binary already built by comparison."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import re
import shutil
import subprocess
import time

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.formats import CANDIDATE_TEST_SUITE_FORMAT
from ..components.comparison_package import package_file,copy_comparison
from ..util import sha256_file,write_json
from .formats import EXPERIMENTAL_COMPONENT_EXECUTION_V1_FORMAT
from .experimental_manifest import load_experimental_policy,selected_comparison,validate_experimental_evidence,load_experimental_manifest,component_binding
from .experimental_program import authored_binary


def symbol_definitions(text: str, components: dict) -> dict:
    owners={}
    for identity,component in components.items():
        for symbol in component['operation_symbols'].values():
            if symbol in owners and owners[symbol]!=identity:
                raise ValueError('selected components claim the same native symbol')
            owners[symbol]=identity
    definitions={}
    rows=[line.split() for line in text.splitlines()]
    for symbol,owner in owners.items():
        matches=[row for row in rows if len(row)==3 and row[1]=='T' and row[2] in {symbol,'_'+symbol}]
        if len(matches)!=1:
            raise ValueError(f'selected operation lacks a unique linked definition: {symbol}')
        address,_,native_symbol=matches[0]
        int(address,16)
        definitions[symbol]={'component_id':owner,'native_symbol':native_symbol,'address':address}
    return definitions


def comparison_suite(root: Path, graph: dict, policy: dict) -> dict:
    cases=[]
    plan=json.loads(package_file(root,'comparison/inputs/comparison-plan.json').read_text())
    normal=bool(plan.get('program_driver',{}).get('process'))
    for index,row in enumerate(graph['cases']):
        stdout=package_file(root,f'comparison/cases/{index:04d}-source.stdout').read_bytes()
        cases.append({'id':row['id'],'kind':'expected-exit','args':row['arguments'] if normal else ['source',*row['arguments']],
            'expected_returncode':row['observations']['source']['exit_code'] if normal else 0,
            'expected_stdout_base64':base64.b64encode(stdout).decode(),
            'expected_stderr_policy':'any'})
    return {'format':CANDIDATE_TEST_SUITE_FORMAT,'target_name':policy['target_id'],
        'suite_id':policy['configuration_id'],'suite_name':'Experimental selected component network',
        'suite_kind':'curated_expected_output','suite_scope':'component-network','upstream_suite':False,'cases':cases}


def _reuse_checks(previous: Path, manifest: dict, graph: dict, plan: dict,
                 comparison: Path, supplied: dict) -> tuple[dict,list[str]]:
    old=json.loads((previous/'comparison/comparison-result.json').read_text())
    units={plan['component_id']:plan,**{unit['id']:unit for unit in plan.get('dependencies',[])}}
    if old['component_id']!=plan['component_id'] or set(manifest['bindings']['components'])!=set(units):
        raise ValueError('experimental reuse requires the same main component and selected components; prepare a new selection')
    if old['oracle']!=graph['oracle'] or manifest['bindings']['tools']!=plan['tools']:
        raise ValueError('experimental reuse has different original inputs or comparison tools; prepare a new selection')
    selected=dict(supplied);reused=[]
    for identity,row in manifest['component_checks'].items():
        if identity==plan['component_id'] or identity in supplied:continue
        binding=component_binding(comparison,units[identity],'dependencies/'+identity+'/')
        if binding!=manifest['bindings']['components'][identity]:
            raise ValueError('selected implementation or contract changed for '+identity+
                '; supply its matching --component-comparison '+identity+'=CHECK')
        selected[identity]=previous/row['path'];reused.append(identity)
    return selected,sorted(reused)


def build_experimental_execution(*, comparison: Path, component_checks: dict[str,Path], policy_path: Path | None,
                                 output: Path, target_id: str, reuse_experimental: Path | None = None) -> dict:
    started=time.monotonic()
    previous=None;reused=[];policy_reused=False
    if reuse_experimental is not None:
        previous=load_experimental_manifest(reuse_experimental)
        if previous['target_id']!=target_id:
            raise ValueError('previous experimental package belongs to another target')
        if policy_path is None:
            policy_path=reuse_experimental/'experimental-policy.json';policy_reused=True
    if policy_path is None:
        raise ValueError('experimental build requires a policy or --reuse-experimental')
    policy=load_experimental_policy(policy_path)
    if policy['target_id']!=target_id:
        raise ValueError('experimental policy belongs to another target')
    graph,plan=selected_comparison(comparison,policy)
    if previous is not None:
        component_checks,reused=_reuse_checks(reuse_experimental,previous,graph,plan,comparison,component_checks)
    for source in [comparison,*component_checks.values(),*([reuse_experimental] if reuse_experimental else [])]:
        if output.resolve().is_relative_to(source.resolve()) or source.resolve().is_relative_to(output.resolve()):
            raise ValueError('experimental output and input comparisons/packages must be separate')
    timings=[{'phase':'evidence-validation','seconds':time.monotonic()-started}]
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError('experimental output must be a new or empty directory')
    output.mkdir(parents=True,exist_ok=True)
    started=time.monotonic()
    copy_comparison(comparison,output/'comparison')
    shutil.copyfile(policy_path,output/'experimental-policy.json')
    checks={plan['component_id']:{'path':'comparison','receipt_sha256':graph['receipt_sha256']}}
    if plan['component_id'] in component_checks:
        raise ValueError('the main component check is supplied by --experimental-comparison')
    for index,(identity,path) in enumerate(sorted(component_checks.items())):
        checked,_=selected_comparison(path,policy)
        relative=f'component-checks/{index}'
        copy_comparison(path,output/relative)
        checks[identity]={'path':relative,'receipt_sha256':checked['receipt_sha256']}
    timings.append({'phase':'evidence-retention','seconds':time.monotonic()-started})
    started=time.monotonic()
    bindings=validate_experimental_evidence(output,policy,checks)
    timings.append({'phase':'evidence-validation','seconds':time.monotonic()-started})
    compiler=Path(plan['tools']['compiler']['path'])
    nm=compiler.with_name(re.sub(r'(?:gcc|cc|clang)(?:-[0-9.]+)?$','nm',compiler.name))
    if nm==compiler or not nm.is_file():
        raise ValueError('selected compiler has no adjacent symbol-inventory tool')
    binary=output/'comparison/build'/authored_binary(bindings)[0]
    started=time.monotonic()
    observed=subprocess.run([str(nm),str(binary)],capture_output=True,text=True,timeout=30,check=True)
    timings.append({'phase':'symbol-inventory','seconds':time.monotonic()-started})
    (output/'symbols.txt').write_text(observed.stdout)
    symbols={'tool':{'path':str(nm),'sha256':sha256_file(nm)},'binary_sha256':sha256_file(binary),
        'definitions':symbol_definitions(observed.stdout,bindings['components']),
        'output_sha256':sha256_file(output/'symbols.txt')}
    suite=comparison_suite(output,graph,policy)
    write_json(output/'candidate-suite.json',suite)
    payload={'format':EXPERIMENTAL_COMPONENT_EXECUTION_V1_FORMAT,'authority':'experimental-execution-only',
        'configuration_id':policy['configuration_id'],'target_id':target_id,'scope':policy['scope'],
        'policy_sha256':sha256_file(output/'experimental-policy.json'),'bindings':bindings,'component_checks':checks,
        'symbols':symbols,'suite_sha256':sha256_file(output/'candidate-suite.json'),'case_ids':[r['id'] for r in suite['cases']]}
    payload['manifest_sha256']=canonical_sha256_v3(payload)
    write_json(output/'experimental-execution.json',payload)
    started=time.monotonic()
    result=load_experimental_manifest(output)
    timings.append({'phase':'evidence-validation','seconds':time.monotonic()-started})
    # Diagnostic measurements are not admission or proof evidence. The manifest
    # binds the reused comparison binary; this operation never recompiles it.
    write_json(output/'experimental-build-costs.json',{'timings':timings,'reused_binary':True,
        **({'previous_manifest_sha256':previous['manifest_sha256'],'reused_policy':policy_reused,
            'reused_component_checks':reused} if previous is not None else {}),
        'work_counts':{'compiler':0,'model':0,'solver':0,'link':0,'execution':0,'symbol_inventory':1}})
    return result
