"""Check each selected unit and execute the real jq network experimentally."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.candidate.formats import EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT
from spaghetti_extractor.components.comparison_package import load_comparison_package
from spaghetti_extractor.components.comparison_representation import representation_policy

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['arrays','paths','workflow','output']:parser.add_argument(name,type=Path)
    parser.add_argument('--reuse-assembly',type=Path,help='offer retained local checks to the public checker; changed inputs still invalidate them')
    parser.add_argument('--local-contracts',action='store_true',help='also request optional formal checks; requires the corresponding checker tools')
    args=parser.parse_args();arrays=args.arrays.resolve();paths=args.paths.resolve();workflow=args.workflow.resolve();out=args.output.resolve()
    if not os.environ.get('WAYLAND_DISPLAY'):raise RuntimeError('requires headless Wayland')
    out.mkdir(parents=True,exist_ok=False);commands=[]
    def run(arguments):
        command=[sys.executable,'-m','spaghetti_extractor',*map(str,arguments)];started=time.monotonic()
        result=subprocess.run(command,capture_output=True,text=True)
        number=len(commands);(out/f'{number:02d}.stdout').write_text(result.stdout);(out/f'{number:02d}.stderr').write_text(result.stderr)
        commands.append(dict(command=command,exit_code=result.returncode,seconds=time.monotonic()-started))
        (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        if result.returncode:raise RuntimeError(f'command {number} failed; inspect {out}')
    graph=workflow/('release-network-repaired' if (workflow/'release-network-repaired/comparison-result.json').is_file() else 'repaired')
    plan,_=load_comparison_package(graph/'inputs')
    units={plan['component_id']:plan,**{row['id']:row for row in plan['dependencies']}}
    checks={'path-set':graph,'storage-set':workflow/'set-compatible','storage-get':workflow/'get-reused'}
    if (workflow/'release-repaired/comparison-result.json').is_file():checks['storage-release']=workflow/'release-repaired'
    for identity in sorted(set(units)-set(checks)):
        package=arrays/identity if identity.startswith('storage-') else paths/('path-get-network' if identity=='path-get' else identity)
        local,_=load_comparison_package(package)
        arguments=['component','check','jq',identity,'--comparison-package',package,'--output',out/identity]
        if args.local_contracts:arguments+=['--local-contracts']
        retained=args.reuse_assembly.resolve()/identity if args.reuse_assembly else None
        if retained and (retained/'comparison-result.json').is_file():
            arguments+=['--reuse-comparison',retained]
        if any(row['id']=='storage-set' for row in local.get('dependencies',[])):
            arguments+=['--dependency-package','storage-set='+str(workflow/'set-draft')]
        run(arguments);checks[identity]=out/identity
    policy=dict(format=EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT,target_id='jq',configuration_id='authored-array-path-network',
        scope='component-network',required_components=sorted(units),
        accepted_assumptions={name:unit['assumptions'] for name,unit in units.items()},
        allowed_formal_statuses=['not-requested','unavailable','timeout','proved'],allow_original_runtime_dependencies=True,
        accepted_input_domains={name:unit.get('input_domain') for name,unit in units.items()},
        accepted_representations={name:representation_policy(unit.get('representation')) for name,unit in units.items()},
        accepted_service_catalogs={name:unit['service_catalog']['catalog_sha256'] if unit.get('service_catalog') else None for name,unit in units.items()},
        accepted_resource_checks={name:canonical_sha256_v3(unit['resource_checks']) if unit.get('resource_checks') else None for name,unit in units.items()})
    (out/'policy.json').write_text(json.dumps(policy,indent=2)+'\n')
    command=['candidate','build','jq','--experimental-comparison',graph,'--experimental-policy',out/'policy.json','--output',out/'experimental']
    for name,check in sorted(checks.items()):
        if name!='path-set':command+=['--component-comparison',name+'='+str(check)]
    run(command)
    run(['candidate','test','jq','--experimental-package',out/'experimental','--output',out/'run'])
    (out/'audit.json').write_text(json.dumps(dict(status='pass',authority='experimental-execution-only',
        checks={name:str(path) for name,path in checks.items()},configuration='experimental',execution='run',
        whole_program_complete=False),indent=2)+'\n')
    print(json.dumps(dict(status='pass',components=len(checks),whole_program_complete=False)))

if __name__=='__main__':main()
