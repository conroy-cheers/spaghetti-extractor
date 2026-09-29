"""Public local/stateful edits, nested consumer comparison, replay, reuse and assembly.

Run inside one headless Wayland desktop. Preparation recipes supply the declared
native, quoting and conversion packages; neighbor checks use existing ID=PATH.
"""
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
from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.util import sha256_file, write_json

HERE = Path(__file__).resolve().parent


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('local_package','engine_package','native_package','controlled_engine_package','output'):
        parser.add_argument(name,type=Path)
    parser.add_argument('--component-comparison',action='append',default=[],metavar='ID=PATH')
    args=parser.parse_args()
    if not os.environ.get('WAYLAND_DISPLAY'): raise ValueError('run inside spaghetti-headless-wayland')
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    local,engine,native,controlled=[getattr(args,name).resolve() for name in
        ('local_package','engine_package','native_package','controlled_engine_package')]
    plan,_=load_comparison_package(native)
    if len(plan['cases'])!=63: raise ValueError('requires all three reviewed native quoting contexts')
    controlled_plan,_=load_comparison_package(controlled)
    if controlled_plan.get('dependencies'): raise ValueError('the unchanged engine check must retain its original runtime services')
    neighbors={}
    for supplied in args.component_comparison:
        name,separator,path=supplied.partition('=')
        if not separator or name in neighbors: raise ValueError('unique neighbor comparisons use ID=PATH')
        neighbors[name]=Path(path).resolve()
    if set(neighbors)!={d['id'] for d in plan['dependencies']}-{'quote-buffer','multibyte-conversion'}:
        raise ValueError('supply every selected local neighbor check other than engine and conversion')
    commands,results=[],{};started=time.monotonic()

    def public(arguments,expected=0):
        command=[sys.executable,'-m','spaghetti_extractor',*map(str,arguments)]
        before=time.monotonic();ran=subprocess.run(command,capture_output=True,text=True,timeout=240)
        number=len(commands)
        (out/f'{number:02d}.stdout').write_text(ran.stdout);(out/f'{number:02d}.stderr').write_text(ran.stderr)
        commands.append(dict(command=command,exit_code=ran.returncode,seconds=time.monotonic()-before))
        write_json(out/'commands.json',commands)
        print(json.dumps(dict(command=number,exit_code=ran.returncode,seconds=commands[-1]['seconds'])),flush=True)
        if ran.returncode!=expected: raise RuntimeError(f'command {number}: expected {expected}, got {ran.returncode}; inspect {out}')

    def check(identity,package,label,*,previous=None,replacement=None,case=None,expected=0):
        command=['component','check','gnu-hello',identity,'--comparison-package',package,'--output',out/label]
        if previous:command+=['--reuse-comparison',previous]
        if replacement:command+=['--dependency-package','multibyte-conversion='+str(replacement)]
        if case:command+=['--case',case]
        public(command,expected);result=load_comparison_result(out/label);results[label]=result;return result

    draft=out/'conversion-draft'
    public(['component','start','gnu-hello','multibyte-conversion','--comparison-package',local,'--output',draft])
    check('multibyte-conversion',draft,'local-baseline')
    check('quote-buffer',engine,'engine-baseline',replacement=draft)
    check('quote-slots',native,'native-baseline',replacement=draft)
    check('quote-buffer',controlled,'controlled-baseline')
    for name,previous in sorted(neighbors.items()):check(name,previous/'inputs',name+'-baseline',previous=previous)
    source=draft/'source/multibyte.c';original=source.read_text()
    assert original.count('if (pending>3)')==1
    edited=original.replace('if (pending>3)','if (3<pending)');source.write_text(edited)
    for identity,package,prefix in [('multibyte-conversion',draft,'local'),('quote-buffer',engine,'engine'),('quote-slots',native,'native')]:
        changed=check(identity,package,prefix+'-compatible',previous=out/(prefix+'-baseline'),
                      replacement=None if prefix=='local' else draft)
        assert changed['work_counts']['compiler']==1
    reused=check('quote-buffer',controlled,'controlled-reused',previous=out/'controlled-baseline')
    assert not any(reused['work_counts'].values())

    store='success:\n    if (output) *output->value=character;'
    assert edited.count(store)==1
    source.write_text(edited.replace(store,'success:\n    if (output) *output->value=0;'))
    scenarios=[('multibyte-conversion',draft,'local','context-2-operation-0-chunk-1'),
               ('quote-buffer',engine,'engine','style-5-flags-7-locale-3'),
               ('quote-slots',native,'native','style-5-kind-1-context-2')]
    try:
        for identity,package,prefix,case in scenarios:
            wrong=check(identity,package,prefix+'-wrong',previous=out/(prefix+'-compatible'),
                replacement=None if prefix=='local' else draft,case=case,expected=2)
            assert wrong['cases'][0]['status']=='mismatch'
    finally:source.write_text(edited)
    for identity,package,prefix,case in scenarios:
        replay=check(identity,out/(prefix+'-wrong/inputs'),prefix+'-wrong-replay',case=case,expected=2)
        assert replay['cases'][0]['first_difference']==results[prefix+'-wrong']['cases'][0]['first_difference']
        repaired=check(identity,package,prefix+'-repaired',previous=out/(prefix+'-compatible'),
            replacement=None if prefix=='local' else draft)
        assert not any(repaired['work_counts'].values())

    # The decoded character is still correct; leaving saved prefix bytes behind
    # is a state-only error that output-only comparison would miss at this step.
    reset='for (uint32_t i=0; i<4; ++i) state->data[i]=0;'
    assert edited.count(reset)==1
    source.write_text(edited.replace(reset,'state->data[0]=0;'))
    state_case='context-2-operation-0-chunk-1'
    try:
        wrong=check('multibyte-conversion',draft,'state-wrong',previous=out/'local-compatible',case=state_case,expected=2)
    finally:source.write_text(edited)
    observed=wrong['cases'][0]['observations']
    assert any(a[2]==b[2] and a[5]!=b[5]
        for left,right in zip(observed['original']['sequences'],observed['source']['sequences'])
        for a,b in zip(left['steps'],right['steps']))
    check('multibyte-conversion',out/'state-wrong/inputs','state-wrong-replay',case=state_case,expected=2)
    repaired=check('multibyte-conversion',draft,'state-repaired',previous=out/'local-compatible')
    assert not any(repaired['work_counts'].values())

    plan,_=load_comparison_package(out/'native-repaired/inputs')
    units={plan['component_id']:plan,**{row['id']:row for row in plan['dependencies']}}
    policy=dict(format=EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT,target_id='gnu-hello',
        configuration_id='native-stateful-conversion',scope='component-network',required_components=sorted(units),
        accepted_assumptions={name:unit['assumptions'] for name,unit in units.items()},
        allowed_formal_statuses=['not-requested','unavailable','timeout','proved'],allow_original_runtime_dependencies=True,
        accepted_input_domains={name:unit.get('input_domain') for name,unit in units.items()},
        accepted_representations={name:representation_policy(unit.get('representation')) for name,unit in units.items()},
        accepted_service_catalogs={name:unit['service_catalog']['catalog_sha256'] if unit.get('service_catalog') else None for name,unit in units.items()},
        accepted_resource_checks={name:canonical_sha256_v3(unit['resource_checks']) if unit.get('resource_checks') else None for name,unit in units.items()})
    write_json(out/'policy.json',policy)
    checks={'quote-buffer':out/'engine-repaired','multibyte-conversion':out/'state-repaired',
            **{name:out/(name+'-baseline') for name in neighbors}}
    command=['candidate','build','gnu-hello','--experimental-comparison',out/'native-repaired',
             '--experimental-policy',out/'policy.json','--output',out/'experimental']
    for name,path in sorted(checks.items()):command+=['--component-comparison',name+'='+str(path)]
    public(command)
    public(['candidate','test','gnu-hello','--experimental-package',out/'experimental','--output',out/'run'])
    assert all(r['formal_check']['status']=='not-requested' for r in results.values())
    write_json(out/'audit.json',dict(status='pass',authority='experimental-execution-only',seconds=time.monotonic()-started,
        commands=len(commands),comparisons=len(results),native_cases=63,engine_cases=220,local_cases=27,
        controlled_utf8=True,original_startup=False,whole_program_complete=False,strong_qualification=False,
        results={name:dict(status=r['status'],receipt_sha256=r['receipt_sha256'],work_counts=r['work_counts'],timings=r['timings'])
                 for name,r in results.items()},
        producers={p.name:sha256_file(p) for p in sorted(HERE.iterdir()) if p.is_file()}))
    print(json.dumps(dict(status='pass',commands=len(commands),comparisons=len(results),strong_authority=False)))


if __name__=='__main__':main()
