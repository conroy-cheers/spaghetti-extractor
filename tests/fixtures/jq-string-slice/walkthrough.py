"""Public edit/replay/reuse and experimental integration of the new jq boundary."""
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
from spaghetti_extractor.util import write_json, sha256_file


def workflow(package,arrays,paths,output):
    if not os.environ.get('WAYLAND_DISPLAY'):raise ValueError('requires spaghetti-headless-wayland')
    output.mkdir(parents=True,exist_ok=False);started=time.monotonic();commands=[];results={}
    draft=output/'component';network=paths/'path-set-network'
    def cli(args,expected=0):
        call=[sys.executable,'-m','spaghetti_extractor',*map(str,args)];before=time.monotonic()
        ran=subprocess.run(call,capture_output=True,text=True,timeout=600);number=len(commands)
        (output/f'{number:02d}.stdout').write_text(ran.stdout);(output/f'{number:02d}.stderr').write_text(ran.stderr)
        commands.append(dict(command=call,exit_code=ran.returncode,seconds=time.monotonic()-before))
        write_json(output/'commands.json',commands);print(number,ran.returncode,flush=True)
        if ran.returncode!=expected:raise ValueError(f'command {number} failed; see {output}')
    def check(identity,inputs,label,previous=None,case=None,dependency=None,expected=0):
        args=['component','check','jq',identity,'--comparison-package',inputs,'--output',output/label]
        if previous:args+=['--reuse-comparison',previous]
        if case:args+=['--case',case]
        if dependency:args+=['--dependency-package','string-slice='+str(dependency)]
        cli(args,expected);row=load_comparison_result(output/label);results[label]=row;return row
    cli(['component','start','jq','string-slice','--comparison-package',package,'--output',draft])
    check('string-slice',draft,'baseline')
    check('storage-get',arrays/'storage-get','neighbor-baseline')
    check('path-set',network,'network-baseline')
    source=draft/'source/slice.c';original=source.read_text()
    old='''        if ((byte & 0xc0U) != 0x80U) return 0;
        codepoint = (codepoint << 6) | (byte & 63U);'''
    new='''        if (byte < 0x80U || byte >= 0xc0U) return 0;
        codepoint = codepoint * 64U + byte - 0x80U;'''
    assert original.count(old)==1;compatible=original.replace(old,new);source.write_text(compatible)
    edited=check('string-slice',draft,'compatible',output/'baseline')
    assert edited['work_counts']['compiler']==1
    neighbor=check('storage-get',arrays/'storage-get','neighbor-reused',output/'neighbor-baseline')
    assert not any(neighbor['work_counts'].values())
    integrated=check('path-set',network,'network-compatible',output/'network-baseline',dependency=draft)
    assert integrated['work_counts']['compiler']==1
    try:
        source.write_text(compatible.replace('if (first < 0x80U)', 'if (first <= 0xffU)'))
        wrong=check('string-slice',draft,'wrong-unicode',output/'compatible','retained',expected=2)
        assert wrong['status']=='mismatch'
        wrong_network=check('path-set',network,'network-wrong',output/'network-compatible',
            'program-string-slices',draft,2)
        assert wrong_network['status']=='mismatch'
    finally:source.write_text(compatible)
    replay=check('string-slice',output/'wrong-unicode/inputs','unicode-replay',case='retained',expected=2)
    assert replay['cases'][0]['first_difference']==wrong['cases'][0]['first_difference']
    replay=check('path-set',output/'network-wrong/inputs','network-replay',case='program-string-slices',expected=2)
    assert replay['cases'][0]['first_difference']==wrong_network['cases'][0]['first_difference']
    try:
        before='''            services->release(context, value);
            return services->empty(context);'''
        after='''            spx_jv_value_v2 empty = services->empty(context);
            services->release(context, value);
            return empty;'''
        assert compatible.count(before)==1;source.write_text(compatible.replace(before,after))
        check('string-slice',draft,'order-normal',output/'compatible','retained')
        order=check('string-slice',draft,'wrong-order',output/'order-normal','nomem-empty',expected=2)
        assert order['status']=='mismatch'
        observed=[json.loads((output/'wrong-order/cases'/('0000-'+side+'.stdout')).read_text())
                  for side in ('original','source')]
        assert [row['sequences'][0]['references'] for row in observed]==[1,2]
        assert [row['allocation_lifetime']['live_bytes'] for row in observed]==[8,27]
    finally:source.write_text(compatible)
    replay=check('string-slice',output/'wrong-order/inputs','order-replay',case='nomem-empty',expected=2)
    assert replay['cases'][0]['first_difference']==order['cases'][0]['first_difference']
    repaired=check('string-slice',draft,'repaired',output/'compatible')
    assert not any(repaired['work_counts'].values())
    repaired_network=check('path-set',network,'network-repaired',output/'network-compatible',dependency=draft)
    assert not any(repaired_network['work_counts'].values())
    plan,_=load_comparison_package(output/'network-repaired/inputs')
    units={plan['component_id']:plan,**{row['id']:row for row in plan['dependencies']}}
    checks={'path-set':output/'network-repaired','string-slice':output/'repaired','storage-get':output/'neighbor-reused'}
    for identity in sorted(set(units)-set(checks)):
        inputs=arrays/identity if identity.startswith('storage-') else paths/('path-get-network' if identity=='path-get' else identity)
        local,_=load_comparison_package(inputs)
        dependency=draft if any(row['id']=='string-slice' for row in local.get('dependencies',[])) else None
        check(identity,inputs,'assembly-'+identity,dependency=dependency);checks[identity]=output/('assembly-'+identity)
    policy=dict(format=EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT,target_id='jq',configuration_id='jq-string-storage-paths',
        scope='component-network',required_components=sorted(units),
        accepted_assumptions={name:unit['assumptions'] for name,unit in units.items()},
        allowed_formal_statuses=['not-requested','unavailable','timeout','proved'],allow_original_runtime_dependencies=True,
        accepted_input_domains={name:unit.get('input_domain') for name,unit in units.items()},
        accepted_representations={name:representation_policy(unit.get('representation')) for name,unit in units.items()},
        accepted_service_catalogs={name:unit['service_catalog']['catalog_sha256'] if unit.get('service_catalog') else None for name,unit in units.items()},
        accepted_resource_checks={name:canonical_sha256_v3(unit['resource_checks']) if unit.get('resource_checks') else None for name,unit in units.items()})
    write_json(output/'policy.json',policy)
    args=['candidate','build','jq','--experimental-comparison',output/'network-repaired',
          '--experimental-policy',output/'policy.json','--output',output/'experimental']
    for identity,path in sorted(checks.items()):
        if identity!='path-set':args+=['--component-comparison',identity+'='+str(path)]
    cli(args);cli(['candidate','test','jq','--experimental-package',output/'experimental','--output',output/'run'])
    write_json(output/'workflow.json',dict(status='pass',seconds=time.monotonic()-started,
        components=sorted(units),checks={name:str(path) for name,path in checks.items()},
        results={label:dict(status=r['status'],receipt_sha256=r['receipt_sha256'],work_counts=r['work_counts'],timings=r['timings']) for label,r in results.items()},
        commands_sha256=sha256_file(output/'commands.json'),producer_sha256=sha256_file(Path(__file__)),
        neighbor_zero_work=True,repair_zero_work=True,defects_replayed_after_repair=True,
        new_proof_rules=False,tooling_gap='mixed numeric/resource lifecycle validation',whole_program_complete=False,strong_qualification=False))
    print('PASS: new jq string boundary, edits, Unicode/failure defects, neighbor reuse and real consumer assembly',flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','arrays','paths','output'):p.add_argument(name,type=Path)
    a=p.parse_args();workflow(*[getattr(a,name).resolve() for name in ('package','arrays','paths','output')])
