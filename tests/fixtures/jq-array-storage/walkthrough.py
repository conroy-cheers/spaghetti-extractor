"""Public edit/reuse/discrepancy workflow. Run inside spaghetti-headless-wayland."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('packages',type=Path);parser.add_argument('output',type=Path)
    parser.add_argument('--path-package',type=Path,help='use the real path-set network as the integration consumer')
    parser.add_argument('--lifetime-negatives',action='store_true',help='exercise missing disposal and incomplete backing-element release with allocation observations')
    parser.add_argument('--reuse-workflow',type=Path,help='ask public checks to reuse matching retained results from an earlier walkthrough')
    parser.add_argument('--local-contracts',action='store_true',help='also request optional formal checks; requires the corresponding checker tools')
    parser.add_argument('--nonlocal-negatives',action='store_true',help='exercise publication before a failing allocation, retained replay and repair')
    args=parser.parse_args();packages=args.packages.resolve();out=args.output.resolve()
    if args.nonlocal_negatives and args.path_package:
        parser.error('nonlocal negatives currently require the array-storage consumer with allocation-failure cases')
    consumer=args.path_package.resolve() if args.path_package else packages/'storage-slice'
    if not os.environ.get('WAYLAND_DISPLAY'):raise RuntimeError('requires a headless Wayland desktop')
    out.mkdir(parents=True,exist_ok=False)
    commands=[]
    def run(arguments, expected=0):
        command=[sys.executable,'-m','spaghetti_extractor',*map(str,arguments)]
        started=time.monotonic()
        result=subprocess.run(command,capture_output=True,text=True)
        index=len(commands)
        (out/f'{index:02d}.stdout').write_text(result.stdout)
        (out/f'{index:02d}.stderr').write_text(result.stderr)
        commands.append(dict(command=command,exit_code=result.returncode,seconds=time.monotonic()-started))
        (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        if result.returncode!=expected:raise RuntimeError(f'command {index}: expected {expected}, got {result.returncode}; inspect {out}')
    def check(unit, package, label, *, previous=None, supplier=None, dependencies=None, case=None, expected=0):
        identity='path-set' if unit=='slice' and args.path_package else 'storage-'+unit
        arguments=['component','check','jq',identity,'--comparison-package',package,'--output',out/label]
        if args.local_contracts:arguments+=['--local-contracts']
        retained=args.reuse_workflow.resolve()/label if args.reuse_workflow else None
        if previous:arguments+=['--reuse-comparison',out/previous]
        elif retained and (retained/'comparison-result.json').is_file():arguments+=['--reuse-comparison',retained]
        if supplier:arguments+=['--dependency-package','storage-set='+str(supplier)]
        for name,path in (dependencies or {}).items():arguments+=['--dependency-package',name+'='+str(path)]
        if case:arguments+=['--case',case]
        run(arguments,expected)
        result_path=out/label/'comparison-result.json'
        if not result_path.is_file():raise RuntimeError(f'{label}: command did not produce comparison evidence; inspect its recorded diagnostic')
        return json.loads(result_path.read_text())
    for unit in ['set','get']:
        run(['component','start','jq','storage-'+unit,'--comparison-package',packages/('storage-'+unit),'--output',out/(unit+'-draft')])
    get_base=check('get',out/'get-draft','get-baseline')
    baseline=check('slice',consumer,'baseline',supplier=out/'set-draft')
    source=out/'set-draft/source/set.c';original=source.read_text()
    before='if (array->length <= position)';after='if (position >= array->length)'
    assert original.count(before)==1
    compatible=original.replace(before,after);source.write_text(compatible)
    supplier=check('set',out/'set-draft','set-compatible')
    edited=check('slice',consumer,'compatible',previous='baseline',supplier=out/'set-draft')
    get_reused=check('get',out/'get-draft','get-reused',previous='get-baseline')
    assert compatible.count('array->refcnt.count == 1')==1
    source.write_text(compatible.replace('array->refcnt.count == 1','array->refcnt.count >= 1'))
    wrong=check('slice',consumer,'wrong-cow',previous='compatible',supplier=out/'set-draft',expected=2)
    source.write_text(compatible)
    failed_case=next(row['id'] for row in wrong['cases'] if row['status']=='mismatch')
    replay=check('slice',out/'wrong-cow/inputs','retained-replay',case=failed_case,expected=2)
    repaired=check('slice',consumer,'repaired',previous='compatible',supplier=out/'set-draft')
    results={name:data for name,data in [('get-baseline',get_base),('baseline',baseline),('set-compatible',supplier),
        ('compatible',edited),('get-reused',get_reused),('wrong-cow',wrong),('retained-replay',replay),('repaired',repaired)]}
    negatives={'wrong-cow','retained-replay'}
    if args.lifetime_negatives:
        draft=out/'release-draft'
        run(['component','start','jq','storage-release','--comparison-package',packages/'storage-release','--output',draft])
        results['release-baseline']=check('release',draft,'release-baseline')
        source=draft/'source/release.c';original=source.read_text()
        dispose='services->dispose(environment, (struct spx_opaque_jq_memory_v5 *)array);'
        assert original.count(dispose)==1
        source.write_text(original.replace(dispose,'(void)array; /* deliberate missing disposal */'))
        try:
            results['wrong-release']=check('slice',consumer,'wrong-release',previous='compatible',supplier=out/'set-draft',
                dependencies={'storage-release':draft},expected=2)
        finally:source.write_text(original)
        missed=next(row for row in results['wrong-release']['cases'] if row['status']=='mismatch' and
            {k:v for k,v in row['observations']['original'].items() if k!='allocation_lifetime'}==
            {k:v for k,v in row['observations']['source'].items() if k!='allocation_lifetime'})
        assert missed['observations']['source']['allocation_lifetime']['live_blocks']>missed['observations']['original']['allocation_lifetime']['live_blocks']
        results['release-replay']=check('slice',out/'wrong-release/inputs','release-replay',case=missed['id'],expected=2)
        assert original.count('i < array->length')==1
        source.write_text(original.replace('i < array->length','i < value.size'))
        try:
            results['wrong-backing-length']=check('release',draft,'wrong-backing-length',case='sequence-10',expected=2)
        finally:source.write_text(original)
        hidden=results['wrong-backing-length']['cases'][0]
        assert hidden['status']=='mismatch' and hidden['first_difference']['path'].startswith('$.allocation_lifetime.')
        results['release-repaired']=check('release',draft,'release-repaired',previous='release-baseline')
        results['release-network-repaired']=check('slice',consumer,'release-network-repaired',previous='compatible',supplier=out/'set-draft',
            dependencies={'storage-release':draft})
        for name in ['release-repaired','release-network-repaired']:assert not any(results[name]['work_counts'].values())
        negatives.update(['wrong-release','release-replay','wrong-backing-length'])
    if args.nonlocal_negatives:
        draft=out/'create-draft'
        run(['component','start','jq','storage-create','--comparison-package',packages/'storage-create','--output',draft])
        results['create-baseline']=check('create',draft,'create-baseline')
        source=draft/'source/create.c';original=source.read_text()
        before='    jq_array *array = (jq_array *)services->allocate'
        assert original.count(before)==1
        source.write_text(original.replace(before,'    output->value = jq_null_value(); /* incorrect early publication */\n'+before))
        try:
            results['wrong-create-output']=check('create',draft,'wrong-create-output',previous='create-baseline',case='nomem-create',expected=2)
            results['wrong-output-network']=check('slice',consumer,'wrong-output-network',previous='compatible',supplier=out/'set-draft',
                dependencies={'storage-create':draft},case='nomem-create',expected=2)
        finally:source.write_text(original)
        for name in ['wrong-create-output','wrong-output-network']:
            row=results[name]['cases'][0]
            assert row['status']=='mismatch' and row['first_difference']['path']=='$.values[2]'
            assert row['observations']['original']['allocation_failure']==row['observations']['source']['allocation_failure']
            assert row['resources']['status']=='satisfied'
        results['create-replay']=check('create',out/'wrong-create-output/inputs','create-replay',case='nomem-create',expected=2)
        results['create-repaired']=check('create',draft,'create-repaired',previous='create-baseline')
        results['create-network-repaired']=check('slice',consumer,'create-network-repaired',previous='compatible',supplier=out/'set-draft',
            dependencies={'storage-create':draft})
        for name in ['create-repaired','create-network-repaired']:assert not any(results[name]['work_counts'].values())
        negatives.update(['wrong-create-output','wrong-output-network','create-replay'])
    assert all(data['status']=='match' for name,data in results.items() if name not in negatives)
    assert all(data['formal_check']['status'] in ('not-requested','unavailable') for data in results.values())
    for name in ['get-reused','repaired']:
        assert results[name]['reuse'],name
        assert not any(row['phase'] in ('compiler','link','execution') for row in results[name]['timings']),name
    summary=dict(status='pass',authorizing=False,scope='Native-layout array storage finite comparisons; no whole jq or strong qualification.',
        results={name:dict(status=data['status'],formal=data['formal_check']['status'],reuse=data['reuse'],
                          receipt_sha256=data['receipt_sha256'],timings=data['timings']) for name,data in results.items()})
    (out/'audit.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({'status':'pass','comparisons':len(results),'authorizing':False}))

if __name__=='__main__':main()
