"""Edit one compared component, update both programs, and diagnose a backend defect."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from build import build
from run import run
from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.util import sha256_file, write_json


def walkthrough(component,neighbor,network,host_project,arm_project,host_baseline,arm_baseline,original,output,runner,server,qemu,pe_cc):
    if not os.environ.get('WAYLAND_DISPLAY'):raise ValueError('requires spaghetti-headless-wayland')
    output.mkdir(parents=True,exist_ok=False);started=time.monotonic();commands=[]
    def cli(arguments):
        command=[sys.executable,'-m','spaghetti_extractor',*map(str,arguments)];before=time.monotonic()
        ran=subprocess.run(command,capture_output=True,text=True,timeout=600);index=len(commands)
        (output/f'{index:02d}.stdout').write_text(ran.stdout);(output/f'{index:02d}.stderr').write_text(ran.stderr)
        commands.append(dict(command=command,exit_code=ran.returncode,seconds=time.monotonic()-before))
        write_json(output/'commands.json',commands)
        if ran.returncode:raise ValueError('public command failed; see '+str(output/f'{index:02d}.stderr'))
        print(index,'public command passed',flush=True)
    draft=output/'component'
    cli(['component','start','jq','string-slice','--comparison-package',component/'inputs','--output',draft])
    # A new shell/desktop may invalidate old environment-bound receipts. Record
    # that preparation separately before measuring a warm local editing cycle.
    cli(['component','check','jq','string-slice','--comparison-package',draft,
         '--reuse-comparison',component,'--output',output/'local-baseline'])
    cli(['component','check','jq','storage-get','--comparison-package',neighbor/'inputs',
         '--reuse-comparison',neighbor,'--output',output/'neighbor-baseline'])
    cli(['component','check','jq','path-set','--comparison-package',network/'inputs',
         '--reuse-comparison',network,'--output',output/'network-baseline'])
    source=draft/'source/slice.c';before=source.read_text()
    old='codepoint = codepoint * 64U + byte - 0x80U;'
    new='codepoint = (codepoint << 6) | (byte & 63U);'
    if before.count(old)!=1:raise ValueError('requires the retained compatible decoder baseline')
    source.write_text(before.replace(old,new))
    cli(['component','check','jq','string-slice','--comparison-package',draft,
         '--reuse-comparison',output/'local-baseline','--output',output/'local-edit'])
    local=load_comparison_result(output/'local-edit')
    assert local['status']=='match' and local['work_counts']['compiler']==1
    cli(['component','check','jq','storage-get','--comparison-package',neighbor/'inputs',
         '--reuse-comparison',output/'neighbor-baseline','--output',output/'neighbor-reused'])
    reused=load_comparison_result(output/'neighbor-reused');assert not any(reused['work_counts'].values())
    cli(['component','check','jq','path-set','--comparison-package',network/'inputs',
         '--dependency-package','string-slice='+str(draft),'--reuse-comparison',output/'network-baseline','--output',output/'network-edit'])
    integrated=load_comparison_result(output/'network-edit')
    assert integrated['status']=='match' and integrated['work_counts']['compiler']==1
    for label,project,baseline in [('host',host_project,host_baseline),('arm',arm_project,arm_baseline)]:
        previous=json.loads((baseline/'build.json').read_text())
        retained={p.relative_to(project).as_posix():sha256_file(p) for p in (project/'bindings').glob('*') if p.is_file()}
        cli(['candidate','export','jq','--comparison',output/'network-edit','--output',project/'lifted','--update'])
        assert retained=={p.relative_to(project).as_posix():sha256_file(p) for p in (project/'bindings').glob('*') if p.is_file()}
        tools=previous['tools'];cc,ar,ranlib=[Path(tools[n]['path']) for n in ('cc','ar','ranlib')]
        built=build(project,output/(label+'-edited-build'),cc,ar,ranlib,'aarch64-linux-gnu' if label=='arm' else None)
        assert built['component_rebuilt_objects']==['lifted/build/string-slice-0.o']
        assert not built['backend_rebuilt_objects']
        assert built['rebuilt_objects']==built['component_rebuilt_objects']
        assert run(output/(label+'-edited-build'),original,output/(label+'-edited-run'),runner,server,qemu,pe_cc=pe_cc)=='match'
    backend=host_project/'bindings/import-runtime.c';correct=backend.read_text()
    assert correct.count('_Exit(3);')==1
    host_tools=json.loads((host_baseline/'build.json').read_text())['tools']
    cc,ar,ranlib=[Path(host_tools[n]['path']) for n in ('cc','ar','ranlib')]
    try:
        backend.write_text(correct.replace('_Exit(3);','_Exit(0);'))
        wrong=build(host_project,output/'wrong-build',cc,ar,ranlib)
        assert wrong['rebuilt_objects']==['build/import-runtime.o']
        assert run(output/'wrong-build',original,output/'wrong-run',runner,server,qemu,'runtime-error',pe_cc)=='mismatch'
        difference=json.loads((output/'wrong-run/results.json').read_text())[0]['differences']
        assert difference==['exit_code']
    finally:backend.write_text(correct)
    assert run(output/'wrong-build',original,output/'replay',runner,server,qemu,'runtime-error',pe_cc)=='mismatch'
    assert json.loads((output/'replay/results.json').read_text())[0]['differences']==difference
    repaired=build(host_project,output/'repaired-build',cc,ar,ranlib)
    assert repaired['rebuilt_objects']==['build/import-runtime.o']
    assert run(output/'repaired-build',original,output/'repaired-run',runner,server,qemu,pe_cc=pe_cc)=='match'
    write_json(output/'walkthrough.json',dict(status='pass',seconds=time.monotonic()-started,
        environment_preparation={name:load_comparison_result(output/(name+'-baseline'))['work_counts'] for name in ('local','neighbor','network')},
        local_edit=dict(work_counts=local['work_counts'],timings=local['timings']),
        network_edit=dict(work_counts=integrated['work_counts'],timings=integrated['timings']),
        neighbor_reused=dict(work_counts=reused['work_counts'],timings=reused['timings']),
        source_programs_updated=['x86_64','aarch64'],backend_rebuilds_for_local_edit=0,
        defect='target assertion reports correctly but exits successfully',replayed_after_source_repair=True,
        commands_sha256=sha256_file(output/'commands.json'),producer_sha256=sha256_file(Path(__file__)),
        new_checker_rules=False,strong_qualification=False,whole_jq_lift=False))
    print('PASS: local edit, neighbor reuse, source updates, both programs, backend defect, replay and repair',flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    names=('component','neighbor','network','host_project','arm_project','host_baseline','arm_baseline','original','output','runner','server','qemu','pe_cc')
    for name in names:p.add_argument('--'+name.replace('_','-'),type=Path,required=True)
    a=p.parse_args();walkthrough(*[getattr(a,n).resolve() for n in names])
