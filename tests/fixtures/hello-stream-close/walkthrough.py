"""New stream boundary: local edit, lifetime/error defects, reuse and real program delivery."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.util import sha256_file, write_json

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'hello-standalone'))
from build import build
from run import run


def workflow(connected, string, package, neighbor, oracle, upstream_tar, output):
    if not os.environ.get('WAYLAND_DISPLAY'):raise ValueError('run inside spaghetti-headless-wayland')
    output.mkdir(parents=True,exist_ok=False);started=time.monotonic();commands=[];results={}
    project=output/'project';library=project/'lifted';draft=output/'component'
    def command(args, expected=0):
        call=list(map(str,args));before=time.monotonic()
        ran=subprocess.run(call,capture_output=True,text=True,timeout=300);index=len(commands)
        (output/f'{index:02d}.stdout').write_text(ran.stdout);(output/f'{index:02d}.stderr').write_text(ran.stderr)
        commands.append(dict(command=call,exit_code=ran.returncode,seconds=time.monotonic()-before))
        write_json(output/'commands.json',commands);print(index,ran.returncode,flush=True)
        if ran.returncode!=expected:raise ValueError(f'command {index} failed; inspect retained logs')
    def cli(args,expected=0):command([sys.executable,'-m','spaghetti_extractor',*args],expected)
    def check(identity, inputs, label, previous=None, case=None, expected=0):
        args=['component','check','gnu-hello',identity,'--comparison-package',inputs,'--output',output/label]
        if previous:args+=['--reuse-comparison',previous]
        if case:args+=['--case',case]
        cli(args,expected);results[label]=load_comparison_result(output/label);return results[label]
    def export(comparison,expected=0):
        cli(['candidate','export','gnu-hello','--comparison',connected,'--comparison',string,
             '--comparison',comparison,'--output',library,'--update'],expected)
    cli(['component','start','gnu-hello','stream-close','--comparison-package',package,'--output',draft])
    check('stream-close',draft,'baseline')
    neighbor_id=load_comparison_result(neighbor)['component_id']
    check(neighbor_id,neighbor/'inputs','neighbor-baseline',neighbor)
    command([sys.executable,HERE.parent/'hello-standalone/prepare.py','--comparison',connected,
        '--comparison',string,'--comparison',output/'baseline','--upstream-tar',upstream_tar,'--output',project])
    note=library/'operator-notes.txt';note.write_text('Retain this stream-boundary integration note.\n')
    outside={p.relative_to(project).as_posix():sha256_file(p) for p in project.rglob('*')
        if p.is_file() and p.relative_to(project).parts[0]!='lifted'}
    build(project,output/'baseline-build',entry='utf8')
    assert run(output/'baseline-build',oracle,output/'baseline-program')=='match'
    source=draft/'source/close.c';original=source.read_text()
    old='''    if (failed) {
        if (!closed) services->clear_errno(services->context);
        return -1;
    }
    if (closed && (pending || !services->bad_descriptor(services->context))) return -1;
    return 0;'''
    new='''    if (!failed && !closed) return 0;
    if (failed && !closed) services->clear_errno(services->context);
    if (!failed && !pending && services->bad_descriptor(services->context)) return 0;
    return -1;'''
    assert original.count(old)==1;compatible=original.replace(old,new);source.write_text(compatible)
    checked=check('stream-close',draft,'compatible',output/'baseline')
    assert checked['work_counts']['compiler']==1
    reused=check(neighbor_id,neighbor/'inputs','neighbor-reused',output/'neighbor-baseline')
    assert not any(reused['work_counts'].values())
    export(output/'compatible')
    build(project,output/'compatible-build',entry='utf8')
    assert run(output/'compatible-build',oracle,output/'compatible-program')=='match'
    try:
        source.write_text(compatible.replace('if (failed && !closed) services->clear_errno(services->context);',
            'if (failed) services->clear_errno(services->context);'))
        wrong=check('stream-close',draft,'wrong-errno',output/'compatible','real-prior-error',2)
        assert wrong['status']=='mismatch' and wrong['cases'][0]['first_difference']['path'].endswith('.errno')
        preserved={p.relative_to(library).as_posix():sha256_file(p) for p in library.rglob('*') if p.is_file()}
        export(output/'wrong-errno',2)
        assert preserved=={p.relative_to(library).as_posix():sha256_file(p) for p in library.rglob('*') if p.is_file()}
        source.write_text(compatible.replace('int32_t closed = services->close(services->context, stream);',
            'int32_t closed = services->close(services->context, stream);\n    (void)services->pending(services->context, stream);'))
        wrong=check('stream-close',draft,'wrong-lifetime',output/'compatible','real-write',2)
        assert wrong['status']!='match'
        assert 'borrow after consumption' in (output/'wrong-lifetime/cases/0000-source.stderr').read_text()
    finally:source.write_text(compatible)
    replay=check('stream-close',output/'wrong-errno/inputs','replay',case='real-prior-error',expected=2)
    assert replay['cases'][0]['first_difference']==results['wrong-errno']['cases'][0]['first_difference']
    repaired=check('stream-close',draft,'repaired',output/'compatible')
    assert not any(repaired['work_counts'].values());export(output/'repaired')
    adapter=project/'application/stream.c';good=adapter.read_text()
    needle='return lifted_stream_close(&context,&stream);';assert good.count(needle)==1
    try:
        adapter.write_text(good.replace(needle,'(void)lifted_stream_close(&context,&stream); return 0;'))
        build(project,output/'wrong-program-build',entry='utf8')
        assert run(output/'wrong-program-build',oracle,output/'wrong-program','stdout-full')=='mismatch'
    finally:adapter.write_text(good)
    assert run(output/'wrong-program-build',oracle,output/'program-replay','stdout-full')=='mismatch'
    build(project,output/'repaired-build',entry='utf8')
    assert run(output/'repaired-build',oracle,output/'repaired-program','stdout-full')=='match'
    assert sha256_file(output/'compatible-build/hello')==sha256_file(output/'repaired-build/hello')
    assert note.read_text()=='Retain this stream-boundary integration note.\n'
    for name,digest in outside.items():assert sha256_file(project/name)==digest
    write_json(output/'workflow.json',dict(status='pass',seconds=time.monotonic()-started,
        local_cases=7,controlled_sequences=216,program_cases=82,unchanged_neighbor_zero_work=True,
        errno_defect_detected=True,lifetime_defect_detected=True,program_defect_detected=True,
        replay_after_repair=True,operator_files_preserved=outside,
        commands_sha256=sha256_file(output/'commands.json'),
        source_export_sha256=sha256_file(library/'source-export.json'),
        results={name:dict(status=row['status'],receipt_sha256=row['receipt_sha256'],
            work_counts=row['work_counts'],timings=row['timings']) for name,row in results.items()},
        new_tool_internals=False,model_seconds=0,solver_seconds=0,pilot_rebuilds=0,strong_qualification=False,
        producer_sha256=sha256_file(Path(__file__))))
    print('PASS: new stream boundary, local error/lifetime checks, reuse, public update and real program replay/repair')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    names=('connected','string','package','neighbor','oracle','upstream_tar','output')
    for name in names:p.add_argument(name,type=Path)
    a=p.parse_args();workflow(*[getattr(a,name).resolve() for name in names])
