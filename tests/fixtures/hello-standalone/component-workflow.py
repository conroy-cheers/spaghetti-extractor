"""Edit/check/re-export a real component while preserving standalone integration."""
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
from spaghetti_extractor.util import sha256_file,write_json


def workflow(project,package,neighbor,oracle,output,all_cases=False,edit_export=False):
    if not os.environ.get('WAYLAND_DISPLAY'):raise ValueError('run inside spaghetti-headless-wayland')
    output.mkdir(parents=True,exist_ok=False)
    commands=[];results={};started=time.monotonic()
    local_case=None if all_cases else 'context-0-transport-1'
    program_case=None if all_cases else 'default'
    outside={p.relative_to(project).as_posix():sha256_file(p) for p in project.rglob('*')
        if p.is_file() and p.relative_to(project).parts[0]!='lifted'}
    library=project/'lifted'
    (library/'operator-notes.txt').write_text('Retain this operator note through both updates.\n')
    note=sha256_file(library/'operator-notes.txt')
    old=json.loads((library/'source-export.json').read_text())

    def command(arguments,expected=0):
        before=time.monotonic()
        call=list(map(str,arguments));ran=subprocess.run(call,capture_output=True,text=True,timeout=300)
        index=len(commands)
        (output/f'{index:02d}.stdout').write_text(ran.stdout);(output/f'{index:02d}.stderr').write_text(ran.stderr)
        commands.append(dict(command=call,exit_code=ran.returncode,seconds=time.monotonic()-before))
        write_json(output/'commands.json',commands);print(index,ran.returncode,flush=True)
        if ran.returncode!=expected:raise ValueError(f'command {index} failed; inspect retained logs')

    def cli(arguments,expected=0):command([sys.executable,'-m','spaghetti_extractor',*arguments],expected)

    def check(identity,inputs,label,previous=None,case=None,expected=0):
        arguments=['component','check','gnu-hello',identity,'--comparison-package',inputs,'--output',output/label]
        if previous:arguments+=['--reuse-comparison',previous]
        if case:arguments+=['--case',case]
        cli(arguments,expected);results[label]=load_comparison_result(output/label)
        return results[label]

    def export(comparison,expected=0):
        cli(['candidate','export','gnu-hello','--comparison',comparison,
             '--output',library,'--update-components'],expected)

    def import_source(name):
        destination=output/name
        cli(['component','start','gnu-hello','string-conversion','--comparison-package',package,
             '--reuse-source',library,'--output',destination])
        return destination

    draft=output/'component'
    if edit_export:draft=import_source('component')
    else:cli(['component','start','gnu-hello','string-conversion','--comparison-package',package,'--output',draft])
    check('string-conversion',draft,'baseline',case=local_case)
    identity=load_comparison_result(neighbor)['component_id']
    neighbor_case=None if all_cases else json.loads((neighbor/'inputs/comparison-plan.json').read_text())['cases'][0]['id']
    check(identity,neighbor/'inputs','neighbor-baseline',neighbor,neighbor_case)
    build(project,output/'baseline-build',entry='utf8')
    assert run(output/'baseline-build',oracle,output/'baseline-program',program_case)=='match'
    source=library/'components/string-conversion/sources/source/string.c' if edit_export else draft/'source/string.c'
    original=source.read_text()
    before='uint32_t size = 1;\n        while (size < 5 && remaining.data[size-1]) ++size;'
    assert original.count(before)==1
    compatible=original.replace(before,'uint32_t size = 5;\n'
        '        for (uint32_t i = 0; i < 4; ++i) {\n'
        '            if (!remaining.data[i]) { size = i + 1; break; }\n'
        '        }')
    source.write_text(compatible)
    if edit_export:draft=import_source('edited-component')
    checked=check('string-conversion',draft,'compatible',output/'baseline',local_case)
    assert checked['work_counts']['compiler']==1
    reused=check(identity,neighbor/'inputs','neighbor-reused',output/'neighbor-baseline',neighbor_case)
    assert not any(reused['work_counts'].values())
    # Ordinary make creates real stale artifacts for the updater to invalidate.
    command(['make','-C',library,'-j2'])
    export(output/'compatible')
    updated=json.loads((library/'source-export.json').read_text())
    assert updated['update']['unchanged_components']==sorted(set(old['components'])-{'string-conversion'})
    assert 'liblifted.a' in updated['update']['invalidated_build_outputs']
    build(project,output/'compatible-build',entry='utf8')
    assert sha256_file(output/'baseline-build/hello')!=sha256_file(output/'compatible-build/hello')
    assert run(output/'compatible-build',oracle,output/'compatible-program',program_case)=='match'
    clear='if (output) *input->value = 0;';assert compatible.count(clear)==1
    source.write_text(compatible.replace(clear,'if (output) { *input->value = 0; if (count) output->value[0] = 88; }'))
    try:
        wrong_draft=import_source('wrong-component') if edit_export else draft
        check('string-conversion',wrong_draft,'wrong',output/'compatible','context-0-transport-1',2)
        retained={p.relative_to(library).as_posix():sha256_file(p) for p in library.rglob('*') if p.is_file()}
        export(output/'wrong',2)
        assert retained=={p.relative_to(library).as_posix():sha256_file(p) for p in library.rglob('*') if p.is_file()}
    finally:source.write_text(compatible)
    check('string-conversion',output/'wrong/inputs','replay',case='context-0-transport-1',expected=2)
    if edit_export:draft=import_source('repaired-component')
    repaired=check('string-conversion',draft,'repaired',output/'compatible',local_case)
    assert not any(repaired['work_counts'].values())
    export(output/'repaired')
    final=json.loads((library/'source-export.json').read_text())
    assert final['update']['unchanged_components']==sorted(old['components'])
    assert len(final['update']['retained_backups'])==len(old.get('update',{}).get('retained_backups',[]))+2
    for name,digest in outside.items():assert sha256_file(project/name)==digest
    assert sha256_file(library/'operator-notes.txt')==note
    assert (library/'components/string-conversion/sources/source/string.c').read_text()==compatible
    build(project,output/'repaired-build',entry='utf8')
    assert run(output/'repaired-build',oracle,output/'repaired-program','default')=='match'
    binaries={name:json.loads((output/(name+'-build')/'build.json').read_text()) for name in ('baseline','compatible','repaired')}
    assert binaries['compatible']['executable_sha256']==binaries['repaired']['executable_sha256']
    assert all(not any(part.startswith('lifted.before-update-') for part in Path(name).parts)
        for name in binaries['repaired']['input_sha256s'])
    write_json(output/'workflow.json',dict(status='pass',seconds=time.monotonic()-started,
        source_project=str(project),outside_library_preserved=outside,operator_note_sha256=note,
        compatible_export=updated,final_export_sha256=sha256_file(library/'source-export.json'),
        commands_sha256=sha256_file(output/'commands.json'),known_mismatch_cannot_update=True,
        replay_after_repair=True,changed_program_binary=True,local_cases=12 if all_cases else 1,
        program_cases=82 if all_cases else 1,unchanged_neighbor_zero_work=True,
        partial_export_update=True,edit_location='exported-source-library' if edit_export else 'comparison-workspace',
        results={name:dict(status=row['status'],receipt_sha256=row['receipt_sha256'],
            work_counts=row['work_counts'],timings=row['timings']) for name,row in results.items()},
        compile_link_seconds={name:row['seconds'] for name,row in binaries.items()},
        clean_program_builds=True,compiler_cache_reuse_claimed=False,
        model_seconds=0,solver_seconds=0,pilot_rebuilds=0,strong_qualification=False,
        producer_sha256=sha256_file(Path(__file__))))
    print('PASS: local component edit, neighbor reuse, safe public export update, replay/repair and standalone program execution')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','package','neighbor','oracle','output'):p.add_argument(name,type=Path)
    p.add_argument('--all-cases',action='store_true',help='rerun the wider local/program matrices instead of the focused edit loop')
    p.add_argument('--edit-export',action='store_true',help='edit the source-project C and import each draft through component start --reuse-source')
    a=p.parse_args();workflow(*[getattr(a,name).resolve() for name in ('project','package','neighbor','oracle','output')],
        all_cases=a.all_cases,edit_export=a.edit_export)
