"""Run Hello, diagnose a backend defect, replay retained inputs, and repair."""
import argparse
import json
import os
from pathlib import Path
import shutil
import time

from build import build
from run import run
from spaghetti_extractor.util import sha256_file, write_json


def walkthrough(project, oracle, output, entry='target', defect='conversion'):
    if not os.environ.get('WAYLAND_DISPLAY'):
        raise ValueError('run inside spaghetti-headless-wayland')
    if defect=='arguments' and entry!='utf8':raise ValueError('argument defect requires the UTF-8 entry profile')
    allocation_fault=defect=='allocation-exit'
    output.mkdir(parents=True,exist_ok=False)
    draft=output/'project'
    shutil.copytree(project,draft,ignore=shutil.ignore_patterns('build','hello','hello.exe','hello-utf8','liblifted.a'))
    if defect=='conversion':
        source='backends/windows-1252/windows-1252.c'
        before,after=b'0x20ac',b'0x20ad';case='non-ascii'
        description='UTF-16 memory changes with identical text output'
    elif defect=='arguments':
        source='backends/windows-1252/windows-1252-best-fit.h'
        before,after=b'{0xff0d,0x2d}',b'{0xff0d,0x3f}';case='best-fit-option'
        description='Wrong best-fit argument mapping changes option parsing and normal program behavior'
    elif defect=='allocation-exit':
        source='application/runtime.c'
        before,after=b'hello_runtime.exit_code=1; exit(1);',b'hello_runtime.exit_code=0; exit(0);'
        case='allocation-default'
        description='Allocation failure prints the right diagnostic but exits successfully'
    else:raise ValueError('unknown defect')
    backend=draft/source
    correct=backend.read_bytes()
    export_before=sha256_file(draft/'lifted/source-export.json')
    started=time.monotonic()
    build(draft,output/'baseline-build',entry=entry,allocation_fault=allocation_fault)
    assert run(output/'baseline-build',oracle,output/'baseline')=='match'

    # The conversion variant round-trips corrupt memory to identical text. The
    # argument variant changes the input contract and observable control flow.
    assert correct.count(before)==1
    backend.write_bytes(correct.replace(before,after))
    build(draft,output/'wrong-build',entry=entry,allocation_fault=allocation_fault)
    assert run(output/'wrong-build',oracle,output/'wrong',case)=='mismatch'
    wrong=json.loads((output/'wrong/cases.json').read_text())[0]
    if defect=='conversion':
        assert set(wrong['differences'])=={'state.word_hash','state.first_words'}
        assert wrong['sides']['plain']==wrong['sides']['portable']
    elif defect=='arguments':
        assert {'state.argv_hex','exit_code','stdout','stderr'}<=set(wrong['differences'])
    else:
        assert wrong['differences']==['exit_code']
        assert wrong['sides']['plain']['exit_code']==1 and wrong['sides']['portable']['exit_code']==0
        assert wrong['native_state']['fatal_entries']==wrong['portable_state']['fatal_entries']==1

    backend.write_bytes(correct)
    assert run(output/'wrong-build',oracle,output/'replay',case)=='mismatch'
    replay=json.loads((output/'replay/cases.json').read_text())[0]
    assert replay['differences']==wrong['differences']
    assert replay['native_state']['word_hash']==wrong['native_state']['word_hash']
    assert replay['portable_state']['word_hash']==wrong['portable_state']['word_hash']
    build(draft,output/'repaired-build',entry=entry,allocation_fault=allocation_fault)
    assert run(output/'repaired-build',oracle,output/'repaired',case)=='match'
    assert sha256_file(draft/'lifted/source-export.json')==export_before
    manifests={name:json.loads((output/(name+'-build')/'build.json').read_text())
               for name in ('baseline','wrong','repaired')}
    assert manifests['baseline']['executable_sha256']==manifests['repaired']['executable_sha256']
    assert manifests['baseline']['input_sha256s']==manifests['repaired']['input_sha256s']
    changed=[name for name,value in manifests['baseline']['input_sha256s'].items()
             if value!=manifests['wrong']['input_sha256s'][name]]
    assert changed==[source]
    reports={name:json.loads((output/name/'run.json').read_text())
             for name in ('baseline','wrong','replay','repaired')}
    write_json(output/'walkthrough.json',dict(status='pass',seconds=time.monotonic()-started,
        baseline_cases=len(reports['baseline']['cases']),entry_profile=entry,allocation_fault=allocation_fault,defect=description,
        changed_sources=changed,retained_binary_replay_after_source_repair=True,
        unchanged_component_receipts=True,source_export_sha256=export_before,
        compile_link_seconds={name:value['seconds'] for name,value in manifests.items()},
        execution_seconds={name:value['seconds'] for name,value in reports.items()},
        reports_sha256={name:sha256_file(output/name/'run.json') for name in reports},
        model_seconds=0,solver_seconds=0,pilot_rebuilds=0,strong_qualification=False,
        clean_evidence_builds=True,compiler_cache_reuse_claimed=False,
        producer_sha256=sha256_file(Path(__file__))))
    print('PASS: standalone execution, '+defect+' defect, retained replay and repaired behavior')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','oracle','output'):p.add_argument(name,type=Path)
    p.add_argument('--entry',choices=('target','utf8'),default='target')
    p.add_argument('--defect',choices=('conversion','arguments','allocation-exit'),default='conversion')
    a=p.parse_args();walkthrough(a.project.resolve(),a.oracle.resolve(),a.output.resolve(),a.entry,a.defect)
