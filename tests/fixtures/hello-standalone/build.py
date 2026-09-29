"""Build an editable standalone project; retain current inputs and compiler output."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import struct
import time

from spaghetti_extractor.components.source import load_component_source_package
from spaghetti_extractor.util import sha256_file, write_json


def build(project, output, compiler=None, archiver=None, entry='target', allocation_fault=False):
    if entry not in ('target','utf8'):raise ValueError('unknown argument entry profile')
    output.mkdir(parents=True,exist_ok=False)
    description=json.loads((project/'standalone-project.json').read_text())
    exported=json.loads((project/'lifted/source-export.json').read_text())
    for name,digest in exported['files'].items():
        if sha256_file(project/'lifted'/name)!=digest: raise ValueError('exported comparison source changed; recheck and re-export '+name)
    for unit in exported['components'].values(): load_component_source_package(project/'lifted'/unit['source_package'])
    backups=exported.get('update',{}).get('retained_backups',[])
    if any(Path(name).name!=name or not name.startswith('lifted.before-update-') for name in backups):
        raise ValueError('invalid retained export backup name')
    # Evidence builds start clean; ordinary direct make remains available for
    # fast editing. Do not present make's mtime cache as exact input binding.
    inputs={p.relative_to(project).as_posix():sha256_file(p) for p in project.rglob('*')
        if p.is_file() and p.relative_to(project).parts[0] not in backups
        and 'build' not in p.relative_to(project).parts and p.name not in ('hello','hello.exe','hello-utf8','liblifted.a')}
    snapshot=output/'sources'; snapshot.mkdir()
    for name,digest in inputs.items():
        destination=snapshot/name;destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(project/name,destination)
        if sha256_file(destination)!=digest:raise ValueError('source changed while retaining '+name)
    compiler=Path(compiler or shutil.which('cc')).absolute(); archiver=Path(archiver or shutil.which('ar')).absolute()
    target='hello' if entry=='target' else 'hello-utf8'
    makefiles=['-f','Makefile','-f','diagnostics/allocation-fault.mk'] if allocation_fault else []
    command=[shutil.which('make'),*makefiles,'-j2',target,'CC='+str(compiler),'AR='+str(archiver)]
    environment={'PATH':os.environ['PATH'],'LC_ALL':'C'}
    started=time.monotonic()
    clean=subprocess.run([command[0],'clean'],cwd=snapshot,env=environment,capture_output=True,timeout=30)
    (output/'clean.stdout').write_bytes(clean.stdout);(output/'clean.stderr').write_bytes(clean.stderr)
    if clean.returncode:raise ValueError('standalone cleanup failed')
    result=subprocess.run(command,cwd=snapshot,env=environment,capture_output=True,timeout=120)
    (output/'make.stdout').write_bytes(result.stdout);(output/'make.stderr').write_bytes(result.stderr)
    after={name:sha256_file(snapshot/name) for name in inputs}
    binary=snapshot/target
    if inputs!=after: raise ValueError('source changed while compiling')
    report=dict(command=command,seconds=time.monotonic()-started,exit_code=result.returncode,
        project_sha256=sha256_file(snapshot/'standalone-project.json'), input_sha256s=inputs,
        compiler=dict(path=str(compiler),sha256=sha256_file(compiler)),
        archiver=dict(path=str(archiver),sha256=sha256_file(archiver)),
        environment_sha256=sha256(json.dumps(environment,sort_keys=True).encode()).hexdigest(),
        clean_build=True,entry_profile=entry,allocation_fault=allocation_fault,retained_backups_excluded=backups,
        source_changes=[name for name,digest in inputs.items() if name!='standalone-project.json' and digest!=description['files'].get(name)],
        executable_sha256=sha256_file(binary) if not result.returncode else None,
        elf_machine=struct.unpack_from('<H',binary.read_bytes(),18)[0] if not result.returncode else None,
        producer_sha256=sha256_file(Path(__file__)),strong_qualification=False)
    write_json(output/'build.json',report)
    if result.returncode: raise ValueError('standalone build failed; inspect make.stderr')
    shutil.copyfile(binary,output/'hello');(output/'hello').chmod(0o755)
    print('built',output/'hello')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('project',type=Path);p.add_argument('output',type=Path)
    p.add_argument('--cc',type=Path);p.add_argument('--ar',type=Path)
    p.add_argument('--entry',choices=('target','utf8'),default='target')
    p.add_argument('--allocation-fault',action='store_true',help='test-only lower allocation service fault; ordinary builds omit it')
    a=p.parse_args();build(a.project.resolve(),a.output.resolve(),a.cc,a.ar,a.entry,a.allocation_fault)
