"""Build the conventional project and retain exact inputs, tools, commands and costs."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from spaghetti_extractor.components.source import load_component_source_package
from spaghetti_extractor.util import sha256_file, write_json
from spaghetti_extractor.candidate.source_assembly import check_native_entries


def inputs(project):
    paths=[]
    for subdir in ('bindings','diagnostics','lifted/components','provenance'):
        paths.extend(p for p in (project/subdir).rglob('*') if p.is_file())
    paths.extend(project/p for p in ('Makefile','portable-project.json','lifted/Makefile','lifted/source-export.json'))
    for p in (project/'backends/jq').rglob('*'):
        if p.is_file() and not p.name.endswith(('~','.pyc')): paths.append(p)
    return {p.relative_to(project).as_posix():sha256_file(p) for p in sorted(paths)}


def build(project,output,cc,ar,ranlib,host=None,ldflags='',allocation_failures=False):
    output.mkdir(parents=True,exist_ok=False)
    exported=json.loads((project/'lifted/source-export.json').read_text())
    for name,digest in exported['files'].items():
        if sha256_file(project/'lifted'/name)!=digest:raise ValueError('source changed; compare and export it first: '+name)
    for unit in exported['components'].values():load_component_source_package(project/'lifted'/unit['source_package'])
    source_inputs=inputs(project)
    snapshot=output/'sources'
    for name,digest in source_inputs.items():
        path=snapshot/name;path.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(project/name,path)
        if sha256_file(path)!=digest:raise ValueError('source changed while retaining '+name)
    prior={p.relative_to(project).as_posix():dict(sha256=sha256_file(p),mtime_ns=p.stat().st_mtime_ns)
           for p in project.rglob('*.o')}
    wrapper=output/'timed-cc'; phase_log=output/'compiler-phases.jsonl'
    wrapper.write_text('#!'+sys.executable+'\n'+'''import json,os,subprocess,sys,time
from pathlib import Path
arguments=sys.argv[1:];started=time.monotonic()
result=subprocess.run(['''+repr(str(cc))+''',*arguments])
cwd=Path.cwd();phase='other-compiler'
if any('conftest' in x for x in arguments):phase='configure-probe'
elif '-c' in arguments:phase='diagnostic-compiler' if any(x.startswith('diagnostics/') for x in arguments) else 'component-compiler' if cwd.name=='lifted' else 'backend-compiler' if 'backends' in cwd.parts else 'binding-compiler'
elif '-o' in arguments and arguments[arguments.index('-o')+1] in ('jq','live-values','failure'):phase='program-link'
row=dict(phase=phase,seconds=time.monotonic()-started,cwd=str(cwd),arguments=arguments,exit_code=result.returncode)
log=os.environ.get('SPX_BUILD_TIMING_LOG')
if log:
 fd=os.open(log,os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)
 try:os.write(fd,(json.dumps(row,separators=(',',':'))+'\\n').encode())
 finally:os.close(fd)
raise SystemExit(result.returncode)
''');wrapper.chmod(0o755)
    command=['make','-j2','-C',str(project),'jq','live-values','CC='+str(wrapper),'AR='+str(ar),'RANLIB='+str(ranlib),'LDFLAGS='+ldflags]
    if allocation_failures: command+=['-f','Makefile','-f','diagnostics/failure.mk','failure']
    if host: command+=['CONFIGURE_FLAGS=--host='+host]
    started=time.monotonic()
    with (output/'build.stdout').open('wb') as out,(output/'build.stderr').open('wb') as err:
        ran=subprocess.run(command,env={**os.environ,'SPX_BUILD_TIMING_LOG':str(phase_log)},stdout=out,stderr=err,timeout=600)
    elapsed=time.monotonic()-started
    after={p.relative_to(project).as_posix():dict(sha256=sha256_file(p),mtime_ns=p.stat().st_mtime_ns)
           for p in project.rglob('*.o')}
    changed=sorted(n for n,row in after.items() if prior.get(n)!=row)
    phases={}
    for line in phase_log.read_text().splitlines() if phase_log.exists() else []:
        row=json.loads(line);phase=phases.setdefault(row['phase'],dict(invocations=0,seconds=0))
        phase['invocations']+=1;phase['seconds']+=row['seconds']
    if source_inputs!=inputs(project):raise ValueError('source inputs changed during the build')
    result=dict(status='built' if ran.returncode==0 else 'failed',command=command,exit_code=ran.returncode,
        seconds=elapsed,input_sha256s=source_inputs,object_sha256s={n:r['sha256'] for n,r in after.items()},
        rebuilt_objects=changed,backend_rebuilt_objects=[n for n in changed if n.startswith('backends/')],
        component_rebuilt_objects=[n for n in changed if n.startswith('lifted/')],
        tools={n:dict(path=str(p),sha256=sha256_file(p),version=subprocess.check_output([str(p),'--version'],text=True).splitlines()[0])
               for n,p in [('cc',cc),('ar',ar),('ranlib',ranlib)]},
        phases=phases,phase_times_are_summed_child_times=True,
        model_seconds=0,solver_seconds=0,strong_qualification=False,whole_jq_lift=False,
        producer_sha256=sha256_file(Path(__file__)),compiler_wrapper_sha256=sha256_file(wrapper))
    if ran.returncode==0:
        result['executable_sha256']=sha256_file(project/'jq')
        result['link_map_sha256']=sha256_file(project/'build/jq.map')
        nm=cc.parent/'nm'
        backend_symbols=subprocess.check_output([str(nm),'--defined-only',str(project/'backends/build/.libs/libjq.a'),
            str(project/'backends/build/src/main.o')],text=True)
        program_symbols=subprocess.check_output([str(nm),'--defined-only',str(project/'jq')],text=True)
        (output/'backend-symbols.txt').write_text(backend_symbols);(output/'program-symbols.txt').write_text(program_symbols)
        selection=json.loads((project/'portable-project.json').read_text())
        check_native_entries(selection['native_entries'],[row.split()[-1] for row in program_symbols.splitlines() if row.split()])
        # The replacement group can remove private helpers as well as public
        # entries. Only declared entries must survive in the final executable;
        # check_native_entries above already checks their unique definitions.
        removed=selection['removed_operations']
        members={};member=None
        for row in backend_symbols.splitlines():
            if row.endswith(':'):
                member=Path(row[:-1]).name;members.setdefault(member,set())
            elif row.split() and member is not None:members[member].add(row.split()[-1])
        for key,record in removed.items():
            name=record.get('symbol',key);member=Path(record['file']).with_suffix('.o').name
            if member not in members:raise ValueError('missing selected backend object: '+member)
            if name in members[member]:
                raise ValueError('original selected symbol survived in the backend: '+record['file']+':'+name)
        result['selected_backend_bodies_absent']=sorted(removed)
        (output/'jq').write_bytes((project/'jq').read_bytes());(output/'jq').chmod(0o755)
        (output/'live-values').write_bytes((project/'live-values').read_bytes());(output/'live-values').chmod(0o755)
        result['live_values_sha256']=sha256_file(output/'live-values')
        if allocation_failures:
            shutil.copyfile(project/'failure',output/'failure');(output/'failure').chmod(0o755)
            result['allocation_failure_sha256']=sha256_file(output/'failure')
    write_json(output/'build.json',result)
    if ran.returncode:raise ValueError('source build failed; see '+str(output))
    print('built',round(elapsed,3),'seconds;',len(changed),'objects;',flush=True)
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','output'):p.add_argument(name,type=Path)
    for name in ('cc','ar','ranlib'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--host')
    p.add_argument('--ldflags',default='')
    p.add_argument('--allocation-failures',action='store_true',help='also build the separate real-handler diagnostic consumer')
    a=p.parse_args();build(a.project.resolve(),a.output.resolve(),a.cc,a.ar,a.ranlib,a.host,a.ldflags,a.allocation_failures)
