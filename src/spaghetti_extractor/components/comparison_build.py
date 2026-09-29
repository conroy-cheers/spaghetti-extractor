"""Compile concrete comparison fixtures using existing C interface/source machinery."""
from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import time

from ..util import sha256_file,write_json
from ..execution import stop_process
from .comparison_package import package_file
from .comparison_dependencies import comparison_units,comparison_includes


def observed_command(command, *, cwd: Path, env: dict, timeout: float, output: Path, phase: str,
                     timings: list, cancel_event=None) -> dict:
    output.parent.mkdir(parents=True,exist_ok=True)
    started=time.monotonic()
    timed_out=False
    cancelled=False
    # Capture an immutable root-exit snapshot, not a path that detached helpers
    # can continue to modify after it has been hashed into a receipt.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process=subprocess.Popen(command,cwd=cwd,env=env,stdin=subprocess.DEVNULL,
                                     stdout=stdout,stderr=stderr,start_new_session=True)
            try:
                if cancel_event is None:
                    process.wait(timeout=timeout)
                else:
                    deadline=time.monotonic()+timeout
                    while process.poll() is None:
                        if cancel_event.is_set():
                            cancelled=True
                            raise InterruptedError(f'{phase} cancelled')
                        remaining=deadline-time.monotonic()
                        if remaining<=0:
                            raise subprocess.TimeoutExpired(command,timeout)
                        try:
                            process.wait(timeout=min(0.05,remaining))
                        except subprocess.TimeoutExpired:
                            pass
            except BaseException as error:
                if not stop_process(process):
                    raise ValueError(f'{phase} process could not be reaped within cleanup deadline') from error
                if not isinstance(error,subprocess.TimeoutExpired) and not cancelled:
                    raise
                timed_out=isinstance(error,subprocess.TimeoutExpired)
        finally:
            for stream,extension in ((stdout,'.stdout'),(stderr,'.stderr')):
                stream.seek(0)
                output.with_suffix(extension).write_bytes(stream.read(os.fstat(stream.fileno()).st_size))
    row={'phase':phase,'seconds':time.monotonic()-started,'command':list(command),
         'returncode':process.returncode,'timed_out':timed_out}
    if cancel_event is not None:
        row['cancelled']=cancelled
    timings.append(row)
    return row


def compilation_units(plan):
    files=[(name,unit) for unit in comparison_units(plan)
        for name in [p for p in unit['sources'] if p.endswith('.c')]+unit['adapters']]
    from .comparison_resources import resource_contracts
    if resource_contracts(plan):
        files.append(('generated/comparison-resources.c',comparison_units(plan)[0]))
    from .comparison_service_runtime import nonlocal_outcomes
    if nonlocal_outcomes(plan):
        files.append(('generated/comparison-services.c',comparison_units(plan)[0]))
    return files


def compile_options(plan,unit):
    return ['-std=c11','-Wall','-Wextra','-Werror','-v','-fno-canonical-system-headers',
            *[arg for directory in comparison_includes(plan,unit) for arg in ('-I',directory)]]


def write_comparison_compiler_views(*, package, plan, output, timings, timeout):
    """Preprocess authored inputs on demand without changing comparison eligibility."""
    from .comparison_compile_cache import compiler_environment
    from .source_compiler_view import write_compiler_view
    views=[]
    for index,(name,unit) in enumerate(compilation_units(plan)):
        if name not in unit['sources']:
            continue
        started=time.monotonic()
        view=output/'compiler-views'/str(index)
        feedback=write_compiler_view([plan['tools']['compiler']['path'],*compile_options(plan,unit),'-c',name],
            cwd=package,output=view,environment=compiler_environment(),timeout=timeout)
        views.append(dict(source=name,status=feedback['status'],path='compiler-views/'+str(index)+'/view.json'))
        timings.append(dict(phase='preprocessing',source=name,seconds=time.monotonic()-started))
    return views


def compile_comparison(*, package: Path, plan: dict, output: Path, timings: list, timeout: float,
                       previous: Path | None = None) -> tuple[Path | None, dict]:
    from .comparison_compile_cache import compiler_environment,configuration,load_cache,entry_valid,make_entry,path_key,keyed_path
    compiler=plan['tools']['compiler']['path']
    files=compilation_units(plan)
    env=compiler_environment()
    objects=[];probe_states={}
    dependencies={}
    started=time.monotonic()
    prior=load_cache(previous,plan)
    cached={row['source']:row for row in prior['units']} if prior else {}
    manifest=dict(version=1,configuration=configuration(plan),units=[])
    failed=False
    timings.append(dict(phase='compile-cache-validation',seconds=time.monotonic()-started))
    for index,(name,unit) in enumerate(files):
        obj=output/f'unit-{index}.o'
        dep=output/f'unit-{index}.d'
        options=compile_options(plan,unit)
        started=time.monotonic();entry=cached.get(name)
        valid=entry is not None and entry_valid(entry,package=package,name=name,unit=unit['id'],
            options=options,build=previous/'build',probe_states=probe_states)
        timings.append(dict(phase='compile-cache-validation',source=name,seconds=time.monotonic()-started))
        if valid:
            started=time.monotonic()
            shutil.copyfile(previous/'build'/entry['object'],obj)
            old_index=Path(entry['object']).stem.removeprefix('unit-')
            for before,after in [(f'unit-{old_index}.d',dep.name),
                    (f'compile-{old_index}.stdout',f'compile-{index}.stdout'),(f'compile-{old_index}.stderr',f'compile-{index}.stderr')]:
                shutil.copyfile(previous/'build'/before,output/after)
            manifest['units'].append({**entry,'object':obj.name,'reused':True})
            dependencies.update({str(keyed_path(package,k)):v for k,v in entry['inputs'].items()})
            objects.append(obj)
            timings.append(dict(phase='compile-cache-retention',source=name,seconds=time.monotonic()-started))
            continue
        # After an error, retain later eligible neighbors without starting more
        # compilation. The next edit can reuse every successful object from this
        # attempt, including new ones built before the error.
        if failed:
            continue
        # Relative logical input paths keep __FILE__/__BASE_FILE__ stable across
        # retained snapshots. Actual output/log paths remain private to this run.
        command=[compiler,*options,'-MD','-MF',str(dep),'-c',name,'-o',str(obj)]
        result=observed_command(command,cwd=package,env=env,timeout=timeout,
                                output=output/f'compile-{index}',phase='compiler',timings=timings)
        # A compiler invocation is a new filesystem boundary. Only consecutive
        # read-only validations share their include lookup observations.
        probe_states.clear()
        if result['returncode'] or result['timed_out']:
            failed=True
            continue
        started=time.monotonic();read_inputs={}
        dependency_text=dep.read_text().replace('\\\n',' ')
        for filename in shlex.split(dependency_text.split(':',1)[1]):
            path=Path(filename)
            if not path.is_absolute():
                path=package/path
            dependencies[str(path)]=sha256_file(path)
            read_inputs[path_key(package,path)]=dependencies[str(path)]
        entry=make_entry(package=package,name=name,unit=unit['id'],options=options,dependencies=read_inputs,
            object_path=obj,stderr=(output/f'compile-{index}.stderr').read_text(),plan=plan)
        manifest['units'].append({**entry,'reused':False})
        timings.append(dict(phase='compile-cache-indexing',source=name,seconds=time.monotonic()-started))
        objects.append(obj)
    write_json(output/'compilation.json',manifest)
    if failed:
        return None,dependencies
    binary=output/'comparison.exe'
    driver=plan.get('program_driver')
    payload=output/driver['library'] if driver else binary
    command=[compiler,*(['-shared'] if driver else []),*map(str,objects),
             *[str(package_file(package,p)) for p in plan['link_files']],'-o',str(payload)]
    result=observed_command(command,cwd=output,env=env,timeout=timeout,
                            output=output/'link',phase='link',timings=timings)
    if result['returncode'] or result['timed_out']:
        return None,dependencies
    if driver:
        if driver.get('process'):
            from .comparison_capture import build_capture
            if not build_capture(compiler=compiler, output=output, env=env, timeout=timeout, timings=timings):
                return None,dependencies
        from pefile import PEFormatError
        from .comparison_pe32_program import add_experimental_import
        started=time.monotonic()
        try:
            add_experimental_import(package_file(package,driver['image']),payload,driver['symbol'],binary)
        except (ValueError,PEFormatError) as error:
            (output/'program-preparation.stderr').write_text('error: '+str(error)+'\n')
            return None,dependencies
        finally:
            timings.append(dict(phase='program-preparation',seconds=time.monotonic()-started))
    return binary,dependencies
