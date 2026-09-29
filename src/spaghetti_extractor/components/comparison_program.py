"""Normal PE program observations inside the existing concrete comparison path.

Keep actual arguments and process output, check observer transparency against an
untouched original, and compare explicitly reported state. The C observer owns
target-specific state normalization and coverage checks; this is not admission.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil

from ..util import sha256_file
from .comparison_build import observed_command
from .comparison_package import package_file
from .comparison_runtime import wine_sessions
from .comparison_files import check_program_files, mutable_files, read_program_files, retain_program_files

REPORT = 'spaghetti-observation.json'
SIDES = ('plain','original','source')
TELEMETRY = (b'SPX_SERVICE ',b'SPX_SERVICE_SCOPE ',b'SPX_SERVICE_HANDLER ')


def program_image_path(driver: dict, runtime: Path) -> str:
    name=Path(driver['image']).name
    drive=driver.get('process',{}).get('drive')
    return drive+':\\'+name if drive else str(runtime/name)


def prepare_program_drive(driver: dict, prefix: Path, runtime: Path) -> None:
    """Map the explicitly declared program pathname in this owned Wine prefix."""
    drive=driver.get('process',{}).get('drive')
    if drive is None:return
    devices=prefix/'dosdevices'
    if not devices.is_dir() or devices.is_symlink():
        raise ValueError('program drive requires an initialized private Wine prefix')
    link=devices/(drive.lower()+':')
    if link.exists() or link.is_symlink():
        raise ValueError('program drive is already mapped in the private Wine prefix')
    link.symlink_to(runtime.resolve(),target_is_directory=True)


def check_program_drive(driver: dict, prefix: Path, runtime: Path) -> None:
    drive=driver.get('process',{}).get('drive')
    if drive is None:return
    link=prefix/'dosdevices'/(drive.lower()+':')
    if not link.is_symlink() or link.readlink()!=runtime.resolve():
        raise ValueError('program drive no longer maps to the admitted runtime directory')


def process_observation(plan: dict, output: Path, index: int, side: str, execution: dict,
                        *, prefix: Path | None = None):
    """Reconstruct compared bytes and state from immutable retained artifacts."""
    from .comparison_run import _observation
    if prefix is None:prefix=output/'cases'/f'{index:04d}-{side}'
    if execution.get('observation_error'):
        raise ValueError(execution['observation_error'])
    from .comparison_capture import CAPTURE, validate_capture
    validate_capture(prefix, execution)
    streams={}
    for stream in ('stdout','stderr'):
        path=prefix.with_suffix('.'+stream)
        if path.stat().st_size>8*1024*1024:
            raise ValueError('program output exceeds the 8 MiB observation limit')
        streams[stream]=path.read_bytes()
    stderr=streams['stderr']
    separate_trace = execution.get('output_capture') == CAPTURE
    if separate_trace:
        trace=prefix.with_suffix('.trace').read_bytes()
        if any(line.startswith(TELEMETRY) for line in stderr.splitlines()):
            raise ValueError('service instrumentation escaped its separate trace channel')
        service_emitted=any(line.startswith(TELEMETRY) for line in trace.splitlines())
        if any(line.startswith(b'SPX_RESOURCE ') for line in trace.splitlines()):
            from .comparison_resources import resource_contracts
            if not any(side in c['checks']['instrumented_sides'] for c in resource_contracts(plan).values()):
                raise ValueError('program emitted resource instrumentation without a declared side/contract')
        cleaned=stderr
    else:
        cleaned=b''.join(line for line in stderr.splitlines(keepends=True) if not line.startswith(TELEMETRY))
        service_emitted=cleaned!=stderr
    if service_emitted and side!='source':
        raise ValueError('non-source program emitted reserved service instrumentation')
    if service_emitted and not any(unit.get('service_catalog') for unit in [plan,*plan.get('dependencies',[])]):
        raise ValueError('program emitted service instrumentation without a declared catalog')
    observation=dict(exit_code=execution['returncode'],stdout=list(streams['stdout']),stderr=list(cleaned))
    if mutable_files(plan['program_driver']):
        observation['files']=read_program_files(plan['program_driver'],prefix)
    diagnostics=None
    if side!='plain':
        if not prefix.with_suffix('.report.json').is_file():
            raise ValueError('program observer did not produce its report')
        report=_observation(prefix.with_suffix('.report.json'),['side','exit_code','observations','diagnostics'])
        if (report['side']!=side or type(report['exit_code']) is not int
                or report['exit_code']!=execution['returncode']):
            raise ValueError('program observer reported another selection or exit status')
        if not isinstance(report['observations'],dict) or not isinstance(report['diagnostics'],dict):
            raise ValueError('program observer requires observation and diagnostic objects')
        observation['state']=report['observations']
        diagnostics=report['diagnostics']
    return observation,diagnostics


def program_case(plan: dict, output: Path, index: int, case: dict, executions: dict) -> dict:
    """The writer and retained-result reader derive the same case classification."""
    from .comparison_run import first_difference
    from .comparison_resources import resource_case
    row=dict(id=case['id'],arguments=case['arguments'],status='match',observations={},
             domain_events={},executions=executions,program_diagnostics={})
    accepted=plan['program_driver']['process']['exit_codes']
    plain=None
    for side in SIDES:
        execution=executions[side]
        if execution.get('not_run'):
            row.update(status='not-run',failed_side=side,diagnostic=execution['observation_error'])
            break
        if execution['timed_out'] or execution['returncode'] not in accepted:
            row.update(status='timeout' if execution['timed_out'] else 'runtime-failed',failed_side=side)
            break
        if execution.get('observation_error'):
            row.update(status='invalid-observation',failed_side=side,diagnostic=execution['observation_error'])
            break
        try:
            observation,diagnostic=process_observation(plan,output,index,side,execution)
            if side=='plain':
                plain=observation
            else:
                if any(field not in observation for field in plan['observation_fields']):
                    raise ValueError('program comparison omits required observation fields')
                row['observations'][side]=observation
                row['program_diagnostics'][side]=diagnostic
        except (ValueError,UnicodeError,OSError) as error:
            row.update(status='invalid-observation',failed_side=side,diagnostic=str(error))
            break
    if plain is not None:
        row['plain_observation']=plain
    if row['status']=='match':
        original=row['observations']['original']
        difference=first_difference(plain,{key:original[key] for key in plain})
        row['instrumentation_difference']=difference
        if difference is not None:
            row.update(status='invalid-observation',failed_side='original',
                diagnostic='instrumentation changes original program behavior: '+difference['path'])
        else:
            row['first_difference']=first_difference(original,row['observations']['source'])
            if row['first_difference'] is not None:row['status']='mismatch'
    resources=resource_case(plan,output,index,executions)
    if resources is not None:row['resources']=resources
    return row


def run_program_cases(*, package: Path, plan: dict, output: Path, cases: list,
                      timings: list, timeout: float) -> list:
    from .comparison_capture import LAUNCHER, capture_command, collect_capture
    build=output/'build';driver=plan['program_driver']
    image_name=Path(driver['image']).name
    directories={};bindings={};environments={}
    active=output/'runtime-active'
    for side in SIDES:
        directory=output/('runtime-'+side);directory.mkdir()
        for name in plan['runtime_files']:
            shutil.copyfile(package_file(package,name),directory/Path(name).name)
        if side!='plain':
            shutil.copyfile(build/'comparison.exe',directory/image_name)
            shutil.copyfile(build/driver['library'],directory/driver['library'])
        bindings[side]={p.name:sha256_file(p) for p in directory.iterdir() if p.is_file()}
        (directory/'tmp').mkdir()
        directories[side]=directory
        prefix=output/('wine-'+side);prefix.mkdir(mode=0o700)
        environments[side]={**os.environ,'WINEPREFIX':str(prefix),'WINEPATH':str(directory),
            'TMPDIR':str(directory/'tmp'),'LC_ALL':'C','WINEDEBUG':'-all'}
    server=plan['tools']['server'];runner=plan['tools']['runner']['path']
    rows=[];halted=None
    with wine_sessions(server=server['path'] if server else None,environments=environments,
            cwd=build,logs=build,timeout=timeout,timings=timings,persistent=True,
            dispose_prefixes=True,runner=runner if server else None):
        for environment in environments.values():
            prepare_program_drive(driver,Path(environment['WINEPREFIX']),active)
        for index,case in enumerate(cases):
            executions={}
            for side in SIDES:
                execution=dict(returncode=None,timed_out=False,not_run=True)
                executions[side]=execution
                if halted is not None:
                    execution['observation_error']='not run after '+halted
                    continue
                # One executable pathname preserves argv/startup observations.
                # Each side keeps its own files and prefix between cases.
                directory=directories[side];directory.rename(active)
                prefix=output/'cases'/f'{index:04d}-{side}'
                try:
                    check_program_files(active,driver,bindings[side])
                    check_program_drive(driver,Path(environments[side]['WINEPREFIX']),active)
                    if (active/REPORT).exists() or (active/REPORT).is_symlink():
                        raise ValueError('program observation was not fresh before execution')
                    env={**environments[side],'WINEPATH':str(active),'TMPDIR':str(active/'tmp'),
                        'SPX_COMPARISON_SIDE':side,'SPX_COMPARISON_REPORT':REPORT}
                    command,env=capture_command([runner,program_image_path(driver,active),*case['arguments']],
                        runtime=active,launcher=build/LAUNCHER,env=env,timeout=timeout)
                    executed=observed_command(command,
                        cwd=active,env=env,timeout=timeout,output=prefix,phase='execution',timings=timings)
                    execution={k:executed[k] for k in ('returncode','timed_out')}
                    executions[side]=execution
                    collect_capture(runtime=active,prefix=prefix,execution=execution)
                    retain_program_files(active,driver,prefix)
                    report=active/REPORT
                    if report.is_symlink() or (report.exists() and not report.is_file()):
                        execution['observation_error']='program report is not an ordinary file'
                    elif report.is_file():
                        if side=='plain':execution['observation_error']='untouched original wrote the reserved observer report'
                        shutil.copyfile(report,prefix.with_suffix('.report.json'))
                        report.unlink()
                    check_program_files(active,driver,bindings[side])
                    check_program_drive(driver,Path(environments[side]['WINEPREFIX']),active)
                except (ValueError,OSError) as error:
                    execution['observation_error']=str(error)
                finally:
                    active.rename(directory)
                if execution.get('observation_error'):
                    halted=case['id']+'/'+side+': '+execution['observation_error']
            rows.append(program_case(plan,output,index,case,executions))
    return rows
