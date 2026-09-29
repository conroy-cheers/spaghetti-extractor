"""Retain PE program execution and observations within experimental selection."""
from __future__ import annotations

import json
from pathlib import Path
import shutil

from ..components.comparison_package import package_file
from ..components.comparison_program import REPORT, process_observation
from ..components.comparison_files import mutable_files, retain_program_files
from ..components.comparison_run import first_difference
from ..util import sha256_file


def program_binding(root: Path, plan: dict) -> dict:
    driver=plan.get('program_driver')
    if not driver:return {}
    from ..components.comparison_capture import CAPTURE, LEGACY_CAPTURE, LAUNCHER
    capture = {}
    if driver.get('process') and (root/'build'/LAUNCHER).is_file():
        # The retained launcher can predate the current capture implementation.
        receipt=json.loads((root/'comparison-result.json').read_text())
        kinds={e['output_capture'] for c in receipt['cases'] for e in c['executions'].values() if 'output_capture' in e}
        if len(kinds)!=1 or not kinds<={CAPTURE,LEGACY_CAPTURE}:
            raise ValueError('retained program capture does not have one supported observed version')
        capture={'capture':dict(kind=next(iter(kinds)),file=LAUNCHER,sha256=sha256_file(root/'build'/LAUNCHER))}
    return {'program':{'driver':driver, **capture,
        'runtime_files':{Path(name).name:name for name in plan['runtime_files']},
        'library_sha256':sha256_file(package_file(root,'build/'+driver['library']))}}


def authored_binary(bindings: dict) -> tuple[str,str]:
    program=bindings.get('program')
    return ((program['driver']['library'],program['library_sha256']) if program else
            ('comparison.exe',bindings['candidate_sha256']))


def normal_program(manifest: dict) -> bool:
    return bool(manifest['bindings'].get('program',{}).get('driver',{}).get('process'))


def runtime_binary_name(manifest: dict) -> str:
    return (Path(manifest['bindings']['program']['driver']['image']).name
            if normal_program(manifest) else 'comparison.exe')


def runtime_bindings(manifest: dict) -> dict:
    bindings=manifest['bindings']
    files=dict(bindings['runtime_sha256s'])
    files[runtime_binary_name(manifest)]=bindings['candidate_sha256']
    if 'program' in bindings:
        name,digest=authored_binary(bindings);files[name]=digest
    return files


def runtime_sources(manifest: dict) -> dict:
    program=manifest['bindings'].get('program')
    files=({name:'comparison/inputs/'+path for name,path in program['runtime_files'].items()}
           if program else {name:'comparison/build/'+name for name in manifest['bindings']['runtime_sha256s']})
    files[runtime_binary_name(manifest)]='comparison/build/comparison.exe'
    if program:files[program['driver']['library']]='comparison/build/'+program['driver']['library']
    return files


def observe_program_case(*, plan: dict, expected: dict, runtime: Path, output: Path,
                         candidate: dict) -> dict:
    """Retain the fresh C report and use the comparison reader for byte/state checks."""
    stdout=Path(candidate['stdout']['path'])
    if not stdout.is_absolute():stdout=output/stdout
    prefix=stdout.with_suffix('');report=runtime/REPORT
    value={'status':'fail','first_difference':None}
    if report.is_symlink() or (report.exists() and not report.is_file()):
        value['diagnostic']='program observer report is not an ordinary file'
        return value
    if report.is_file():
        retained=prefix.with_suffix('.report.json')
        shutil.move(report,retained)
        value.update(observer_report=str(retained.relative_to(output)),observer_report_sha256=sha256_file(retained))
    if candidate['timed_out']:
        value['diagnostic']='program execution timed out'
        return value
    try:
        retain_program_files(runtime,plan['program_driver'],prefix)
        if mutable_files(plan['program_driver']):
            file_report=prefix.with_suffix('.files.json')
            value.update(file_report=str(file_report.relative_to(output)),file_report_sha256=sha256_file(file_report))
        actual,diagnostics=process_observation(plan,output,0,'source',candidate,prefix=prefix)
        value.update(observations=actual,diagnostics=diagnostics,
                     first_difference=first_difference(expected,actual))
        if value['first_difference'] is None:value['status']='pass'
    except (ValueError,UnicodeError,OSError) as error:
        value['diagnostic']=str(error)
    return value


def observe_captured_process(*, launcher, capture_kind, **arguments):
    """Run normal programs through the same Win32 capture as component checks."""
    from ..components.comparison_capture import capture_command, collect_capture
    from .functional import _run_observed_process, _stream_artifact
    if arguments['stdin_bytes'] or arguments['stdout_sink'] != 'capture':
        raise ValueError('normal program capture requires empty stdin and captured stdout')
    runtime = Path(arguments['cwd'])
    command, env = capture_command(arguments['command'], runtime=runtime, launcher=launcher,
        env=arguments['env'], timeout=arguments['timeout_seconds'])
    result = _run_observed_process(**{**arguments, 'command':tuple(command), 'env':env})
    prefix = arguments['out_prefix']
    collect_capture(runtime=runtime, prefix=prefix, execution=result, kind=capture_kind)
    for stream in ('stdout', 'stderr'):
        path = prefix.with_suffix('.'+stream)
        result[stream] = _stream_artifact(path, path.read_bytes())
    return result
