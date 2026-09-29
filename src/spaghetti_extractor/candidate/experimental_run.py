"""Experimental suite and per-case gates above the existing candidate runner."""
from __future__ import annotations

import json
from functools import partial
import math
import os
from pathlib import Path
import shutil
import time

from ..artifacts.artifact_set import canonical_sha256_v3
from ..components.comparison_runtime import wine_sessions
from ..components.comparison_program import program_image_path, prepare_program_drive, check_program_drive
from ..components.comparison_files import check_program_files
from ..components.comparison_package import package_file
from ..util import sha256_file,sha256_text,write_json
from .formats import EXPERIMENTAL_COMPONENT_RUN_V1_FORMAT
from .experimental_admission import _ExperimentalAdmission
from .functional import run_candidate_test_case,aggregate_candidate_test_cases
from .experimental_program import normal_program, runtime_binary_name, runtime_bindings, runtime_sources, observe_program_case


def _runtime_files(manifest: dict) -> dict:
    return runtime_bindings(manifest)


def _prepare_runtime(package: Path, output: Path, manifest: dict) -> Path:
    runtime=output/'runtime';runtime.mkdir()
    for name,source in runtime_sources(manifest).items():
        shutil.copy2(package_file(package,source),runtime/name)
    if normal_program(manifest):(runtime/'tmp').mkdir()
    return runtime


def _case_environment(runtime: Path, manifest: dict | None = None) -> dict[str,str]:
    env={'WINEPREFIX':str(runtime.parent/'wine'),'WINEPATH':str(runtime),'WINEDEBUG':'-all','LC_ALL':'C'}
    if manifest and normal_program(manifest):
        from ..components.comparison_program import REPORT
        env.update(SPX_COMPARISON_SIDE='source',SPX_COMPARISON_REPORT=REPORT,TMPDIR=str(runtime/'tmp'))
    return env


def _effective_suite(package: Path, runtime: Path, manifest: dict | None = None) -> dict:
    if manifest is None:manifest=json.loads((package/'experimental-execution.json').read_text())
    value=json.loads((package/'candidate-suite.json').read_text())
    for row in value['cases']:
        row.update(cwd=str(runtime),env=_case_environment(runtime,manifest))
    return value


def _validate_execution_inputs(*, admission: _ExperimentalAdmission, runtime: Path, suite: Path) -> None:
    manifest=admission.manifest
    normal=normal_program(manifest)
    if normal and (not (runtime/'tmp').is_dir() or (runtime/'tmp').is_symlink()):
        raise ValueError('experimental program requires its private temporary directory')
    if normal:
        check_program_files(runtime,manifest['bindings']['program']['driver'],_runtime_files(manifest))
    else:
        paths=list(runtime.iterdir())
        if any(not p.is_file() or p.is_symlink() for p in paths):
            raise ValueError('experimental runtime has unexpected directory or symbolic-link inputs')
        actual={p.name:sha256_file(p) for p in paths}
        if actual!=_runtime_files(manifest):
            raise ValueError('experimental runtime binary/input binding is stale')
    effective=json.loads(suite.read_text())
    if effective!=_effective_suite(admission.package,runtime,manifest):
        raise ValueError('experimental effective suite differs from admitted inputs or runtime')
    runner=manifest['bindings']['tools']['runner']
    if runner is not None and not os.environ.get('WAYLAND_DISPLAY'):
        raise ValueError('Wine execution requires a headless Wayland desktop; use spaghetti-headless-wayland')


def _run_admitted_case(*, admission: _ExperimentalAdmission, case_id: str, output: Path,
                       runtime: Path, suite: Path, timeout: float, timings: list | None) -> dict:
    started=time.monotonic()
    admission.check(case_id)
    _validate_execution_inputs(admission=admission,runtime=runtime,suite=suite)
    if timings is not None:
        timings.append({'phase':'evidence-validation','case_id':case_id,'seconds':time.monotonic()-started})
    manifest=admission.manifest
    runner=manifest['bindings']['tools']['runner']
    binary=runtime/runtime_binary_name(manifest)
    image_path=str(binary.resolve())
    if normal_program(manifest):
        driver=manifest['bindings']['program']['driver']
        check_program_drive(driver,runtime.parent/'wine',runtime)
        image_path=program_image_path(driver,runtime)
    command=([runner['path']] if runner else [])+[image_path]
    observer=None
    capture=manifest['bindings'].get('program',{}).get('capture')
    if capture:
        from .experimental_program import observe_captured_process
        observer=partial(observe_captured_process,
            launcher=admission.package/'comparison/build'/capture['file'],capture_kind=capture['kind'])
    started=time.monotonic()
    result=run_candidate_test_case(suite=suite,case_id=case_id,candidate_binary=binary,
        candidate_command=tuple(command),out=output,timeout_seconds=timeout,observe_process=observer)
    if timings is not None:
        timings.append({'phase':'candidate-execution','case_id':case_id,'seconds':time.monotonic()-started})
    if normal_program(manifest):
        check_program_drive(driver,runtime.parent/'wine',runtime)
        started=time.monotonic()
        program=observe_program_case(plan=admission.plan,expected=admission.program_observations[case_id],
            runtime=runtime,output=output,candidate=result['case']['candidate'])
        write_json(output/'program-observations.json',dict(manifest_sha256=manifest['manifest_sha256'],case_id=case_id,**program))
        result={**result,'behavioral_status':result['status'],'program':program}
        if program['status']!='pass':result['status']='fail'
        if timings is not None:
            timings.append({'phase':'program-observation','case_id':case_id,'seconds':time.monotonic()-started})
    started=time.monotonic()
    # Last-case changes must not escape detection, and current resource checks
    # must use the same admitted declarations rather than a changed plan file.
    admission.check(case_id)
    _validate_execution_inputs(admission=admission,runtime=runtime,suite=suite)
    if timings is not None:
        timings.append({'phase':'evidence-validation','step':'after-case','case_id':case_id,'seconds':time.monotonic()-started})
    started=time.monotonic()
    from ..components.comparison_resources import resource_observations
    from ..components.comparison_capture import instrumentation_path
    stderr=output/result['case']['candidate']['stderr']['path']
    trace=instrumentation_path(stderr.with_suffix(''),result['case']['candidate'])
    resources=resource_observations(admission.plan,{'source':trace})
    if resources is not None:
        write_json(output/'resource-observations.json',{'manifest_sha256':manifest['manifest_sha256'],
            'case_id':case_id,'stderr_sha256':sha256_file(stderr),
            'instrumentation_file':str(trace.relative_to(output)),'instrumentation_sha256':sha256_file(trace),'resources':resources})
        # Keep the existing candidate report as the behavioral observation. This
        # result additionally enforces experimental resource applicability.
        result={**result,'behavioral_status':result.get('behavioral_status',result['status']),'resources':resources}
        if resources['status']!='satisfied':
            result['status']='fail'
    if timings is not None:
        timings.append({'phase':'resource-validation','case_id':case_id,'seconds':time.monotonic()-started})
    return result


def run_experimental_case(*, package: Path, case_id: str, output: Path, runtime: Path,
                          suite: Path, timeout: float = 30, timings: list | None = None) -> dict:
    # A direct case always creates its own full admission. No caller-provided
    # success flag or manifest can bypass the public per-case gate.
    if not math.isfinite(timeout) or timeout<=0:
        raise ValueError('experimental execution requires a finite positive deadline')
    started=time.monotonic()
    admission=_ExperimentalAdmission(package)
    if timings is not None:
        timings.append({'phase':'evidence-validation','step':'case-admission',
            'reuse_limitation':admission.reuse_limitation,'seconds':time.monotonic()-started})
    return _run_admitted_case(admission=admission,case_id=case_id,output=output,
        runtime=runtime.resolve(),suite=suite,timeout=timeout,timings=timings)


def run_experimental_suite(*, package: Path, output: Path, target_id: str, timeout: float = 30) -> dict:
    package=package.resolve();output=output.resolve()
    if not math.isfinite(timeout) or timeout<=0 or output.is_relative_to(package) or package.is_relative_to(output):
        raise ValueError('experimental execution requires a positive deadline and separate output')
    started=time.monotonic()
    admission=_ExperimentalAdmission(package)
    manifest=admission.manifest
    timings=[{'phase':'evidence-validation','step':'suite-admission',
        'reuse_limitation':admission.reuse_limitation,'seconds':time.monotonic()-started}]
    if manifest['target_id']!=target_id:
        raise ValueError('experimental package belongs to another target')
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError('experimental run output must be new or empty')
    output.mkdir(parents=True,exist_ok=True)
    started=time.monotonic()
    runtime=_prepare_runtime(package,output,manifest)
    prefix=output/'wine';prefix.mkdir(mode=0o700)
    environment=_case_environment(runtime,manifest)
    effective=_effective_suite(package,runtime,manifest)
    suite=output/'effective-suite.json';write_json(suite,effective)
    timings.append({'phase':'preparation','seconds':time.monotonic()-started})
    reports=[];resources={};resource_reports={};programs={};program_reports={}
    environment_sha256=sha256_text(json.dumps(dict(os.environ),sort_keys=True))
    server=manifest['bindings']['tools']['server']
    with wine_sessions(server=server['path'] if server else None,
            environments={'candidate':{**os.environ,**environment}}, cwd=runtime,
            logs=output, timeout=timeout, timings=timings, persistent=normal_program(manifest), dispose_prefixes=True,
            runner=manifest['bindings']['tools']['runner']['path'] if server else None):
        if normal_program(manifest):
            prepare_program_drive(manifest['bindings']['program']['driver'],prefix,runtime)
        for index,identity in enumerate(manifest['case_ids']):
            destination=output/'cases'/str(index)
            case_result=_run_admitted_case(admission=admission,case_id=identity,output=destination,
                runtime=runtime,suite=suite,timeout=timeout,timings=timings)
            reports.append(destination)
            if 'program' in case_result:
                programs[identity]=case_result['program']
                program_reports[str((destination/'program-observations.json').relative_to(output))]=sha256_file(destination/'program-observations.json')
            if 'resources' in case_result:
                resources[identity]=case_result['resources']
                resource_reports[str((destination/'resource-observations.json').relative_to(output))]=sha256_file(destination/'resource-observations.json')
    started=time.monotonic()
    admission.check()
    _validate_execution_inputs(admission=admission,runtime=runtime,suite=suite)
    timings.append({'phase':'evidence-validation','step':'before-report','seconds':time.monotonic()-started})
    started=time.monotonic()
    report=aggregate_candidate_test_cases(suite=suite,out=output/'test-results',case_reports=reports)
    timings.append({'phase':'reporting','seconds':time.monotonic()-started})
    result={'format':EXPERIMENTAL_COMPONENT_RUN_V1_FORMAT,'authority':'experimental-execution-only',
        'status':report['status'],'scope':manifest['scope'],'manifest_sha256':manifest['manifest_sha256'],
        'environment_sha256':environment_sha256,
        'runtime_state':{'process_scope':'fresh-per-case','prefix_scope':'suite-shared',
            'explicit_server_persistence':normal_program(manifest) and server is not None},
        'candidate_sha256':manifest['bindings']['candidate_sha256'],
        'candidate_report_sha256':sha256_file(output/'test-results/candidate-test-report.json'),
        'effective_suite_sha256':sha256_file(suite),'timings':timings}
    if normal_program(manifest):
        driver=manifest['bindings']['program']['driver']
        result['runtime_state']['program_path']=dict(drive=driver['process'].get('drive'),
            image=program_image_path(driver,runtime),runtime_directory='runtime')
    if resources:
        result['behavioral_status']=result['status']
        result['resources']=resources
        result['resource_report_sha256s']=resource_reports
        if any(row['status']!='satisfied' for row in resources.values()):
            result['status']='fail'
    if programs:
        result.setdefault('behavioral_status',report['status'])
        result['programs']=programs
        result['program_report_sha256s']=program_reports
        if any(row['status']!='pass' for row in programs.values()):result['status']='fail'
    # Timings retain floating-point measurements outside the stable run binding.
    result['binding_sha256']=canonical_sha256_v3({k:v for k,v in result.items() if k!='timings'})
    write_json(output/'experimental-run.json',result)
    return result
