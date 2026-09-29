"""Capture Win32 application streams separately from Wine host diagnostics."""
from __future__ import annotations

import json
from pathlib import Path
import shutil

from .comparison_services import INSTRUMENTATION_LIMIT

LEGACY_CAPTURE = 'win32-standard-handles-v1'
CAPTURE = 'win32-standard-handles-and-trace-v2'
TRACE_PREFIXES = (b'SPX_SERVICE ', b'SPX_SERVICE_SCOPE ', b'SPX_SERVICE_HANDLER ', b'SPX_RESOURCE ')
LAUNCHER = 'spaghetti-capture.exe'
RESOURCES = Path(__file__).parents[1]/'resources/native'
SOURCES = ('pe32-output-capture.c', 'pe32-process-observer.h')
PYTHON_RESOURCES = (
    'src/spaghetti_extractor/resources/native/pe32-output-capture.c',
    'src/spaghetti_extractor/resources/native/pe32-process-observer.h',
)


def build_capture(*, compiler, output, env, timeout, timings):
    from .comparison_build import observed_command
    for name in SOURCES:
        shutil.copyfile(RESOURCES/name, output/name)
    result = observed_command([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
        '-municode', 'pe32-output-capture.c', '-o', LAUNCHER], cwd=output, env=env,
        timeout=timeout, output=output/'capture-compiler', phase='capture-compiler', timings=timings)
    return not result['returncode'] and not result['timed_out']


def capture_command(command, *, runtime, launcher, env, timeout):
    directory = runtime/'tmp/spaghetti-capture'
    if directory.exists() or directory.is_symlink():
        raise ValueError('program capture directory was not fresh before execution')
    directory.mkdir()
    # Program files live in cwd. Preserve an explicitly selected DOS drive;
    # otherwise use a relative Windows pathname, never a Unix path in CreateProcess.
    runner, image, *arguments = command
    if image.startswith('/'):
        image = '.\\'+Path(image).name
    return [runner, str(launcher), image, *arguments], {
        **env, 'SPX_CAPTURE_TIMEOUT_MS': str(max(1, min(0xfffffffe, int(timeout*1000))))}


def collect_capture(*, runtime, prefix, execution, kind=CAPTURE):
    """Retain both channels, even on failure. Never fall back to mixed output."""
    directory = runtime/'tmp/spaghetti-capture'
    if kind not in (CAPTURE, LEGACY_CAPTURE):
        raise ValueError('unknown program output capture')
    execution['output_capture'] = kind
    for stream in ('stdout', 'stderr'):
        prefix.with_suffix('.'+stream).rename(prefix.with_suffix('.host.'+stream))
        source = directory/stream
        if source.is_symlink() or not source.is_file():
            execution['observation_error'] = 'program capture did not retain application '+stream
            prefix.with_suffix('.'+stream).write_bytes(b'')
        else:
            shutil.copyfile(source, prefix.with_suffix('.'+stream))
    if kind == CAPTURE:
        source = directory/'trace'
        if source.is_symlink() or not source.is_file():
            execution['observation_error'] = 'program capture did not retain instrumentation trace'
        else:
            shutil.copyfile(source, prefix.with_suffix('.trace'))
    report = directory/'result.json'
    if report.is_symlink() or not report.is_file():
        execution['observation_error'] = 'program capture did not produce its completion report'
    else:
        shutil.copyfile(report, prefix.with_suffix('.capture.json'))
        try:
            validate_capture(prefix, execution)
        except (ValueError, OSError) as error:
            execution['observation_error'] = str(error)
    if directory.is_dir() and not directory.is_symlink():
        shutil.rmtree(directory)


def validate_capture(prefix, execution):
    if 'output_capture' not in execution:
        return  # Retained comparisons predating separate capture keep their meaning.
    version = execution['output_capture']
    if version not in (LEGACY_CAPTURE, CAPTURE):
        raise ValueError('unknown program output capture')
    report = json.loads(prefix.with_suffix('.capture.json').read_text())
    fields = {'status', 'error', 'exit_code'} | ({'trace_status', 'trace_bytes'} if version == CAPTURE else set())
    if (not isinstance(report, dict) or set(report) != fields
            or any(type(value) is not int or not 0 <= value <= 0xffffffff for value in report.values())):
        raise ValueError('invalid program capture completion report')
    if report['status'] != 0:
        stages = {1:'setup', 2:'spawn', 3:'I/O', 4:'output limit', 5:'timeout', 6:'wait'}
        stage = stages.get(report['status'], 'unknown status '+str(report['status']))
        if report.get('trace_status'):
            stage = 'instrumentation '+stage
        raise ValueError(f'program capture failed: {stage}, Win32 error={report["error"]}')
    if version == CAPTURE:
        trace = prefix.with_suffix('.trace')
        if (report['trace_status'] or report['trace_bytes'] > INSTRUMENTATION_LIMIT or trace.is_symlink()
                or not trace.is_file() or trace.stat().st_size != report['trace_bytes']):
            raise ValueError('program instrumentation trace is missing, incomplete or oversized')
        with trace.open('rb') as stream:
            if any(not line.startswith(TRACE_PREFIXES) for line in stream):
                raise ValueError('program instrumentation trace contains unclassified bytes')
    if report['exit_code'] % 256 != execution['returncode']:
        raise ValueError('program exit differs from runner exit')


def instrumentation_path(prefix, execution):
    """Never fall back to application bytes when a separate trace was required."""
    return prefix.with_suffix('.trace' if execution.get('output_capture') == CAPTURE else '.stderr')
