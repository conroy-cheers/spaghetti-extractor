"""Exercise actual registry/relative-file state in two owned comparison runtimes."""
import json
import os
from pathlib import Path
import shutil
import sys
import time

from spaghetti_extractor.components.comparison_build import observed_command
from spaghetti_extractor.components.comparison_runtime import (
    wine_sessions, prepare_comparison_runtime, check_runtime_inputs,
)
from spaghetti_extractor.util import write_json


def exercise(binary, output):
    output.mkdir()
    runner = shutil.which('wine')
    server = shutil.which('wineserver')
    if not runner or not server:
        raise ValueError('requires the provisioned Wine runtime')
    build = output/'build'
    build.mkdir()
    shutil.copyfile(binary, build/'comparison.exe')
    runtime = prepare_comparison_runtime(build=build, output=output, names=['comparison.exe'])
    environments = {}
    for side, directory in runtime['directories'].items():
        prefix = output/f'wine-{side}'
        prefix.mkdir(mode=0o700)
        environments[side] = dict(os.environ, WINEPREFIX=str(prefix), WINEPATH=str(directory),
            WINEDEBUG='-all', TMPDIR=str(directory/'tmp'))
    timings = []
    observations = []
    started = time.monotonic()
    with wine_sessions(server=server, environments=environments, cwd=build, logs=build,
            timeout=30, timings=timings, persistent=True, dispose_prefixes=True, runner=runner):
        for index in range(2):
            for side, directory in runtime['directories'].items():
                check_runtime_inputs(directory, runtime['bindings'])
                log = output/f'case-{index}-{side}'
                result = observed_command([runner, str(directory/'comparison.exe')], cwd=directory,
                    env=environments[side], timeout=30, output=log, phase='execution', timings=timings)
                if result['returncode'] or result['timed_out']:
                    raise ValueError(f'probe failed; inspect {log}')
                observed = json.loads(log.with_suffix('.stdout').read_text())
                if observed != {'registry':index, 'file':index}:
                    raise ValueError(f'private suite-shared runtime state differs: {side} {index} {observed}')
                observations.append(dict(side=side, case=index, observed=observed))
                check_runtime_inputs(directory, runtime['bindings'])
    if any(Path(env['WINEPREFIX']).exists() for env in environments.values()):
        raise ValueError('owned prefix was not disposed')
    write_json(output/'isolation.json', dict(status='pass', observations=observations, timings=timings,
        seconds=time.monotonic()-started, binary_sha256=runtime['bindings']['comparison.exe']))


if __name__ == '__main__':
    exercise(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
