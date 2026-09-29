"""Optional diagnostic preprocessing using the selected compilation command.

Raw authored C remains the export input. These per-configuration views are not
effect checks, portable sources, proof inputs, or permission to execute.
"""
from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file, write_json


def write_compiler_view(command, *, cwd: Path, output: Path, environment=None, timeout=30) -> dict:
    """Retain active C, macro definitions, line markers and exact consumed inputs."""
    output.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ) if environment is None else environment
    options = []
    arguments = iter(command[1:])
    for argument in arguments:
        if argument in ('-o', '-MF'):
            next(arguments)
        elif argument not in ('-c', '-MD', '-MMD'):
            options.append(argument)
    active = output/'active.i'
    dependencies = output/'dependencies.d'
    diagnostic = output/'compiler.stderr'
    invocation = [command[0], *options, '-E', '-dD', '-MD', '-MF', str(dependencies), '-o', str(active)]
    result = dict(status='unavailable', command=invocation,
        compilation_command=list(command), compiler_sha256=sha256_file(Path(command[0]).resolve()),
        environment_sha256=canonical_sha256_v3(environment), inputs={},
        scope='diagnostic preprocessing invocation for this configuration; author and export the original C')
    try:
        with diagnostic.open('w') as stream:
            completed = subprocess.run(invocation, cwd=cwd, env=environment, stdout=stream,
                                       stderr=subprocess.STDOUT, timeout=timeout, check=False)
        result['returncode'] = completed.returncode
        if completed.returncode == 0:
            for filename in shlex.split(dependencies.read_text().replace('\\\n', ' ').split(':', 1)[1]):
                path = Path(filename)
                path = path if path.is_absolute() else cwd/path
                result['inputs'][str(path)] = sha256_file(path)
            result['status'] = 'available'
    except (OSError, ValueError, IndexError, subprocess.SubprocessError) as error:
        result['diagnostic'] = str(error)
    result['files'] = {path.name: sha256_file(path) for path in (active, dependencies, diagnostic) if path.is_file()}
    write_json(output/'view.json', result)
    return result
