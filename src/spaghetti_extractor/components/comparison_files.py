"""Declared mutable working files in concrete normal-program comparisons.

Initial bytes stay in the input package. Runtime copies persist within one side
of a suite; per-case snapshots retain file presence and exact resulting bytes.
This follows the existing flat runtime-file layout, not a filesystem sandbox.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil

from ..util import sha256_file, write_json
from .comparison_runtime import check_runtime_inputs

MAX_FILE_BYTES = 64 * 1024 * 1024


def mutable_files(driver: dict) -> list[str]:
    return driver.get('process', {}).get('mutable_files', [])


def checked_mutable_files(driver: dict, runtime_files: list[str]) -> None:
    names = mutable_files(driver)
    if not isinstance(names, list) or any(not isinstance(name, str) for name in names):
        raise ValueError('program mutable_files must be a list of working-directory filenames')
    reserved = {'tmp', 'spaghetti-observation.json', 'spaghetti-capture.exe', 'comparison.exe',
                Path(driver['image']).name.casefold(), driver['library'].casefold()}
    devices = {'con', 'prn', 'aux', 'nul', *('com'+str(i) for i in range(1, 10)),
               *('lpt'+str(i) for i in range(1, 10))}
    seeds = {Path(name).name.casefold() for name in runtime_files}
    for name in names:
        if (not name or name in {'.', '..'} or name.endswith((' ', '.'))
                or any(ord(c) < 32 or c in '/\\:*?"<>|' for c in name)
                or name.casefold() in reserved or name.split('.')[0].casefold() in devices):
            raise ValueError('invalid or reserved mutable program filename: '+name)
        if name.casefold() in seeds and Path(name).suffix.casefold() in {'.exe', '.dll', '.com', '.drv', '.ocx', '.sys'}:
            raise ValueError('program executable/library inputs cannot be mutable: '+name)
    if len({name.casefold() for name in names}) != len(names):
        raise ValueError('mutable program filenames collide under Windows case folding')


def immutable_bindings(driver: dict, bindings: dict) -> dict:
    mutable = {name.casefold() for name in mutable_files(driver)}
    return {name: digest for name, digest in bindings.items() if name.casefold() not in mutable}


def _entries(directory: Path) -> dict[str, Path]:
    paths = list(directory.iterdir())
    entries = {path.name.casefold(): path for path in paths}
    if len(entries) != len(paths):
        raise ValueError('program working filenames collide under Windows case folding')
    return entries


def _file_state(path: Path | None) -> dict:
    if path is None:
        return {'status': 'absent'}
    if path.is_symlink() or not path.is_file():
        raise ValueError('mutable program file is not an ordinary file: '+path.name)
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError('mutable program file exceeds the 64 MiB observation limit: '+path.name)
    return {'status': 'present', 'size': size, 'sha256': sha256_file(path)}


def check_program_files(directory: Path, driver: dict, bindings: dict) -> None:
    check_runtime_inputs(directory, immutable_bindings(driver, bindings))
    entries = _entries(directory)
    temporary = directory/'tmp'
    if temporary.is_symlink() or not temporary.is_dir():
        raise ValueError('program requires its private temporary directory')
    allowed = {name.casefold() for name in bindings} | {name.casefold() for name in mutable_files(driver)} | {'tmp'}
    extra = sorted(entries.keys()-allowed)
    if extra:
        raise ValueError('unexpected program working-directory mutation: '+', '.join(extra))
    for name in mutable_files(driver):
        _file_state(entries.get(name.casefold()))


def retain_program_files(directory: Path, driver: dict, prefix: Path) -> None:
    names = mutable_files(driver)
    if not names:
        return
    destination = prefix.with_suffix('.files')
    destination.mkdir()
    entries = _entries(directory)
    observations = {}
    for name in names:
        path = entries.get(name.casefold())
        state = _file_state(path)
        if path is not None:
            shutil.copyfile(path, destination/name)
            if _file_state(destination/name) != state:
                raise ValueError('program file changed during observation: '+name)
        observations[name] = state
    write_json(prefix.with_suffix('.files.json'), observations)


def read_program_files(driver: dict, prefix: Path) -> dict:
    names = mutable_files(driver)
    report = prefix.with_suffix('.files.json')
    directory = prefix.with_suffix('.files')
    if (report.is_symlink() or not report.is_file() or directory.is_symlink()
            or (directory.exists() and not directory.is_dir())):
        raise ValueError('program file observations are missing')
    if report.stat().st_size > 8 * 1024 * 1024:
        raise ValueError('program file observation report exceeds 8 MiB')
    observations = json.loads(report.read_text())
    if not isinstance(observations, dict) or set(observations) != set(names):
        raise ValueError('program file observations differ from declared mutable files')
    # Reuse copies bound files, so an all-absent snapshot needs no empty directory.
    entries = _entries(directory) if directory.is_dir() else {}
    if set(entries)-{name.casefold() for name in names}:
        raise ValueError('program file snapshot includes an undeclared file')
    for name in names:
        if observations[name] != _file_state(entries.get(name.casefold())):
            raise ValueError('program file snapshot differs from its observation: '+name)
    return observations
