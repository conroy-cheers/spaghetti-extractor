"""Owned Wine server lifecycles shared by comparison and experimental execution.

Prefixes are created by the caller for this run. Persistence is explicit; it
never promises case-state isolation. Cases within a prefix share external state,
while comparison sides receive distinct prefixes. Admission remains in callers.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
import os
from pathlib import Path
import signal
import shutil
import threading
import sys
import time

from ..util import sha256_file
from .comparison_build import observed_command

RUNTIME_CLEANUP_COMMAND_SECONDS = 2.0
PREFIX_DISPOSAL_SECONDS = 10.0


def _start_prefixes(*, runner, environments, cwd, logs, timeout, timings):
    """Boot private prefixes together; finish every worker before any teardown.

    Cancellation stops running commands and joins them before teardown. Suppress
    repeat signals so no worker can write into a disposed prefix.
    Cases remain ordered and cannot start until all prefixes are ready.
    """
    if not environments:
        return
    started = time.monotonic()
    command_timings = {label: [] for label in environments}
    cancellation = threading.Event()
    handlers = {}

    def boot(label):
        result = observed_command([runner, 'wineboot.exe', '--init'], cwd=cwd,
            env=environments[label], timeout=timeout, output=logs/f'prefix-start-{label}',
            phase='runtime-startup', timings=command_timings[label], cancel_event=cancellation)
        if result['returncode'] or result['timed_out'] or result['cancelled']:
            raise ValueError(f'Wine prefix startup failed for {label}; inspect retained startup log')

    try:
        if len(environments) == 1:
            boot(next(iter(environments)))
        else:
            with ThreadPoolExecutor(max_workers=2) as pool:
                try:
                    futures = [pool.submit(boot, label) for label in environments]
                    for future in as_completed(futures):
                        future.result()
                except BaseException:
                    if threading.current_thread() is threading.main_thread():
                        handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
                        for sig in handlers:
                            signal.signal(sig, lambda signum, frame: None)
                    cancellation.set()
                    # Join bounded process cleanup before wine_sessions stops
                    # servers or disposes prefixes.
                    pool.shutdown(wait=True, cancel_futures=True)
                    raise
    finally:
        for label, rows in command_timings.items():
            timings.extend({**row, 'runtime': label} for row in rows)
        timings.append({'phase': 'runtime-startup-wall', 'seconds': time.monotonic() - started,
            'max_concurrency': min(2, len(environments)), 'overlaps': ['runtime-startup']})
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


@contextmanager
def wine_sessions(*, server: str | None, environments: dict[str, dict],
                  cwd: Path, logs: Path, timeout: float, timings: list,
                  persistent: bool, dispose_prefixes: bool = False, runner: str | None = None):
    if server is not None and not os.environ.get('WAYLAND_DISPLAY'):
        raise ValueError('Wine execution requires a headless Wayland desktop; use spaghetti-headless-wayland')
    owned = environments if server is not None else {}
    prefixes = [Path(env['WINEPREFIX']).resolve() for env in owned.values()]
    if len(set(prefixes)) != len(prefixes) or any(not p.is_dir() for p in prefixes):
        raise ValueError('Wine sessions require distinct, existing private prefixes')
    original_error = None
    cleanup_errors = []
    old_handlers = {}
    # SIGINT already raises KeyboardInterrupt. SIGTERM must also unwind Python
    # contexts so the owned server is stopped before the outer desktop exits.
    if threading.current_thread() is threading.main_thread():
        old_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
        def terminate(signum, frame):
            raise SystemExit(128 + signum)
        signal.signal(signal.SIGTERM, terminate)
    try:
        if persistent:
            for label, env in owned.items():
                setup = observed_command([server, '-p'], cwd=cwd, env=env,
                    timeout=timeout, output=logs/f'server-start-{label}',
                    phase='runtime-setup', timings=timings)
                if setup['returncode'] or setup['timed_out']:
                    raise ValueError(f'Wine runtime startup failed for {label}; inspect retained server log')
        if runner is not None:
            _start_prefixes(runner=runner, environments=owned, cwd=cwd,
                logs=logs, timeout=timeout, timings=timings)
        yield
    except BaseException as error:
        original_error = error
        raise
    finally:
        # A second cancellation must not interrupt the finite server teardown.
        for sig in old_handlers:
            signal.signal(sig, lambda signum, frame: None)
        try:
            for label, env in owned.items():
                failures_before = len(cleanup_errors)
                for name, argument in (('stop', '-k'), ('wait', '-w')):
                    try:
                        result = observed_command([server, argument], cwd=cwd, env=env,
                            timeout=min(timeout, RUNTIME_CLEANUP_COMMAND_SECONDS),
                            output=logs/f'server-{name}-{label}',
                            phase='runtime-teardown', timings=timings)
                        # -k returns 1 when no server remains. The following -w
                        # must still succeed; it is not safe to ignore wait errors.
                        accepted = (0, 1) if name == 'stop' else (0,)
                        if result['timed_out'] or result['returncode'] not in accepted:
                            cleanup_errors.append(f'{label}: {name} failed')
                    except Exception as error:
                        cleanup_errors.append(f'{label}: {name}: {error}')
                if dispose_prefixes and len(cleanup_errors) == failures_before:
                    try:
                        # The caller explicitly owns this disposable prefix.
                        # Bound deletion too; retain logs and replay inputs outside it.
                        result = observed_command([sys.executable, '-I', '-c',
                            'import shutil,sys; shutil.rmtree(sys.argv[1])', env['WINEPREFIX']],
                            cwd=cwd, env=env, timeout=PREFIX_DISPOSAL_SECONDS,
                            output=logs/f'prefix-dispose-{label}', phase='runtime-disposal', timings=timings)
                        if result['timed_out'] or result['returncode']:
                            cleanup_errors.append(f'{label}: prefix disposal failed')
                    except Exception as error:
                        cleanup_errors.append(f'{label}: prefix disposal: {error}')
        finally:
            for sig, handler in old_handlers.items():
                signal.signal(sig, handler)
        if cleanup_errors:
            message = 'Wine runtime cleanup failed: ' + '; '.join(cleanup_errors)
            if original_error is not None:
                original_error.add_note(message)
            else:
                raise ValueError(message)


def prepare_comparison_runtime(*, build: Path, output: Path, names: list[str]) -> dict:
    """Private per-side working files; deliberately not a host filesystem sandbox.

    Immutable build inputs remain the replay authority. Only the copies execute,
    and their identities are checked before and after every case. Mutable relative
    files persist between cases within one side but cannot contaminate its peer.
    """
    bindings = {name: sha256_file(build/name) for name in names}
    sides = {}
    for side in ('original', 'source'):
        directory = output/f'runtime-{side}'
        directory.mkdir()
        for name in names:
            shutil.copy2(build/name, directory/name)
        (directory/'tmp').mkdir()
        sides[side] = directory
    return {'directories': sides, 'bindings': bindings}


def check_runtime_inputs(directory: Path, bindings: dict) -> None:
    for name, expected in bindings.items():
        path = directory/name
        if path.is_symlink() or not path.is_file() or sha256_file(path) != expected:
            raise ValueError(f'comparison runtime input changed: {name}')
