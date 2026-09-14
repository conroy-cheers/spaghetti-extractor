"""Stable compiler paths without rewriting compiled programs or cache keys."""

from pathlib import Path
import shutil

from .bisimulation_support import BisimulationRefinementError


VIRTUAL_WORKSPACE = Path('/tmp/spx-proof')


def workspace_compile_command(command, workspace):
    """Keep authored input paths; give generated proof files one private path.

    GOTO stores the compiler's working directory as source metadata. A separate
    mount namespace makes that directory stable even for concurrent builds.
    External source/include paths retain their spelling and contents, including
    observable __FILE__ strings. No compiled bytes are subsequently normalized.
    """
    root = Path(workspace).resolve()
    executable = shutil.which('bwrap')
    if executable is None:
        raise BisimulationRefinementError('stable proof compilation requires the Nix bubblewrap tool')
    if not root.is_dir():
        raise BisimulationRefinementError('proof compiler workspace is absent')
    restored = set()
    translated = []
    for argument in command:
        path = Path(argument)
        if path.is_absolute() and path.is_relative_to(root):
            translated.append(str(VIRTUAL_WORKSPACE / path.relative_to(root)))
        else:
            translated.append(argument)
            # /tmp becomes private writable compiler scratch. Restore declared
            # external inputs there, such as a source package in a test fixture.
            if path.is_absolute() and path.is_relative_to('/tmp') and path.exists():
                restored.add(path if path.is_dir() else path.parent)
    if any(path == Path('/tmp') or path == VIRTUAL_WORKSPACE
           or path.is_relative_to(VIRTUAL_WORKSPACE) or VIRTUAL_WORKSPACE.is_relative_to(path)
           for path in restored):
        raise BisimulationRefinementError('external compiler input overlaps its private workspace')
    restored = sorted(path for path in restored if not any(
        path != parent and path.is_relative_to(parent) for parent in restored))
    return [executable, '--die-with-parent', '--ro-bind', '/', '/',
            '--tmpfs', '/tmp', '--setenv', 'TMPDIR', '/tmp',
            *(arg for path in restored for arg in ('--ro-bind', str(path), str(path))),
            '--bind', str(root), str(VIRTUAL_WORKSPACE), '--chdir', str(VIRTUAL_WORKSPACE),
            *translated]
