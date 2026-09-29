"""Convenient destinations for repeated checks; receipts keep their normal authority.

History is an append-only directory of ordinary comparisons and a replaceable
latest symlink. The semantic engine still validates every reuse request. It is
not another evidence format or a mutable result directory.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import tempfile


def _latest(history: Path, target: str, component: str) -> Path | None:
    pointer=history/'latest'
    if not pointer.is_symlink():
        if pointer.exists():raise ValueError('comparison history latest must be its managed symlink')
        return None
    name=Path(os.readlink(pointer))
    result=history/name
    if (name.is_absolute() or len(name.parts)!=1 or not name.name.startswith('check-')
            or result.is_symlink() or not result.is_dir()):
        raise ValueError('comparison history latest must name a retained check in this directory')
    # This only keeps unrelated components out of one history. run_comparison
    # performs the complete existing evidence validation before reusing anything.
    try:
        value=json.loads((result/'comparison-result.json').read_text())
    except (OSError,ValueError) as error:
        raise ValueError('comparison history latest has no readable terminal result: '+str(result)) from error
    if not isinstance(value,dict) or (value.get('target_id'),value.get('component_id'))!=(target,component):
        raise ValueError('comparison history belongs to another target/component; choose a separate history')
    return result


@contextmanager
def comparison_history(*, history: Path, package: Path, target: str, component: str,
                       reuse: Path | None = None, baseline: Path | None = None):
    """Allocate one check and publish latest only after the caller validates it."""
    history=history.resolve()
    if history.is_relative_to(package.resolve()):
        raise ValueError('comparison history must be outside the editable input package')
    history.mkdir(parents=True,exist_ok=True)
    if (history/'.lock').is_symlink():
        raise ValueError('comparison history lock must not be a symlink')
    with (history/'.lock').open('a') as lock:
        try:
            fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError('another check is using this comparison history; wait for it to finish') from error
        prior=_latest(history,target,component)
        output=Path(tempfile.mkdtemp(prefix='check-',dir=history))
        selected=reuse if reuse is not None else prior if prior is not None else baseline
        yield output,selected.resolve() if selected is not None else None
        if not (output/'comparison-result.json').is_file():
            raise ValueError('comparison did not retain a terminal result: '+str(output))
        if _latest(history,target,component)!=prior:
            raise ValueError('comparison completed at '+str(output)+'; history latest changed and was left untouched')
        pending=history/('.latest-'+output.name)
        pending.symlink_to(output.name)
        try:
            pending.replace(history/'latest')
        finally:
            pending.unlink(missing_ok=True)
