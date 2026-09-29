"""Apply reviewed declarations through the target's existing canonical indexes.

This changes authoring inputs only. C source, evidence and activation are not
installed. Multi-file writes share component start's lock and roll back caught
failures; retained staging after process death blocks another application.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tempfile
from typing import Mapping

from ..components.bisimulation import ComponentBisimulationIntentV1
from ..components.indexes_v5 import ComponentIntentIndexV5, load_component_intent_index_v5
from ..components.lifting_intent import ComponentLiftingIntentV1
from ..components.relation_v5 import ComponentRelationIntentV1
from ..target_bundles.metadata import TargetMetadata
from .component_review import reviewed_configured_component_inputs
from .component_start import _component_start_lock_path


def _path(bundle: Path, relative: str) -> Path:
    if not isinstance(relative, str):
        raise ValueError('component application path must be text')
    name = PurePosixPath(relative)
    if (not name.parts or name.is_absolute() or name.as_posix() != relative
            or any(part in {'.', '..'} for part in name.parts)):
        raise ValueError('component application requires canonical relative paths')
    path = bundle
    for part in name.parts:
        path /= part
        if path.is_symlink():
            raise ValueError(f'component application path contains a symbolic link: {relative}')
    if path.exists() and not path.is_file():
        raise ValueError(f'component application path is not a regular file: {relative}')
    return path


def _json_bytes(payload: Mapping) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + '\n').encode()


def _apply_files(bundle: Path, originals: dict[Path, bytes | None], updates: dict[Path, bytes]) -> None:
    """Stage before mutation, detect intervening writes, preserve recovery data."""
    updates = {path: data for path, data in updates.items() if data != originals[path]}
    if not updates:
        return
    staging = Path(tempfile.mkdtemp(prefix='.component-review-', dir=bundle))
    installed = []
    created_dirs = []
    cleanup = True
    try:
        journal = []
        for index, (path, data) in enumerate(updates.items()):
            candidate = staging / f'{index}.new'
            candidate.write_bytes(data)
            before = originals[path]
            if before is not None:
                mode = path.stat().st_mode & 0o777
                candidate.chmod(mode)
                backup = staging / f'{index}.original'
                backup.write_bytes(before)
                backup.chmod(mode)
            journal.append({'path': path.relative_to(bundle).as_posix(),
                            'original': None if before is None else f'{index}.original',
                            'staged': f'{index}.new'})
        (staging / 'journal.json').write_bytes(_json_bytes({'files': journal}))
        for path, before in originals.items():
            _path(bundle, path.relative_to(bundle).as_posix())
            current = path.read_bytes() if path.exists() else None
            if current != before:
                raise ValueError(f'component application input changed during review: {path}')
        try:
            for index, (path, data) in enumerate(updates.items()):
                missing = []
                parent = path.parent
                while not parent.exists():
                    missing.append(parent)
                    parent = parent.parent
                for parent in reversed(missing):
                    parent.mkdir()
                    created_dirs.append(parent)
                installed.append((index, path, data))
                os.replace(staging / f'{index}.new', path)
        except BaseException:
            cleanup = False
            for index, path, data in reversed(installed):
                # Do not undo a non-cooperating writer's intervening edit.
                _path(bundle, path.relative_to(bundle).as_posix())
                current = path.read_bytes() if path.exists() else None
                if current == originals[path]:
                    continue  # The attempted rename did not take effect.
                if current != data:
                    raise ValueError(f'rollback conflicts with an external edit; recovery inputs: {staging}')
                if originals[path] is None:
                    path.unlink()
                else:
                    os.replace(staging / f'{index}.original', path)
            for parent in reversed(created_dirs):
                parent.rmdir()
            cleanup = True
            raise
    finally:
        if cleanup:
            shutil.rmtree(staging)


def apply_reviewed_component_inputs(*, draft: Path, package: Mapping, target: str,
                                   bundle: Path, authoring_paths: Mapping | None) -> dict:
    reviewed = reviewed_configured_component_inputs(draft=draft, package=package, program_id=target)
    if not isinstance(authoring_paths, Mapping) or set(authoring_paths) != {'intent', 'interface_index', 'binding_index'}:
        raise ValueError('target operator index has no complete component authoring paths; refresh its SDK')
    bundle = bundle.resolve()
    paths = {name: _path(bundle, value) for name, value in authoring_paths.items()}
    if len(set(paths.values())) != len(paths):
        raise ValueError('component authoring paths overlap')
    with _component_start_lock_path(paths['intent']).open('a+') as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError('another component authoring transaction is active') from exc
        pending = sorted(bundle.glob('.component-review-*'))
        if pending:
            raise ValueError(f'interrupted component application requires recovery from {pending[0]} before retrying')
        return _apply_locked(draft, package, target, bundle, paths, reviewed)


def _apply_locked(draft, package, target, bundle, paths, reviewed):
    originals = {}
    updates = {}

    def read(path):
        _path(bundle, path.relative_to(bundle).as_posix())
        originals[path] = path.read_bytes() if path.exists() else None
        return json.loads(originals[path]) if originals[path] is not None else None

    def update(path, payload):
        if path in updates:
            raise ValueError('component application destinations overlap')
        before = read(path) if path not in originals else (
            json.loads(originals[path]) if originals[path] is not None else None)
        updates[path] = originals[path] if payload == before else _json_bytes(payload)

    metadata_path = _path(bundle, 'target.json')
    metadata = TargetMetadata.parse(read(metadata_path))
    metadata_paths = dict(metadata.paths)
    if metadata.identity != target or str(metadata_paths.get('components')) != paths['intent'].relative_to(bundle).as_posix():
        raise ValueError('operator authoring paths disagree with local target metadata')
    lifting = ComponentLiftingIntentV1.parse(read(paths['intent']))
    identity = package['component_id']
    selected = [dict(row) for row in lifting.components if row['id'] == identity]
    if len(selected) != 1:
        raise ValueError('reviewed component is absent from the target lifting intent')
    component = selected[0]
    baseline = package['requirements']['editing_inputs']
    for kind, key, field, directory, original_key in (
        ('interface', 'interface_index', 'interface_intent', 'interfaces-v5', 'interface'),
        ('machine_binding', 'binding_index', 'binding_intent', 'bindings-v5', 'binding'),
    ):
        index_path = paths[key]
        index = ComponentIntentIndexV5.parse(read(index_path), kind=kind)
        for row in index.components:
            read(index_path.parent / row[field])
        load_component_intent_index_v5(index_path, kind=kind)
        matches = [row for row in index.components if row['component_id'] == identity]
        if len(matches) != 1 or matches[0]['intent_sha256'] != baseline[original_key]['intent_sha256']:
            raise ValueError(f'component {original_key} baseline is stale in the local target')
        replacement = reviewed[f'{directory}/{identity}.json']
        update(index_path.parent / matches[0][field], replacement)
        rows = [{**row, 'intent_sha256': replacement['intent_sha256']} if row['component_id'] == identity else row
                for row in index.components]
        blockers = [row for row in index.blockers if row['component_id'] != identity]
        blockers.extend(reviewed[f'{directory}/index.json']['blockers'])
        update(index_path, ComponentIntentIndexV5.create(kind=kind, components=rows, blockers=blockers).to_payload())

    for field, original_key, directory, label, parser in (
        ('bisimulation_intent', 'bisimulation', 'bisimulation', 'cutpoint', ComponentBisimulationIntentV1),
        ('relation_intent', 'relation', 'relations', 'relation', ComponentRelationIntentV1),
    ):
        relative = component.get(field)
        old = None
        if relative is not None:
            path = _path(bundle, (paths['intent'].parent.relative_to(bundle) / relative).as_posix())
            old = parser.parse(read(path)).to_payload()
        if old != baseline.get(original_key):
            raise ValueError(f'component {label} baseline is stale in the local target')
        new = reviewed.get(f'{directory}/{identity}.json')
        if new is not None:
            relative = relative or f'{directory}/{identity}.json'
            if any(row['id'] != identity and row.get(field) == relative for row in lifting.components):
                raise ValueError(f'component {label} destination is shared by another component')
            path = _path(bundle, (paths['intent'].parent.relative_to(bundle) / relative).as_posix())
            if old is None and (path.exists() or path.is_symlink()):
                raise ValueError(f'new component {label} destination is occupied')
            update(path, new)
            component[field] = relative
    if component != next(row for row in lifting.components if row['id'] == identity):
        components = [component if row['id'] == identity else row for row in lifting.components]
        update(paths['intent'], ComponentLiftingIntentV1.create(program_id=lifting.program_id,
            components=components, groups=lifting.groups, configurations=lifting.configurations).to_payload())

    source = component.get('source', {})
    source_root = metadata_paths.get('component_sources')
    if source.get('files') and source_root is None:
        raise ValueError('target metadata must declare component_sources to identify checked C')
    source_files = [] if source_root is None else [
        _path(bundle, (source_root / name).as_posix()).relative_to(bundle).as_posix() for name in source.get('files', [])]
    changed = [path.relative_to(bundle).as_posix() for path, value in updates.items() if value != originals[path]]
    _apply_files(bundle, originals, updates)
    return {'authority': False, 'component_id': identity, 'changed_files': sorted(changed),
            'source_installed': False, 'configured_source_files': source_files,
            'draft_source': str(draft / 'src/component.c'),
            'next_action': 'Review/install authored C in the configured source files, then run component check --source '
                           'and the complete component check; recheck changed contracts before selection.'}
