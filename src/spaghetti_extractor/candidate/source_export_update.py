"""Refresh an existing compared source library without discarding operator work.

Ordinary updates keep boundaries fixed. Operators can explicitly accept reviewed
boundary/header changes for named components, then revalidate their integration.
This records source provenance, not contract compatibility. The prior tree is retained.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

from ..util import sha256_file, write_json
from ..components.source import load_component_source_workspace
from .source_export import _build_path, checked_source_build, export_comparison_sources, source_makefile


def _inventory(root: Path) -> dict:
    result = {}
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix()
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink(): result[name] = ('link', mode, os.readlink(path))
        elif path.is_file(): result[name] = ('file', mode, sha256_file(path))
        elif path.is_dir(): result[name] = ('directory', mode)
        else: raise ValueError('source export update cannot retain a special file: '+name)
    return result


def _owned_files(report: dict) -> dict:
    files = report.get('files')
    if not isinstance(files, dict) or 'source-export.json' in files:
        raise ValueError('source export update requires a valid previous file inventory')
    for name, digest in files.items():
        if not isinstance(name, str) or _build_path(name) != Path(name).as_posix() or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError('source export update has an invalid previous file entry')
    return files


def _sources(root: Path, report: dict, files: dict) -> tuple[set, dict, set, set]:
    from .source_export_bindings import source_private_headers
    authored = set(); objects = {}; headers = set(); private = set()
    for identity, unit in report['components'].items():
        package = _build_path(unit['source_package'])
        if files.get(package) != sha256_file(root/package):
            raise ValueError('source export update has a modified source package: '+package)
        source = json.loads((root/package).read_text())
        names = [row['path'] for row in source['files'] if row['path'].endswith('.c')]
        authored.update((Path(package).parent/'sources'/_build_path(name)).as_posix() for name in names)
        headers.update((Path(package).parent/'sources'/_build_path(row['path'])).as_posix()
                       for row in source['files'] if row['path'].endswith('.h'))
        private.update((Path(package).parent/'sources'/name).as_posix() for name in source_private_headers(unit,source))
        objects[identity] = {name for i in range(len(names))
            for name in (f'build/{identity}-{i}.o', f'build/{identity}-{i}.d')}
    return authored, objects, headers, private


def _previous_builds(root: Path, report: dict) -> dict:
    """Read current metadata or recognize the previous generated Makefile exactly.

    This is a data migration, never execution or inference of include precedence.
    A different legacy recipe requires a full export before partial updates.
    """
    units={name:dict(unit) for name,unit in report['components'].items()}
    make=(root/'Makefile').read_text()
    for identity,unit in units.items():
        package=_build_path(unit['source_package'])
        if report['files'].get(package)!=sha256_file(root/package):
            raise ValueError('source export update has a modified source package: '+package)
        source=json.loads((root/package).read_text())
        if 'build' not in unit:
            base=(Path(unit['source_package']).parent/'sources').as_posix()+'/'
            pattern=(re.escape('build/'+identity+'-')+r'(\d+)\.o: ([^\n]*)\n\t@mkdir -p build\n'
                r'\t\$\(CC\) \$\(CPPFLAGS\) \$\(CFLAGS\) ([^\n]*) -MMD -MP -c ([^\n ]+) -o \$@')
            rows=re.findall(pattern,make)
            if not rows or [int(row[0]) for row in rows]!=list(range(len(rows))):
                raise ValueError('legacy source build needs a full --update before --update-components')
            inputs=rows[0][1].split();includes=rows[0][2].split();sources=[row[3] for row in rows]
            if (any(row[1].split()!=inputs or row[2].split()!=includes for row in rows)
                    or any(not p.startswith(base) for p in inputs+sources)
                    or any(not p.startswith('-I'+base) for p in includes)):
                raise ValueError('legacy source build has unsupported component paths; use a full --update')
            unit['build']=dict(inputs=[p.removeprefix(base) for p in inputs],
                includes=[p.removeprefix('-I'+base) for p in includes],sources=[p.removeprefix(base) for p in sources])
        checked_source_build(unit['build'],source)
    if source_makefile(units)!=make:
        raise ValueError('source build recipe differs from its component metadata; use a full --update')
    return units


def _merge_components(root: Path, previous: dict, fresh: Path, report: dict,
                      accepted: set[str], removed: set[str]) -> tuple[list[str], dict[str, str]]:
    """Retain unmentioned source packages and their own comparison provenance."""
    incoming=set(report['components']);retained=set(previous['components'])-incoming-removed
    if incoming & removed:
        raise ValueError('source update both supplies and removes components: '+', '.join(sorted(incoming & removed)))
    unreviewed=incoming-previous['components'].keys()-accepted
    if unreviewed:
        raise ValueError('source update adds components: '+', '.join(sorted(unreviewed))+
            '; review application/backend bindings, then pass --accept-boundary-change COMPONENT for each addition')
    units=_previous_builds(root,previous);drafts={};draft_components=set()
    for identity in retained:
        prefix='components/'+identity+'/'
        if any(not units[identity][key].startswith(prefix) for key in ('source_package','interface')):
            raise ValueError('partial update requires the conventional component directory layout')
        _,edits=load_component_source_workspace(root/units[identity]['source_package'],
            private_headers=units[identity].get('private_headers'))
        base=Path(units[identity]['source_package']).parent/'sources'
        drafts.update({(base/name).as_posix():digest for name,digest in edits.items()})
        if edits:draft_components.add(identity)
        report['components'][identity]=units[identity]
        for name,digest in previous['files'].items():
            if not name.startswith(prefix):continue
            path=root/name
            if not path.is_file() or path.is_symlink() or sha256_file(path)!=drafts.get(name,digest):
                raise ValueError('retained source export input is stale or invalid: '+name)
            destination=fresh/name;destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(path,destination)
    from ..components.state_ownership import check_state_owner_selection
    check_state_owner_selection({name:unit['contract'].get('state_owners') for name,unit in report['components'].items()})
    # A new local result does not refine contracts still required by another unit.
    symbols={};representations={name:unit['contract'].get('representation') for name,unit in report['components'].items()}
    for identity,unit in report['components'].items():
        for symbol in unit['operation_symbols'].values():
            if symbol in symbols:raise ValueError('selected components repeat an operation symbol: '+symbol)
            symbols[symbol]=identity
        for req in unit.get('requirements',[]):
            supplier=report['components'].get(req['supplier'])
            if supplier is None or supplier['contract_sha256']!=req['contract_sha256']:
                raise ValueError('source update must refine '+identity+'/'+req['id']+
                    ' for supplier '+req['supplier']+'; include its reviewed comparison too')
        binding=representations[identity]
        if binding:
            for member in binding['group']['members']:
                if member in representations and representations[member]!=binding:
                    raise ValueError('source update has incompatible representation group '+binding['group']['id'])
    receipts={row['receipt_sha256']:row for row in previous['comparisons']+report['comparisons']}
    referenced={ref['comparison_receipt_sha256'] for unit in report['components'].values()
        for ref in unit.get('comparison_binding_references',[])}
    if any(not unit.get('comparison_binding_references') for unit in report['components'].values()):
        referenced.update(receipts)  # Older exports did not record per-unit references.
    report['comparisons']=[receipts[name] for name in sorted(referenced)]
    (fresh/'Makefile').write_text(source_makefile(report['components']))
    from ..operator.source_export_guidance import write_source_export_guidance
    write_source_export_guidance(fresh, report, draft_components=draft_components)
    report['files']={p.relative_to(fresh).as_posix():sha256_file(p)
        for p in fresh.rglob('*') if p.is_file() and p!=fresh/'source-export.json'}
    # Keep compared hashes for unchecked drafts. Their current bytes never gain
    # the neighbor's old evidence or the incoming consumer's new evidence.
    report['files'].update({name:previous['files'][name] for name in drafts})
    write_json(fresh/'source-export.json',report)
    from .source_export_bindings import source_export_workspace
    _,observed=source_export_workspace(fresh)
    if observed!=drafts:raise ValueError('retained source drafts changed while preparing the update')
    return sorted(retained), drafts


def update_comparison_sources(*, comparisons: list[Path], target_id: str, output: Path,
                              accept_boundary_changes: list[str] | None = None, partial: bool = False,
                              component_ids: list[str] | None = None,
                              remove_component_ids: list[str] | None = None) -> dict:
    if component_ids is not None and (not partial or not component_ids or len(set(component_ids))!=len(component_ids)):
        raise ValueError('named source updates require distinct components and --update-components')
    if remove_component_ids is not None and (not partial or not isinstance(remove_component_ids,list)
            or not remove_component_ids or any(not isinstance(name,str) for name in remove_component_ids)
            or len(set(remove_component_ids))!=len(remove_component_ids)):
        raise ValueError('component removal requires distinct names and --update-components')
    removed=set(remove_component_ids or [])
    output = Path(output)
    if output.is_symlink(): raise ValueError('source export update requires a real directory, not a symlink')
    output = output.resolve()
    if not output.is_dir(): raise ValueError('source export update requires an existing exported library')
    for comparison in comparisons:
        comparison = Path(comparison).resolve()
        if output.is_relative_to(comparison) or comparison.is_relative_to(output):
            raise ValueError('source export output must be separate from comparison inputs')
    before = _inventory(output)
    manifest = before.get('source-export.json', ())
    if not manifest or manifest[0] != 'file':
        raise ValueError('source export update requires a regular source-export.json')
    previous = json.loads((output/'source-export.json').read_text())
    if not isinstance(previous, dict) or previous.get('version') != 1 or previous.get('authority') != 'source-provenance-only' or previous.get('target_id') != target_id:
        raise ValueError('source export update requires a previous export for the same target')
    if not isinstance(previous.get('components'), dict):
        raise ValueError('source export update requires a previous component selection')
    if removed-previous['components'].keys():
        raise ValueError('source removal names an absent component: '+', '.join(sorted(removed-previous['components'].keys())))
    old_files = _owned_files(previous)
    with tempfile.TemporaryDirectory(prefix='source-export-update-', dir=output.parent) as temporary:
        fresh = Path(temporary)/'fresh'
        report = export_comparison_sources(comparisons=comparisons, target_id=target_id, output=fresh)
        if component_ids is not None:
            missing=set(component_ids)-report['components'].keys()
            if missing:raise ValueError('source update comparison has no component: '+', '.join(sorted(missing)))
            for identity in report['components'].keys()-set(component_ids):
                shutil.rmtree(fresh/'components'/identity)
                del report['components'][identity]
        updated=sorted(report['components'])
        accepted=set(accept_boundary_changes or [])
        retained,drafts=_merge_components(output,previous,fresh,report,accepted,removed) if partial else ([],{})
        new_files = report['files']
        if (previous['components'].keys()!=report['components'].keys()
                and (not partial or previous['components'].keys()-report['components'].keys()!=removed)):
            raise ValueError('source export update changes the component selection; create a separate export and review integration')
        if accepted-set(updated):
            raise ValueError('boundary review names an absent component: '+', '.join(sorted(accepted-set(updated))))
        boundary_changes={}
        for identity, unit in report['components'].items():
            if identity not in previous['components']:
                boundary_changes[identity]=['new component']
                continue
            old = previous['components'][identity]
            for field in ('interface_sha256', 'operation_symbols', 'contract_sha256', 'contract',
                          'assumptions', 'requirements', 'recursion_groups', 'local_shared_contract', 'required_services'):
                if old.get(field) != unit.get(field):
                    boundary_changes.setdefault(identity,[]).append(field)
        old_authored, old_objects, _, old_private = _sources(output, previous, old_files)
        new_authored, new_objects, new_headers, new_private = _sources(fresh, report, new_files)
        # New authored helper headers belong to an implementation refactor.
        # Existing header edits and declared contract changes still need review.
        added_headers = new_headers - old_files.keys()
        removed_sources=[(Path(previous['components'][identity]['source_package']).parent/'sources').as_posix()+'/'
                         for identity in removed]
        old_shared = {name: digest for name, digest in old_files.items() if '/sources/' in name and name not in old_authored|old_private
                      and not any(name.startswith(prefix) for prefix in removed_sources)}
        new_shared = {name: digest for name, digest in new_files.items() if '/sources/' in name
                      and name not in new_authored|new_private and name not in added_headers}
        if old_shared != new_shared:
            changed={name for name in old_shared.keys()|new_shared.keys() if old_shared.get(name)!=new_shared.get(name)}
            for identity in report['components']:
                prefixes={(Path(r['components'][identity]['source_package']).parent/'sources').as_posix()+'/'
                          for r in (previous,report) if identity in r['components']}
                paths=sorted(name for name in changed if any(name.startswith(prefix) for prefix in prefixes))
                if paths:
                    boundary_changes.setdefault(identity,[]).extend('shared/header input '+name for name in paths)
                    changed.difference_update(paths)
            if changed:
                raise ValueError('source export update cannot associate shared/header inputs with a component')
        unreviewed=boundary_changes.keys()-accepted
        if unreviewed:
            details='; '.join(name+' ('+', '.join(boundary_changes[name])+')' for name in sorted(unreviewed))
            raise ValueError('source export update changes the boundary for '+details+
                '; review application/backend bindings, then pass --accept-boundary-change COMPONENT for each affected component')
        for name, digest in old_files.items():
            current = before.get(name, ())
            if not current and name in old_authored|old_private and name not in new_files:
                continue  # A compared refactor can retire an already removed implementation file.
            if not current or current[0] != 'file' or current[2] not in (digest, new_files.get(name), drafts.get(name)):
                raise ValueError('source export update would overwrite a local edit or missing file: '+name)
        for name, digest in new_files.items():
            for parent in Path(name).parents:
                current_parent = before.get(parent.as_posix())
                if current_parent and current_parent[0] != 'directory':
                    raise ValueError('source export update conflicts with an operator path: '+parent.as_posix())
            current = before.get(name)
            if name not in old_files and current is not None and (current[0] != 'file' or current[2] != digest):
                raise ValueError('source export update conflicts with an operator file: '+name)
        if before.get('build', ('directory',))[0] != 'directory':
            raise ValueError('source export update requires a real build directory')
        merged = Path(temporary)/'merged'
        shutil.copytree(output, merged, symlinks=True)
        if _inventory(merged) != before or _inventory(output) != before:
            raise ValueError('source export changed while preparing the update')
        for name in old_files.keys() - new_files.keys(): (merged/name).unlink(missing_ok=True)
        for name, digest in new_files.items():
            destination = merged/name
            if name in drafts:continue  # Preserve the operator's current bytes and mtime.
            if before.get(name, (None, None, None))[2:] == (digest,): continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(fresh/name, destination)
        # Implementation identities include the compiled source and shared inputs.
        # Keep ordinary make outputs for unchanged units, including their mtimes;
        # accepting a declaration change does not make old program evidence valid.
        # A different generated build recipe invalidates all units conservatively.
        # This is build reuse under the operator's existing toolchain/flags, never
        # program validation or qualification authority.
        unchanged = {name for name, unit in report['components'].items()
            if name in previous['components'] and unit['implementation_sha256'] == previous['components'][name]['implementation_sha256']
            and not any(path.startswith((Path(unit['source_package']).parent/'sources').as_posix()+'/') for path in drafts)}
        rebuild = report['components'].keys() - unchanged
        if old_files.get('Makefile') != new_files.get('Makefile'):
            if partial:
                # Both recipes have been recognized by the shared renderer.
                # A local file split or include change need not rebuild neighbors.
                prior_builds=_previous_builds(output,previous)
                rebuild |= {name for name in report['components']
                    if name not in prior_builds or prior_builds[name]['build']!=report['components'][name]['build']}
            else:
                rebuild = report['components'].keys()
        named_outputs = set().union(*old_objects.values(), *new_objects.values()) | {'liblifted.a'}
        discard = set().union(*(old_objects.get(name,set()) | new_objects[name] for name in rebuild))
        discard.update(set().union(*(old_objects[name] for name in removed)))
        if rebuild or removed: discard.add('liblifted.a')
        invalidated = []
        for name in sorted(named_outputs):
            path = merged/name
            if path.is_symlink() or path.is_file():
                if name in discard:
                    path.unlink(); invalidated.append(name)
            elif path.exists(): raise ValueError('source export update has a non-file build output: '+name)
        backup = Path(tempfile.mkdtemp(prefix=output.name+'.before-update-', dir=output.parent))
        backup.rmdir()
        report['update'] = dict(previous_export_sha256=manifest[2], backup=str(backup),
            **(dict(updated_components=updated,retained_components=retained,
                    added_components=sorted(report['components'].keys()-previous['components'].keys()),
                    removed_components=sorted(removed)) if partial else {}),
            preserved_source_drafts=drafts,
            retained_backups=[*previous.get('update', {}).get('retained_backups', []), backup.name],
            changed_files=sorted(name for name, digest in new_files.items() if old_files.get(name) != digest),
            removed_files=sorted(old_files.keys() - new_files.keys()), invalidated_build_outputs=invalidated,
            retained_build_outputs=sorted(name for name in named_outputs - discard if (merged/name).is_file()),
            unchanged_components=sorted(unchanged),
            accepted_boundary_changes=boundary_changes,
            authority='source-provenance-only', program_validation_required=True)
        write_json(merged/'source-export.json', report)
        if _inventory(output) != before: raise ValueError('source export changed before publishing the update')
        output.rename(backup)
        try:
            if _inventory(backup) != before: raise ValueError('source export changed while publishing the update')
            merged.rename(output)
        except BaseException:
            try: backup.rename(output)
            except OSError as failure:
                raise ValueError('source export update interrupted; previous tree retained at '+str(backup)) from failure
            raise
        # Keep the old tree even after success: it preserves artifacts and any
        # late writes through file handles held by an external editor.
    return report
