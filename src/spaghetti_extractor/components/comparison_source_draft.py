"""Select one component's C without importing its surrounding implementations.

This is an authoring input to the existing snapshot path, not another artifact
or assurance claim. Boundary changes still need explicit package refinement.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath


@dataclass(frozen=True)
class SourceDraft:
    path: Path
    source_edits: dict[str, Path] | None = None
    remove_sources: list[str] | None = None
    private_headers: list[str] | None = None


@dataclass(frozen=True)
class DraftFiles:
    files: dict[str, bytes]
    private_headers: list[str]


def edited_draft_files(draft: DraftFiles, selection: SourceDraft, *, prefix: str = '') -> DraftFiles:
    """Apply explicitly named file edits before checking the combined selection."""
    files=dict(draft.files);removed=selection.remove_sources or [];replacements=selection.source_edits or {}
    if len(set(removed))!=len(removed) or set(removed) & replacements.keys():
        raise ValueError('source removals must be unique and cannot also name replacement files')
    for name in removed:
        if prefix+name not in files:
            raise ValueError('source removal is not an authored file: '+name)
        del files[prefix+name]
    for name,path in replacements.items():files[prefix+name]=path.read_bytes()
    private=sorted((set(draft.private_headers) & files.keys()) |
        {prefix+name for name in selection.private_headers or []})
    return DraftFiles(files,private)


DependencySelection = Path | SourceDraft


def selection_path(selection: DependencySelection) -> Path:
    return selection.path if isinstance(selection, SourceDraft) else selection


def read_interface_authoring_files(root: Path, *, component_id: str):
    """Read the explicitly selected current source tree, without running its recipe."""
    from .comparison_package import package_file
    from .interface_package_v5 import ComponentInterfaceIntentV1

    if (root/'comparison-plan.json').exists() or (root/'source-export.json').exists():
        raise ValueError('interface authoring source must be an interface-only workspace')
    interface=ComponentInterfaceIntentV1.parse(json.loads(package_file(root,'interface.json').read_text()))
    if interface.component_id!=component_id:
        raise ValueError('interface authoring source belongs to another component')
    directory=root/'source'
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('interface authoring source/ must be an ordinary directory')
    files={}
    for path in sorted(directory.rglob('*')):
        if path.is_symlink():
            raise ValueError('interface authoring source/ must not contain symbolic links')
        if path.is_file() and path.suffix in ('.c','.h'):
            files[path.relative_to(root).as_posix()]=path.read_bytes()
    return interface,files


def read_interface_authoring_knowledge(root: Path, interface):
    """Read optional existing preparation declarations, without inferring evidence."""
    from .comparison_package import package_file
    from .service_authoring import checked_service_catalog
    from .comparison_resources import checked_resource_checks

    def optional(name):
        return json.loads(package_file(root,name).read_text()) if (root/name).exists() else None

    catalog=checked_service_catalog(optional('service-catalog.json'),interface)
    assumptions=optional('assumptions.json')
    if assumptions is not None and (not isinstance(assumptions,list) or
            any(not isinstance(value,str) or not value.strip() for value in assumptions)):
        raise ValueError('interface authoring assumptions must be a list of nonempty strings')
    resources=checked_resource_checks(optional('resource-checks.json'),interface)
    from .state_ownership import checked_state_owners
    state=checked_state_owners(optional('state-owners.json'))
    return {name:value for name,value in (
        ('service_catalog',catalog.to_payload() if catalog is not None else None),
        ('assumptions',assumptions),('state_owners',state),('resource_checks',resources)) if value is not None}


def interface_authoring_draft(root: Path, *, package: Path, plan: dict, component_id: str,
                              selection: SourceDraft | None = None) -> DraftFiles:
    """Attach unassured C to a matching declaration and an explicit execution setup.

    The comparison retains its target, symbols, header roles, assumptions, services,
    adapters and cases. Interface-only authoring carries no such execution evidence.
    Entry symbols are checked when the regenerated C conformance unit is linked.
    """
    from .comparison_package import package_file
    from .interface_package_v5 import ComponentInterfaceIntentV1

    if component_id==plan['component_id']:
        unit=plan;prefix=''
    else:
        units={row['id']:row for row in plan.get('dependencies',[])}
        if component_id not in units:
            raise ValueError('source draft component is absent from the selection: '+component_id)
        unit=units[component_id];prefix='dependencies/'+component_id+'/'
    interface,files=read_interface_authoring_files(root,component_id=component_id)
    expected=ComponentInterfaceIntentV1.parse(json.loads(package_file(package,unit['interface']).read_text()))
    if interface.intent_sha256!=expected.intent_sha256:
        raise ValueError('interface authoring declaration differs for '+component_id+
            '; revise the comparison boundary or reopen the C with its selected interface before importing it: '+
            str(package/unit['interface']))
    for name,value in read_interface_authoring_knowledge(root,interface).items():
        if value!=unit.get(name):
            raise ValueError('interface authoring '+name+' differs for '+component_id+
                '; review the comparison boundary and authored premises before importing C')
    carried={prefix+name:data for name,data in files.items()}
    private=sorted(set(unit.get('private_headers',[])) & carried.keys())
    draft=edited_draft_files(DraftFiles(carried,private),selection or SourceDraft(root),prefix=prefix)
    return checked_source_draft_inputs(package,plan,unit,draft.files,private_headers=draft.private_headers)


def source_draft_inputs(root: Path | SourceDraft, *, package: Path, plan: dict,
                        component_id: str) -> DraftFiles:
    """Carry selected implementation files under the consumer's unchanged boundary."""
    selection=root if isinstance(root,SourceDraft) else SourceDraft(root)
    root=selection.path
    if (root/'source-export.json').is_file():
        from .source_handoff import source_export_draft
        return source_export_draft(root, package=package, plan=plan, component_id=component_id,selection=selection)
    if not (root/'comparison-plan.json').exists() and (root/'interface.json').is_file():
        return interface_authoring_draft(root,package=package,plan=plan,component_id=component_id,selection=selection)

    from .comparison_contract_diagnostics import contract_changes, describe_contract_changes
    from .comparison_package import load_comparison_package, package_file

    source, _ = load_comparison_package(root)
    if source['target_id'] != plan['target_id']:
        raise ValueError('source draft belongs to another target')

    def unit(value):
        if value['component_id'] == component_id:
            return value, ''
        selected = {row['id']: row for row in value.get('dependencies', [])}
        if component_id not in selected:
            raise ValueError('source draft component is absent from the selection: '+component_id)
        return selected[component_id], 'dependencies/'+component_id+'/'

    previous, prefix = unit(plan)
    proposed, source_prefix = unit(source)
    changes = [row for row in contract_changes(package, previous, root, proposed) if row['field']!='private_headers']
    if changes:
        raise ValueError('source draft boundary differs for '+component_id+
            '; refine the boundary before importing C\n'+describe_contract_changes(changes))
    carried = {prefix+name.removeprefix(source_prefix): package_file(root, name).read_bytes()
               for name in proposed['sources']}
    private = [prefix+name.removeprefix(source_prefix) for name in proposed.get('private_headers',[])]
    draft=edited_draft_files(DraftFiles(carried,private),selection,prefix=prefix)
    return checked_source_draft_inputs(package, plan, previous, draft.files, private_headers=draft.private_headers)


def checked_source_draft_inputs(root: Path, plan: dict, unit: dict,
                               files: dict[str, bytes], *, private_headers=None,
                               adopt_files: set[str] = frozenset()) -> DraftFiles:
    """Accept implementation edits under the consumer's existing header roles."""
    from .comparison_package import package_file

    draft=checked_source_file_selection(root,plan,unit,files,private_headers=private_headers,adopt_files=adopt_files)
    previous = set(unit['sources'])
    old_private = set(unit.get('private_headers',[]))
    changed_roles = (old_private ^ set(draft.private_headers)) & previous & files.keys()
    if changed_roles:
        raise ValueError('source draft header roles changed: '+', '.join(sorted(changed_roles))+'; refine the boundary before importing C')
    for name in previous:
        if not name.endswith('.c') and name not in old_private and files.get(name) != package_file(root, name).read_bytes():
            raise ValueError('source draft authored header changed: '+name+'; review the boundary and shared inputs')
    return draft


def checked_source_file_selection(root: Path, plan: dict, unit: dict,
                                  files: dict[str, bytes], *, private_headers=None,
                                  adopt_files: set[str] = frozenset()) -> DraftFiles:
    """Validate file ownership for an explicit authoring carry-over.

    This validates paths and roles, not boundary compatibility. Ordinary C-only
    imports additionally use checked_source_draft_inputs. Direct workspace reuse
    may deliberately carry existing header edits into a reviewed new boundary.
    """
    from .source import checked_private_headers

    previous = set(unit['sources'])
    private = checked_private_headers(private_headers,files,protected=[*plan['original']['files'],
        *(unit.get('representation') or {}).get('inputs',{}).values()])
    if (previous | files.keys()) & plan['original']['files'].keys():
        raise ValueError('cannot import authored C that also supplies the original comparison oracle')
    prefix = '' if 'component_id' in unit else 'dependencies/'+unit['id']+'/'
    if not files or not any(name.endswith('.c') for name in files):
        raise ValueError('source draft requires a C translation unit')
    for name in files:
        path = PurePosixPath(name)
        if (path.is_absolute() or '..' in path.parts or str(path) != name
                or path.suffix not in ('.c', '.h')):
            raise ValueError('source draft authored path is invalid: '+name)
        if name not in previous:
            if (not name.startswith(prefix+'source/')
                    or not (root/name).resolve().is_relative_to((root/(prefix+'source')).resolve())):
                raise ValueError('new source draft files must belong to the component source directory: '+name)
            same_local_file=(name in adopt_files and (root/name).is_file()
                and not (root/name).is_symlink() and (root/name).read_bytes()==files[name])
            if ((root/name).exists() or (root/name).is_symlink()) and not same_local_file:
                raise ValueError('source draft would replace an unowned file: '+name)
    return DraftFiles(files,private)


def edit_source_files(root: Path, plan: dict, *, component_id: str, origin: Path,
                      replacements: dict[str,Path], removed: list[str], private_headers: list[str]) -> None:
    """Apply explicit local file edits through the existing C-only boundary checks.

    Names are relative to the selected unit, including source/. Existing header
    roles remain; only new private headers can be declared without refinement.
    A new file already written in that unit can be adopted when the operator
    names that exact file as the input and its captured bytes still match.
    """
    from .comparison_package import package_file

    unit=plan if component_id==plan['component_id'] else next(row for row in plan['dependencies'] if row['id']==component_id)
    prefix='' if unit is plan else 'dependencies/'+component_id+'/'
    current=DraftFiles({name:package_file(root,name).read_bytes() for name in unit['sources']},unit.get('private_headers',[]))
    edited=edited_draft_files(current,SourceDraft(origin,replacements,removed,private_headers),prefix=prefix)
    adopted={prefix+name for name,path in replacements.items() if path.resolve()==(origin/(prefix+name)).resolve()}
    draft=checked_source_draft_inputs(root,plan,unit,edited.files,private_headers=edited.private_headers,adopt_files=adopted)
    install_source_draft(root,unit,draft)


def install_source_draft(root: Path, unit: dict, draft: DraftFiles) -> None:
    """Install a checked file selection within the caller's preparation transaction."""
    from .comparison_package import package_file

    files = draft.files
    for name in set(unit['sources']) - files.keys():
        package_file(root, name).unlink()
    for name, data in files.items():
        path = root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    unit['sources'] = sorted(files)
    if draft.private_headers:unit['private_headers'] = draft.private_headers
    else:unit.pop('private_headers',None)
