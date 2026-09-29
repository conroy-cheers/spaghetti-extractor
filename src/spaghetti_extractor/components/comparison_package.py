"""Executable local-test setup over existing interfaces and source packages.

The package describes a concrete fixture, never a checked semantic summary or
permission to activate a provider. Source and fixture edits are hashed on check.
"""
from __future__ import annotations

from contextlib import contextmanager
import copy
import json
from pathlib import Path, PurePosixPath
import shutil
import tempfile

from ..util import sha256_file, write_json
from .interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from .component_c_v5 import render_component_c_headers_v5
from .formats import COMPONENT_COMPARISON_PLAN_V1_FORMAT
from .comparison_source_draft import DependencySelection, SourceDraft, selection_path


def package_file(root: Path, relative: object) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError('comparison file must be a relative path')
    path = PurePosixPath(relative)
    candidate = root / path
    if (path.is_absolute() or '..' in path.parts or candidate.is_symlink()
            or not candidate.resolve().is_relative_to(root.resolve()) or not candidate.is_file()):
        raise ValueError(f'comparison file is absent or escapes the package: {relative}')
    return candidate


def copy_comparison(source: Path, destination: Path) -> None:
    """Retain bound evidence without copying mutable Wine execution prefixes."""
    source=source.resolve();destination=destination.resolve()
    if source.is_relative_to(destination) or destination.is_relative_to(source):
        raise ValueError('comparison evidence output must be separate from its inputs')
    destination.mkdir(parents=True)
    for name in ('inputs','build','cases','reuse','formal','refinement'):
        if (source/name).is_dir():
            shutil.copytree(source/name,destination/name)
    shutil.copyfile(package_file(source,'comparison-result.json'),destination/'comparison-result.json')


def _checked_cases(cases):
    if not isinstance(cases,list) or not cases:
        raise ValueError('comparison has no cases')
    ids=[]
    for case in cases:
        if (not isinstance(case,dict) or set(case) != {'id','arguments'}
                or not isinstance(case['id'],str) or not case['id']
                or not isinstance(case['arguments'],list)
                or any(not isinstance(v,str) or '\0' in v for v in case['arguments'])):
            raise ValueError('comparison case requires an id and string arguments')
        ids.append(case['id'])
    if len(set(ids)) != len(ids):
        raise ValueError('comparison case ids must be unique')
    return cases


def load_comparison_package(root: Path) -> tuple[dict, ComponentInterfaceIntentV1]:
    plan = json.loads(package_file(root, 'comparison-plan.json').read_text())
    fields = {'format', 'target_id', 'component_id', 'interface', 'sources', 'adapters',
              'operation_symbols', 'include_directories', 'link_files', 'runtime_files',
              'original', 'cases', 'observation_fields', 'assumptions', 'scope', 'tools'}
    if not isinstance(plan, dict) or set(plan)-{'dependencies','input_domain','representation','resource_checks','service_catalog','service_bridge','requirements','composition','recursion_groups','export_adapters','local_shared_contract','program_driver','private_headers','state_owners'} != fields or plan['format'] != COMPONENT_COMPARISON_PLAN_V1_FORMAT:
        raise ValueError('unsupported comparison plan fields or format')
    if any(not isinstance(plan[k], str) or not plan[k] for k in ('target_id','component_id','scope')):
        raise ValueError('comparison identity and scope are required')
    interface = ComponentInterfaceIntentV1.parse(json.loads(package_file(root, plan['interface']).read_text()))
    from .practical_contracts import checked_local_shared_contract
    checked_local_shared_contract(plan.get('local_shared_contract'),interface)
    from .comparison_resources import checked_resource_checks
    checked_resource_checks(plan.get('resource_checks'),interface)
    from .service_authoring import checked_service_catalog
    checked_service_catalog(plan.get('service_catalog'),interface)
    from .service_c import materialize_service_bridge
    materialize_service_bridge(plan,interface)
    if interface.component_id != plan['component_id']:
        raise ValueError('comparison interface belongs to another component')
    for field in ('sources','adapters','link_files','runtime_files'):
        rows = plan[field]
        if not isinstance(rows, list) or any(not isinstance(v,str) for v in rows) or len(set(rows)) != len(rows):
            raise ValueError(f'comparison {field} must be unique file paths')
        for name in rows:
            package_file(root, name)
    if not plan['sources'] or not plan['adapters']:
        raise ValueError('comparison requires authored source and a fixture adapter')
    if set(plan['sources']) & set(plan['adapters']):
        raise ValueError('authored source and fixture roles overlap')
    if (any(not p.endswith(('.c','.h')) for p in plan['sources'])
            or not any(p.endswith('.c') for p in plan['sources'])
            or any(not p.endswith('.c') for p in plan['adapters'])):
        raise ValueError('comparison requires C translation units and optional authored headers')
    directories = plan['include_directories']
    if not isinstance(directories, list) or any(not isinstance(p,str) for p in directories):
        raise ValueError('comparison include directories must be paths')
    for name in directories:
        path = root / name
        if not path.is_dir() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError('comparison include directory escapes package')
    original = plan['original']
    if (not isinstance(original,dict) or set(original) != {'kind','files'}
            or original['kind'] not in {'native-original','retained-c','fixture'}
            or not isinstance(original['files'],dict) or not original['files']):
        raise ValueError('comparison requires an explicit bound oracle')
    for name, digest in original['files'].items():
        if sha256_file(package_file(root,name)) != digest:
            raise ValueError(f'original comparison input is stale: {name}')
    _checked_cases(plan['cases'])
    for field in ('observation_fields','assumptions'):
        if not isinstance(plan[field],list) or not plan[field] or any(not isinstance(v,str) or not v for v in plan[field]):
            raise ValueError(f'comparison {field} must be explicit nonempty strings')
    tools = plan['tools']
    if not isinstance(tools,dict) or set(tools) != {'compiler','runner','server'}:
        raise ValueError('comparison tools are incomplete')
    if tools['runner'] is None and tools['server'] is not None:
        raise ValueError('comparison server requires a runner')
    for name, tool in tools.items():
        if tool is None and name != 'compiler':
            continue
        if (not isinstance(tool,dict) or set(tool) != {'path','sha256'}
                or not isinstance(tool['path'],str) or not Path(tool['path']).is_absolute()
                or not Path(tool['path']).is_file() or sha256_file(Path(tool['path'])) != tool['sha256']):
            raise ValueError(f'comparison tool is absent or stale: {name}')
    runtime_names=[Path(p).name.casefold() for p in plan['runtime_files']]
    if len(set(runtime_names)) != len(runtime_names) or 'comparison.exe' in runtime_names:
        raise ValueError('comparison runtime library basenames collide')
    from .comparison_pe32_program import checked_program_driver
    checked_program_driver(plan)
    from .comparison_dependencies import validate_dependencies
    from .comparison_domain import checked_input_domain
    checked_input_domain(plan.get('input_domain'))
    validate_dependencies(root,plan)
    from .state_ownership import unit_state_owners, check_state_owner_selection
    state_units={plan['component_id']:plan, **{row['id']:row for row in plan.get('dependencies',[])}}
    check_state_owner_selection({name:unit_state_owners(unit) for name,unit in state_units.items()})
    exports=plan.get('export_adapters',[])
    if not isinstance(exports,list) or len(set(exports))!=len(exports) or any(p not in plan['adapters'] for p in exports):
        raise ValueError('exported dependency adapters must be unique materialized adapters')
    from .comparison_composition import validate_composition
    validate_composition(root,plan)
    from .comparison_representation import representation_binding
    representation_binding(root,plan)
    from .source import checked_private_headers
    checked_private_headers(plan.get('private_headers'),plan['sources'],protected=[*original['files'],
        *(plan.get('representation') or {}).get('inputs',{}).values()])
    return plan, interface


def materialize_comparison_headers(root: Path, plan: dict, interface: ComponentInterfaceIntentV1) -> None:
    from .comparison_domain import domain_header
    headers=render_component_c_headers_v5(compile_component_interface_v5(interface), plan['operation_symbols'])
    destination=root/'generated'
    destination.mkdir(exist_ok=True)
    for name,text in headers.items():
        (destination/name).write_text(text)
    (destination/'comparison-input-domain.h').write_text(domain_header(plan['component_id'],plan.get('input_domain')))
    from .comparison_composition import selection_header
    (destination/'comparison-selection.h').write_text(selection_header(plan))
    for row in plan.get('dependencies',[]):
        intent=ComponentInterfaceIntentV1.parse(json.loads(package_file(root,row['interface']).read_text()))
        headers=render_component_c_headers_v5(compile_component_interface_v5(intent),row['operation_symbols'])
        destination=root/'dependencies'/row['id']/'generated'
        destination.mkdir(exist_ok=True)
        for name,text in headers.items():
            (destination/name).write_text(text)
        (destination/'comparison-input-domain.h').write_text(domain_header(row['id'],row.get('input_domain')))
        (destination/'comparison-selection.h').write_text(selection_header(plan))
    from .comparison_resources import materialize_resource_runtime
    materialize_resource_runtime(root,plan)
    from .comparison_service_runtime import materialize_service_runtime
    materialize_service_runtime(root,plan)
    from .service_c import materialize_service_bridge
    for unit,destination,intent in [(plan,root/'generated',interface),*[
            (row,root/'dependencies'/row['id']/'generated',ComponentInterfaceIntentV1.parse(json.loads(package_file(root,row['interface']).read_text())))
            for row in plan.get('dependencies',[])]]:
        bridge=materialize_service_bridge(unit,intent)
        if bridge is not None:
            (destination/'comparison-service-bridge.h').write_text(bridge[0])
            write_json(destination/'service-coverage.json',bridge[1])


def prepare_comparison_inputs(*, package: Path, snapshot: Path, plan: dict,
                              interface: ComponentInterfaceIntentV1,
                              dependency_packages: dict[str,DependencySelection] | None = None,
                              rewrite_plan: bool = False) -> tuple[dict, ComponentInterfaceIntentV1]:
    """Snapshot the checker's actual inputs without compiling or executing them."""
    from .comparison_dependencies import comparison_units, replace_dependency_packages
    # Capture the editable draft so compilation, replay and reported identities
    # refer to the same bytes even if the operator continues editing the draft.
    snapshot.mkdir()
    names=set(plan['sources']+plan['adapters']+plan['link_files']+plan['runtime_files']+
              list(plan['original']['files'])+[plan['interface'],'comparison-plan.json'])
    units=comparison_units(plan)
    for unit in units:
        names.update(unit['sources']+unit['adapters']+[unit['interface']])
    for directory in [name for unit in units for name in unit['include_directories']]:
        (snapshot/directory).mkdir(parents=True,exist_ok=True)
        for path in (package/directory).rglob('*'):
            if path.is_symlink():
                raise ValueError('comparison include tree contains symbolic links')
            if path.is_file():
                names.add(path.relative_to(package).as_posix())
    for name in sorted(names):
        destination=snapshot/name
        destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(package_file(package,name),destination)
    # Revalidate pinned original files after snapshotting; source edits are
    # intentionally accepted and bound below rather than requiring manual hashes.
    if rewrite_plan:
        # Keep the supplied arguments in the existing plan/receipt path so replay
        # needs neither this CLI option nor the original editable workspace.
        write_json(snapshot/'comparison-plan.json',plan)
    if any((selection_path(path)/'source-export.json').is_file() for path in (dependency_packages or {}).values()):
        # A source draft must match the current generated interface as well as
        # the retained C headers. The fresh snapshot has no generated files yet.
        materialize_comparison_headers(snapshot,plan,interface)
    replace_dependency_packages(snapshot,plan,dependency_packages or {})
    plan,interface=load_comparison_package(snapshot)
    from .comparison_representation import validate_representation_selection
    validate_representation_selection(snapshot,plan)
    materialize_comparison_headers(snapshot,plan,interface)
    return plan,interface


@contextmanager
def _comparison_workspace(package: Path | None, output: Path):
    """Publish fresh or revised authoring inputs only after validation succeeds."""
    if output.is_symlink() or (output.exists() and (not output.is_dir() or any(output.iterdir()))):
        raise ValueError('comparison output must be a new or empty directory')
    if package is not None:
        if output.resolve().is_relative_to(package.resolve()) or package.resolve().is_relative_to(output.resolve()):
            raise ValueError('comparison source and output packages must be separate')
        if any(p.is_symlink() for p in package.rglob('*')):
            raise ValueError('comparison package contains symbolic links')
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.component-start-',dir=output.parent) as directory:
        staged=Path(directory)/'workspace'
        if package is None:
            staged.mkdir()
        else:
            shutil.copytree(package,staged)
            for p in (staged,*staged.rglob('*')):
                p.chmod(p.stat().st_mode | 0o200 | (0o100 if p.is_dir() else 0))
        yield staged
        if output.is_symlink():
            raise ValueError('comparison output changed to a symbolic link during preparation')
        staged.replace(output)


def comparison_preparation(output: Path):
    """Stage an operator's complete preparation recipe until it succeeds.

    Yield a new writable directory. An exception discards only that staging
    directory; successful exit publishes it at a new or empty output. Use this
    around generated adapters and multiple prepare_comparison_package calls so
    the complete recipe can be corrected and retried without manual cleanup.
    This does not execute comparisons or confer assurance.
    """
    return _comparison_workspace(None,output)


def start_comparison_package(*, package: Path, output: Path, target_id: str, component_id: str,
                             reuse_source: Path | None = None,
                             reuse_cases: list[Path] | None = None,
                             case_files: list[Path] | None = None,
                             source_edits: dict[str,Path] | None = None,
                             remove_sources: list[str] | None = None,
                             private_headers: list[str] | None = None,
                             dependency_packages: dict[str,DependencySelection] | None = None,
                             refine_requirements: dict[str,Path] | None = None) -> None:
    """Open a selected unit for editing while retaining the package's check scope.

    A supplier focus does not invent its own driver or change the comparison entry.
    Reused supplier C takes the existing source-only selection path; the enclosing
    caller, other bodies and adapters remain the package's current selection.
    reuse_cases appends named argument definitions from packages or results in
    order, without importing bodies or observations. The current driver and
    boundary interpret those arguments; importing them grants no admission or
    evidence. Identical names/arguments coalesce; conflicting names are rejected.
    case_files then appends plain JSON lists of the same case definitions. These
    are operator inputs for the current driver, not saved execution evidence.
    source_edits and remove_sources change only the selected unit's authored file
    inventory. Names include source/ and omit any dependencies/UNIT/ prefix.
    Existing files and header roles are retained unless explicitly removed;
    private_headers can classify new helper headers. Shared-header changes still
    require reviewed refinement. With reuse_source, edits apply to that selection.
    """
    plan,interface=load_comparison_package(package)
    selected={plan['component_id'],*[row['id'] for row in plan.get('dependencies',[])]}
    if plan['target_id']!=target_id or component_id not in selected:
        raise ValueError('comparison package has another target/component identity')
    editing_files=bool(source_edits or remove_sources or private_headers)
    if editing_files and component_id in (dependency_packages or {}):
        raise ValueError('choose explicit source-file edits or another source selection for '+component_id)
    cases={case['id']:case for case in plan['cases']}
    def append_cases(incoming, label):
        for case in incoming:
            existing=cases.get(case['id'])
            if existing is not None and existing['arguments']!=case['arguments']:
                raise ValueError(label+' case name has different arguments: '+case['id']+
                    '; give the input a distinct case name before importing it')
            cases.setdefault(case['id'],case)
    for origin in reuse_cases or []:
        root=origin if (origin/'comparison-plan.json').is_file() else origin/'inputs'
        previous,_=load_comparison_package(root)
        if (previous['target_id'],previous['component_id']) != (plan['target_id'],plan['component_id']):
            raise ValueError('reused cases have another comparison target/component identity: '+str(origin))
        append_cases(previous['cases'],'reused')
    for origin in case_files or []:
        try:
            append_cases(_checked_cases(json.loads(origin.read_text())),'imported')
        except (OSError,ValueError) as error:
            raise ValueError('case file '+str(origin)+': '+str(error)) from error
    plan['cases']=list(cases.values())
    if component_id!=plan['component_id'] and reuse_source is not None:
        if component_id in (dependency_packages or {}):
            raise ValueError('focused component has both reused C and an explicit dependency selection: '+component_id)
        dependency_packages={**(dependency_packages or {}),component_id:SourceDraft(
            reuse_source,source_edits,remove_sources,private_headers)}
        reuse_source=None
        editing_files=False
    for selection in [*(dependency_packages or {}).values(),*(refine_requirements or {}).values()]:
        dependency=selection_path(selection)
        if output.resolve().is_relative_to(dependency.resolve()) or dependency.resolve().is_relative_to(output.resolve()):
            raise ValueError('dependency workspace and output must be separate')
    carried = None
    if reuse_source is not None:
        selection=SourceDraft(reuse_source,source_edits,remove_sources,private_headers)
        if output.resolve().is_relative_to(reuse_source.resolve()) or reuse_source.resolve().is_relative_to(output.resolve()):
            raise ValueError('source workspace and output must be separate')
        if set(plan['sources']) & plan['original']['files'].keys():
            raise ValueError('cannot reuse authored files that also supply the original comparison oracle')
        if (reuse_source/'source-export.json').is_file():
            from .source_handoff import source_export_draft
            carried=source_export_draft(reuse_source,package=package,plan=plan,selection=selection)
        elif not (reuse_source/'comparison-plan.json').exists() and (reuse_source/'interface.json').is_file():
            from .comparison_source_draft import interface_authoring_draft
            carried=interface_authoring_draft(reuse_source,package=package,plan=plan,component_id=component_id,selection=selection)
        else:
            previous,_ = load_comparison_package(reuse_source)
            if (previous['target_id'],previous['component_id']) != (target_id,component_id):
                raise ValueError('source workspace has another target/component identity')
            from .comparison_source_draft import DraftFiles, checked_source_file_selection, edited_draft_files
            files={name:package_file(reuse_source,name).read_bytes() for name in previous['sources']}
            # The chosen setup owns existing header roles, including a reviewed
            # boundary refinement. New private helper files retain their roles.
            private=sorted((set(plan.get('private_headers',[])) & files.keys()) |
                (set(previous.get('private_headers',[]))-set(plan['sources'])))
            draft=edited_draft_files(DraftFiles(files,private),selection)
            changed_roles=(set(private)^set(draft.private_headers)) & set(plan['sources']) & draft.files.keys()
            if changed_roles:
                raise ValueError('source draft header roles changed: '+', '.join(sorted(changed_roles))+
                    '; refine the boundary before importing C')
            carried=checked_source_file_selection(package,plan,plan,draft.files,private_headers=draft.private_headers)
        editing_files=False
    # Resolve the selection before publishing an editable workspace. A rejected
    # supplier must not leave a plausible draft containing the old default body.
    with _comparison_workspace(package,output) as staged:
        if reuse_cases or case_files:
            write_json(staged/'comparison-plan.json',plan)
        if carried is not None:
            from .comparison_source_draft import install_source_draft
            install_source_draft(staged,plan,carried)
            write_json(staged/'comparison-plan.json',plan)
            plan,interface=load_comparison_package(staged)
        if refine_requirements is not None:
            from .comparison_dependencies import refine_dependency_requirements
            refine_dependency_requirements(staged,plan,refine_requirements)
            write_json(staged/'comparison-plan.json',plan)
            plan,interface=load_comparison_package(staged)
        if dependency_packages:
            from .comparison_dependencies import replace_dependency_packages
            replace_dependency_packages(staged,plan,dependency_packages)
        if editing_files:
            from .comparison_source_draft import edit_source_files
            edit_source_files(staged,plan,component_id=component_id,origin=package,
                replacements=source_edits or {},removed=remove_sources or [],private_headers=private_headers or [])
            write_json(staged/'comparison-plan.json',plan)
            plan,interface=load_comparison_package(staged)
        materialize_comparison_headers(staged,plan,interface)


def revise_comparison_package(*, package: Path, output: Path,
                              component_id: str | None = None,
                              interface: ComponentInterfaceIntentV1 | None = None,
                              reviewed_requirements: list[str] | None = None,
                              refine_requirements: dict[str,Path] | None = None,
                              dependencies: list | None = None,
                              remove_dependencies: list[str] | None = None,
                              source_files: dict | None = None,
                              adapter_files: dict | None = None, include_files: dict | None = None,
                              link_files: dict | None = None, runtime_files: dict | None = None,
                              program_entry_packages: dict[str,Path] | None = None,
                              representation_updates: dict | None = None,
                              **changes) -> None:
    """Revise component declarations while retaining fixtures and selected neighbors.

    component_id optionally selects a supplier already in this package. Its
    interface, assumptions, operation symbols, source_files, adapter_files,
    include_files and component-level optional declarations can change in place.
    File names are relative to that component, as in initial preparation; its
    adapters remain in bridges/. The enclosing driver, oracle, cases, tools and
    selection are retained, without manufacturing an independent local setup.
    Incoming changed contracts require exact reviewed_requirements names
    (CONSUMER/REQUIREMENT). These acknowledge manual call-site review, not proved
    compatibility. Unreviewed callers remain frozen. For a root revision the
    same review input can explicitly update its internal recursive requirements.

    Required declarations: assumptions, scope, cases, observation_fields and
    operation_symbols. Optional declarations: input_domain, representation,
    resource_checks, service_catalog, service_bridge, requirements,
    recursion_groups, export_adapters, local_shared_contract, program_driver and
    private_headers. Omitted fields
    are retained; None removes an optional declaration. Interface changes use a
    reviewed ComponentInterfaceIntentV1, constructed by the existing authoring API.

    When interface changes and resource_checks is omitted, retain its declared
    roles, allowances and observation limits if each observed operation's value
    declarations and reachable types are unchanged. Rebind their schema metadata
    through the existing lifecycle builder. Changed values/types require explicit
    resource_checks; this neither infers new roles nor carries previous evidence.

    refine_requirements maps reviewed CONSUMER/REQUIREMENT names to supplier
    packages; bare requirement names refer to the root. It retains other callers,
    and bundled suppliers with matching contracts keep their selected bodies. It
    cannot invent an edge or implicitly refine another consumer. Raw root
    requirements and named refinement
    are alternative authoring inputs.

    dependencies adds reviewed supplier selections using the same input as initial
    preparation (including bind_dependencies), also when component_id selects a
    nested caller. Existing selections are retained; conflicting shared bodies
    reject. Supply explicit requirements for the added edges on the revised
    component, retaining its existing requirements. Omitted requirements stay
    frozen. remove_dependencies explicitly drops named current selections before
    resolving replacements. Review affected requirements and program entries in
    the same revision; dangling consumers still reject. A named component can be
    explicitly reselected with a revised package. Neither input infers C wiring.

    Supplier requirements remain frozen unless explicitly replaced. This produces
    a prepared package, without checking behavior or inheriting assurance. Use
    component start on it to regenerate editor commands and workspace guidance.
    source_files replaces the root's complete authored C/header set using paths
    relative to source/, with the same inputs accepted by preparation. It preserves
    fixtures and neighbors, and cannot replace oracle or unowned files.

    adapter_files, include_files, link_files and runtime_files replace complete
    root file roles, using the same relative names as preparation. Omission keeps
    a role; an empty mapping clears it. compiler, runner and server explicitly
    replace tools (None clears runner/server). An oracle change requires reviewed
    original_files, with optional oracle_kind; hashes are derived from those
    materialized inputs. Otherwise its existing bytes remain pinned. These inputs
    support a new executable driver without rewriting plans or selected neighbors.
    They do not carry previous evidence or establish contract compatibility.

    program_entry_packages names additional independent program-entry packages.
    Their exported adapters and transitive selections use the existing composition
    resolver, retaining current implementations and rejecting conflicting shared
    selections. This requires a program_driver. It adds entries, not caller edges;
    execution still depends on reviewed entry/ABI/state adapters.

    representation_updates maps group identities to a new revision, replacement
    named input files and reviewed_requirements (consumer/requirement names).
    It updates every selected member together while retaining C and adapters;
    absent group members remain absent. Only explicitly reviewed requirements are
    rebound. This is manual boundary refinement, not compatibility evidence.

    private_headers explicitly names authored header paths used only inside this
    implementation. Shared representation and original inputs cannot use this
    role. Changing an existing header's role requires reviewed refinement;
    ordinary body imports then carry its edits without changing the boundary.
    """
    required={'assumptions','scope','cases','observation_fields','operation_symbols'}
    optional={'input_domain','representation','resource_checks','service_catalog','service_bridge',
              'requirements','recursion_groups','export_adapters','local_shared_contract','program_driver','private_headers','state_owners'}
    execution={'compiler','runner','server','original_files','oracle_kind'}
    unknown=set(changes)-required-optional-execution
    if unknown:
        raise ValueError('unsupported comparison revision fields: '+', '.join(sorted(unknown)))
    if refine_requirements is not None and 'requirements' in changes:
        raise ValueError('choose named requirement refinement or explicit requirements, not both')
    if dependencies is not None and (not isinstance(dependencies,list) or any(
            not isinstance(row,dict) or not {'id','package'}<=row.keys()<={'id','package','adapters'}
            for row in dependencies)):
        raise ValueError('revised dependencies must be a list of reviewed id/package selections')
    if program_entry_packages is not None and (not isinstance(program_entry_packages,dict)
            or any(not isinstance(name,str) or not name for name in program_entry_packages)):
        raise ValueError('program_entry_packages must map component identities to reviewed packages')
    for dependency in [*(refine_requirements or {}).values(),*(program_entry_packages or {}).values(),
                       *(row['package'] for row in dependencies or [])]:
        if output.resolve().is_relative_to(Path(dependency).resolve()) or Path(dependency).resolve().is_relative_to(output.resolve()):
            raise ValueError('reviewed supplier workspace and output must be separate')
    plan,current=load_comparison_package(package)
    identity=plan['component_id'] if component_id is None else component_id
    selected=next((row for row in plan.get('dependencies',[]) if row['id']==identity),None)
    if identity==plan['component_id']:
        selected=plan
    elif selected is None:
        raise ValueError('component is absent from the comparison selection: '+str(identity))
    nested=selected is not plan
    previous_selected=copy.deepcopy(selected)
    if nested:
        unavailable=set(changes) & (execution | {'scope','cases','observation_fields','export_adapters','local_shared_contract','program_driver'})
        unavailable.update(name for name,value in [('link_files',link_files),('runtime_files',runtime_files),
            ('remove_dependencies',remove_dependencies),
            ('program_entry_packages',program_entry_packages),('refine_requirements',refine_requirements),
            ('representation_updates',representation_updates)] if value is not None)
        if unavailable:
            raise ValueError('selected component revision retains the enclosing execution and selection; '
                'revise the root separately for: '+', '.join(sorted(unavailable)))
        current=ComponentInterfaceIntentV1.parse(json.loads(package_file(package,selected['interface']).read_text()))
        prefix='dependencies/'+identity+'/'
        if changes.get('private_headers') is not None:
            changes['private_headers']=[prefix+name for name in changes['private_headers']]
        if changes.get('representation') is not None:
            changes['representation']={**changes['representation'],
                'inputs':{name:prefix+path for name,path in changes['representation']['inputs'].items()}}
    if remove_dependencies is not None and (not isinstance(remove_dependencies,list) or not remove_dependencies
            or any(not isinstance(name,str) for name in remove_dependencies)
            or len(set(remove_dependencies))!=len(remove_dependencies)):
        raise ValueError('removed dependencies must be distinct selected component names')
    removed=set(remove_dependencies or [])
    missing=removed-{row['id'] for row in plan.get('dependencies',[])}
    if missing:
        raise ValueError('dependency removal names an absent selection: '+', '.join(sorted(missing)))
    original_files=changes.pop('original_files',None)
    oracle_kind=changes.pop('oracle_kind',None)
    if original_files is not None and (not isinstance(original_files,list) or not original_files
            or any(not isinstance(name,str) for name in original_files) or len(set(original_files))!=len(original_files)):
        raise ValueError('revised original_files must be explicit unique package paths')
    if oracle_kind is not None and original_files is None:
        raise ValueError('changing the oracle kind requires reviewed original_files')
    for name in ('compiler','runner','server'):
        if name in changes:
            path=changes.pop(name)
            plan['tools'][name]=None if path is None else dict(path=str(Path(path).resolve()),sha256=sha256_file(path))
    if interface is not None:
        revised_interface=ComponentInterfaceIntentV1.parse(interface.to_payload())
        if revised_interface.component_id!=identity:
            raise ValueError('revised interface belongs to another component')
        if 'resource_checks' not in changes and selected.get('resource_checks') is not None:
            from .resource_authoring import rebind_resource_checks
            changes['resource_checks']=rebind_resource_checks(selected['resource_checks'],
                previous=current,interface=revised_interface)
        current=revised_interface
    for name,value in changes.items():
        if value is None and name in optional:
            selected.pop(name,None)
        else:
            selected[name]=value
    with _comparison_workspace(package,output) as staged:
        for removed_identity in removed:
            shutil.rmtree(staged/'dependencies'/removed_identity)
        if removed:
            plan['dependencies']=[row for row in plan['dependencies'] if row['id'] not in removed]
        for role,files in [('adapters',adapter_files),('headers',include_files),('link',link_files),('runtime',runtime_files)]:
            if files is not None:
                _revise_comparison_files(staged,plan,role,files,rebind_original=original_files is not None,unit=selected)
        if source_files is not None:
            previous=set(selected['sources'])
            if previous & plan['original']['files'].keys():
                raise ValueError('cannot revise authored files that also supply the original comparison oracle')
            with _comparison_source(component_id=identity,source_package=None,
                    source_files=source_files,operation_symbols=selected['operation_symbols']) as (source,source_root):
                names=[('dependencies/'+identity+'/' if nested else '')+'source/'+row['path'] for row in source['files']]
                for name in names:
                    if name not in previous and (staged/name).exists():
                        raise ValueError('authored source revision would replace an unowned file: '+name)
                for name in previous:
                    package_file(staged,name).unlink()
                for row,name in zip(source['files'],names):
                    path=staged/name;path.parent.mkdir(parents=True,exist_ok=True)
                    shutil.copyfile(source_root/row['path'],path)
                selected['sources']=names
        if interface is not None:
            write_json(staged/selected['interface'],current.to_payload())
        if nested or reviewed_requirements is not None:
            from .comparison_composition import review_selected_contract
            review_selected_contract(staged,plan,identity,[] if reviewed_requirements is None else reviewed_requirements,
                previous=(package,previous_selected))
        if refine_requirements is not None:
            from .comparison_dependencies import refine_dependency_requirements
            refine_dependency_requirements(staged,plan,refine_requirements)
        if original_files is not None:
            plan['original']=dict(kind=oracle_kind or plan['original']['kind'],
                files={name:sha256_file(package_file(staged,name)) for name in original_files})
        if dependencies is not None:
            from .comparison_composition import resolve_composition
            resolve_composition(output=staged,plan=plan,selections=dependencies,
                requirements=plan.get('requirements') or [],retain_selected=True)
        if program_entry_packages:
            if not isinstance(plan.get('program_driver'),dict):
                raise ValueError('independent program entry selection requires a program_driver')
            from .comparison_composition import resolve_composition
            selections=[]
            for identity,entry_package in program_entry_packages.items():
                entry_package=Path(entry_package)
                entry,_=load_comparison_package(entry_package)
                if entry['target_id']!=plan['target_id']:
                    raise ValueError('program entry package belongs to another target: '+identity)
                selections.append(dict(id=identity,package=entry_package))
            entries=plan['program_driver'].get('entries',[plan['component_id']])
            if (not isinstance(entries,list) or not entries or any(not isinstance(name,str) for name in entries)
                    or entries!=sorted(set(entries)) or plan['component_id'] not in entries):
                raise ValueError('program entries must be sorted unique identities including the package entry')
            plan['program_driver']={**plan['program_driver'],'entries':sorted(set(entries) | program_entry_packages.keys())}
            resolve_composition(output=staged,plan=plan,selections=selections,
                requirements=plan.get('requirements') or [],retain_selected=True)
        explicitly_selected={row['id'] for row in dependencies or []} | (program_entry_packages or {}).keys()
        unexpected=(removed & {row['id'] for row in plan.get('dependencies',[])}) - explicitly_selected
        if unexpected:
            raise ValueError('a supplied caller still selects removed dependencies: '+', '.join(sorted(unexpected)))
        if representation_updates is not None:
            from .comparison_representation import revise_representation_inputs
            revise_representation_inputs(staged,plan,representation_updates)
        if 'composition' in plan or any(unit.get('requirements') or unit.get('recursion_groups')
                                        for unit in [plan,*plan.get('dependencies',[])]) or 'entries' in plan.get('program_driver',{}):
            from .comparison_composition import composition_graph
            plan['composition']=composition_graph(staged,plan)
        write_json(staged/'comparison-plan.json',plan)
        plan,current=load_comparison_package(staged)
        # A removed service/interface must not leave its old generated API behind.
        for directory in [staged/'generated',*[staged/'dependencies'/u['id']/'generated' for u in plan.get('dependencies',[])]]:
            if directory.exists():
                shutil.rmtree(directory)
        for name in ('AUTHORING.md','compile_commands.json'):
            (staged/name).unlink(missing_ok=True)
        materialize_comparison_headers(staged,plan,current)


def _revise_comparison_files(root,plan,role,files,*,rebind_original,unit=None):
    """Replace one unit's declared file role in the existing revision transaction."""
    unit=plan if unit is None else unit
    prefix='' if unit is plan else 'dependencies/'+unit['id']+'/'
    directory=prefix+('bridges' if prefix and role=='adapters' else role)
    if not isinstance(files,dict):
        raise ValueError('revised '+role+' must map relative names to files')
    contents={}
    for name,origin in files.items():
        if not isinstance(name,str) or not name:
            raise ValueError('revised '+role+' requires nonempty relative file names')
        path=PurePosixPath(name)
        if path.is_absolute() or name=='.' or '..' in path.parts or path.as_posix()!=name:
            raise ValueError('revised '+role+' path is invalid: '+name)
        contents[directory+'/'+name]=Path(origin).read_bytes()
    if role=='headers':
        previous={p.relative_to(root).as_posix() for p in (root/directory).rglob('*') if p.is_file()}
        if any(name.startswith(directory+'/') for name in unit['include_directories']):
            raise ValueError('header revision requires a single headers include directory; use full preparation')
    else:
        previous=set(unit['adapters' if role=='adapters' else role+'_files'])
    if any(not name.startswith(directory+'/') for name in previous):
        raise ValueError('revision cannot replace files outside the '+role+' role; use full preparation')
    if not rebind_original:
        for name in previous & plan['original']['files'].keys():
            if contents.get(name)!=package_file(root,name).read_bytes():
                raise ValueError('changing original comparison input requires reviewed original_files: '+name)
    for name in contents.keys()-previous:
        if (root/name).exists():
            raise ValueError('comparison revision would replace an unowned file: '+name)
    for name in previous:
        package_file(root,name).unlink()
    for name,data in contents.items():
        destination=root/name;destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(data)
    if role=='headers':
        if contents and directory not in unit['include_directories']:
            unit['include_directories'].append(directory)
        elif not contents:
            unit['include_directories']=[name for name in unit['include_directories'] if name!=directory]
    else:
        unit['adapters' if role=='adapters' else role+'_files']=sorted(contents)


def retained_comparison_environment(package: Path) -> dict:
    """Reuse a validated package's tools and link/runtime files for new boundaries.

    This deliberately does not inherit its component, cases, oracle declaration,
    contracts, adapters or selected implementations. Callers still choose those
    inputs explicitly. Return values are existing prepare_comparison_package
    keyword arguments, not a new artifact or mutable environment configuration.
    """
    package=package.resolve()
    plan,_=load_comparison_package(package)
    result={name:None if tool is None else Path(tool['path']) for name,tool in plan['tools'].items()}
    for role in ('link','runtime'):
        files={}
        for relative in plan[role+'_files']:
            try:
                name=PurePosixPath(relative).relative_to(role).as_posix()
            except ValueError as exc:
                raise ValueError(f'retained {role} input is outside its package role: {relative}') from exc
            files[name]=package_file(package,relative)
        result[role+'_files']=files
    return result


@contextmanager
def _comparison_source(*, component_id, source_package, source_files, operation_symbols):
    from .source import build_component_source_package,load_component_source_package

    if source_package is not None:
        if source_files is not None or operation_symbols is not None:
            raise ValueError('choose a source package or authored files and operation symbols, not both')
        yield load_component_source_package(source_package),source_package/'sources'
    else:
        if source_files is None or operation_symbols is None:
            raise ValueError('authored comparison files require explicit operation symbols')
        with tempfile.TemporaryDirectory(prefix='spaghetti-comparison-source-') as temporary:
            root=Path(temporary)
            build_component_source_package(lift_unit_id=component_id,files=source_files,
                shared_inputs={},operation_symbols=operation_symbols,out_dir=root)
            yield load_component_source_package(root),root/'sources'


def prepare_comparison_package(*, interface_package: Path | ComponentInterfaceIntentV1,
        source_package: Path | None = None, source_files: dict | None = None, operation_symbols: dict | None = None,
        target_id: str, component_id: str, adapter_files: dict, include_files: dict,
        link_files: dict, runtime_files: dict, original_files: list[str], oracle_kind: str,
        cases: list, observation_fields: list[str], assumptions: list[str], scope: str,
        compiler: Path, runner: Path | None, server: Path | None, output: Path,
        dependencies: list | None = None, input_domain: dict | None = None, representation: dict | None = None,
        resource_checks: dict | None = None, service_catalog: dict | None = None, service_bridge: dict | None = None, requirements: list | None = None,
        recursion_groups: list | None = None, export_adapters: list | None = None, local_shared_contract: dict | None = None,
        program_driver: dict | None = None, private_headers: list[str] | None = None, state_owners: list | None = None) -> None:
    """Materialize executable setup from existing packages or authored C files.

    Direct inputs use the same interface parser and source-package builder; no
    separate file format or weaker checking path is introduced. Authored headers
    belong in source_files; target/runtime adapters belong in include_files.
    private_headers names implementation-only authored paths (including source/).
    This is an operator declaration, not a proof of header-use isolation.
    state_owners declares shared storage and C lifecycle assumptions, with source
    names relative to this component's authored source directory. It does not
    change formal qualification or implement a state reset/serialization model.
    Each dependencies selection names an id in its package. A nested id retains
    that unit's declared supplier closure and selected adapters; a package-entry
    id retains the complete package selection. No comparison evidence is imported.
    A rejected preparation leaves the destination unchanged, ready for a retry.
    """
    from .source import component_operation_symbols

    if isinstance(interface_package,ComponentInterfaceIntentV1):
        intent=ComponentInterfaceIntentV1.parse(interface_package.to_payload())
    else:
        interface_file=interface_package/'component-interface-intent-v1.json' if interface_package.is_dir() else interface_package
        intent=ComponentInterfaceIntentV1.parse(json.loads(interface_file.read_text()))
    if intent.component_id!=component_id:
        raise ValueError('comparison interface belongs to another component')
    with comparison_preparation(output) as output:
        paths={}
        def copy_file(relative, origin):
            path=PurePosixPath(relative)
            if path.is_absolute() or '..' in path.parts or relative in paths:
                raise ValueError('comparison preparation path is invalid or duplicated')
            destination=output/path
            destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(origin,destination)
            paths[relative]=sha256_file(destination)
        write_json(output/'interface.json',intent.to_payload())
        paths['interface.json']=sha256_file(output/'interface.json')
        with _comparison_source(component_id=component_id,source_package=source_package,
                source_files=source_files,operation_symbols=operation_symbols) as (source,source_root):
            if source['lift_unit_id']!=component_id:
                raise ValueError('comparison source package belongs to another component')
            for row in source['files']+source['shared_inputs']:
                copy_file('source/'+row['path'],source_root/row['path'])
        for role,files in [('adapters',adapter_files),('headers',include_files),('link',link_files),('runtime',runtime_files)]:
            for name,path in files.items():
                copy_file(role+'/'+name,Path(path))
        if not original_files or any(name not in paths for name in original_files):
            raise ValueError('comparison original files must name materialized inputs')
        def tool(path):
            return None if path is None else {'path':str(path.resolve()),'sha256':sha256_file(path)}
        plan={'format':COMPONENT_COMPARISON_PLAN_V1_FORMAT,'target_id':target_id,'component_id':component_id,
              'interface':'interface.json','sources':['source/'+row['path'] for row in source['files']],
              'adapters':['adapters/'+name for name in sorted(adapter_files)],'operation_symbols':component_operation_symbols(source),
              'include_directories':['source']+(['headers'] if include_files else []),
              'link_files':['link/'+name for name in sorted(link_files)],'runtime_files':['runtime/'+name for name in sorted(runtime_files)],
              'original':{'kind':oracle_kind,'files':{name:paths[name] for name in original_files}},
              'cases':cases,'observation_fields':observation_fields,'assumptions':assumptions,'scope':scope,
              'tools':{'compiler':tool(compiler),'runner':tool(runner),'server':tool(server)}}
        if state_owners is not None:
            plan['state_owners']=state_owners
        if local_shared_contract is not None:
            plan['local_shared_contract']=local_shared_contract
        if private_headers is not None:
            plan['private_headers']=private_headers
        if program_driver is not None:
            plan['program_driver']=program_driver
        if resource_checks is not None:
            plan['resource_checks']=resource_checks
        if service_catalog is not None:
            plan['service_catalog']=service_catalog
        if service_bridge is not None:
            plan['service_bridge']=service_bridge
        if input_domain is not None:
            plan['input_domain']=input_domain
        if representation is not None:
            plan['representation']=representation
        if export_adapters is not None:
            plan['export_adapters']=export_adapters
        if recursion_groups is not None:
            plan['recursion_groups']=recursion_groups
        if dependencies or requirements is not None or recursion_groups or 'entries' in (program_driver or {}):
            from .comparison_composition import resolve_composition
            resolve_composition(output=output,plan=plan,selections=dependencies or [],requirements=requirements)
        write_json(output/'comparison-plan.json',plan)
        plan,intent=load_comparison_package(output)
        materialize_comparison_headers(output,plan,intent)
