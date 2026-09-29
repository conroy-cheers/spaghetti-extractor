"""Selected authored dependencies with their own existing C interfaces.

Resolved selections retain each body once with its own interface and bridge.
Independent packages can still use native or controlled services without selecting
a neighboring authored body.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil

from ..util import write_json
from .interface_package_v5 import ComponentInterfaceIntentV1
from .comparison_source_draft import DependencySelection, SourceDraft, selection_path, source_draft_inputs, install_source_draft


def comparison_units(plan: dict) -> list[dict]:
    return [dict(id=plan['component_id'], **{k: plan[k] for k in
        ('sources','adapters','include_directories','operation_symbols','interface')},
        **({'state_owners':plan['state_owners']} if 'state_owners' in plan else {})), *plan.get('dependencies', [])]


def comparison_includes(plan: dict, unit: dict) -> list[str]:
    generated='generated' if unit['id']==plan['component_id'] else f"dependencies/{unit['id']}/generated"
    return [generated,*unit['include_directories']]


def validate_dependencies(root: Path, plan: dict) -> None:
    from .comparison_package import package_file
    rows=plan.get('dependencies', [])
    if not isinstance(rows,list):
        raise ValueError('comparison dependencies must be a list')
    ids={plan['component_id']}
    files=set(plan['sources']+plan['adapters'])
    for row in rows:
        if not isinstance(row,dict) or set(row)-{'input_domain','representation','resource_checks','service_catalog','service_bridge','requirements','recursion_groups','private_headers','state_owners'}!={'id','interface','sources','adapters','include_directories','operation_symbols','assumptions'}:
            raise ValueError('comparison dependency fields are invalid')
        from .comparison_domain import checked_input_domain
        checked_input_domain(row.get('input_domain'))
        identity=row['id']
        if not isinstance(identity,str) or not re.fullmatch(r'[a-zA-Z0-9_.-]+',identity) or identity in {'.','..'} or identity in ids:
            raise ValueError('comparison dependency identity is invalid or repeated')
        ids.add(identity)
        prefix=f'dependencies/{identity}/'
        interface=ComponentInterfaceIntentV1.parse(json.loads(package_file(root,row['interface']).read_text()))
        from .comparison_resources import checked_resource_checks
        checked_resource_checks(row.get('resource_checks'),interface)
        from .service_authoring import checked_service_catalog
        checked_service_catalog(row.get('service_catalog'),interface)
        from .service_c import materialize_service_bridge
        materialize_service_bridge(row,interface)
        if interface.component_id!=identity or not row['interface'].startswith(prefix):
            raise ValueError('comparison dependency interface identity differs')
        if not isinstance(row['assumptions'],list) or not row['assumptions'] or any(not isinstance(v,str) or not v for v in row['assumptions']):
            raise ValueError('comparison dependency assumptions must be explicit')
        for role in ('sources','adapters'):
            values=row[role]
            if not isinstance(values,list) or not values or any(not isinstance(v,str) for v in values):
                raise ValueError('comparison dependency requires source and bridge files')
            for name in values:
                package_file(root,name)
                if not name.startswith(prefix) or name in files or not name.endswith(('.c','.h') if role=='sources' else '.c'):
                    raise ValueError('comparison dependency file is shared, misplaced or unsupported')
                files.add(name)
        if not any(name.endswith('.c') for name in row['sources']):
            raise ValueError('comparison dependency has no C translation unit')
        if not isinstance(row['include_directories'],list):
            raise ValueError('comparison dependency include directories must be a list')
        for name in row['include_directories']:
            if not isinstance(name,str) or not name.startswith(prefix) or not (root/name).is_dir() or not (root/name).resolve().is_relative_to(root.resolve()):
                raise ValueError('comparison dependency include directory escapes its package')

        from .comparison_representation import representation_binding
        representation_binding(root,row)
        from .source import checked_private_headers
        checked_private_headers(row.get('private_headers'),row['sources'],protected=[*plan['original']['files'],
            *(row.get('representation') or {}).get('inputs',{}).values()])


def install_dependency(*, output: Path, identity: str, package: Path, adapters: dict,
                       expected: dict | None = None) -> dict:
    from .comparison_package import load_comparison_package
    plan,intent=load_comparison_package(package)
    if identity!=plan['component_id'] or not re.fullmatch(r'[a-zA-Z0-9_.-]+',identity) or identity in {'.','..'}:
        raise ValueError('selected dependency package has another component identity')
    if plan.get('dependencies'):
        raise ValueError('select dependency bodies explicitly; nested selections are not imported')
    return install_unit(output=output,identity=identity,root=package,unit=plan,adapters=adapters,expected=expected)


def install_unit(*, output: Path, identity: str, root: Path, unit: dict, adapters: dict,
                 expected: dict | None = None) -> dict:
    from .comparison_package import package_file
    from .comparison_representation import checked_representation
    plan=unit;package=root
    intent=ComponentInterfaceIntentV1.parse(json.loads(package_file(package,plan['interface']).read_text()))
    origin_prefix='' if 'component_id' in plan else 'dependencies/'+identity+'/'
    def unit_relative(name):
        if not name.startswith(origin_prefix):raise ValueError('selected unit file is outside its namespace')
        return name.removeprefix(origin_prefix)
    if expected is not None:
        current=ComponentInterfaceIntentV1.parse(json.loads(package_file(output,expected['interface']).read_text()))
        if (current.to_payload()!=intent.to_payload() or expected['operation_symbols']!=plan['operation_symbols']
                or expected.get('state_owners')!=plan.get('state_owners')
                or expected.get('resource_checks')!=plan.get('resource_checks')
                or expected.get('service_catalog')!=plan.get('service_catalog')
                or expected.get('requirements',[])!=plan.get('requirements',[])
                or expected.get('recursion_groups',[])!=plan.get('recursion_groups',[])
                or {unit_relative(name) for name in plan.get('private_headers',[])}
                != {name.removeprefix('dependencies/'+identity+'/') for name in expected.get('private_headers',[])}
                or expected['assumptions']!=plan['assumptions'] or expected.get('input_domain')!=plan.get('input_domain')
                or {k:v for k,v in (checked_representation(expected.get('representation'),identity) or {}).items() if k!='inputs'}
                != {k:v for k,v in (checked_representation(plan.get('representation'),identity) or {}).items() if k!='inputs'}):
            from .comparison_contract_diagnostics import contract_changes,describe_contract_changes
            raise ValueError('dependency contract changed for '+identity+
                '; refine the selection explicitly before replacing its implementation\n'+
                describe_contract_changes(contract_changes(output,expected,package,plan)))
    prefix=f'dependencies/{identity}/'
    names=set(plan['sources']+[plan['interface']])
    for directory in plan['include_directories']:
        for path in (package/directory).rglob('*'):
            if path.is_symlink():
                raise ValueError('dependency include tree contains symbolic links')
            if path.is_file():
                names.add(path.relative_to(package).as_posix())
    contents={prefix+unit_relative(name):package_file(package,name).read_bytes() for name in names}
    bridge_names=[]
    for name,path in adapters.items():
        if not re.fullmatch(r'[a-zA-Z0-9_.-]+\.c',name):
            raise ValueError('dependency bridge requires a C file basename')
        relative=prefix+'bridges/'+name
        contents[relative]=Path(path).read_bytes()
        bridge_names.append(relative)
    destination=output/'dependencies'/identity
    if destination.exists():
        shutil.rmtree(destination)
    for name,data in contents.items():
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
    for directory in plan['include_directories']:
        (output/prefix/unit_relative(directory)).mkdir(parents=True,exist_ok=True)
    return {'id':identity,'interface':prefix+unit_relative(plan['interface']),
        'sources':[prefix+unit_relative(name) for name in plan['sources']], 'adapters':sorted(bridge_names),
        'include_directories':[prefix+unit_relative(name) for name in plan['include_directories']],
        'operation_symbols':plan['operation_symbols'],'assumptions':plan['assumptions'],
        **({'private_headers':[prefix+unit_relative(name) for name in plan['private_headers']]} if 'private_headers' in plan else {}),
        **({'requirements':plan['requirements']} if 'requirements' in plan else {}),
        **({'recursion_groups':plan['recursion_groups']} if 'recursion_groups' in plan else {}),
        **({'service_bridge':plan['service_bridge']} if 'service_bridge' in plan else {}),
        **({'service_catalog':plan['service_catalog']} if 'service_catalog' in plan else {}),
        **({'state_owners':plan['state_owners']} if 'state_owners' in plan else {}),
        **({'resource_checks':plan['resource_checks']} if 'resource_checks' in plan else {}),
        **({'input_domain':plan['input_domain']} if 'input_domain' in plan else {}),
        **({'representation':{**plan['representation'],'inputs':{k:prefix+unit_relative(v) for k,v in plan['representation']['inputs'].items()}}} if 'representation' in plan else {})}


def _dependency_updates(snapshot: Path, plan: dict, replacements: dict[str,DependencySelection], *,
                        allow_new_suppliers: bool = False) -> tuple[dict,dict]:
    """Resolve explicit choices and bundled defaults before changing any files."""
    selected={row['id']:row for row in plan.get('dependencies',[])}
    if set(replacements)-selected.keys():
        raise ValueError('replacement names a dependency absent from this comparison')
    from .comparison_package import load_comparison_package
    from .comparison_composition import contract_identity,implementation_identity
    packages={};drafts={}
    for requested,selection in replacements.items():
        package=selection_path(selection)
        if isinstance(selection,SourceDraft) or (package/'source-export.json').is_file():
            drafts[requested]=source_draft_inputs(selection,package=snapshot,plan=plan,component_id=requested)
            # Explicit C-only choice: preserve the consumer's adapter and all
            # neighboring selections, including when another caller bundles it.
            packages[requested]=(snapshot,selected[requested])
            continue
        replacement,_=load_comparison_package(package)
        if replacement['target_id']!=plan['target_id']:
            raise ValueError('replacement package belongs to another target')
        if replacement['component_id']!=requested:raise ValueError('replacement package has another component identity')
        packages[requested]=(package,replacement)
    updates={};fingerprints={}
    for requested,(package,replacement) in packages.items():
        for unit in [replacement,*replacement.get('dependencies',[])]:
            identity=unit.get('id',unit.get('component_id'))
            if identity==plan['component_id']:
                raise ValueError('replacement cannot redefine the enclosing entry component')
            if identity not in selected and not allow_new_suppliers:
                raise ValueError('replacement adds unselected supplier '+identity+'; refine the composition explicitly')
            old=selected.get(identity)
            if identity in replacements and identity!=requested:
                # An explicitly edited supplier has one global selected body.
                # Bundled defaults must agree with the explicitly chosen contract.
                # Callers decide separately whether that contract was reviewed or
                # must remain identical to the previous selected boundary.
                chosen_root,chosen=packages[identity]
                if contract_identity(package,unit)!=contract_identity(chosen_root,chosen):
                    raise ValueError('dependency contract changed for '+identity+
                        ' in replacement '+requested+'; refine the selection explicitly')
                continue
            exported=unit.get('export_adapters',[]) if 'component_id' in unit else unit['adapters']
            if not exported and old is None:
                raise ValueError('new supplier requires explicit exported adapters: '+identity)
            adapters=({Path(name).name:package/name for name in exported} if exported else
                      {Path(name).name:snapshot/name for name in old['adapters']})
            digest=(contract_identity(package,unit),implementation_identity(package,unit,adapters))
            if identity in updates and fingerprints[identity]!=digest:
                raise ValueError('conflicting replacement selections for '+identity)
            updates[identity]=(package,unit,adapters);fingerprints[identity]=digest
    return updates,drafts


def replace_dependency_packages(snapshot: Path, plan: dict, replacements: dict[str,DependencySelection]) -> None:
    from .comparison_composition import contract_identity
    selected={row['id']:row for row in plan.get('dependencies',[])}
    updates,drafts=_dependency_updates(snapshot,plan,replacements)
    # Frozen caller requirements would reject these changes after installation.
    # Explain them while the snapshot still contains the expected shared files.
    for identity,(package,unit,_) in updates.items():
        consumers=[e['consumer']+'/'+e['id'] for e in plan.get('composition',{}).get('edges',[])
            if e['supplier']==identity and e['contract_sha256']!=contract_identity(package,unit)]
        if consumers:
            from .comparison_contract_diagnostics import contract_changes,describe_contract_changes
            raise ValueError('dependency contract changed for '+identity+'; consumers requiring refinement: '+
                ', '.join(consumers)+'\n'+describe_contract_changes(contract_changes(snapshot,selected[identity],package,unit)))
    for identity,(package,unit,adapters) in updates.items():
        try:
            selected[identity]=install_unit(output=snapshot,identity=identity,root=package,unit=unit,
                adapters=adapters,expected=selected[identity])
        except ValueError as error:
            consumers=[e['consumer']+'/'+e['id'] for e in plan.get('composition',{}).get('edges',[]) if e['supplier']==identity]
            if consumers and 'contract changed' in str(error):
                raise ValueError(str(error)+'; consumers requiring refinement: '+', '.join(consumers)) from error
            raise
    for identity,files in drafts.items():
        install_source_draft(snapshot,selected[identity],files)
    if replacements:
        plan['dependencies']=[selected[row['id']] for row in plan['dependencies']]
        if 'composition' in plan:
            from .comparison_composition import composition_graph
            plan['composition']=composition_graph(snapshot,plan)
        write_json(snapshot/'comparison-plan.json',plan)


def refine_dependency_requirements(snapshot: Path, plan: dict, reviewed: dict[str,Path]) -> None:
    """Author named caller requirements; leave every unreviewed caller frozen.

    This is preparation of a new comparison package, not implementation replacement
    or evidence of compatibility. Names are CONSUMER/REQUIREMENT, with a bare
    requirement referring to the package entry. The caller publishes atomically.
    Bundled suppliers with matching contracts retain the selected implementations.
    Newly declared suppliers are imported from the reviewed package's closure;
    the final graph must justify every selected unit and retain frozen callers.
    """
    from .comparison_package import load_comparison_package
    from .comparison_composition import contract_identity,composition_graph
    if not isinstance(reviewed,dict) or not reviewed or any(not isinstance(name,str) for name in reviewed):
        raise ValueError('reviewed requirements must map requirement names to supplier packages')
    if 'composition' not in plan:
        raise ValueError('requirement refinement needs an existing resolved composition')
    units={plan['component_id']:plan,**{row['id']:row for row in plan.get('dependencies',[])}}
    requirements={identity+'/'+row['id']:(identity,row) for identity,unit in units.items()
                  for row in unit.get('requirements',[])}
    named={}
    for name,path in reviewed.items():
        full=name if '/' in name else plan['component_id']+'/'+name
        if full in named:raise ValueError('caller requirement is reviewed twice: '+full)
        named[full]=path
    if named.keys()-requirements.keys():
        raise ValueError('review names an absent caller requirement: '+', '.join(sorted(named.keys()-requirements.keys())))
    replacements={};contracts={}
    for name,path in named.items():
        _,row=requirements[name]
        if row['kind']=='internal':
            raise ValueError('internal recursion requires explicit interface/requirement preparation')
        package=Path(path).resolve();unit,_=load_comparison_package(package)
        identity=row['supplier']
        if unit['component_id']!=identity:
            raise ValueError('reviewed requirement '+name+' names another supplier component')
        if identity in replacements and replacements[identity]!=package:
            raise ValueError('conflicting reviewed packages for '+identity)
        replacements[identity]=package
        contracts[name]=contract_identity(package,unit)
    updates,_=_dependency_updates(snapshot,plan,replacements,allow_new_suppliers=True)
    # A supplier package can retain old defaults for other selected units. Their
    # unchanged contracts do not justify replacing independent implementation
    # edits in this network. Explicit supplier choices still take precedence.
    updates={identity:value for identity,value in updates.items()
             if identity in replacements or identity not in units
             or contract_identity(value[0],value[1])!=contract_identity(snapshot,units[identity])}
    proposed={identity:(snapshot,unit) for identity,unit in units.items()}
    proposed.update({identity:(package,unit) for identity,(package,unit,_) in updates.items()})
    bindings={identity:contract_identity(package,unit) for identity,(package,unit) in proposed.items()}
    revised={}
    for identity,(_,unit) in proposed.items():
        rows=[]
        for row in unit.get('requirements',[]):
            name=identity+'/'+row['id']
            if name in named:
                previous=requirements[name][1]
                if any(row[key]!=previous[key] for key in ('supplier','kind','service')):
                    raise ValueError('reviewed caller requirement changed in the supplied package: '+name+
                                     '; prepare that caller explicitly')
                row=dict(row,contract_sha256=contracts[name])
            rows.append(row)
        revised[identity]=rows
    present={identity+'/'+row['id'] for identity,rows in revised.items() for row in rows}
    if named.keys()-present:
        raise ValueError('reviewed caller requirement was removed by the supplied package: '+', '.join(sorted(named.keys()-present)))
    missing=sorted(identity+'/'+row['id'] for identity,rows in revised.items() for row in rows
                   if row['contract_sha256']!=bindings.get(row['supplier']))
    if missing:
        raise ValueError('supplier contract changed for '+', '.join(missing)+
                         '; review each CONSUMER/REQUIREMENT explicitly')
    selected={row['id']:row for row in plan.get('dependencies',[])}
    for identity,(package,unit,adapters) in updates.items():
        selected[identity]=install_unit(output=snapshot,identity=identity,root=package,unit=unit,adapters=adapters)
    plan['dependencies']=[selected[identity] for identity in sorted(selected)]
    for identity,unit in [(plan['component_id'],plan),*selected.items()]:
        if 'requirements' in unit or revised[identity]:unit['requirements']=revised[identity]
    # Unreviewed consumers, including shared transitive callers, must still agree.
    plan['composition']=composition_graph(snapshot,plan)


def check_comparison_sources(snapshot: Path, plan: dict, output: Path) -> tuple[dict,dict]:
    from .comparison_package import package_file
    from .source import build_component_source_package
    from .source_profile import check_component_source_profile
    from .source_dialect import practical_source_profile
    profiles={}
    for unit in comparison_units(plan):
        path=output/'source-packages'/unit['id']
        build_component_source_package(lift_unit_id=unit['id'],
            files={name:package_file(snapshot,name) for name in unit['sources']},shared_inputs={},
            operation_symbols=unit['operation_symbols'],out_dir=path)
        profiles[unit['id']]=practical_source_profile(check_component_source_profile(package=path), state_owners=unit.get('state_owners'))
    return next((p for p in profiles.values() if p['status']=='incomplete'),
                profiles[plan['component_id']]),profiles


def finish_comparison_profiles(profiles, plan, build):
    """Inspect every compiled authored TU, including macro/header state and cache hits."""
    import json
    from .source_dialect import inspect_object_storage, practical_source_profile
    compilation = json.loads((build/'compilation.json').read_text())
    units = {unit['id']: unit for unit in comparison_units(plan)}
    for name, profile in list(profiles.items()):
        if profile['status'] != 'pending-storage':
            continue
        storage = [dict(inspect_object_storage(Path(plan['tools']['compiler']['path']), build/row['object']),
                        source=row['source']) for row in compilation['units']
                   if row['unit'] == name and row['source'] in units[name]['sources']]
        state=units[name].get('state_owners')
        if state is not None:
            prefix='source/' if name==plan['component_id'] else 'dependencies/'+name+'/source/'
            for row in storage:row['authored_source']=row['source'].removeprefix(prefix)
        profiles[name] = practical_source_profile(profile['proof_profile'], storage, state_owners=state)
    return next((p for p in profiles.values() if p['status'] != 'satisfied'), profiles[plan['component_id']])
