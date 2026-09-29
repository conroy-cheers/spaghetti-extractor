"""Explicit requirement resolution over existing comparison-package units.

The graph binds declared boundary contracts and selected implementations. It does
not establish service semantics, checked-summary composition or recursion progress.
"""
from __future__ import annotations

import json
from pathlib import Path
import re

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file
from .interface_package_v5 import ComponentInterfaceIntentV1


def contract_binding(root: Path, unit: dict) -> dict:
    from .comparison_package import package_file
    from .comparison_representation import representation_binding
    intent=ComponentInterfaceIntentV1.parse(json.loads(package_file(root,unit['interface']).read_text()))
    return dict(interface=intent.intent_sha256,operation_symbols=unit['operation_symbols'],
        assumptions=unit['assumptions'],input_domain=unit.get('input_domain'),
        resource_checks=unit.get('resource_checks'),service_catalog=unit.get('service_catalog'),
        representation=representation_binding(root,unit),
        **({'state_owners':unit['state_owners']} if 'state_owners' in unit else {}))


def contract_identity(root: Path, unit: dict) -> str:
    return canonical_sha256_v3(contract_binding(root,unit))


def requirement(*, identity: str, supplier: str, root: Path, unit: dict,
                kind: str = 'consumer', service: str | None = None) -> dict:
    """Record an explicit requirement against the currently reviewed contract."""
    return dict(id=identity,supplier=supplier,contract_sha256=contract_identity(root,unit),kind=kind,service=service)


def review_selected_contract(root: Path, plan: dict, identity: str, reviewed: list[str], *,
                             previous: tuple[Path,dict] | None = None) -> None:
    """Rebind explicitly reviewed incoming requirements to an edited selected unit.

    This records operator review in the existing graph. It neither imports a
    supplier package nor changes caller C, and establishes no compatibility proof.
    """
    if (not isinstance(reviewed,list) or any(not isinstance(name,str) for name in reviewed)
            or len(set(reviewed))!=len(reviewed)):
        raise ValueError('reviewed requirements must be unique CONSUMER/REQUIREMENT names')
    units={plan['component_id']:plan,**{row['id']:row for row in plan.get('dependencies',[])}}
    contract=contract_identity(root,units[identity])
    changed={consumer+'/'+row['id']:row for consumer,unit in units.items()
        for row in unit.get('requirements',[])
        if row['supplier']==identity and row['contract_sha256']!=contract}
    missing=changed.keys()-set(reviewed)
    if missing:
        message='component '+identity+' needs reviewed requirements: '+', '.join(sorted(missing))
        if previous is not None:
            from .comparison_contract_diagnostics import contract_changes,describe_contract_changes
            message+='\nProposed boundary changes (not published):\n'+describe_contract_changes(
                contract_changes(*previous,root,units[identity]),include_paths=False)
        raise ValueError(message)
    extra=set(reviewed)-changed.keys()
    if extra:
        raise ValueError('component review names an unaffected or absent requirement: '+', '.join(sorted(extra)))
    for row in changed.values():
        row['contract_sha256']=contract


def bind_dependencies(*, services: dict[str,Path | dict] | None = None,
                      consumers: dict[str,Path | dict] | None = None) -> dict:
    """Select reviewed packages and freeze their requirements for initial setup.

    Keys name interface services or explicit consumer requirements. The package
    supplies its component identity and exact contract, including assumptions and
    representation inputs. The returned values are existing preparation kwargs,
    not another artifact or evidence of contract compatibility. Subsequent edits
    use dependency replacement against these frozen requirements; regenerating
    them is an explicit refinement, not automatic acceptance of a changed contract.
    Values may also use the existing selection mapping {id, package, adapters?}
    to name a unit already selected inside a network. Its declared supplier closure
    and adapters are resolved by preparation; no surrounding driver is imported.
    """
    from .comparison_package import load_comparison_package
    packages={};loaded={};requirements=[];names=set()
    for kind, selected in [('service',services),('consumer',consumers)]:
        if selected is None:continue
        if not isinstance(selected,dict):raise ValueError('dependency bindings must be named package mappings')
        for name,reference in selected.items():
            if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_.-]+',name) or name in ('.','..'):
                raise ValueError('dependency requirement name is invalid')
            if name in names:raise ValueError('dependency requirement name is repeated: '+name)
            names.add(name)
            selection=dict(reference) if isinstance(reference,dict) else dict(package=reference)
            if isinstance(reference,dict) and not {'id','package'}<=selection.keys()<={'id','package','adapters'}:
                raise ValueError('dependency binding selection requires id, package and optional adapters')
            root=Path(selection['package']).resolve()
            if root not in loaded:
                loaded[root]=load_comparison_package(root)[0]
            plan=loaded[root]
            identity=selection.get('id',plan['component_id'])
            units={plan['component_id']:plan,**{row['id']:row for row in plan.get('dependencies',[])}}
            if not isinstance(identity,str) or identity not in units:
                raise ValueError('dependency binding names an absent selected component; available: '+', '.join(units))
            unit=units[identity]
            choice=dict(id=identity,package=root)
            if 'adapters' in selection:
                adapters=selection['adapters']
                if not isinstance(adapters,dict):
                    raise ValueError('dependency binding adapters must map C filenames to paths')
                if adapters:choice['adapters']={key:Path(path).resolve() for key,path in adapters.items()}
            if identity in packages and packages[identity]!=choice:
                raise ValueError('ambiguous package selection for '+identity)
            packages[identity]=choice
            requirements.append(requirement(identity=name,supplier=identity,root=root,unit=unit,
                kind=kind,service=name if kind=='service' else None))
    return dict(dependencies=list(packages.values()),
                requirements=requirements)


def checked_requirements(value, interface):
    if value is None:return []
    if not isinstance(value,list):raise ValueError('component requirements must be a list')
    ids=set();services={s['id'] for s in interface.services}
    for row in value:
        if not isinstance(row,dict) or set(row)!={'id','supplier','contract_sha256','kind','service'}:
            raise ValueError('component requirement fields are invalid')
        for key in ('id','supplier'):
            if not isinstance(row[key],str) or not re.fullmatch(r'[A-Za-z0-9_.-]+',row[key]) or row[key] in ('.','..'):
                raise ValueError('component requirement identity is invalid')
        if row['id'] in ids:raise ValueError('component requirement identity is repeated')
        ids.add(row['id'])
        if not isinstance(row['contract_sha256'],str) or not re.fullmatch(r'[0-9a-f]{64}',row['contract_sha256']):
            raise ValueError('component requirement must bind an exact supplier contract')
        if row['kind'] not in ('service','consumer','internal'):
            raise ValueError('component requirement kind is unsupported')
        if row['kind']=='service':
            if not isinstance(row['service'],str) or row['service'] not in services:raise ValueError('component requirement names an absent interface service')
        elif row['service'] is not None:
            raise ValueError('non-service requirement cannot invent an interface service')
        if row['kind']=='internal' and row['supplier']!=interface.component_id:
            raise ValueError('internal recursion must name its own component; use a service requirement for a cross-component call')
    return value


def _cycles(ids,edges):
    adjacent={name:[] for name in ids}
    for edge in edges:adjacent[edge['consumer']].append(edge['supplier'])
    counter=0;indices={};low={};stack=[];active=set();cycles=[]
    def visit(name):
        nonlocal counter
        indices[name]=low[name]=counter;counter+=1;stack.append(name);active.add(name)
        for target in adjacent[name]:
            if target not in indices:visit(target);low[name]=min(low[name],low[target])
            elif target in active:low[name]=min(low[name],indices[target])
        if low[name]==indices[name]:
            members=[]
            while True:
                item=stack.pop();active.remove(item);members.append(item)
                if item==name:break
            if len(members)>1 or name in adjacent[name]:cycles.append(sorted(members))
    for name in sorted(ids):
        if name not in indices:visit(name)
    return sorted(cycles)


def composition_entries(plan: dict) -> list[str]:
    """Program entry components are selections, not invented caller edges."""
    if 'entries' not in plan.get('program_driver',{}):return [plan['component_id']]
    entries=plan['program_driver']['entries']
    selected={plan['component_id'],*[row['id'] for row in plan.get('dependencies',[])]}
    if (not isinstance(entries,list) or not entries or any(not isinstance(name,str) for name in entries)
            or entries!=sorted(set(entries)) or plan['component_id'] not in entries
            or not set(entries)<=selected):
        raise ValueError('program entries must be sorted unique selected component identities including the package entry')
    return entries


def composition_graph(root: Path, plan: dict) -> dict:
    from .comparison_package import package_file
    units={plan['component_id']:plan,**{row['id']:row for row in plan.get('dependencies',[])}}
    contracts={name:contract_identity(root,row) for name,row in units.items()}
    edges=[];groups={}
    for name,unit in units.items():
        intent=ComponentInterfaceIntentV1.parse(json.loads(package_file(root,unit['interface']).read_text()))
        for req in checked_requirements(unit.get('requirements'),intent):
            if req['supplier'] not in units:
                raise ValueError(f"missing supplier {req['supplier']} required by {name}/{req['id']}")
            if contracts[req['supplier']]!=req['contract_sha256']:
                raise ValueError(f"supplier contract changed for {name}/{req['id']}; refine that requirement explicitly")
            edges.append(dict(consumer=name,**req))
        declarations=unit.get('recursion_groups',[])
        if not isinstance(declarations,list):raise ValueError('recursion groups must be explicit declarations')
        for group in declarations:
            if not isinstance(group,dict) or set(group)!={'id','members','mode','progress'}:
                raise ValueError('recursion group requires id, members, mode and progress')
            if group['mode']!='synchronous-comparison' or group['progress']!='unproved':
                raise ValueError('unsupported recursive selection: only synchronous concrete comparison with unproved progress is available')
            if not isinstance(group['id'],str) or not group['id'] or not isinstance(group['members'],list) or not group['members'] or any(not isinstance(x,str) for x in group['members']) or group['members']!=sorted(set(group['members'])):
                raise ValueError('recursion group identities/members are invalid')
            if name!=plan['component_id'] and name not in group['members']:raise ValueError('recursion declaration must belong to a member component')
            if group['id'] in groups and groups[group['id']]!=group:raise ValueError('conflicting recursive group declarations')
            groups[group['id']]=group
    entries=composition_entries(plan)
    seen=set(entries)
    while True:
        more={e['supplier'] for e in edges if e['consumer'] in seen}-seen
        if not more:break
        seen.update(more)
    if seen!=set(units):raise ValueError('selected components have no requirement path from the entry: '+', '.join(sorted(set(units)-seen)))
    cycles=_cycles(units,edges)
    declared=[g['members'] for g in groups.values()]
    if sorted(declared)!=cycles:
        raise ValueError('recursive selection requires one explicit synchronous-comparison group for each cycle; observed='+repr(cycles))
    return dict(entry=plan['component_id'],
        **({'program_entries':entries} if 'entries' in plan.get('program_driver',{}) else {}),
        nodes={name:dict(contract_sha256=contracts[name],
        required_by=sorted([dict(component=e['consumer'],requirement=e['id'],kind=e['kind']) for e in edges if e['supplier']==name],key=lambda r:(r['component'],r['requirement']))) for name in sorted(units)},
        edges=sorted(edges,key=lambda e:(e['consumer'],e['id'])),recursion_groups=sorted(groups.values(),key=lambda g:g['id']),
        authority='declared-contract-selection-only')


def validate_composition(root,plan):
    if 'composition' not in plan:
        if ('entries' in plan.get('program_driver',{}) or
                any(row.get('requirements') or row.get('recursion_groups') for row in [plan,*plan.get('dependencies',[])])):
            raise ValueError('declared requirements need a resolved composition graph')
        return
    from .comparison_representation import validate_representation_selection
    validate_representation_selection(root,plan)
    expected=composition_graph(root,plan)
    if plan['composition']!=expected:raise ValueError('resolved composition graph is stale')


def implementation_identity(root,unit,adapters):
    """Exact conservative deduplication; compilation caching has its own inputs."""
    from .comparison_package import package_file
    prefix='' if 'component_id' in unit else 'dependencies/'+unit['id']+'/'
    paths=set(unit['sources'])
    for directory in unit['include_directories']:
        paths.update(p.relative_to(root).as_posix() for p in (root/directory).rglob('*') if p.is_file())
    return canonical_sha256_v3(dict(files={name.removeprefix(prefix):sha256_file(package_file(root,name)) for name in sorted(paths)},
        adapters={name:sha256_file(path) for name,path in sorted(adapters.items())},service_bridge=unit.get('service_bridge'),
        requirements=unit.get('requirements',[]),recursion_groups=unit.get('recursion_groups',[]),
        **({'private_headers':sorted(name.removeprefix(prefix) for name in unit['private_headers'])} if unit.get('private_headers') else {})))


def _selected_units(plan: dict, identity: str) -> list[dict]:
    """Select a named unit and its declared requirements from an existing network.

    Selecting the package entry retains the existing complete-package behavior.
    A nested selection uses only the already declared graph, never inferred calls
    or the enclosing program's other entries, driver or comparison evidence.
    """
    units={plan['component_id']:plan,**{row['id']:row for row in plan.get('dependencies',[])}}
    if identity not in units:
        raise ValueError('selection names another component package; selected components: '+', '.join(units))
    if identity==plan['component_id']:
        return list(units.values())
    if 'composition' not in plan:
        raise ValueError('selecting a nested component requires declared supplier requirements; prepare an explicit local selection')
    needed={identity}
    while more:={req['supplier'] for name in needed for req in units[name].get('requirements',[])}-needed:
        needed.update(more)
    selected=[]
    for name in [identity,*sorted(needed-{identity})]:
        unit=units[name]
        groups=[group for group in plan['composition']['recursion_groups'] if name in group['members']]
        if groups or 'recursion_groups' in unit:
            # A declaration held by the enclosing entry travels with its cycle's
            # members, not with unrelated callers of those members.
            unit={**unit,'recursion_groups':groups}
        selected.append(unit)
    return selected


def resolve_composition(*, output: Path, plan: dict, selections: list, requirements: list | None,
                        retain_selected: bool = False):
    from .comparison_package import load_comparison_package
    from .comparison_dependencies import install_unit
    selected={row['id']:row for row in plan.get('dependencies',[])} if retain_selected else {}
    fingerprints={name:(contract_identity(output,row),implementation_identity(output,row,
        {Path(p).name:output/p for p in row['adapters']})) for name,row in selected.items()}
    defaults=[];packages={};legacy=[]
    for selection in selections:
        package=Path(selection['package']).resolve()
        if package not in packages:
            packages[package]=load_comparison_package(package)[0]
        parent=packages[package]
        if parent['target_id']!=plan['target_id']:
            raise ValueError('selected dependency belongs to another target: '+selection['id'])
        identity=selection['id']
        units=_selected_units(parent,identity)
        defaults.append(requirement(identity=identity,supplier=identity,root=package,unit=units[0]))
        for unit in units:
            name=unit.get('id',unit.get('component_id'))
            if name==plan['component_id']:
                if identity==parent['component_id']:
                    raise ValueError('a dependency embeds the entry body; express recursion as requirements, not duplicate packages')
                if contract_identity(package,unit)!=contract_identity(output,plan):
                    raise ValueError('selected supplier requires a different entry contract; refine that requirement explicitly')
                continue  # A declared back-edge uses the local entry body.
            paths=unit.get('export_adapters',[]) if 'component_id' in unit else unit['adapters']
            adapters=(selection.get('adapters') if name==identity else None) or {Path(p).name:package/p for p in paths}
            if not adapters:raise ValueError('selection '+name+' needs exported dependency adapters or an explicit adapter mapping')
            digest=(contract_identity(package,unit),implementation_identity(package,unit,adapters))
            if name in selected:
                if fingerprints[name]!=digest:raise ValueError('conflicting selections for '+name+'; choose one compatible implementation consistently')
                continue
            selected[name]=install_unit(output=output,identity=name,root=package,unit=unit,adapters=adapters)
            fingerprints[name]=digest
        if identity==parent['component_id'] and parent.get('dependencies') and 'composition' not in parent:
            legacy.append((identity,package,parent))
    plan['dependencies']=[selected[name] for name in sorted(selected)]
    plan['requirements']=list({r['id']:r for r in defaults}.values()) if requirements is None else [dict(row) for row in requirements]
    for row in plan['requirements']:
        if row.get('kind')=='internal' and row.get('supplier')==plan['component_id'] and row.get('contract_sha256')=='self':
            row['contract_sha256']=contract_identity(output,plan)
    # Legacy nested flat packages have no declared graph. Their selected root
    # requirements are made explicit during import, not silently discarded.
    for identity,package,parent in legacy:
        selected[identity]['requirements']=[requirement(identity=r['id'],supplier=r['id'],root=package,unit=r) for r in parent['dependencies']]
    from .comparison_representation import validate_representation_selection
    validate_representation_selection(output,plan)
    plan['composition']=composition_graph(output,plan)
    validate_composition(output,plan)


def selection_header(plan):
    from .component_c_v5 import _c
    ids=[plan['component_id'],*[row['id'] for row in plan.get('dependencies',[])]]
    names=['SPX_SELECTED_'+_c(name).upper() for name in ids]
    if len(names)!=len(set(names)):raise ValueError('component identities collide in generated C selection names')
    program='#define SPX_COMPARISON_PROGRAM 1\n' if plan.get('program_driver') else ''
    return '#ifndef SPX_COMPARISON_SELECTION_H\n#define SPX_COMPARISON_SELECTION_H\n'+program+''.join('#define '+name+' 1\n' for name in sorted(names))+'#endif\n'


def selection_impact(plan, changed_inputs, ignored_headers=()):
    """Explain exact changed declared unit inputs and transitive integration impact.

    Unchanged unit inputs do not claim that any local proof has been reused. The
    normal evidence reader still decides applicability under its full bindings.
    """
    if 'composition' not in plan:return None
    changed_inputs=[p for p in changed_inputs if p not in ignored_headers]
    units={plan['component_id']:plan,**{r['id']:r for r in plan.get('dependencies',[])}}
    changed={}
    for name,unit in units.items():
        generated='generated/' if name==plan['component_id'] else 'dependencies/'+name+'/generated/'
        exact=set(unit['sources']+unit['adapters']+[unit['interface']])
        directories=[p+'/' for p in unit['include_directories']]+[generated]
        paths=sorted(p for p in changed_inputs if p in exact or any(p.startswith(d) for d in directories))
        if paths:changed[name]=paths
    affected=set(changed)
    while True:
        more={e['consumer'] for e in plan['composition']['edges'] if e['supplier'] in affected}-affected
        if not more:break
        affected.update(more)
    context=[p for p in changed_inputs if p not in {p for paths in changed.values() for p in paths}]
    return dict(changed_unit_inputs=changed,unchanged_unit_inputs=sorted(set(units)-changed.keys()),
        affected_integrations=sorted(affected),comparison_context_changes=sorted(context),
        **({'program_integration_affected':bool(changed or context)} if 'entries' in plan.get('program_driver',{}) else {}),
        **({'ignored_unread_headers':sorted(ignored_headers)} if ignored_headers else {}),
        evidence_reuse='determined separately by exact retained comparison bindings')
