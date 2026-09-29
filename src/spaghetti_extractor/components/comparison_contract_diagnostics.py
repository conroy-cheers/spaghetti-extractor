"""Readable changes to existing declared dependency contracts.

This is an inspection view, not another contract format or compatibility test.
Exact selection checks and executable comparisons retain their existing roles.
"""
from __future__ import annotations

from difflib import ndiff
import json
from pathlib import Path

from .comparison_composition import contract_binding, contract_identity
from .comparison_source_draft import DependencySelection, SourceDraft, selection_path, source_draft_inputs


def _declaration_changes(previous, proposed) -> list[dict]:
    """Locate declaration edits by stable names, retaining order as a change.

    Named lists remain ordered: matching their members by id must not conceal a
    changed parameter order or record layout. Other lists use positional paths.
    The original values remain available in the containing inspection row.
    """
    absent=object();changes=[]
    def walk(left,right,path):
        if left==right:return
        if isinstance(left,dict) and isinstance(right,dict):
            for key in sorted(left.keys()|right.keys()):
                walk(left.get(key,absent),right.get(key,absent),path+'['+json.dumps(key)+']')
            return
        if isinstance(left,list) and isinstance(right,list):
            def name(row):
                if not isinstance(row,dict):return None
                return row.get('id',row.get('source_id',row.get('value',{}).get('id') if isinstance(row.get('value'),dict) else None))
            old_names=[name(row) for row in left];new_names=[name(row) for row in right]
            if (all(isinstance(n,str) for n in [*old_names,*new_names])
                    and len(set(old_names))==len(old_names) and len(set(new_names))==len(new_names)):
                if old_names!=new_names:
                    changes.append(dict(field=path+' (order)',previous=old_names,proposed=new_names,change='changed'))
                old=dict(zip(old_names,left));new=dict(zip(new_names,right))
                for key in sorted(old.keys()|new.keys()):
                    walk(old.get(key,absent),new.get(key,absent),path+'['+json.dumps(key)+']')
            elif any(isinstance(row,(dict,list)) for row in [*left,*right]):
                for index in range(max(len(left),len(right))):
                    walk(left[index] if index<len(left) else absent,right[index] if index<len(right) else absent,path+f'[{index}]')
            else:
                changes.append(dict(field=path,previous=left,proposed=right,change='changed'))
            return
        changes.append(dict(field=path,previous=None if left is absent else left,
            proposed=None if right is absent else right,
            change='added' if left is absent else 'removed' if right is absent else 'changed'))
    walk(previous,proposed,'$')
    return changes


def contract_changes(previous_root: Path, previous: dict, proposed_root: Path, proposed: dict) -> list[dict]:
    before=contract_binding(previous_root,previous)
    after=contract_binding(proposed_root,proposed)
    # These selection declarations are checked by install_unit separately from
    # the supplier's own contract identity. Include them without redefining it.
    for key in ('requirements','recursion_groups'):
        before[key]=previous.get(key,[]); after[key]=proposed.get(key,[])
    for value,unit in ((before,previous),(after,proposed)):
        prefix='' if 'component_id' in unit else 'dependencies/'+unit['id']+'/'
        value['private_headers']=sorted(name.removeprefix(prefix) for name in unit.get('private_headers',[]))
    changes=[]
    def changed(field,left,right):
        if left!=right:changes.append(dict(field=field,previous=left,proposed=right))
    for field in sorted(before.keys()|after.keys()):
        left,right=before.get(field),after.get(field)
        if left==right:continue
        if field=='representation' and left is not None and right is not None:
            for key in ('group','revision'):
                changed(field+'.'+key,left[key],right[key])
            for name in sorted(left['inputs'].keys()|right['inputs'].keys()):
                old,new=left['inputs'].get(name),right['inputs'].get(name)
                if old==new:continue
                def entry(root,unit,digest):
                    return None if digest is None else dict(
                        path=str((root/unit['representation']['inputs'][name]).resolve()),sha256=digest)
                changed(field+'.inputs.'+name,entry(previous_root,previous,old),entry(proposed_root,proposed,new))
        elif field=='interface':
            changed(field,dict(path=str((previous_root/previous['interface']).resolve()),sha256=left),
                dict(path=str((proposed_root/proposed['interface']).resolve()),sha256=right))
            def declaration(root,unit):
                value=json.loads((root/unit['interface']).read_text())
                value.pop('intent_sha256',None)
                value['schema'].pop('schema_sha256',None)
                return value
            changes[-1]['declaration_changes']=_declaration_changes(
                declaration(previous_root,previous),declaration(proposed_root,proposed))
        else:
            changed(field,left,right)
            if field in {'input_domain','resource_checks','service_catalog','requirements','recursion_groups','state_owners'}:
                changes[-1]['declaration_changes']=_declaration_changes(left,right)
    return changes


def describe_contract_changes(changes: list[dict], *, include_paths: bool = True) -> str:
    def value(item):
        if isinstance(item,dict) and set(item)=={'path','sha256'}:
            return (item['path']+' ' if include_paths else '')+'(sha256 '+item['sha256'][:12]+')'
        text=json.dumps(item,sort_keys=True,ensure_ascii=True)
        return text if len(text)<=240 else text[:237]+'...'
    lines=[]
    for row in changes:
        if row['field']=='assumptions':
            lines.append('  assumptions:')
            previous=[json.dumps(item,ensure_ascii=True) for item in row['previous']]
            proposed=[json.dumps(item,ensure_ascii=True) for item in row['proposed']]
            lines.extend('    '+line for line in ndiff(previous,proposed) if line.startswith(('- ','+ ')))
        elif row.get('declaration_changes') and row['field']!='interface':
            lines.append('  '+row['field']+':')
        else:
            lines.append('  '+row['field']+': '+value(row['previous'])+' -> '+value(row['proposed']))
        for detail in row.get('declaration_changes',[]):
            left='<absent>' if detail['change']=='added' else value(detail['previous'])
            right='<absent>' if detail['change']=='removed' else value(detail['proposed'])
            lines.append('    '+detail['field']+': '+left+' -> '+right)
    return '\n'.join(lines)


def dependency_contract_preview(root: Path, plan: dict, replacements: dict[str,DependencySelection]) -> list[dict]:
    from .comparison_package import load_comparison_package
    selected={row['id']:row for row in plan.get('dependencies',[])}
    if set(replacements)-selected.keys():
        raise ValueError('replacement names a dependency absent from this comparison')
    current_edges=plan.get('composition',{}).get('edges',[])
    reports=[]
    for requested,selection in replacements.items():
        package=selection_path(selection)
        draft=None;proposed_root=package
        exported=(package/'source-export.json').is_file()
        authoring=not (package/'comparison-plan.json').exists() and (package/'interface.json').is_file()
        if isinstance(selection,SourceDraft) or exported:
            draft=source_draft_inputs(selection,package=root,plan=plan,component_id=requested)
            units=[selected[requested]];proposed_root=root;edges=current_edges
        else:
            replacement,_=load_comparison_package(package)
            if replacement['component_id']!=requested:
                raise ValueError('replacement package has another component identity')
            units=[replacement,*replacement.get('dependencies',[])]
            # Show the proposed outgoing requirements and the existing callers
            # entering this closure. This is a declaration preview, not selection
            # resolution or acceptance of those callers' frozen requirements.
            proposed_ids={unit.get('id',unit.get('component_id')) for unit in units}
            if plan['component_id'] in proposed_ids:
                raise ValueError('replacement bundles this comparison entry; refine the composition explicitly')
            edges=[edge for edge in current_edges if edge['consumer'] not in proposed_ids]
            edges+=replacement.get('composition',{}).get('edges',[])
        for unit in units:
            identity=unit.get('id',unit.get('component_id'))
            before=selected.get(identity)
            changes=contract_changes(root,before,proposed_root,unit) if before is not None else []
            affected={identity}
            while more:={edge['consumer'] for edge in edges if edge['supplier'] in affected}-affected:
                affected.update(more)
            reports.append(dict(component_id=identity,proposed_by=requested,package=str(package.resolve()),
                explicit=identity==requested,changes=changes,
                status='added' if before is None else 'changed' if changes else 'unchanged',
                previous_contract_sha256=contract_identity(root,before) if before is not None else None,
                proposed_contract_sha256=contract_identity(proposed_root,unit),
                **(dict(source_kind='exported-c-draft' if exported else 'interface-c-draft' if authoring else 'comparison-c-draft',changed_sources=sorted(
                    (set(before['sources'])-draft.files.keys()) |
                    {name for name,data in draft.files.items() if name not in before['sources'] or (root/name).read_bytes()!=data}),
                    added_sources=sorted(draft.files.keys()-set(before['sources'])),
                    removed_sources=sorted(set(before['sources'])-draft.files.keys())) if draft is not None else {}),
                consumers=[dict(component=edge['consumer'],requirement=edge['id'])
                    for edge in edges if edge['supplier']==identity],
                current_consumers=[dict(component=edge['consumer'],requirement=edge['id'])
                    for edge in current_edges if edge['supplier']==identity],
                transitive_consumers=sorted(affected-{identity}),
                authority='authoring-guidance',compatibility='not-evaluated'))
    return reports
