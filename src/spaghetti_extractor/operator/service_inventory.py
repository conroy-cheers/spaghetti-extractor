"""Discover reusable declarations from the existing workspace authoring view.

Grouping uses exact interaction bindings, not names or signatures. C locations
are lexical navigation candidates; none of this selects an implementation,
infers an adapter closure or transfers another component's evidence.
"""
from __future__ import annotations

from pathlib import Path
import shlex

from .comparison_guidance import workspace_view


def service_inventory(package: Path, target: str, *, queries: list[str], source_project: bool = False) -> dict:
    from ..components.comparison_package import load_comparison_package

    if any(not query.strip() for query in queries):
        raise ValueError('service query must not be empty')
    if source_project:
        from .source_export_guidance import source_export_view
        workspace=source_export_view(package,target)
    else:
        plan,_=load_comparison_package(package)
        workspace=workspace_view(package,target,plan['component_id'])
    grouped={};components={};selected=set()
    for unit in workspace['units']:
        signatures={row['id']:row for row in unit['interface']['schema']['signatures']}
        catalog={row['id']+':'+row['contract_sha256']:row for row in (unit['service_catalog'] or {}).get('contracts',[])}
        bridge=unit['service_bridge'] or {}
        requirements={row['service']:row for row in unit['requirements'] if row['kind']=='service'}
        for service in unit['interface']['services']:
            name=service['id'];binding=service['interaction_contract_id']
            adapter=bridge.get('adapters',{}).get(name)
            examples=[]
            for reference in unit.get('binding_references',[]):
                recorded=(reference['service_bridge'] or {}).get('adapters',{})
                example=recorded.get(name) if isinstance(recorded,dict) else None
                if isinstance(example,dict):
                    examples.append(dict(comparison_receipt_sha256=reference['comparison_receipt_sha256'],adapter=example))
            searchable=' '.join([unit['id'],name,binding or '',(adapter or {}).get('symbol',''),
                *[str(row['adapter'].get('symbol','')) for row in examples]]).casefold()
            if queries and not any(query.casefold() in searchable for query in queries):continue
            # Unbound declarations never become a common contract merely because
            # they have the same spelling, or because their binding is absent.
            key=('bound',binding) if binding else ('unbound',unit['id'],name)
            group=grouped.setdefault(key,dict(binding_id=binding,contract=catalog.get(binding),declarations=[]))
            group['declarations'].append(dict(component_id=unit['id'],service_id=name,
                signature=signatures[service['signature_id']],adapter=adapter,
                binding_examples=examples,
                requirement=requirements.get(name),
                source_navigation=unit['source_navigation']['services'].get(name)))
            selected.add(unit['id'])
        if unit['id'] in selected:
            components[unit['id']]={name:unit[name] for name in ('interface_path','adapters','include_directories',
                'assumptions','input_domain','representation','local_shared_contract')}
            components[unit['id']]['transports']=bridge.get('transports',{})
            if source_project:
                components[unit['id']].update(guide=unit['guide'],sources=unit['sources'],
                    unchecked_c_draft=unit['unchecked_c_draft'],binding_references=unit['binding_references'])
    groups=sorted(grouped.values(),key=lambda row:(row['binding_id'] or '',
        row['declarations'][0]['component_id'],row['declarations'][0]['service_id']))
    return dict(target_id=target,component_id=workspace['component_id'],authority='authoring-guidance',
        assurance='not-evaluated',queries=list(queries),groups=groups,components=components,
        origin='source-project' if source_project else 'comparison-package',
        source_edits=workspace.get('source_edits',{}),
        knowledge_inputs_sha256=workspace['knowledge_inputs_sha256'])


def _values(values: list[dict]) -> str:
    return ', '.join(value['id']+': '+value['type_id']+(' (nullable)' if value['nullable'] else '')
                     for value in values) or 'void'


def render_service_inventory(view: dict, *, package: Path) -> str:
    package=package.resolve();groups=view['groups'];detailed=bool(view['queries'])
    exported=view.get('origin')=='source-project'
    lines=[f"{view['target_id']}: {sum(len(g['declarations']) for g in groups)} service declarations, "
        f"{len(groups)} exact binding groups, {len(view['components'])} components",
        'Authoring guidance; assurance not evaluated. Matching declarations do not establish adapter compatibility.']
    if exported:
        lines+=['Source-library declarations. Recorded comparison adapters are examples, not selected backend bindings.']
        if view.get('source_edits'):
            lines+=['Unchecked C edits are present; the declarations below retain their recorded boundaries.']
    if not groups:
        return '\n'.join([*lines,'No service declarations match the query.' if detailed else 'No services declared.'])
    for group in groups:
        contract=group['contract'];subject=(contract or {}).get('subject',{})
        names=', '.join(sorted({row['service_id'] for row in group['declarations']}))
        lines+=['',names+' — '+(group['binding_id'] or 'no bound interaction contract')]
        if detailed:
            signature=group['declarations'][0]['signature']
            lines+=['  '+_values(signature['parameters'])+' -> '+_values(signature['results'])]
            if contract:
                lines+=['  Outcomes: '+', '.join(subject['outcomes'])+
                    '; nonlocal: '+(', '.join(subject.get('nonlocal_outcomes',[])) or 'none declared')]
                for role in subject['lifecycle']['bindings']:
                    path=role['path'];name=path['root']+'.'+path['value_id']+''.join('.'+f for f in path['fields'])
                    lines+=['  '+name+': '+role['transition']+' '+role['resource_kind']+' from '+role['provider_domain']+
                        (' (conditional; inspect the bound declaration)' if role['condition'] is not None else '')]
                lines+=['  Effects: '+(', '.join(row['primitive'] for row in contract['effects']) or 'none declared')]
                lines+=['  Unobserved: '+gap for gap in subject['unobserved']]
        for row in group['declarations']:
            adapter=row['adapter'];requirement=row['requirement']
            lines+=['  '+row['component_id']+'/'+row['service_id']+': '+
                ((adapter['symbol']+' ('+adapter['kind']+')') if adapter else
                 'backend binding not selected here' if exported else 'manual C binding; inspect component')+
                ('; selected supplier '+requirement['supplier'] if requirement else '')]
            if detailed:
                for example in row.get('binding_examples',[]):
                    lines+=['    Recorded comparison adapter: '+str(example['adapter'].get('symbol','unspecified'))+
                        '; receipt '+example['comparison_receipt_sha256']]
                definitions=(row['source_navigation'] or {}).get('definitions',[])
                lines+=['    C definition candidate: '+str(package/definition['path'])+':'+str(definition['line'])
                        for definition in definitions]
                if not definitions:lines+=['    No C definition candidate in the selected files.']
    listing=['spaghetti-extractor','component','list',view['target_id'],
        '--source-project' if exported else '--comparison-package',str(package)]
    if detailed:
        lines+=['', 'Review the selected component\'s assumptions, shared objects and available inputs:']
        if exported:
            lines+=['  '+str(package/unit['guide'])+
                (' (unchecked C draft)' if unit['unchecked_c_draft'] else '') for unit in view['components'].values()]
            lines+=['Use services_from_source_export(project, names={"LOCAL_NAME": "COMPONENT/SERVICE", ...}) for declarations.',
                    'Choose C headers, executable adapters, transport and comparison inputs explicitly; none are imported by that helper.']
        else:
            lines += ['  '+shlex.join(['spaghetti-extractor','component','status',view['target_id'],identity,
                '--comparison-package',str(package),'--details']) for identity in view['components']]
            lines+=['Use retained_service_inputs(package, component_id=..., names=[...], ...) after reviewing C and transport inputs.',
                    'To combine declarations or use local aliases, pass names={"LOCAL_NAME": "COMPONENT/SERVICE", ...} instead of component_id.']
        lines+=['File locations are lexical candidates, not a compiler-resolved dependency closure. Use --json for declarations and input paths.']
    else:
        lines+=['', 'Inspect matches: '+shlex.join([*listing,'--service','QUERY']),
                'QUERY matches component, local service, contract identity or C adapter; repeat it to include more matches.']
    return '\n'.join(lines)
