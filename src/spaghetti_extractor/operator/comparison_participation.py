"""Case participation projected from validated retained service observations."""
from __future__ import annotations

import json
from pathlib import Path
import shlex


def comparison_participation(result: dict, plan: dict, *, component: str,
                             output: Path, case_id: str | None = None) -> dict:
    """Inspect one selected unit without attributing a shared catalog to its body.

    Callers load the result and its bound inputs through the existing readers.
    Scope starts describe recorded adapter activity, not operation/branch coverage.
    Uninstrumented or incomplete cases cannot establish absence of execution.
    """
    units={plan['component_id']:plan,**{unit['id']:unit for unit in plan.get('dependencies',[])}}
    if component not in units:
        raise ValueError('comparison result has another target/component identity; selected components: '+', '.join(units))
    if case_id is not None and not any(row['id']==case_id for row in result['cases']):
        raise ValueError('case is absent from this retained comparison: '+case_id)
    output=output.resolve()
    catalog=(units[component].get('service_catalog') or {}).get('catalog_sha256')
    shared=sorted(identity for identity,unit in units.items() if identity!=component and catalog is not None
        and (unit.get('service_catalog') or {}).get('catalog_sha256')==catalog)
    cases=[]
    for index,row in enumerate(result['cases']):
        if case_id is not None and row['id']!=case_id:continue
        resources=row.get('resources',{});services=resources.get('services') or {}
        starts=None
        if catalog is None:
            observed='unavailable'
        elif not services:
            observed='not-recorded'
        elif services['status']!='satisfied':
            observed='incomplete'
        else:
            starts=sum(event.get('catalog_sha256')==catalog and event['event']=='begin'
                for event in services['events'])
            observed='not-observed' if not starts else 'shared' if shared else 'observed'
        trace=output/'cases'/f'{index:04d}-source.stderr'
        cases.append(dict(id=row['id'],arguments=row['arguments'],consumer_status=row['status'],
            resource_status=resources.get('status','not-recorded'),service_trace_status=services.get('status','not-recorded'),
            service_scope=dict(status=observed,starts=starts),
            source_trace=str(trace) if trace.is_file() else None))
    selection=[] if result['case_selection'] is None else ['--case',result['case_selection']]
    prefix=['spaghetti-extractor','component']
    return dict(authority='authoring-guidance',component_id=component,comparison_entry=result['component_id'],
        target_id=result['target_id'],consumer_status=result['status'],result=str(output),
        receipt_sha256=result['receipt_sha256'],case_filter=case_id,catalog_sha256=catalog,
        catalog_shared_with=shared,cases=cases,
        boundary_command=[*prefix,'status',result['target_id'],component,'--comparison-package',str(output/'inputs'),'--details'],
        replay_command=[*prefix,'check',result['target_id'],result['component_id'],'--comparison-package',str(output/'inputs'),
            *selection,'--reuse-comparison',str(output),'--rerun','--output',str(output.with_name(output.name+'-'+component+'-replay'))],
        limits=['Retained consumer observations; no fresh execution or independent component check.',
            'Service scopes record adapter activity, not branch or input-domain coverage.',
            'Replay keeps the original case selection and order, including shared runtime setup.'])


def render_participation(view: dict) -> str:
    lines=[view['component_id']+': retained cases through '+view['comparison_entry']+
        ' (consumer comparison='+view['consumer_status']+')',*view['limits']]
    if view['catalog_sha256'] is None:
        lines.append('No generated service catalog for this component; participation is unavailable.')
    elif view['catalog_shared_with']:
        lines.append('Catalog shared with '+', '.join(view['catalog_shared_with'])+
            '; observed scopes cannot identify which component executed.')
    if not view['cases']:lines.append('No case observations retained.')
    for row in view['cases']:
        scope=row['service_scope'];starts=scope['starts']
        lines.append(row['id']+': consumer='+row['consumer_status']+'; resources='+row['resource_status']+
            '; service scope='+scope['status']+(' ('+str(starts)+' starts)' if starts is not None else ''))
        arguments=json.dumps(row['arguments'],ensure_ascii=True)
        lines.append('  arguments: '+(arguments if len(arguments)<=1200 else arguments[:1200]+' ... [see --json]'))
        if row['source_trace']:lines.append('  source trace: '+row['source_trace'])
    lines+=['boundary: '+shlex.join(view['boundary_command']),'replay: '+shlex.join(view['replay_command'])]
    return '\n'.join(lines)
