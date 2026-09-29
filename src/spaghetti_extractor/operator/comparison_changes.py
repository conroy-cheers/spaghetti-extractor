"""Read-only edit and reuse preview using the checker's actual input/cache rules."""
from __future__ import annotations

from pathlib import Path
import tempfile

from ..components.comparison_build import compilation_units, compile_options
from ..components.comparison_compile_cache import configuration, entry_valid, load_cache
from ..components.comparison_contract_diagnostics import contract_changes, describe_contract_changes
from ..components.comparison_package import load_comparison_package, prepare_comparison_inputs
from ..components.comparison_reuse import assess_comparison_reuse, comparison_execution_context, comparison_runtime_state
from ..components.comparison_run import load_comparison_result
from ..components.comparison_source_draft import DependencySelection
from ..util import sha256_file


def comparison_change_preview(root: Path, previous: Path, *, case_id: str | None = None,
                              dependency_packages: dict[str,DependencySelection] | None = None) -> dict:
    root=root.resolve();previous=previous.resolve()
    prior=load_comparison_result(previous)
    plan,interface=load_comparison_package(root)
    if (prior['target_id'],prior['component_id'])!=(plan['target_id'],plan['component_id']):
        raise ValueError('previous comparison has another target/component identity')
    if case_id is not None and not any(row['id']==case_id for row in plan['cases']):
        raise ValueError('selected comparison case does not exist')
    before,_=load_comparison_package(previous/'inputs')
    with tempfile.TemporaryDirectory(prefix='component-change-preview-') as temporary:
        snapshot=Path(temporary)/'inputs'
        plan,_=prepare_comparison_inputs(package=root,snapshot=snapshot,plan=plan,interface=interface,
            dependency_packages=dependency_packages)
        current=dict(input_sha256s={p.relative_to(snapshot).as_posix():sha256_file(p)
                for p in snapshot.rglob('*') if p.is_file()},
            tools=plan['tools'],case_selection=case_id,execution_context=comparison_execution_context(),
            runtime_state=comparison_runtime_state(plan))
        reuse=assess_comparison_reuse(previous=previous,prior=prior,package=snapshot,current=current)
        reuse['status']='recheck-required' if reuse['reasons'] else 'eligible-after-source-checks'
        cache=load_cache(previous,plan,check_configuration=False)
        settings=configuration(plan)
        configuration_changes=sorted(key for key in settings if cache is None or cache['configuration'].get(key)!=settings[key])
        entries={row['source']:row for row in cache['units']} if cache else {}
        compilation=[]
        for name,unit in compilation_units(plan):
            entry=entries.get(name)
            eligible=not configuration_changes and entry is not None and entry_valid(entry,
                package=snapshot,name=name,unit=unit['id'],options=compile_options(plan,unit),build=previous/'build')
            reasons=(['configuration: '+key for key in configuration_changes] if configuration_changes
                else ['no retained object for this source'] if entry is None
                else entry['unsupported'] or ([] if eligible else ['compiled inputs, options or include resolution changed']))
            compilation.append(dict(component_id=unit['id'],source=name,
                status='reusable' if eligible else 'compile-required',reasons=reasons))
        def units(value):
            return {value['component_id']:value,**{unit['id']:unit for unit in value.get('dependencies',[])}}
        old_units=units(before);new_units=units(plan);changed=set(reuse['changed_inputs']);components=[];affected=set()
        for identity in sorted(old_units.keys()|new_units.keys()):
            old=old_units.get(identity);new=new_units.get(identity)
            contracts=contract_changes(previous/'inputs',old,snapshot,new) if old and new else []
            for item in contracts:
                value=item['proposed']
                if isinstance(value,dict) and set(value)=={'path','sha256'}:
                    value['path']=str(root/Path(value['path']).relative_to(snapshot))
            sources=sorted(changed & (set((old or {}).get('sources',[]))|set((new or {}).get('sources',[]))))
            adapters=sorted(changed & (set((old or {}).get('adapters',[]))|set((new or {}).get('adapters',[]))))
            selection='added' if old is None else 'removed' if new is None else 'retained'
            if sources or adapters or contracts or selection!='retained':affected.add(identity)
            components.append(dict(component_id=identity,selection=selection,changed_sources=sources,
                changed_adapters=adapters,contract_changes=contracts))
        edges=[*before.get('composition',{}).get('edges',[]),*plan.get('composition',{}).get('edges',[])]
        while extra:={edge['consumer'] for edge in edges if edge['supplier'] in affected}-affected:
            affected.update(extra)
        if changed:affected.add(plan['component_id'])  # The containing comparison binds its complete selection.
        context_changes=sorted(key for key,value in current['execution_context'].items()
            if prior['execution_context'].get(key)!=value)
    return dict(authority='authoring-guidance',assurance='not-evaluated',previous_result=str(previous),
        previous_status=prior['status'],case_selection=case_id,execution_reuse=reuse,components=components,
        affected_consumers=sorted(affected),compilation=compilation,
        compile_configuration_changes=configuration_changes,execution_context_changes=context_changes,
        limits=['Preview only; the check still validates source profiles and any selected formal checks.',
            'Cached objects are eligible only while these files, tools and environment remain unchanged.',
            'This consumer result does not supply independent evidence for its selected neighbors.'])


def render_change_preview(preview: dict) -> list[str]:
    from .comparison_guidance import _text
    reuse=preview['execution_reuse']
    lines=['## Changes since comparison', '',
        'Previous result: `'+_text(preview['previous_result'])+'` ('+preview['previous_status']+').',
        'Execution reuse: '+reuse['status']+'. Case selection: '+_text(preview['case_selection'] or 'all cases')+'.']
    for reason in reuse['reasons']:
        lines.append('- '+_text(reason))
    if preview['execution_context_changes']:
        lines.append('Changed execution context: '+', '.join(preview['execution_context_changes'])+'.')
    if preview['compile_configuration_changes']:
        lines.append('Changed compilation context: '+', '.join(preview['compile_configuration_changes'])+'.')
    lines+=['', 'Changed inputs: '+(', '.join('`'+_text(p)+'`' for p in reuse['changed_inputs']) or 'none')+'.', '']
    for unit in preview['components']:
        identity=unit['component_id'];rows=[r for r in preview['compilation'] if r['component_id']==identity]
        reusable=sum(r['status']=='reusable' for r in rows)
        lines+=['- `'+_text(identity)+'`: '+unit['selection']+'; '+str(len(unit['changed_sources']))+
            ' authored files changed; '+str(len(unit['changed_adapters']))+' adapter files changed; '+
            str(len(unit['contract_changes']))+' contract fields changed.',
            '  Compiled files: '+str(reusable)+' reusable, '+str(len(rows)-reusable)+' require compilation if source checks pass.']
        if unit['contract_changes']:
            lines+=['', '```text',describe_contract_changes(unit['contract_changes']),'```', '']
    lines+=['', 'Affected consumers/selection: '+(', '.join(map(_text,preview['affected_consumers'])) or 'none from input changes')+'.',
        *preview['limits'], '']
    return lines
