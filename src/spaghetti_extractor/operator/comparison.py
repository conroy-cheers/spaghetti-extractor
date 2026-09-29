"""Public local comparison actions without qualification admission."""
from __future__ import annotations

import json
from pathlib import Path
import shlex

from ..components.comparison_package import start_comparison_package,load_comparison_package
from ..components.comparison_run import run_comparison,load_comparison_result,first_difference


def start_component_comparison(args, *, reuse_comparison: Path | None = None) -> int:
    if args.output is None or args.apply:
        raise ValueError('comparison preparation requires --output; it does not adopt a qualified source')
    package=args.comparison_package;case=None
    adding_cases=bool(getattr(args,'reuse_cases',None) or getattr(args,'case_file',None))
    retained=getattr(args,'comparison_result',None)
    if retained is not None:
        retained=retained.resolve();destination=args.output.resolve()
        if destination.is_relative_to(retained) or retained.is_relative_to(destination):
            raise ValueError('editable workspace and retained comparison result must be separate')
        previous=load_comparison_result(retained)
        if previous['target_id']!=args.target:
            raise ValueError('comparison result belongs to another target')
        package=retained/'inputs'
        reuse_comparison=retained
        if not adding_cases:case=previous['case_selection']
    dependencies=dependency_selections(args)
    reviewed=dependency_packages(getattr(args,'refine_requirement',None),
        option='--refine-requirement',key='REQUIREMENT')
    source_edits=dependency_packages(getattr(args,'source_file',None),option='--source-file',key='NAME')
    start_comparison_package(package=package,output=args.output,
                             target_id=args.target,component_id=args.unit,reuse_source=args.reuse_source,
                             reuse_cases=getattr(args,'reuse_cases',None),
                             case_files=getattr(args,'case_file',None),
                             source_edits=source_edits,remove_sources=getattr(args,'remove_source',None),
                             private_headers=getattr(args,'private_header',None),
                             dependency_packages=dependencies,refine_requirements=reviewed or None)
    from .source_guidance import write_authoring_guidance
    from ..components.comparison_dependencies import comparison_units,comparison_includes
    plan,_=load_comparison_package(args.output)
    workspace=args.output.resolve()
    command=shlex.join(['spaghetti-extractor','component','check',args.target,args.unit,
        '--comparison-package',str(workspace),
        *(['--case',case] if case is not None else []),
        '--history',str(workspace.with_name(workspace.name+'-checks')),
        *(['--history-baseline',str(reuse_comparison.resolve())] if reuse_comparison else [])])
    units=comparison_units(plan)
    focused=next(unit for unit in units if unit['id']==args.unit)
    directory='generated' if args.unit==plan['component_id'] else 'dependencies/'+args.unit+'/generated'
    editor_units=units if args.unit==plan['component_id'] else [focused]
    write_authoring_guidance(args.output,sources=[p for unit in editor_units for p in unit['sources']],
        adapter_sources=[p for unit in editor_units for p in unit['adapters']],
        source_include_directories={p:comparison_includes(plan,unit) for unit in units for p in unit['sources']+unit['adapters']},
        compiler=plan['tools']['compiler']['path'],header=directory+'/portable-component-implementation.h',check_command=command)
    from .comparison_guidance import write_workspace_guidance
    from .local_comparison_recipe import write_boundary_revision_recipe, write_local_comparison_recipe
    local_recipe=write_local_comparison_recipe(args.output,target=args.target,component=args.unit,plan=plan)
    revision_recipe=write_boundary_revision_recipe(args.output,target=args.target,component=args.unit,plan=plan)
    write_workspace_guidance(args.output,args.target,args.unit)
    print(f'wrote editable component comparison package: {args.output}')
    if retained is not None:
        print('reopened retained comparison: '+str(retained)+' ('+previous['status']+')')
        print('Editable draft; the next check assesses reuse against the retained inputs and environment.')
    if args.unit!=plan['component_id']:
        print('editing selected component '+args.unit+'; retained consumer check: '+plan['component_id'])
        print('edit: '+', '.join(str(workspace/name) for name in focused['sources']))
        print('This keeps the enclosing selection and its cases; it supplies no independent local comparison.')
        print('local setup recipe: '+str(workspace/local_recipe))
    if args.reuse_source is not None:
        print(f'carried {len(focused["sources"])} authored files from {args.reuse_source}; check them against the selected boundary')
    if adding_cases:
        print(f'retained {len(plan["cases"])} case definitions under the current driver and boundary; run the expanded suite')
    if source_edits or getattr(args,'remove_source',None) or getattr(args,'private_header',None):
        print(f'updated authored file selection for {args.unit}; boundary and neighboring C retained; check the new draft')
    if dependencies:
        print('selected suppliers retained: '+', '.join(sorted(dependencies))+'; behavior has not been checked')
    if getattr(args,'dependency_source',None):
        print('imported only named component C; consumer adapters and neighboring selections retained')
    if reviewed:
        print('reviewed caller requirements: '+', '.join(sorted(reviewed))+'; compatibility and behavior still need checking')
    print(f'boundary and dependencies: {args.output / directory / "workspace.md"}')
    print('boundary revision recipe: '+str(workspace/revision_recipe))
    print('next: '+command)
    return 0


def dependency_packages(entries, *, option='--dependency-package', key='COMPONENT') -> dict[str,Path]:
    dependencies={}
    for entry in entries or []:
        identity,separator,path=entry.partition('=')
        if not separator or not identity or not path or identity in dependencies:
            raise ValueError(option+' requires unique '+key+'=DIR entries')
        dependencies[identity]=Path(path)
    return dependencies


def dependency_selections(args):
    from ..components.comparison_source_draft import SourceDraft
    selected=dependency_packages(getattr(args,'dependency_package',None))
    sources=dependency_packages(getattr(args,'dependency_source',None),option='--dependency-source')
    repeated=selected.keys() & sources.keys()
    if repeated:
        raise ValueError('choose --dependency-package or --dependency-source for each component: '+', '.join(sorted(repeated)))
    return {**selected,**{name:SourceDraft(path) for name,path in sources.items()}}


def check_component_comparison(args) -> int:
    if (args.source or args.conditional or args.compare_baseline
            or args.region or (args.query_timeout is not None and not args.local_contracts) or args.entry_query_timeout is not None):
        raise ValueError('concrete comparison cannot combine with source/proof check flags')
    history=getattr(args,'history',None)
    baseline=getattr(args,'history_baseline',None)
    if baseline is not None and history is None:
        raise ValueError('component check --history-baseline requires --history')
    if args.output is None and history is None:
        raise ValueError('concrete comparison requires --output or --history for retained inputs and replay')
    case_arguments=None
    if getattr(args,'case_arguments',None) is not None:
        try:
            case_arguments=json.loads(args.case_arguments)
        except ValueError as error:
            raise ValueError('--case-arguments requires a JSON array of strings') from error
        if not isinstance(case_arguments,list):
            raise ValueError('--case-arguments requires a JSON array of strings')
    dependencies=dependency_selections(args)
    plan,_=load_comparison_package(args.comparison_package)
    entry=plan['component_id']
    selected=[entry,*[unit['id'] for unit in plan.get('dependencies',[])]]
    if plan['target_id']!=args.target or args.unit not in selected:
        raise ValueError('comparison package has another target/component identity; selected components: '+', '.join(selected))
    if args.unit!=entry and not args.json:
        print('checking selected component '+args.unit+' through enclosing comparison '+entry)
        print('This runs the retained consumer cases and records consumer evidence; it supplies no independent local check.')
    def check(output,reuse):
        run_comparison(package=args.comparison_package,output=output,target_id=args.target,
                       component_id=entry,case_id=args.case,case_arguments=case_arguments,timeout=args.comparison_timeout,
                       reuse_previous=reuse,rerun=args.rerun,dependency_packages=dependencies,
                       local_contracts=args.local_contracts,query_timeout=args.query_timeout,
                       compiler_view=getattr(args,'compiler_view',False))
        return load_comparison_result(output)
    output=args.output
    if history is None:
        result=check(output,args.reuse_comparison)
    else:
        from .comparison_history import comparison_history
        with comparison_history(history=history,package=args.comparison_package,target=args.target,
                component=entry,reuse=args.reuse_comparison,baseline=baseline) as (output,reuse):
            result=check(output,reuse)
        if not args.json:
            print('history latest: '+str(history.resolve()/'latest'))
    if result.get('compiler_views') and not args.json:
        print('compiler views: '+str(output/'build/compiler-views')+' (diagnostic only)')
    return report_component_comparison(result,output=output,target=args.target,component=entry,
        json_output=args.json,selected_component=args.unit)


def inspect_component_comparison(args) -> int:
    if args.dependency_package or getattr(args,'dependency_source',None):
        raise ValueError('dependency selection status requires --comparison-package')
    if args.development or args.all or args.family or args.code or args.limit != 20:
        raise ValueError('retained comparison status supports --comparison-result and --json, not provider-status filters')
    if args.reuse_comparison is not None:
        raise ValueError('edit/reuse assessment requires --comparison-package; retained result inspection does not assess current edits')
    result=load_comparison_result(args.comparison_result)
    if result['target_id']!=args.target:
        raise ValueError('comparison result has another target/component identity')
    if args.unit!=result['component_id'] or args.details or args.case is not None:
        from .comparison_participation import comparison_participation,render_participation
        plan,_=load_comparison_package(args.comparison_result/'inputs')
        view=comparison_participation(result,plan,component=args.unit,output=args.comparison_result,case_id=args.case)
        print(json.dumps(view,indent=2,sort_keys=True) if args.json else render_participation(view))
        return 0
    if not args.json:
        print('Retained evidence: no fresh execution or current-workspace reuse assessment.')
    report_component_comparison(result,output=args.comparison_result,target=args.target,component=args.unit,json_output=args.json)
    return 0


def _observation_context(original, source, path='$'):
    """Find the enclosing record or array window without parsing display paths."""
    if isinstance(original,dict) and isinstance(source,dict):
        for key in sorted(original.keys() | source.keys()):
            if key not in original or key not in source:
                break
            left,right=original[key],source[key]
            if first_difference(left,right) is not None:
                if isinstance(left,(dict,list)) and type(left) is type(right):
                    return _observation_context(left,right,path+'['+json.dumps(key)+']')
                break
    elif isinstance(original,list) and isinstance(source,list):
        index=min(len(original),len(source))
        for i,(left,right) in enumerate(zip(original,source)):
            if first_difference(left,right) is not None:
                if isinstance(left,(dict,list)) and type(left) is type(right):
                    return _observation_context(left,right,f'{path}[{i}]')
                index=i
                break
        start=max(0,index-2)
        stop=index+3
        return f'{path}[{start}:{stop}]',original[start:stop],source[start:stop]
    return path,original,source


def _observation_excerpt(value) -> str:
    text=json.dumps(value,sort_keys=True)
    return text if len(text)<=1200 else text[:1200]+' ... [truncated; see full observations]'


def _program_stream_excerpt(original, source, stream):
    """Show exact application bytes without assuming UTF-8 or emitting controls."""
    left,right=original[stream],source[stream]
    if left==right:return None
    offset=next((i for i,(a,b) in enumerate(zip(left,right)) if a!=b),min(len(left),len(right)))
    start=max(0,offset-24);stop=offset+72
    def excerpt(value):
        return ('... ' if start else '')+repr(bytes(value[start:stop]))+(' ...' if len(value)>stop else '')
    return offset,start,excerpt(left),excerpt(right)


def _runtime_feedback(row: dict, *, output: Path, index: int) -> list[str]:
    """Explain retained process failure without changing its classification."""
    executions=row.get('executions',{});states=[]
    for side in ('plain','original','source'):
        execution=executions.get(side)
        if execution is None:
            if side!='plain':states.append(side+' not run')
        elif execution.get('not_run'):
            states.append(side+' not run')
        elif execution['timed_out']:
            states.append(side+' timed out')
        elif execution['returncode'] is not None and execution['returncode']<0:
            states.append(side+' signal '+str(-execution['returncode']))
        else:
            states.append(side+' exit '+str(execution['returncode']))
    lines=['  execution: '+ '; '.join(states)]
    observation_error=executions.get(row['failed_side'],{}).get('observation_error')
    if observation_error and observation_error!=row.get('diagnostic'):
        lines.append('  '+row['failed_side']+' observation: '+observation_error)
    services=row.get('resources',{}).get('services') or {}
    events=services.get('events',[])
    if row['failed_side']=='source' and events:
        event=events[-1]
        if 'contract_sha256' in event:
            names=[name for name,coverage in services.get('coverage',{}).items()
                   if coverage['contract_sha256']==event['contract_sha256']]
            detail='service '+event['event']+' '+(', '.join(names) or event['contract_sha256'])
            if event['outcome']:detail+=' ('+event['outcome']+')'
        elif 'handler' in event:
            detail='handler '+str(event['handler'])+' '+event['event']
            if event['outcome']:detail+=' ('+event['outcome']+')'
        else:
            detail='service scope '+event['event']
        lines.append('  last parsed source event (trace context): '+detail)
    log=output/'cases'/f"{index:04d}-{row['failed_side']}.stderr"
    if log.is_file():
        telemetry=('SPX_SERVICE ','SPX_SERVICE_SCOPE ','SPX_SERVICE_HANDLER ','SPX_RESOURCE ')
        text=[line for line in log.read_text(errors='replace').splitlines()
              if line.strip() and not line.startswith(telemetry)]
        if text:
            lines.append('  '+row['failed_side']+' stderr tail (instrumentation omitted):')
            for line in text[-6:]:
                safe=''.join(c if c.isprintable() or c=='\t' else ascii(c)[1:-1] for c in line)
                lines.append('    '+(safe if len(safe)<=500 else safe[:500]+' ...'))
        lines.append('  full '+row['failed_side']+' stderr: '+str(log.resolve()))
    trace=log.with_suffix('.trace')
    if trace.is_file():
        lines.append('  instrumentation trace: '+str(trace.resolve()))
    host_log=log.with_suffix('.host.stderr')
    if host_log.is_file():
        lines.append('  Wine/host diagnostics: '+str(host_log.resolve()))
    return lines


def report_component_comparison(result: dict, *, output: Path, target: str, component: str,
                                json_output: bool, selected_component: str | None = None) -> int:
    from ..components.comparison_resources import resource_applicability
    resource_status=resource_applicability(result)
    if json_output:
        print(json.dumps(result,indent=2,sort_keys=True))
    else:
        print(f"{component}: comparison={result['status']} ({len(result['cases'])} concrete cases; no qualification authority)")
        print(f"scope: {result['scope']}")
        print('work performed: '+json.dumps(result['work_counts'],sort_keys=True))
        if result.get('reuse'):
            reuse=result['reuse']
            print(f"evidence reuse: {reuse['status']} (retained observations; no fresh execution when reused)")
            for reason in reuse['reasons']:
                print('  invalidated by: '+reason)
            for name in reuse['changed_inputs']:
                print('  changed input: '+name)
            for name in reuse.get('ignored_unread_headers',[]):
                print('  unread under checked compiler lookups: '+name)
        print('C source profile: '+result['source_profile']['status']+'; compiler/adapters and sampled behavior are checked separately from local proof')
        profile=result.get('source_profiles',{}).get(selected_component or component,result['source_profile'])
        if 'proof_profile' in profile:
            print('Formal source eligibility: '+profile['proof_profile']['status']+
                  ' ('+(selected_component or component)+'; separate from executable comparison)')
        if result.get('refinement'):
            refinement=result['refinement']
            print('domain refinement: '+', '.join(f"{k}={v['relation']}" for k,v in refinement['domain_changes'].items()))
            for row in refinement['excluded_previous_cases']:
                print(f"  retained excluded case {row['id']}: previous={row['previous_status']} words={row['input_words']}")
                if row['counterexample']:
                    print('  excluded counterexample: '+json.dumps(row['counterexample'],sort_keys=True))
        print('resource contract applicability: '+resource_status)
        formal=result['formal_check']
        print(f"formal check: {formal['status']}" + (f" ({formal['claim']})" if 'claim' in formal else ''))
        if 'result' in formal:
            print('  '+formal['result'].get('detail','see retained formal result and query diagnostics'))
            print('  formal work: '+json.dumps(formal['work_counts'],sort_keys=True))
            for check in formal['result'].get('checks',[]):
                if check['status']!='satisfied':
                    print('  '+check.get('code','incomplete')+': '+str(check.get('detail','inspect formal query evidence')))
                    if check.get('source'):
                        print('  source: '+json.dumps(check['source'],sort_keys=True))
                    break
        selected,_=load_comparison_package(output/'inputs')
        normal_program=bool(selected.get('program_driver',{}).get('process'))
        if normal_program:
            separate=any(execution.get('output_capture') for row in result['cases']
                for execution in row.get('executions',{}).values())
            streams='application streams (Wine/host diagnostics retained separately)' if separate else 'raw streams'
            print('normal program comparison: unchanged arguments, '+streams+', exit status and observer state; untouched-original control included')
        from ..components.comparison_representation import validate_representation_selection
        groups=validate_representation_selection(output/'inputs',selected)
        if groups:
            complete=sum(not group['missing_members'] for group in groups.values())
            print(f'replacement groups: {complete}/{len(groups)} complete selected groups (membership only)')
        for identity,group in groups.items():
            missing=group['missing_members']
            if missing:
                print(f"  {identity}: local check missing {', '.join(missing)}")
        domains={selected['component_id']:selected.get('input_domain'),**{r['id']:r.get('input_domain') for r in selected.get('dependencies',[])}}
        focus=selected_component or component
        domain=domains.get(focus)
        if domain is not None:
            bounds={r['argument_index']:(r['minimum'],r['maximum']) for r in domain['constraints']}
            print('input domain '+focus+': '+', '.join(f"{name}={bounds.get(i,(0,0xffffffff))}" for i,name in enumerate(domain['words'])))
        other_domains=sum(value is not None for identity,value in domains.items() if identity!=focus)
        if other_domains:
            print(f'other declared input domains: {other_domains}; inspect retained boundaries for bounds')
        if selected.get('composition'):
            graph=selected['composition']
            print(f"composition: {len(graph['edges'])} declared bindings across {len(domains)} selected components; no composition proof")
            if graph.get('program_entries'):
                print('  independent program entries: '+', '.join(graph['program_entries']))
            if graph['recursion_groups']:
                print(f"  recursive groups: {len(graph['recursion_groups'])}; progress unproved")
        if result.get('selection_impact'):
            impact=result['selection_impact']
            if impact['changed_unit_inputs']:
                print('changed unit inputs: '+', '.join(impact['changed_unit_inputs']))
            if impact['affected_integrations']:
                print('integrations requiring recheck: '+', '.join(impact['affected_integrations']))
            if impact.get('program_integration_affected'):
                print('program integration requires recheck for the selected entry components')
            print(('unchanged effective unit inputs' if impact.get('ignored_unread_headers') else 'unchanged unit inputs')+
                ': '+str(len(impact['unchanged_unit_inputs']))+' (not a proof-reuse claim)')
            if impact['comparison_context_changes']:
                print('comparison context changed: '+', '.join(impact['comparison_context_changes']))
        from ..components.state_ownership import state_owner_guidance
        for line in state_owner_guidance(selected.get('state_owners')):print(line)
        if selected.get('service_catalog'):
            catalog=selected['service_catalog']
            print('service definitions: '+str(len(catalog['contracts']))+' exact bound contracts; executable protocol checks only')
        if selected.get('dependencies'):
            print('selected authored dependencies: '+str(len(selected['dependencies'])))
        compilation=output/'build/compilation.json'
        if compilation.is_file() and (result.get('reuse') or {}).get('status')!='reused':
            units=json.loads(compilation.read_text())['units']
            compiled='successfully compiled' if result['status']=='compile-failed' else 'compiled'
            print(f"translation units: {sum(not u['reused'] for u in units)} {compiled}, {sum(u['reused'] for u in units)} reused")
            for unit in units:
                if unit['unsupported']:
                    print('  '+unit['source']+': '+', '.join(unit['unsupported']))
        if result['status']=='compile-failed':
            diagnostics=[]
            for log in sorted((output/'build').glob('*.stderr')):
                diagnostic=log.read_text(errors='replace').strip()
                if diagnostic:
                    diagnostics.append(diagnostic)
                    lines=diagnostic.splitlines()
                    errors=[i for i,line in enumerate(lines) if 'error:' in line]
                    excerpt='\n'.join(line for i in errors for line in lines[max(0,i-1):i+4])
                    if excerpt:
                        print(str(log)+':\n'+excerpt[:4000])
                        break
            else:
                if diagnostics:print(diagnostics[-1][-4000:])
            for phase in result['timings']:
                if phase.get('timed_out') and phase['phase'] in ('compiler','link'):
                    print(phase['phase']+' timed out; inspect the retained command and build logs')
            print('after repairing the editable workspace, retain eligible objects with '+
                  shlex.join(['--reuse-comparison',str(output.resolve())])+' on the next check')
        for index,row in enumerate(result['cases']):
            resources=row.get('resources',{})
            if row['status']=='match' and resources.get('status','satisfied')=='satisfied' and not resources.get('diagnostics'):
                continue
            print(f"  {row['id']}: {row['status']}")
            if row.get('failed_side'):
                print('\n'.join(_runtime_feedback(row,output=output,index=index)))
            if resources:
                print('  resource applicability: '+resources['status'])
                for finding in resources['diagnostics'][:8]:
                    print('  '+json.dumps(finding,sort_keys=True))
                print('  unobserved: '+', '.join(resources['unobserved']))
            for side,event in row.get('domain_events',{}).items():
                inputs=dict(zip(domains[event['component_id']]['words'],event['words'],strict=True))
                print(f"  {side}: {event['component_id']} rejected inputs "+json.dumps(inputs,sort_keys=True))
            if row.get('first_difference'):
                print('  first difference: '+json.dumps(row['first_difference'],sort_keys=True))
                original,source=row['observations']['original'],row['observations']['source']
                stream_difference=normal_program and any(row['first_difference']['path']==f'$.{stream}' or
                    row['first_difference']['path'].startswith(f'$.{stream}[') for stream in ('stdout','stderr'))
                if not stream_difference:
                    context,left,right=_observation_context(original,source)
                    print('  observation context at '+context+':')
                    print('    original: '+_observation_excerpt(left))
                    print('    source:   '+_observation_excerpt(right))
                if normal_program:
                    for stream in ('stdout','stderr'):
                        excerpt=_program_stream_excerpt(original,source,stream)
                        if excerpt is not None:
                            offset,start,left,right=excerpt
                            print(f'  application {stream} differs at byte {offset} (escaped bytes; excerpt starts at {start}):')
                            print('    original: '+left)
                            print('    source:   '+right)
                suffix='report.json' if normal_program else 'stdout'
                print(('  reported state: ' if normal_program else '  full observations: ')+', '.join(str(output.resolve()/'cases'/f'{index:04d}-{side}.{suffix}')
                    for side in ('original','source')))
                if normal_program and 'files' in original:
                    print('  file observations and saved bytes: '+str(output.resolve()/'cases')+f'/{index:04d}-*.files*')
            if row.get('diagnostic'):
                print('  '+row['diagnostic'])
            if normal_program:
                print('  retained program reports and streams: '+str(output.resolve()/'cases')+f'/{index:04d}-*')
            selection=[] if result['case_selection'] is None else ['--case',result['case_selection']]
            if result['case_selection'] is None and len(result['cases'])>1:
                print('  replay keeps the full retained suite in order because cases share runtime state.')
            print('  replay: '+shlex.join(['spaghetti-extractor','component','check',target,component,
                '--comparison-package',str(output.resolve()/'inputs'),*selection,
                '--reuse-comparison',str(output.resolve()),'--rerun',
                '--output',str(output.resolve().with_name(output.name+'-replay'))]))
            break
        if result['status']=='source-profile-failed':
            from .source_guidance import source_issue_guidance
            for issue in result['source_profile']['issues']:
                source=issue.get('source','compiled C')
                if isinstance(source,dict):
                    source=source['path']+(f":{source['line']}" if 'line' in source else '')
                print(f"  {source}: {issue.get('diagnostic') or source_issue_guidance(issue['code'])}")
        print(f"evidence: {output / 'comparison-result.json'}")
        print('boundary details: '+shlex.join(['spaghetti-extractor','component','status',target,focus,
            '--comparison-package',str(output.resolve()/'inputs'),'--details']))
    return 0 if result['status']=='match' and resource_status in ('not-requested','satisfied') and result['formal_check']['status'] not in {'disproved','incomplete'} else 2
