"""Checked interval changes and retained counterexamples in practical domains.

This compares declared word domains and concrete caller observations. It does
not prove reachability, heap predicates, or universal contract compatibility.
"""
from __future__ import annotations

from pathlib import Path
import time

from ..util import sha256_file
from .comparison_package import load_comparison_package,package_file,copy_comparison
from .comparison_domain import admitted_words


def domain_relation(previous, current):
    if previous is None or current is None or previous['words']!=current['words']:
        raise ValueError('domain refinement needs the same named input projections; establish an unrestricted baseline first')
    def bounds(domain):
        result=[(0,0xffffffff)]*len(domain['words'])
        for row in domain['constraints']:
            result[row['argument_index']]=(row['minimum'],row['maximum'])
        return result
    old,new=bounds(previous),bounds(current)
    if old==new:
        return 'equivalent'
    if all(a<=c<=d<=b for (a,b),(c,d) in zip(old,new,strict=True)):
        return 'narrowed'
    if all(c<=a<=b<=d for (a,b),(c,d) in zip(old,new,strict=True)):
        return 'widened'
    return 'incomparable'


def _projection_binding(root, plan):
    names=set(plan['adapters']+plan['runtime_files']+plan['link_files']+list(plan['original']['files'])+[plan['interface']])
    for directory in plan['include_directories']:
        names.update(p.relative_to(root).as_posix() for p in (root/directory).rglob('*.h'))
    for row in plan.get('dependencies',[]):
        names.update(row['adapters']+[row['interface']])
        for directory in row['include_directories']:
            names.update(p.relative_to(root).as_posix() for p in (root/directory).rglob('*.h'))
    return {'files':{n:sha256_file(package_file(root,n)) for n in sorted(names)},
            'tools':plan['tools'],'operation_symbols':plan['operation_symbols'],'observation_fields':plan['observation_fields']}


def refinement_report(*, previous: Path, output: Path, result: dict):
    from .comparison_run import load_comparison_evidence
    old,old_plan=load_comparison_evidence(previous)
    plan,_=load_comparison_package(output/'inputs')
    return _refinement_report(previous=previous,output=output,result=result,
        old=old,old_plan=old_plan,plan=plan)


def _refinement_report(*, previous: Path, output: Path, result: dict,
                       old: dict, old_plan: dict, plan: dict):
    """Compare declarations already checked for the current preparation step."""
    if (old_plan['target_id'],old_plan['component_id'])!=(plan['target_id'],plan['component_id']):
        raise ValueError('domain refinement belongs to another component')
    old_domains={old_plan['component_id']:old_plan.get('input_domain'),**{r['id']:r.get('input_domain') for r in old_plan.get('dependencies',[])}}
    domains={plan['component_id']:plan.get('input_domain'),**{r['id']:r.get('input_domain') for r in plan.get('dependencies',[])}}
    changed=[identity for identity in old_domains.keys()|domains.keys() if old_domains.get(identity)!=domains.get(identity)]
    if not changed:
        if old['case_selection'] is None and result['case_selection'] is None:
            current={row['id']:row['arguments'] for row in plan['cases']}
            for row in old['cases']:
                if row['status']!='excluded' and current.get(row['id'])!=row['arguments']:
                    raise ValueError(f'comparison drops or changes still-admitted baseline case {row["id"]}; use an explicit domain refinement or diagnostic --case replay')
        return None
    if old['case_selection'] is not None or result['case_selection'] is not None:
        raise ValueError('domain refinement requires full baseline and current case selections')
    if _projection_binding(previous/'inputs',old_plan)!=_projection_binding(output/'inputs',plan):
        raise ValueError('domain refinement changed input projection, adapter or oracle bindings; re-establish the baseline')
    changes={identity:{'previous':old_domains.get(identity),'current':domains.get(identity),
                       'relation':domain_relation(old_domains.get(identity),domains.get(identity))} for identity in sorted(changed)}
    excluded=[];assumptions=[]
    current_cases={row['id']:row['arguments'] for row in plan['cases']}
    for row in old['cases']:
        if row['status']=='assumption-violated' and plan['component_id'] not in changes:
            if current_cases.get(row['id'])!=row['arguments']:
                raise ValueError(f'domain refinement drops caller assumption failure {row["id"]}')
            for side,event in row['domain_events'].items():
                assumptions.append({'case_id':row['id'],'side':side,**event,
                    'now_admitted':admitted_words(domains[event['component_id']],event['words'])})
            continue
        if row['status'] not in {'match','mismatch','excluded'}:
            raise ValueError('domain refinement baseline has unresolved fixture/runtime failures')
        if row['status']=='excluded':
            words=row['domain_events']['original']['words']
        else:
            left=row['observations']['original'].get('input_words')
            right=row['observations']['source'].get('input_words')
            if left!=right:
                raise ValueError('domain refinement cannot hide disagreement in initial input observations')
            words=left
        admitted=True
        if plan['component_id'] in changes:
            admitted=admitted_words(plan['input_domain'],words)
        if admitted and current_cases.get(row['id'])!=row['arguments']:
            raise ValueError(f'domain refinement drops or changes still-admitted baseline case {row["id"]}')
        if not admitted:
            excluded.append({'id':row['id'],'arguments':row['arguments'],'input_words':words,
                'previous_status':row['status'],'counterexample':row.get('first_difference')})
    return {'authorizing':False,'previous_receipt_sha256':old['receipt_sha256'],
        'domain_changes':changes,'excluded_previous_cases':excluded,
        **({'previous_assumption_violations':assumptions} if assumptions else {}),
        'caller_reassessment':{r['id']:r['status'] for r in result['cases']},
        'scope':'declared word intervals and retained concrete observations; no universal caller or heap proof'}


def retain_refinement(*, previous: Path | None, output: Path, result: dict, timings: list | None = None):
    if previous is None:
        return None
    started=time.monotonic()
    report=refinement_report(previous=previous,output=output,result=result)
    if report is None and (previous/'refinement/previous/comparison-result.json').is_file():
        previous=previous/'refinement/previous'
        report=refinement_report(previous=previous,output=output,result=result)
    if timings is not None:
        timings.append({'phase':'evidence-validation','step':'refinement-history','seconds':time.monotonic()-started})
    if report is not None:
        started=time.monotonic()
        copy_comparison(previous,output/'refinement/previous')
        if timings is not None:
            timings.append({'phase':'evidence-retention','step':'refinement-history-copy','seconds':time.monotonic()-started})
    return report


def validate_refinement(output: Path, result: dict):
    report=result.get('refinement')
    if report is None:
        return
    expected=refinement_report(previous=output/'refinement/previous',output=output,result=result)
    if expected!=report:
        raise ValueError('comparison domain refinement or excluded counterexamples are stale')
