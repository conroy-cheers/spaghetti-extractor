"""Contract-bound resource observations, separate from behavioral comparison.

These are executable instrumentation findings, never checked heap summaries.
Canonical lifecycle declarations supply identity and boundary roles; no lifecycle
receipt is promoted to a proof of the C implementation by this module.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary import BoundaryLifecycleV1

PREFIX = 'SPX_RESOURCE '


def checked_resource_checks(value, interface):
    if value is None:
        return None
    fields={'capacity','frame_capacity','instrumented_sides','unobserved','contracts'}
    if not isinstance(value,dict) or set(value)!=fields:
        raise ValueError('resource checks require capacities, coverage and lifecycle contracts')
    for key,limit in [('capacity',65536),('frame_capacity',4096)]:
        if type(value[key]) is not int or not 1<=value[key]<=limit:
            raise ValueError(f'resource instrumentation {key} is outside supported bounds')
    sides=value['instrumented_sides']
    if not isinstance(sides,list) or not sides or len(set(sides))!=len(sides) or any(s not in ('original','source') for s in sides):
        raise ValueError('resource instrumentation sides must be explicit and unique')
    gaps=value['unobserved']
    if not isinstance(gaps,list) or any(not isinstance(g,str) or not g for g in gaps):
        raise ValueError('resource instrumentation gaps must be explicit strings')
    contracts=value['contracts']
    if not isinstance(contracts,list) or not contracts:
        raise ValueError('resource checks require at least one boundary contract')
    operations={op['id']:op for op in interface.operations}
    ids=set()
    for rule in contracts:
        if not isinstance(rule,dict) or set(rule)-{'nonlocal_allowances'}!={'operation_id','lifecycle','max_untransferred','max_retained'}:
            raise ValueError('resource contract fields are unsupported')
        identity=rule['operation_id']
        if not isinstance(identity,str) or identity not in operations or identity in ids:
            raise ValueError('resource contract operation is absent or repeated')
        ids.add(identity)
        lifecycle=BoundaryLifecycleV1.parse(rule['lifecycle'],schema=interface.schema)
        if lifecycle.signature_id!=operations[identity]['signature_id']:
            raise ValueError('resource lifecycle binds another operation signature')
        # Owned inputs and produced results require roles. Plain numeric values
        # need no token; a scalar explicitly interpreted as a resource still does.
        # Records, pointers and opaque objects cannot silently lose accounting.
        signature=interface.schema.signature_index[lifecycle.signature_id]
        expected={('parameter',v.identity):'consume' for v in signature.parameters}
        expected.update({('result',v.identity):'produce' for v in signature.results})
        numeric={
            (root,v.identity)
            for root,values in [('parameter',signature.parameters),('result',signature.results)]
            for v in values if v.interpretation=='value' and
                interface.schema.type_index[v.type_id].kind in ('integer','float')
        }
        observed={}
        for binding in lifecycle.bindings:
            key=(binding.path.root,binding.path.value_id)
            if binding.path.fields or key in observed:
                raise ValueError('resource lifecycle path needs unsupported instrumentation')
            observed[key]=binding.transition
        if (set(expected)-numeric-set(observed) or
                any(expected.get(key)!=transition for key,transition in observed.items())):
            raise ValueError('resource instrumentation currently requires consume parameters and produce results')
        allowances=rule.get('nonlocal_allowances',{})
        if 'nonlocal_allowances' in rule:
            if not isinstance(allowances,dict) or not allowances:
                raise ValueError('nonlocal resource allowances require explicit outcomes')
            from .service_authoring import checked_service_protocol
            checked_service_protocol('synchronous-return-or-nonlocal',['return'],list(allowances))
            if any(not isinstance(limits,dict) or set(limits)!={'max_untransferred','max_retained'} for limits in allowances.values()):
                raise ValueError('nonlocal resource allowances require both bounded counts')
        for limits in (rule,*allowances.values()):
            for key in ('max_untransferred','max_retained'):
                if type(limits[key]) is not int or not 0<=limits[key]<=value['capacity']:
                    raise ValueError('resource contract allowance must be a bounded unsigned count')
    return value


def resource_contracts(plan):
    rows=[dict(id=plan['component_id'],resource_checks=plan.get('resource_checks')),*plan.get('dependencies',[])]
    result={}
    for unit in rows:
        checks=unit.get('resource_checks')
        if checks:
            for rule in checks['contracts']:
                digest=canonical_sha256_v3(rule)
                if digest in result:
                    raise ValueError('selected resource contracts have ambiguous identities')
                result[digest]={'component_id':unit['id'],'checks':checks,'rule':rule}
    return result


def materialize_resource_runtime(root,plan):
    contracts=resource_contracts(plan)
    if not contracts:
        return
    from .comparison_resource_runtime import runtime_header,runtime_source
    configs=[entry['checks'] for entry in contracts.values()]
    capacities={(c['capacity'],c['frame_capacity']) for c in configs}
    if len(capacities)!=1:
        raise ValueError('selected resource instrumentation capacities disagree')
    header=runtime_header(*next(iter(capacities)))
    # Each unit sees the same ABI, while only one runtime owns the token table.
    directories=[root/'generated',*[root/'dependencies'/u['id']/'generated' for u in plan.get('dependencies',[])]]
    for directory in directories:
        directory.mkdir(exist_ok=True,parents=True)
        (directory/'comparison-resources.h').write_text(header)
    (root/'generated/comparison-resources.c').write_text(runtime_source(contracts))


def _resource_event(text):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:
                raise ValueError('duplicate resource event field')
            result[key]=value
        return result
    return json.loads(text,object_pairs_hook=pairs)


def resource_case(plan,output: Path,index: int,executions: dict):
    from .comparison_capture import instrumentation_path
    return resource_observations(plan,{side:instrumentation_path(output/'cases'/f'{index:04d}-{side}',executions[side])
        if side in executions else None for side in ('original','source')})


def _frame_violations(contracts,side,digest,frame,row,outcome=None):
    rule=contracts[digest]['rule']
    limits=rule.get('nonlocal_allowances',{}).get(outcome,rule)
    return [dict(side=side,classification='contract-violation',contract_sha256=digest,
        frame=frame,event=key+'-allowance-exceeded',observed=row[key],allowed=limits['max_'+key],
        **({'outcome':outcome} if outcome is not None else {}))
        for key in ('untransferred','retained') if row[key]>limits['max_'+key]]


def _resource_observations(plan,streams: dict):
    from .comparison_services import INSTRUMENTATION_LIMIT
    contracts=resource_contracts(plan)
    if not contracts:
        return None
    events={};findings=[];incomplete=False;violated=False
    sides=sorted({side for entry in contracts.values() for side in entry['checks']['instrumented_sides']} & streams.keys())
    if not sides:
        return None
    for side in sides:
        path=streams[side]
        rows=[];active={};begun=set();reported_tokens=set()
        handlers=[];seen_handlers=set();pending=[]
        if path is None or not path.is_file():
            incomplete=True
        else:
            try:
                if path.stat().st_size>INSTRUMENTATION_LIMIT:
                    raise ValueError('resource event stream exceeds 64 MiB')
                for line in path.read_text().splitlines():
                    if line.startswith('SPX_SERVICE_HANDLER '):
                        event=_resource_event(line[len('SPX_SERVICE_HANDLER '):])
                        if (not isinstance(event,dict) or set(event)!={'handler','event','outcome'} or
                                type(event['handler']) is not int or not 1<=event['handler']<=0xffffffff):
                            raise ValueError('malformed resource handler observation')
                        identity=event['handler']
                        if event['event']=='begin' and event['outcome']=='':
                            if identity in seen_handlers or pending:
                                raise ValueError('resource handler is repeated or interrupts unfinished unwind')
                            seen_handlers.add(identity);handlers.append((identity,tuple(active)))
                        elif handlers and handlers[-1][0]==identity and tuple(active)==handlers[-1][1]:
                            if event['event']=='catch' and isinstance(event['outcome'],str) and event['outcome']:
                                for digest,frame,row in pending:
                                    violations=_frame_violations(contracts,side,digest,frame,row,event['outcome'])
                                    violated=violated or bool(violations);findings+=violations
                                pending=[]
                            elif event['event']=='end' and event['outcome']=='' and not pending:
                                handlers.pop()
                            else:
                                raise ValueError('resource handler completion leaves unfinished unwind')
                        else:
                            raise ValueError('resource handler escaped its exact enclosing frames')
                        continue
                    if not line.startswith(PREFIX):
                        continue
                    event=_resource_event(line[len(PREFIX):])
                    fields={'contract_sha256','frame','event','count','token','generation','object'}
                    if not isinstance(event,dict) or set(event)!=fields:
                        raise ValueError('malformed resource event')
                    digest=event['contract_sha256'];kind=event['event'];frame=event['frame']
                    if pending and kind not in ('untransferred','unwind'):
                        raise ValueError('resource activity interrupts unfinished unwind')
                    if not isinstance(digest,str) or digest not in contracts or side not in contracts[digest]['checks']['instrumented_sides']:
                        raise ValueError('resource event is not bound to a selected side/contract')
                    if any(type(event[k]) is not int or not 0<=event[k]<=0xffffffffffffffff for k in fields-{'contract_sha256','event'}):
                        raise ValueError('resource event counters must be unsigned')
                    if any(event[k]>0xffffffff for k in ('frame','count','token','generation')):
                        raise ValueError('resource event exceeds its C counter widths')
                    if kind in ('begin','end','unwind') and any(event[k] for k in ('token','generation','object')):
                        raise ValueError('resource frame event unexpectedly names a token')
                    if kind=='begin':
                        if not frame or frame in begun or event['count'] or len(active)>=contracts[digest]['checks']['frame_capacity']:
                            raise ValueError('resource frame identity is repeated')
                        begun.add(frame);active[frame]={'contract':digest,'untransferred':0,'retained':0}
                    elif frame not in active or active[frame]['contract']!=digest:
                        raise ValueError('resource event has no matching active frame')
                    elif kind in ('acquire','borrow','consume'):
                        if event['count'] or not 1<=event['token']<=contracts[digest]['checks']['capacity'] or not event['generation']:
                            raise ValueError('resource reference observation is invalid')
                    elif kind in ('untransferred','retained'):
                        if event['count']!=1:
                            raise ValueError('resource reference diagnostic must identify one token')
                        token=(event['token'],event['generation'])
                        if (not 1<=token[0]<=contracts[digest]['checks']['capacity'] or not token[1] or token in reported_tokens):
                            raise ValueError('resource diagnostic token is invalid or repeated')
                        reported_tokens.add(token)
                        active[frame][kind]+=1
                        findings.append({'side':side,'classification':'resource-diagnostic',**event})
                    elif kind in ('end','unwind'):
                        if frame!=next(reversed(active)):
                            raise ValueError('resource frames must return in nesting order')
                        row=active.pop(frame)
                        if event['count']!=row['untransferred']:
                            raise ValueError('resource frame accounting is inconsistent')
                        if kind=='unwind' and handlers:
                            if frame in handlers[-1][1]:
                                raise ValueError('resource unwind consumes an enclosing handler frame')
                            pending.append((digest,frame,row))
                        else:
                            violations=_frame_violations(contracts,side,digest,frame,row)
                            violated=violated or bool(violations);findings+=violations
                    elif kind in ('expired','wrong-frame'):
                        violated=True
                        findings.append({'side':side,'classification':'contract-violation',**event})
                    elif kind in ('capacity','generation','frame-capacity'):
                        incomplete=True
                        findings.append({'side':side,'classification':'instrumentation-limit',**event})
                    else:
                        raise ValueError('unsupported resource event')
                    rows.append(event)
                if active or handlers or pending or not begun:
                    incomplete=True
            except (ValueError,UnicodeError) as error:
                incomplete=True
                findings.append({'side':side,'classification':'instrumentation-error','detail':str(error)})
        events[side]=rows
    return {'status':'violated' if violated else 'incomplete' if incomplete else 'satisfied',
        'events':events,'diagnostics':findings,'instrumented_sides':sides,
        'contract_coverage':{digest:{'component_id':entry['component_id'],
            'operation_id':entry['rule']['operation_id'],
            'frames_by_side':{side:sum(e['event']=='begin' and e['contract_sha256']==digest for e in rows) for side,rows in events.items()}}
            for digest,entry in contracts.items()},
        'unobserved':sorted({gap for entry in contracts.values() for gap in entry['checks']['unobserved']}),
        'authority':'boundary-instrumentation-only'}


def resource_applicability(result):
    values=[row['resources']['status'] for row in result['cases'] if 'resources' in row]
    return 'violated' if 'violated' in values else 'incomplete' if 'incomplete' in values else 'satisfied' if values else 'not-requested'


def resource_observations(plan,streams: dict):
    from .comparison_services import service_observations
    result=_resource_observations(plan,streams)
    services=service_observations(plan,streams)
    if services is None:return result
    if result is None:
        result=dict(status='satisfied',events={},diagnostics=[],instrumented_sides=['source'],
                    contract_coverage={},unobserved=[],authority='boundary-instrumentation-only')
    result['services']=services
    result['diagnostics']+=services['diagnostics']
    result['unobserved']=sorted(set(result['unobserved'])|set(services['unobserved']))
    if result['status']=='satisfied' and services['status']!='satisfied':result['status']=services['status']
    return result
