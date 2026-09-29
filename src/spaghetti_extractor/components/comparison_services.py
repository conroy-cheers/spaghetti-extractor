"""Checked nesting/outcome observations for generated C service wrappers.

These observations establish only the emitted concrete protocol. Declared native
semantics and lifecycle premises do not become checked summaries through tracing.
"""
from __future__ import annotations

from collections import Counter
from functools import lru_cache
import json

from .interaction_contract import InteractionContractCatalogV1

INSTRUMENTATION_LIMIT = 64*1024*1024


@lru_cache(maxsize=64)
def _catalog_index(contents):
    """Cache validated immutable facts by full content, never a claimed digest.

    Each observation still reads and checks its current stream. No trace verdict
    or admission result is cached, and callers cannot mutate these cached facts.
    """
    catalog=InteractionContractCatalogV1.parse(json.loads(contents))
    return catalog.catalog_sha256,tuple((c.contract_sha256,c.identity,
        frozenset(c.subject['outcomes']),frozenset(c.subject.get('nonlocal_outcomes',[])),
        tuple(c.subject['unobserved'])) for c in catalog.contracts)


def service_observations(plan,streams):
    units=[dict(id=plan['component_id'],service_catalog=plan.get('service_catalog')),*plan.get('dependencies',[])]
    catalogs={};contracts={}
    for unit in units:
        if not unit.get('service_catalog'):continue
        digest,index=_catalog_index(json.dumps(unit['service_catalog'],sort_keys=True,separators=(',',':'),allow_nan=False))
        catalogs[digest]=frozenset(row[0] for row in index)
        contracts.update({sha:(identity,outcomes,nonlocal_outcomes,gaps) for sha,identity,outcomes,nonlocal_outcomes,gaps in index})
    if not catalogs or 'source' not in streams:return None
    findings=[];events=[];scopes=[];calls=[];begun=set();incomplete=False
    handlers=[];seen_handlers=set()
    from .comparison_resources import _resource_event
    try:
        path=streams['source']
        if path is None or not path.is_file():raise ValueError('service observation stream is absent')
        if path.stat().st_size>INSTRUMENTATION_LIMIT:raise ValueError('service observation stream exceeds 64 MiB')
        for line in path.read_text().splitlines():
            if line.startswith('SPX_SERVICE_HANDLER '):
                event=_resource_event(line[len('SPX_SERVICE_HANDLER '):])
                if (not isinstance(event,dict) or set(event)!={'handler','event','outcome'} or
                        type(event['handler']) is not int or not 1<=event['handler']<=0xffffffff):
                    raise ValueError('malformed service handler observation')
                identity=event['handler']
                if event['event']=='begin' and event['outcome']=='':
                    if identity in seen_handlers:
                        raise ValueError('service handler identity is repeated')
                    seen_handlers.add(identity);handlers.append((identity,tuple(scopes),tuple(calls)))
                elif handlers and handlers[-1][0]==identity:
                    _,saved_scopes,saved_calls=handlers[-1]
                    scope_depth,call_depth=len(saved_scopes),len(saved_calls)
                    if tuple(scopes[:scope_depth])!=saved_scopes or tuple(calls[:call_depth])!=saved_calls:
                        raise ValueError('service handler escaped its enclosing scope')
                    if event['event']=='catch':
                        if not isinstance(event['outcome'],str) or len(calls)==call_depth:
                            raise ValueError('service nonlocal outcome has no interrupted call')
                        for digest,_,_ in calls[call_depth:]:
                            if event['outcome'] not in contracts[digest][2]:
                                raise ValueError('interrupted service did not declare this nonlocal outcome')
                        del scopes[scope_depth:];del calls[call_depth:]
                    elif event['event']=='end' and event['outcome']=='' and (len(scopes),len(calls))==(scope_depth,call_depth):
                        handlers.pop()
                    else:
                        raise ValueError('service handler completion leaves pending calls or scopes')
                else:
                    raise ValueError('service handler catch/end is absent or out of nesting order')
                events.append(event)
            elif line.startswith('SPX_SERVICE_SCOPE '):
                event=_resource_event(line[len('SPX_SERVICE_SCOPE '):])
                if not isinstance(event,dict) or set(event)!={'catalog_sha256','event'}:
                    raise ValueError('malformed service scope observation')
                digest=event['catalog_sha256']
                if not isinstance(digest,str) or digest not in catalogs:
                    raise ValueError('service scope is not bound to the selection')
                if event['event']=='begin':
                    scopes.append((digest,len(calls),len(events)));begun.add(digest)
                elif event['event']=='end' and scopes and scopes[-1][:2]==(digest,len(calls)):
                    scopes.pop()
                else:raise ValueError('service scope return or pending calls disagree')
                events.append(event)
            elif line.startswith('SPX_SERVICE '):
                event=_resource_event(line[len('SPX_SERVICE '):])
                if not isinstance(event,dict) or set(event)!={'contract_sha256','event','outcome'}:
                    raise ValueError('malformed service observation')
                digest=event['contract_sha256']
                if not isinstance(digest,str) or digest not in contracts or not scopes:
                    raise ValueError('service observation lacks a selected active contract')
                _,outcomes,_,_=contracts[digest]
                # One definition may occur in multiple component catalogs.
                if digest not in catalogs[scopes[-1][0]]:
                    raise ValueError('service call is outside the active component contract')
                if event['event']=='call' and event['outcome']=='':calls.append((digest,len(scopes),len(events)))
                elif event['event']=='return' and calls and calls[-1][:2]==(digest,len(scopes)):
                    if event['outcome'] not in outcomes:
                        raise ValueError('service returned an undeclared outcome')
                    calls.pop()
                else:raise ValueError('service call/return nesting disagrees')
                events.append(event)
        root_catalog = (plan.get('service_catalog') or {}).get('catalog_sha256')
        # A manually adapted root can exit before calling any selected supplier.
        # Its completed handler still witnesses an observed execution boundary;
        # it does not witness a supplier invocation. A root with its own catalog
        # still needs a service scope (including delegated supplier execution).
        # Keep missing streams and unbalanced traces fatal.
        if scopes or calls or handlers or (not begun and (root_catalog or not seen_handlers)):
            raise ValueError('service scope is absent or incomplete')
    except (ValueError,UnicodeError) as error:
        incomplete=True
        findings.append(dict(side='source',classification='instrumentation-error',detail=str(error)))
    counts=Counter(e['contract_sha256'] for e in events if e['event']=='call')
    return dict(status='incomplete' if incomplete else 'satisfied',events=events,diagnostics=findings,
        coverage={identity:dict(contract_sha256=digest,calls=counts[digest]) for digest,(identity,_,_,_) in contracts.items()},
        unobserved=sorted({gap for _,_,_,gaps in contracts.values() for gap in gaps} |
            ({'No selected service was exercised in this case; completed handler scopes do not establish supplier behavior.'}
             if not begun and not incomplete else set())),
        authority='concrete-service-protocol-only')
