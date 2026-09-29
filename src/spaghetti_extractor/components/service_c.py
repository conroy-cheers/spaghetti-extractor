"""Mechanical C transport bridges and trace scaffolding for reusable services.

Only declared whole-value consume/borrow/produce transport is generated. Custom
portable adapters handle semantic conversions; their lifecycle implementation is
reported as adapter-owned rather than inferred from the C signature.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re

from ..boundary._canonical import BoundaryModelError
from .component_c_v5 import _c, _fresh_c_name, _parameter_type, _result_type
from .service_authoring import ServiceDefinition, service_catalog


def symbol(value):
    if not isinstance(value,str) or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',value) is None:
        raise BoundaryModelError('service adapter symbol must be a C identifier')
    return value


@dataclass(frozen=True)
class CTransport:
    native_type: str
    take: str
    borrow: str
    pack: str

    def __post_init__(self):
        for v in (self.native_type,self.take,self.borrow,self.pack):
            symbol(v)


def _trace(definition,event,outcome='',*,enabled=True):
    # Service observations are bound byte-for-byte by the comparison receipt.
    # This scaffolding reports protocol boundaries, not native heap contents.
    if not enabled:return ''
    row=dict(contract_sha256=definition.contract.contract_sha256,event=event,outcome=outcome)
    return '  fputs('+json.dumps('SPX_SERVICE '+json.dumps(row,sort_keys=True,separators=(',',':'))+'\n')+', stderr);'


def _scope_event(catalog_sha256, event, *, enabled=True):
    if not enabled:return ''
    row=dict(catalog_sha256=catalog_sha256,event=event)
    return '  fputs('+json.dumps('SPX_SERVICE_SCOPE '+json.dumps(row,separators=(',',':'))+'\n')+', stderr);'


def render_service_bridges(*, services: dict[str,ServiceDefinition], adapters: dict,
                           transports: dict[str,CTransport], trace_services: bool=True) -> tuple[str,dict]:
    """Generate wrappers; explicit native/portable adapter choices never add authority.

    Adapter config: symbol, kind ('native' or 'portable'), and outcomes mapping
    declared outcome IDs to predicate function symbols, or None for a sole return.
    declare=True emits an extern prototype for a separately defined C adapter.
    Its types follow the selected transport and optional context argument; the
    operator still reviews that the actual adapter implements this calling shape.
    Predicates borrow the portable result and must not mutate it. They are bound
    fixture code; the generator cannot prove arbitrary predicate semantics.
    """
    if type(trace_services) is not bool:
        raise BoundaryModelError('service tracing selection must be a boolean')
    if set(adapters)!=set(services):
        raise BoundaryModelError('service adapters must cover exactly the selected services')
    lines=['#include <stdio.h>','#include <stdlib.h>']
    coverage={}
    for name,definition in services.items():
        symbol(name)
        adapter=adapters[name]
        if (set(adapter)-{'context','declare'}!={'symbol','kind','outcomes'}
                or adapter['kind'] not in ('native','portable')
                or any(type(adapter.get(key,False)) is not bool for key in ('context','declare'))):
            raise BoundaryModelError('service adapter requires symbol, native/portable kind and outcome predicates')
        target=symbol(adapter['symbol']); predicates=adapter['outcomes']
        declared=definition.contract.subject['outcomes']
        if set(predicates)!=set(declared):
            raise BoundaryModelError('service outcome predicates must cover declared outcomes exactly')
        if any(p is None for p in predicates.values()) and (len(predicates)!=1 or next(iter(predicates.values())) is not None):
            raise BoundaryModelError('unconditional outcome requires a single declared outcome')
        for p in predicates.values():
            if p is not None:symbol(p)
        schema=definition.schema;sig=schema.signature_index['call']
        occupied={symbol(v.identity) for v in sig.parameters}|{target}|{
            p for p in predicates.values() if p is not None}
        occupied.update(function for transport in transports.values()
                        for function in (transport.take,transport.borrow,transport.pack))
        environment=_fresh_c_name('e',occupied)
        returned=_fresh_c_name('spx_result',occupied)
        outcome_names=[_fresh_c_name(f'outcome_{n}',occupied) for n in range(len(predicates))]
        roles={(r.path.root,r.path.value_id,r.path.fields):r.transition for r in definition.lifecycle.bindings}
        if adapter['kind']=='native' and any(fields for _,_,fields in roles):
            raise BoundaryModelError('nested resource conversion requires an explicit portable adapter')
        params=[];arguments=[];native_params=[]
        for v in sig.parameters:
            symbol(v.identity)
            params.append(_parameter_type(schema.type_index,v)+' '+v.identity)
            native_params.append(transports[v.type_id].native_type if adapter['kind']=='native' and v.type_id in transports
                                 else _parameter_type(schema.type_index,v))
            mode=roles.get(('parameter',v.identity,()))
            if v.type_id in transports and adapter['kind']=='native':
                transport=transports[v.type_id]
                if mode not in ('consume','borrow_shared'):
                    raise BoundaryModelError('native service transport needs explicit consume or borrow_shared: '+name+'.'+v.identity)
                arguments.append((transport.take if mode=='consume' else transport.borrow)+'('+v.identity+')')
            else:
                if mode and adapter['kind']=='native':
                    raise BoundaryModelError('resource parameter has no C transport: '+name+'.'+v.identity)
                arguments.append(v.identity)
        result=_result_type(schema.type_index,sig)
        if result=='void' and any(p is not None for p in predicates.values()):
            raise BoundaryModelError('void service supports only an unconditional return outcome')
        native_result=result
        if sig.results and adapter['kind']=='native' and sig.results[0].type_id in transports:
            native_result=transports[sig.results[0].type_id].native_type
        signature=', '.join((['void *'] if adapter.get('context') else [])+native_params) or 'void'
        if adapter.get('declare'):
            lines.append(f'extern {native_result} {target}({signature});')
        if any(t.kind=='float' for t in schema.types):
            lines.append(f'_Static_assert(_Generic(&{target}, {native_result} (*)({signature}): 1, default: 0), '
                         f'"floating service adapter signature differs: {name}");')
            for predicate in predicates.values():
                if predicate is not None:
                    lines.append(f'_Static_assert(_Generic(&{predicate}, int (*)({result}): 1, default: 0), '
                                 f'"floating outcome predicate signature differs: {name}");')
        lines.extend([f'static {result} service_{name}(void *{environment}'+''.join(', '+p for p in params)+') {',
                      f'  (void){environment};',_trace(definition,'call',enabled=trace_services)])
        call=target+'('+', '.join(([environment] if adapter.get('context') else [])+arguments)+')'
        if sig.results and adapter['kind']=='native':
            v=sig.results[0];mode=roles.get(('result',v.identity,()))
            if v.type_id in transports:
                if mode!='produce':
                    raise BoundaryModelError('native service transport result must declare produce: '+name)
                call=transports[v.type_id].pack+'('+call+')'
            elif mode:
                raise BoundaryModelError('resource result has no C transport: '+name)
        lines.append('  '+(result+' '+returned+' = ' if result!='void' else '')+call+';')
        if next(iter(predicates.values())) is None:
            lines.append(_trace(definition,'return',next(iter(predicates)),enabled=trace_services))
        else:
            # Exactly one observed outcome; overlapping predicates are failed
            # premises rather than an arbitrary first-match choice.
            for n,predicate in enumerate(predicates.values()):
                lines.append(f'  int {outcome_names[n]} = !!{predicate}({returned});')
            lines.extend(['  if ('+' + '.join(outcome_names)+' != 1) {',
                '    fputs("service outcome predicates are not exclusive and total\\n", stderr); exit(78);','  }'])
            for n,label in enumerate(predicates):
                lines.extend([f'  if ({outcome_names[n]}) {{',_trace(definition,'return',label,enabled=trace_services),'  }'])
        if result!='void':lines.append('  return '+returned+';')
        lines.append('}')
        coverage[name]=dict(contract_sha256=definition.contract.contract_sha256,
            generated=['C-signature']+(['call-return-trace'] if trace_services else [])+['outcome-partition']+
                (['whole-value-transport'] if adapter['kind']=='native' else [])+
                (['adapter-declaration'] if adapter.get('declare') else []),
            adapter_owned=['native-effect-semantics','outcome-predicate-semantics']+
                (['nonlocal-delivery-and-handler-scope'] if definition.contract.subject.get('nonlocal_outcomes') else [])+
                (['resource-field-conversion'] if adapter['kind']=='portable' else [])+
                (['opaque-object-contents-aliases-and-lifetime'] if any(t.kind=='opaque' for t in schema.types) else []),
            unobserved=list(definition.contract.subject['unobserved'])+
                ([] if trace_services else ['service-call-return-protocol']))
    return '\n'.join(lines)+'\n',coverage


def render_operation_bridge(*, interface, operation_symbol: str, native_symbol: str,
                            services: dict, transports: dict, resource_rule: dict | None=None,
                            trace_services: bool=True):
    """Generate a whole-value owned operation entry using existing F2 checks."""
    from ..artifacts.artifact_set import canonical_sha256_v3
    if interface.state or len(interface.operations)!=1 or interface.operations[0]['id']!='run':
        raise BoundaryModelError('generated operation bridge supports a stateless single run operation')
    if set(services)!={s['id'] for s in interface.services}:
        raise BoundaryModelError('generated operation bridge services differ from its interface')
    sig=interface.schema.signature_index['operation.run']
    if len(sig.results)>1:
        raise BoundaryModelError('operation bridge requires at most one result')
    symbol(operation_symbol);symbol(native_symbol)
    occupied={symbol(v.identity) for v in sig.parameters}|{operation_symbol}
    occupied.update(function for transport in transports.values() for function in (transport.pack,transport.take))
    table=_fresh_c_name('s',occupied)
    context=_fresh_c_name('context',occupied)
    returned=_fresh_c_name('result',occupied)
    frame=_fresh_c_name('resource_frame',occupied)
    component=_c(interface.component_id)
    result_transport=transports.get(sig.results[0].type_id) if sig.results else None
    result_type=result_transport.native_type if result_transport else _result_type(interface.schema.type_index,sig)
    params=[(transports[v.type_id].native_type if v.type_id in transports else _parameter_type(interface.schema.type_index,v))+' '+symbol(v.identity) for v in sig.parameters]
    lines=[result_type+' '+native_symbol+'('+(', '.join(params) or 'void')+') {',
           f'  spx_{component}_services_v5 {table} = {{0}};']
    if resource_rule is not None:
        lines.append('  uint32_t '+frame+' = spx_resource_frame_enter("'+canonical_sha256_v3(resource_rule)+'");')
    scope=service_catalog(services).catalog_sha256 if services else None
    if scope is not None:
        lines.append(_scope_event(scope,'begin',enabled=trace_services))
    lines += [f'  {table}.{symbol(name)} = service_{symbol(name)};' for name in services]
    args=['&'+context,*[transports[v.type_id].pack+'('+v.identity+')' if v.type_id in transports else v.identity for v in sig.parameters]]
    call=operation_symbol+'('+', '.join(args)+')'
    if result_transport:call=result_transport.take+'('+call+')'
    lines += [f'  spx_{component}_context_v5 {context} = {{0}};', f'  {context}.services = &{table};',
              '  '+(result_type+' '+returned+' = ' if sig.results else '')+call+';']
    if scope is not None:
        lines.append(_scope_event(scope,'end',enabled=trace_services))
    if resource_rule is not None:lines.append('  spx_resource_frame_leave('+frame+');')
    return '\n'.join(lines+(['  return '+returned+';'] if sig.results else [])+['}'])+'\n'


def _manual_entry_support(interface, services, *, trace_services=True):
    """Wire services without inventing entry transport or resetting shared state."""
    prefix='spx_'+_c(interface.component_id)
    table=prefix+'_services_v5'
    lines=[f'static inline {table} {prefix}_bind_services(void *context) {{',
           f'  {table} services = {{0}};', '  services.context = context;']
    lines.extend(f'  services.{symbol(name)} = service_{symbol(name)};' for name in services)
    lines.extend(['  return services;','}'])
    scope=service_catalog(services).catalog_sha256 if services else None
    for event in ('begin','end'):
        lines.append(f'static inline void {prefix}_services_{event}(void) {{')
        if scope is not None:lines.append(_scope_event(scope,event,enabled=trace_services))
        lines.append('}')
    return '\n'.join(lines)+'\n'


def materialize_service_bridge(plan, interface, *, trace_services=True):
    """Compile a package's explicit adapter choices into its generated header."""
    from .service_authoring import services_from_interface
    spec=plan.get('service_bridge')
    if spec is None:return None
    if not isinstance(spec,dict) or set(spec)!={'adapters','transports','native_symbol'}:
        raise BoundaryModelError('service bridge requires adapters, transports and a native entry symbol (null for manual entries)')
    services=services_from_interface(interface,plan.get('service_catalog'))
    if not isinstance(spec['adapters'],dict) or not isinstance(spec['transports'],dict):
        raise BoundaryModelError('service bridge adapters and transports must be mappings')
    if any(not isinstance(v,dict) or set(v)!={'native_type','take','borrow','pack'} for v in spec['transports'].values()):
        raise BoundaryModelError('service C transport requires native_type, take, borrow and pack')
    if set(spec['transports'])-interface.schema.type_index.keys():
        raise BoundaryModelError('service C transport names an absent boundary type')
    transports={name:CTransport(**value) for name,value in spec['transports'].items()}
    wrappers,coverage=render_service_bridges(services=services,adapters=spec['adapters'],transports=transports,
        trace_services=trace_services)
    rules=plan.get('resource_checks',{}).get('contracts',[])
    prefix='#include "comparison-resources.h"\n' if rules else ''
    if spec['native_symbol'] is None:
        for row in coverage.values():
            row['adapter_owned'].extend(['operation-entry-dispatch','context-state-and-lifetime',
                *(['operation-service-scopes'] if trace_services else []),*(['operation-resource-frames'] if rules else [])])
        return prefix+wrappers+_manual_entry_support(interface,services,trace_services=trace_services),coverage
    if interface.state or len(interface.operations)!=1 or interface.operations[0]['id']!='run':
        raise BoundaryModelError('grouped or stateful components require native_symbol=None and operator-owned C entries')
    if len(rules)>1 or (rules and rules[0]['operation_id']!='run'):
        raise BoundaryModelError('generated entry instrumentation supports a single run operation')
    entry=render_operation_bridge(interface=interface,operation_symbol=plan['operation_symbols']['run'],
        native_symbol=spec['native_symbol'],services=services,transports=transports,resource_rule=rules[0] if rules else None,
        trace_services=trace_services)
    return prefix+wrappers+entry,coverage
