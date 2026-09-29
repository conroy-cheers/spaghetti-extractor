"""Reusable C service definitions compiled to existing boundary artifacts.

Definitions are authoring inputs, not checked summaries. Their complete schema,
lifecycle and declared behavior are bound by an InteractionContractV1 identity.
Adapters remain ordinary C; native semantics are never inferred from a signature.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from ..boundary import BoundaryLifecycleV1, BoundarySchemaV1, BoundaryTypeV1
from ..boundary._canonical import BoundaryModelError
from .component_c_v5 import _c, _plain_type
from .interface_package_v5 import ComponentInterfaceIntentV1
from .interaction_contract import InteractionContractCatalogV1, InteractionContractV1


def value(name: str, type_id: str) -> dict:
    return dict(id=name, type_id=type_id, interpretation='value', nullable=False,
                access='none', extent=dict(kind='none', bytes=None, value_id=None),
                provider_domain=None, resource_kind=None)


def signature(name, parameters, result):
    return (dict(id=name+'.function', kind='function', calling_convention='cdecl',
                 parameter_type_ids=[t for _,t in parameters], result_type_id=result, variadic=False),
            dict(id=name, function_type_id=name+'.function',
                 parameters=[value(n,t) for n,t in parameters],
                results=[] if result=='unit' else [value('result',result)]))


def _nullable_signature(sig, types, parameters, result):
    """Make optional object values explicit without changing their C ABI."""
    if (not isinstance(parameters, (list, tuple)) or any(not isinstance(p, str) for p in parameters)
            or len(set(parameters)) != len(parameters) or type(result) is not bool):
        raise BoundaryModelError('nullable values need unique parameter names and a boolean result flag')
    names = {v['id'] for v in sig['parameters']}
    if set(parameters)-names or (result and not sig['results']):
        raise BoundaryModelError('nullable value is absent from the signature')
    available = {t['id']: t for t in types}
    for item in [*[v for v in sig['parameters'] if v['id'] in parameters], *(sig['results'] if result else [])]:
        if available[item['type_id']]['kind'] != 'opaque':
            raise BoundaryModelError('nullable service authoring values must be opaque objects')
        item['nullable'] = True


def checked_service_protocol(protocol, outcomes, nonlocal_outcomes):
    for values in (outcomes, nonlocal_outcomes):
        if (not isinstance(values, (list, tuple)) or
                any(not isinstance(v, str) or not v for v in values) or len(set(values)) != len(values)):
            raise BoundaryModelError('service outcomes must be unique explicit names')
        for item in values:
            _c(item)
    expected = 'synchronous-return-or-nonlocal' if nonlocal_outcomes else 'synchronous-return'
    if not outcomes or set(outcomes) & set(nonlocal_outcomes) or protocol != expected:
        raise BoundaryModelError('service synchronous-return protocol/outcomes need an available checker')


def service_resource_roles(parameters: Sequence[tuple[str, str]], *,
                           consumes: Sequence[str] = (), borrows: Sequence[str] = (),
                           produces: bool = False, resource_kind: str,
                           provider_domain: str) -> list[dict]:
    """Author explicit whole-value service roles in signature order.

    borrows means borrow_shared; produces names the single result. Every role
    shares the supplied classification. Unlisted parameters have no role. This
    does not infer ownership from types, require exclusive access, or transport
    memory. ServiceDefinition.create applies the existing lifecycle validation.
    Nested paths, mutable borrows and heterogeneous classifications use its full
    resources list instead. Ordering matches parameter order, then result, so a
    prepared recipe can retain its existing role IDs and contract identity.
    """
    selected = {}
    for transition, names in [('consume', consumes), ('borrow_shared', borrows)]:
        if (not isinstance(names, (list, tuple))
                or any(not isinstance(name, str) or not name for name in names)):
            raise BoundaryModelError('service resource roles need explicit parameter names')
        for name in names:
            if name in selected:
                raise BoundaryModelError('service resource role is repeated: ' + name)
            selected[name] = transition
    absent = set(selected) - {name for name, _ in parameters}
    if absent:
        raise BoundaryModelError('service resource parameters are absent: ' + ', '.join(sorted(absent)))
    if type(produces) is not bool:
        raise BoundaryModelError('service resource produces flag must be boolean')
    paths = [('parameter', name, selected[name]) for name, _ in parameters if name in selected]
    if produces:
        paths.append(('result', 'result', 'produce'))
    return [dict(root=root, value=name, fields=[], transition=transition,
                 kind=resource_kind, domain=provider_domain) for root, name, transition in paths]


@dataclass(frozen=True)
class ServiceDefinition:
    """A reusable one-call contract; resource paths use canonical lifecycle rules."""
    identity: str
    schema: BoundarySchemaV1
    lifecycle: BoundaryLifecycleV1
    contract: InteractionContractV1

    @classmethod
    def create(cls, *, identity: str, types: Sequence[dict], parameters: Sequence[tuple[str,str]],
               result: str, resources: Sequence[dict], effects: Sequence[str],
               outcomes: Sequence[str], unobserved: Sequence[str],
               protocol: str | None = None, nonlocal_outcomes: Sequence[str] = (),
               nullable_parameters: Sequence[str] = (), nullable_result: bool = False) -> 'ServiceDefinition':
        _c(identity)
        if protocol is None:
            protocol = 'synchronous-return-or-nonlocal' if nonlocal_outcomes else 'synchronous-return'
        checked_service_protocol(protocol, outcomes, nonlocal_outcomes)
        for item in (*outcomes,*effects):
            _c(item)
        if not isinstance(unobserved,(list,tuple)) or any(not isinstance(s,str) or not s for s in unobserved):
            raise BoundaryModelError('service instrumentation gaps must be explicit strings')
        fn,sig=signature('call',parameters,result)
        _nullable_signature(sig, types, nullable_parameters, nullable_result)
        available={t['id']:t for t in types}
        if len(available)!=len(types):
            raise BoundaryModelError('service types have duplicate identities')
        reachable=set()
        def visit(name):
            if name in reachable:return
            if name not in available:raise BoundaryModelError('service type is absent: '+name)
            reachable.add(name);t=available[name]
            if t['kind']=='record':
                for field in t['fields']:visit(field['type_id'])
            elif t['kind'] not in ('integer','bool','float','void','opaque'):
                raise BoundaryModelError('service authoring supports integer/binary32/binary64 scalars, records and nominal opaque C objects: '+name)
        for name in [result,*[t for _,t in parameters]]:visit(name)
        schema=BoundarySchemaV1.create(schema_id='service.'+identity,types=[*[available[n] for n in sorted(reachable)],fn],signatures=[sig])
        # Probe the actual C renderer before authoring an adapter around an
        # unsupported type. Function schemas are validated by BoundarySchemaV1.
        for v in (*schema.signature_index['call'].parameters,*schema.signature_index['call'].results):
            _c(v.identity)
            _plain_type(schema.type_index,schema.type_index[v.type_id])
        bindings=[]
        paths=set()
        for role in resources:
            if set(role)!={'root','value','fields','transition','kind','domain'}:
                raise BoundaryModelError('service resource role fields differ')
            path=(role['root'],role['value'],tuple(role['fields']))
            if path in paths:
                raise BoundaryModelError('service resource path is repeated')
            paths.add(path)
            bindings.append(dict(id='role.'+str(len(bindings)),
                path=dict(root=role['root'],value_id=role['value'],fields=role['fields']),
                transition=role['transition'],resource_kind=role['kind'],provider_domain=role['domain'],
                service_id=identity,interaction_contract_id=identity,condition=None))
        lifecycle=BoundaryLifecycleV1.create(schema=schema,signature_id='call',bindings=bindings)
        used={t for _,t in parameters}|({result} if result!='unit' else set())
        logical_types=[]
        for name in sorted(used):
            t=schema.type_index[name]
            if t.kind not in ('record','integer','bool','float','opaque'):
                raise BoundaryModelError('service authoring supports integer/floating scalars, records and nominal opaque C objects; '+name+' needs an explicit supported adapter')
            # An opaque C pointer is an executable adapter boundary, not a
            # grant of pointee contents, extent, ownership or lifetime. The
            # canonical schema retains its nominal identity. Existing formal
            # readers must independently establish their supported relation.
            logical_types.append(dict(id=name,kind='reference' if t.kind=='opaque' else 'record' if t.kind=='record' else 'scalar',
                width=None if t.kind in ('record','opaque') else 8 if t.kind=='bool' else t.body['value_bits'] if t.kind=='float' else t.body['width_bits'],
                element_width=None,access=None,nullable=None,nul_terminated=None))
        contract=InteractionContractV1.create(identity=identity,primitive_id=identity,
            subject=dict(kind='c-service-definition',schema=schema.to_payload(),lifecycle=lifecycle.to_payload(),
                outcomes=list(outcomes),protocol=protocol,
                **({'nonlocal_outcomes':list(nonlocal_outcomes)} if nonlocal_outcomes else {}),
                checkers=['C-conformance','transport-lifecycle','service-trace'],unobserved=list(unobserved)),
            type_parameters=logical_types,
            ports=sorted([dict(id=n,direction='input',type_parameter=t) for n,t in parameters]+
                ([] if result=='unit' else [dict(id='result',direction='output',type_parameter=result)]),
                key=lambda p:(p['direction'],p['id'])),
            effects=[dict(primitive=e,arguments=[],result=None) for e in effects],
            provenance=dict(kind='authored-service-definition',source=identity,reviewed=False))
        return cls(identity,schema,lifecycle,contract)

    @property
    def binding_id(self):
        return self.identity+':'+self.contract.contract_sha256


@dataclass(frozen=True)
class OperationDefinition:
    """An authored entry in one component; private helpers stay private C."""
    parameters: Sequence[tuple[str,str]]
    result: str
    allowed_services: Sequence[str] = ()
    nullable_parameters: Sequence[str] = ()
    nullable_result: bool = False


def service_types(services: Mapping[str,ServiceDefinition], *, types: Sequence[dict] = ()) -> list[dict]:
    """Reuse shared value declarations, adding explicit component-local types.

    Service schemas already carry the transitive types of their call values.
    Merge exact declarations by identity; never pick a layout based on ordering
    or import another component's unrelated types. Function signatures are rebuilt
    in the consumer's namespace. This does not infer object contents or lifetime.
    The result can also supply types when defining a related lower service.
    """
    merged={};origins={}
    for row in types:
        definition=BoundaryTypeV1.parse(row)
        if definition.identity in merged:
            raise BoundaryModelError('component types have duplicate identities: '+definition.identity)
        merged[definition.identity]=definition
        origins[definition.identity]='component type declarations'
    for name,service in sorted(services.items()):
        origin='service '+name+' ('+service.identity+')'
        for definition in service.schema.types:
            if definition.kind=='function':continue
            previous=merged.get(definition.identity)
            if previous is not None and previous.to_payload()!=definition.to_payload():
                raise BoundaryModelError('service schema differs for type '+definition.identity+
                    ' between '+origins[definition.identity]+' and '+origin)
            if previous is None:
                merged[definition.identity]=definition
                origins[definition.identity]=origin
    return [merged[name].to_payload() for name in sorted(merged)]


def component_interface(*, component_id: str, types: Sequence[dict] = (),
                        services: Mapping[str,ServiceDefinition],
                        parameters: Sequence[tuple[str,str]] | None = None, result: str | None = None,
                        nullable_parameters: Sequence[str] = (), nullable_result: bool = False,
                        operations: Mapping[str,OperationDefinition] | None = None,
                        state: Sequence[dict] = (), schema_id: str | None = None) -> ComponentInterfaceIntentV1:
    """Construct one run operation or named entries sharing a component context.

    Entries have identity value projections and the synchronous ready protocol.
    State uses the existing explicit value/initial declarations; adapters still
    establish its contents and lifetime. Richer protocols, projections and
    operation lifecycle bindings use ComponentInterfaceIntentV1 directly.
    Shared value types come from services; types adds local declarations and
    need not repeat them. Existing explicit type lists retain their identities.
    """
    types=service_types(services,types=types)
    if operations is None:
        if parameters is None or result is None:
            raise BoundaryModelError('component authoring needs parameters/result or named operations')
        operations={'run':OperationDefinition(parameters,result,tuple(services),nullable_parameters,nullable_result)}
    elif parameters is not None or result is not None or nullable_parameters or nullable_result:
        raise BoundaryModelError('named operations cannot be combined with the single run signature')
    if (not isinstance(operations,Mapping) or not operations
            or any(not isinstance(op,OperationDefinition) for op in operations.values())):
        raise BoundaryModelError('named operations require a nonempty mapping of OperationDefinition values')
    if (not isinstance(state,(list,tuple)) or
            any(not isinstance(row,Mapping) or set(row)!={'value','initial'} for row in state)):
        raise BoundaryModelError('component state requires explicit value and initial declarations')
    for name,operation in operations.items():
        _c(name)
        selected=operation.allowed_services
        if (not isinstance(selected,(list,tuple)) or any(not isinstance(s,str) for s in selected)
                or len(set(selected))!=len(selected) or set(selected)-services.keys()):
            raise BoundaryModelError('operation '+name+' must select unique available services')
    specs={'operation.'+name:(op.parameters,op.result) for name,op in operations.items()}
    for name,definition in services.items():
        _c(name)
        sig=definition.schema.signature_index['call']
        specs['service.'+name]=([(v.identity,v.type_id) for v in sig.parameters],
                               sig.results[0].type_id if sig.results else 'unit')
    rows=[signature(name,*spec) for name,spec in sorted(specs.items())]
    for _, row in rows:
        if row['id'].startswith('operation.'):
            operation=operations[row['id'][len('operation.'):]]
            _nullable_signature(row, types, operation.nullable_parameters, operation.nullable_result)
        else:
            service = services[row['id'][len('service.'):]].schema.signature_index['call']
            # Preserve all value semantics from the checked declaration, including
            # nullability. A same-signature caller cannot silently narrow them.
            row['parameters'] = [v.to_payload() for v in service.parameters]
            row['results'] = [v.to_payload() for v in service.results]
    schema=BoundarySchemaV1.create(schema_id=schema_id if schema_id is not None else 'component.'+component_id,
        types=[*types,*[r[0] for r in rows]],signatures=[r[1] for r in rows])
    entries=[]
    for name,operation in sorted(operations.items()):
        sig=schema.signature_index['operation.'+name]
        entries.append(dict(id=name,signature_id='operation.'+name,
            source_values=[v.to_payload() for v in (*sig.parameters,*sig.results)],
            projection_entries=[dict(source_id=v.identity,target=dict(root=root,value_id=v.identity,fields=[]))
                                for root,values in [('parameter',sig.parameters),('result',sig.results)] for v in values],
            effect_ids=[],allowed_service_ids=list(operation.allowed_services),checked_interaction_contract_ids=[],
            pre_states=['ready'],post_states=['ready'],lifecycle_bindings=[],
            lifecycle_additional_roots=dict(state=[row['value'] for row in state])))
    return ComponentInterfaceIntentV1.create(component_id=component_id,schema=schema,state=state,effects=[],
        services=[dict(id=name,signature_id='service.'+name,interaction_contract_id=d.binding_id,effect_ids=[])
                  for name,d in services.items()],protocol_states=['ready'],initial_protocol_state='ready',
        operations=entries)


def service_catalog(services: Mapping[str,ServiceDefinition]) -> InteractionContractCatalogV1:
    """Retain one exact contract per identity even when local service names alias it."""
    contracts={};origins={}
    for name,definition in services.items():
        previous=contracts.get(definition.identity)
        if previous is not None and previous.to_payload()!=definition.contract.to_payload():
            raise BoundaryModelError('service contract differs for identity '+definition.identity+
                ' between '+origins[definition.identity]+' and '+name)
        contracts[definition.identity]=definition.contract
        origins.setdefault(definition.identity,name)
    return InteractionContractCatalogV1.create(list(contracts.values()))


def services_from_interface(interface: ComponentInterfaceIntentV1,
                            catalog: InteractionContractCatalogV1 | dict | None, *,
                            names: Sequence[str] | None = None) -> dict[str,ServiceDefinition]:
    """Reuse exact service declarations without their original authoring recipe.

    Select by the interface's local service names. Preserve the complete bound
    contracts, including lifecycle, effects, outcomes and unobserved behavior.
    Adapters, object transport and evidence are still separate operator inputs.
    """
    if isinstance(catalog, InteractionContractCatalogV1):
        catalog = catalog.to_payload()
    checked = checked_service_catalog(catalog, interface)
    if checked is None and interface.services:
        raise BoundaryModelError('generated service bridge requires exact service contracts')
    available = {row['id']: row for row in interface.services}
    if isinstance(names, (str, bytes)):
        raise BoundaryModelError('selected services must be a sequence of names')
    selected = list(available) if names is None else list(names)
    if any(not isinstance(name, str) for name in selected) or len(set(selected)) != len(selected):
        raise BoundaryModelError('selected service names must be unique strings')
    unknown = set(selected) - available.keys()
    if unknown:
        raise BoundaryModelError('unknown interface services: '+', '.join(sorted(unknown)))
    by_binding = {c.identity+':'+c.contract_sha256: c for c in checked.contracts} if checked is not None else {}
    services = {}
    for name in selected:
        contract = by_binding[available[name]['interaction_contract_id']]
        schema = BoundarySchemaV1.parse(contract.subject['schema'])
        lifecycle = BoundaryLifecycleV1.parse(contract.subject['lifecycle'], schema=schema)
        services[name] = ServiceDefinition(contract.identity, schema, lifecycle, contract)
    return services


def checked_service_catalog(payload, interface):
    """Validate exact declaration bindings, without asserting adapter correctness."""
    if payload is None:
        return None
    catalog=InteractionContractCatalogV1.parse(payload)
    contracts={c.identity+':'+c.contract_sha256:c for c in catalog.contracts}
    selected={s['interaction_contract_id']:s for s in interface.services}
    if set(contracts)!=set(selected):
        raise BoundaryModelError('service catalog must bind exactly the selected interface services')
    for binding,contract in contracts.items():
        subject=contract.subject
        if set(subject)-{'nonlocal_outcomes'}!={'kind','schema','lifecycle','outcomes','protocol','checkers','unobserved'} or subject['kind']!='c-service-definition':
            raise BoundaryModelError('service definition subject is unsupported')
        schema=BoundarySchemaV1.parse(subject['schema'])
        lifecycle=BoundaryLifecycleV1.parse(subject['lifecycle'],schema=schema)
        if lifecycle.signature_id!='call' or len(schema.signatures)!=1:
            raise BoundaryModelError('service lifecycle must bind the single call signature')
        outcomes=subject['outcomes'];gaps=subject['unobserved']
        checked_service_protocol(subject['protocol'], outcomes, subject.get('nonlocal_outcomes', []))
        if 'nonlocal_outcomes' in subject and not subject['nonlocal_outcomes']:
            raise BoundaryModelError('service nonlocal outcomes must be omitted when empty')
        if not isinstance(gaps,list) or any(not isinstance(v,str) or not v for v in gaps):
            raise BoundaryModelError('service definition instrumentation gaps are malformed')
        if (subject['checkers']!=['C-conformance','transport-lifecycle','service-trace']
                or contract.requires or contract.ensures
                or any(e['arguments'] or e['result'] is not None for e in contract.effects)):
            raise BoundaryModelError('service definition requests an unsupported predicate or checker')
        sig=schema.signature_index['call']
        selected_sig=interface.schema.signature_index[selected[binding]['signature_id']]
        if [v.to_payload() for v in (*sig.parameters,*sig.results)] != [v.to_payload() for v in (*selected_sig.parameters,*selected_sig.results)] or len(sig.parameters)!=len(selected_sig.parameters):
            raise BoundaryModelError('service catalog signature differs from component interface')
        for t in schema.types:
            if t.kind!='function' and (t.identity not in interface.schema.type_index or t.to_payload()!=interface.schema.type_index[t.identity].to_payload()):
                raise BoundaryModelError('service catalog type differs from component interface')
    return catalog
