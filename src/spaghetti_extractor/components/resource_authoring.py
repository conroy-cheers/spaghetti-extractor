"""Author existing operation resource checks without duplicating lifecycle payloads.

This module prepares declarations only. Runtime validation and instrumentation
stay in comparison_resources; changing this helper need not invalidate execution
when its generated package inputs are unchanged.
"""
from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence

from ..boundary import BoundaryLifecycleV1
from .comparison_resources import checked_resource_checks
from .interface_package_v5 import ComponentInterfaceIntentV1


def rebind_resource_checks(checks: dict | None, *, previous: ComponentInterfaceIntentV1,
                           interface: ComponentInterfaceIntentV1) -> dict | None:
    """Rebind declarations when their operation values and reachable types stay exact.

    Service-only or unrelated schema edits need not recreate these explicit roles,
    limits and observation gaps. Changed operation values, representation types or
    nominal identities require newly reviewed declarations instead. This preserves
    resource declarations, not behavioral compatibility or previous evidence.
    """
    checked_resource_checks(checks,previous)
    if checks is None:return None
    if previous.component_id!=interface.component_id:
        raise ValueError('resource declarations cannot implicitly move to another component')
    revised=copy.deepcopy(checks)
    operations={op['id']:op for op in interface.operations}
    old_types=previous.schema.type_index;new_types=interface.schema.type_index
    for rule in revised['contracts']:
        identity=rule['operation_id']
        message='resource declarations for operation '+identity+' need review: '
        if identity not in operations:
            raise ValueError(message+'operation was removed; supply resource_checks explicitly')
        lifecycle=BoundaryLifecycleV1.parse(rule['lifecycle'],schema=previous.schema)
        old_signature=previous.schema.signature_index[lifecycle.signature_id]
        signature=interface.schema.signature_index[operations[identity]['signature_id']]
        if old_signature.to_payload()!=signature.to_payload():
            raise ValueError(message+'input/result declarations changed; supply resource_checks explicitly')
        additional={root.root:root.values for root in lifecycle.roots if root.root not in ('parameter','result')}
        pending=[signature.function_type_id,*[value.type_id for values in additional.values() for value in values]]
        seen=set()
        while pending:
            name=pending.pop()
            if name in seen:continue
            seen.add(name)
            if name not in old_types or name not in new_types or old_types[name].to_payload()!=new_types[name].to_payload():
                raise ValueError(message+'type '+name+' changed; supply resource_checks explicitly')
            pending.extend(old_types[name].references())
        rule['lifecycle']=BoundaryLifecycleV1.create(schema=interface.schema,
            signature_id=signature.identity,bindings=lifecycle.bindings,additional_roots=additional).to_payload()
    return checked_resource_checks(revised,interface)


def component_resource_checks(interface: ComponentInterfaceIntentV1, *,
        consumes: Sequence[str], produces: Sequence[str], resource_kind: str,
        provider_domain: str, service_id: str, interaction_contract_id: str,
        instrumented_sides: Sequence[str], unobserved: Sequence[str],
        operation_id: str = 'run', capacity: int = 4096, frame_capacity: int = 256,
        max_untransferred: int = 0, max_retained: int = 0,
        nonlocal_allowances: Mapping[str, dict] | None = None,
        binding_ids: Mapping[str, str] | None = None) -> dict:
    """Declare top-level consumed inputs and produced results of one operation.

    Names and ownership roles are explicit; numeric values may be omitted. This
    does not infer lifetimes, require exclusive ownership, or install C transport.
    Classification is shared by these values. For heterogeneous resources or
    multiple operations, use the existing full lifecycle/check declaration API.

    Binding IDs default to ROOT.VALUE. Optional binding_ids preserves existing
    IDs when migrating a prepared recipe without changing its evidence inputs.
    The existing validator determines which declarations are instrumentable.
    """
    operations={operation['id']:operation for operation in interface.operations}
    if not isinstance(operation_id,str) or operation_id not in operations:
        raise ValueError('resource authoring operation is absent from the interface')
    for names in (consumes,produces):
        if (not isinstance(names,(list,tuple)) or any(not isinstance(name,str) or not name for name in names)
                or len(set(names))!=len(names)):
            raise ValueError('resource authoring needs unique explicit consumed/produced value names')
    paths={root+'.'+name for root,names in [('parameter',consumes),('result',produces)] for name in names}
    ids={} if binding_ids is None else binding_ids
    if (not isinstance(ids,Mapping) or set(ids)-paths
            or any(not isinstance(value,str) or not value for value in ids.values())):
        raise ValueError('resource binding IDs must name declared ROOT.VALUE paths')
    if any(not isinstance(values,(list,tuple)) for values in (instrumented_sides,unobserved)):
        raise ValueError('resource authoring needs explicit instrumentation sides and unobserved effects')
    bindings=[dict(id=ids.get(root+'.'+name,root+'.'+name),
        path=dict(root=root,value_id=name,fields=[]),transition=transition,
        resource_kind=resource_kind,provider_domain=provider_domain,
        service_id=service_id,interaction_contract_id=interaction_contract_id,condition=None)
        for root,names,transition in [('parameter',consumes,'consume'),('result',produces,'produce')]
        for name in names]
    lifecycle=BoundaryLifecycleV1.create(schema=interface.schema,
        signature_id=operations[operation_id]['signature_id'],bindings=bindings)
    rule=dict(operation_id=operation_id,lifecycle=lifecycle.to_payload(),
        max_untransferred=max_untransferred,max_retained=max_retained)
    if nonlocal_allowances is not None:
        rule['nonlocal_allowances']=copy.deepcopy(dict(nonlocal_allowances))
    return checked_resource_checks(dict(capacity=capacity,frame_capacity=frame_capacity,
        instrumented_sides=list(instrumented_sides),unobserved=list(unobserved),contracts=[rule]),interface)
