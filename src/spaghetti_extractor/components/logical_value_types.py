"""Keep value contracts distinct when their physical boundary type is shared."""
from __future__ import annotations

from dataclasses import replace

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary import BoundaryModelError
from ..boundary._canonical import array, object_


def checked_nullable_input_values(bundle, contract):
    """Admit only direct byte inputs with the production decoder's exact binding.

    This establishes a logical shape, not the caller's reference, memory or
    lifetime premises. Those remain checked by entry and cut transport.
    """
    schema = bundle.intent.schema
    operations = bundle.interface.operations
    inputs = [(operation, value) for operation in operations
              for value in schema.signature_index[operation.signature_id].parameters
              if value.interpretation == 'view' and value.nullable]
    if contract is not None:
        from .machine_overlay_result_views import checked_parameter_exit_transports
        operation_index = {operation.identity: operation for operation in operations}
        for semantics in contract.machine_semantics:
            operation = operation_index[semantics.operation_id]
            checked_parameter_exit_transports(bundle, schema.signature_index[operation.signature_id],
                                             semantics.machine_projection['operation'])
    if not inputs or contract is None:
        return set()
    semantics = {row.operation_id: row for row in contract.machine_semantics}
    if (contract.interface_sha256 != bundle.interface.interface_sha256 or
            set(semantics) != {row.identity for row in operations} or
            len(semantics) != len(contract.machine_semantics)):
        raise BoundaryModelError('nullable inputs require current, total operation bindings')
    forbidden = {id(value) for operation in operations
                 for value in schema.signature_index[operation.signature_id].results}
    forbidden.update(id(value) for service in bundle.interface.services
                     for value in (*schema.signature_index[service.signature_id].parameters,
                                   *schema.signature_index[service.signature_id].results))
    forbidden.update(id(row.value) for row in bundle.interface.state)
    from .machine_overlay_result_views import checked_nullable_input_projection
    for operation, value in inputs:
        node = schema.type_index[value.type_id]
        element = schema.type_index[str(node.body['pointee_type_id'])]
        if (id(value) in forbidden or value.extent['kind'] != 'none' or
                value.access not in {'read', 'write', 'read_write'} or
                element.kind != 'integer' or element.body['width_bits'] != 8 or
                element.body['signed']):
            raise BoundaryModelError('nullable inputs require a direct byte origin-remainder contract')
        projection = object_(semantics[operation.identity].machine_projection.get('operation'),
                             'nullable input operation')
        rows = array(projection.get('parameters'), 'nullable input parameters')
        parameters = {row['id']: row for row in rows}
        if (len(parameters) != len(rows) or set(parameters) != {
                row.identity for row in schema.signature_index[operation.signature_id].parameters}):
            raise BoundaryModelError('nullable inputs require total parameter bindings')
        checked_nullable_input_projection(parameters[value.identity]['projection'])
    return {id(value) for _, value in inputs}


def logical_value_type_identity(value, *, bytes_view=False, callback_retained=False):
    metadata = {key: item for key, item in value.to_payload().items() if key != "id"}
    return "spx_value_" + canonical_sha256_v3({
        "value": metadata, "bytes_view": bytes_view,
        "callback_retained": value.interpretation == "callback" and callback_retained,
    })[:24]


def logical_value_type_uses(bundle, contract):
    schema = bundle.intent.schema
    occurrences = {}
    for signature in schema.signatures:
        for value in (*signature.parameters, *signature.results):
            occurrences.setdefault(value.type_id, []).append(value)
    for item in bundle.interface.state:
        occurrences.setdefault(item.value.type_id, []).append(item.value)
    byte_values = set()
    if contract is not None:
        operations = {item.identity: item for item in bundle.interface.operations}
        for semantics in contract.machine_semantics:
            signature = schema.signature_index[operations[semantics.operation_id].signature_id]
            parameters = {item.identity: item for item in signature.parameters}
            projection = object_(semantics.machine_projection.get("operation"), "logical projection")
            for raw in array(projection.get("parameters"), "logical parameters"):
                row = object_(raw, "logical parameter")
                machine = object_(row.get("projection"), "parameter projection")
                if machine.get("kind") == "bytes_view" and row.get("id") in parameters:
                    byte_values.add(id(parameters[row["id"]]))
    escaped_callbacks = {binding.path.value_id for lifecycle in bundle.lifecycles.values()
                         for binding in lifecycle.bindings if binding.transition == "escape_callback"}
    result, value_types, ambiguous = [], {}, set()
    reserved = set(schema.type_index)
    for node in schema.types:
        values = occurrences.get(node.identity, [])
        groups = {}
        for value in values:
            key = logical_value_type_identity(value, bytes_view=id(value) in byte_values,
                                              callback_retained=value.identity in escaped_callbacks)
            groups.setdefault(key, []).append(value)
        if node.kind not in {"pointer", "opaque"} or len(groups) <= 1:
            result.append((node, values, any(id(value) in byte_values for value in values)))
            continue
        ambiguous.add(node.identity)
        for key, group in sorted(groups.items()):
            identity = key
            if identity in reserved:
                raise BoundaryModelError("logical value type identity collides with a declared type")
            reserved.add(identity)
            result.append((replace(node, identity=identity), group, id(group[0]) in byte_values))
            value_types.update((id(value), identity) for value in group)
    # Nested physical references carry no value occurrence with which to select
    # a contract. Refuse ambiguity instead of inheriting a sibling's extent.
    for node in schema.types:
        if node.kind in {"record", "array", "pointer"} and set(node.references()) & ambiguous:
            raise BoundaryModelError(f"logical nested type {node.identity!r} has ambiguous value contracts")
        if node.kind == "pointer" and any(v.interpretation == "callback" for v in occurrences.get(node.identity, [])):
            function = schema.type_index[str(node.body["pointee_type_id"])]
            if set(function.references()) & ambiguous:
                raise BoundaryModelError(f"logical callback type {node.identity!r} has ambiguous value contracts")
    return result, value_types
