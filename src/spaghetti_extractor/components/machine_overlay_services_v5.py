"""Checked external-service bindings for direct V5 machine overlays."""

from __future__ import annotations

from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..external.contracts import CheckedExternalSiteContractError
from ..external.import_sites import bind_import_site
from ..external.resolved_contract import resolved_import_contract_behavior
from ..boundary._canonical import BoundaryModelError, array, object_
from ..external.resolved import (
    ExternalEnvironmentError,
    ResolvedExternalEnvironmentV1,
    resolved_interface_method_index_v1,
)
from ..transfer.model import _Call, _Transfer
from ..transfer.call_sites import external_tail_call
from .aggregate_result_binding import normalize_aggregate_result_words
from .component_c_v5 import _parameter_type, _result_type
from .interface_package_v5 import CompiledComponentInterfaceV5
from .machine_overlay_external_v5 import _checked_service_argument_transducers, _entry_target_capture_lines
from .machine_binding import external_target_sampling

def _raw_service_provider_kind(value: object) -> object:
    row = object_(value, "component service binding")
    return object_(row.get("provider"), "component service provider").get("kind")

def _resolved_external_contract_index(
    value: Mapping[str, object] | None,
) -> dict[tuple[str, str, int | None], Mapping[str, object]]:
    if value is None:
        return {}
    try:
        environment = ResolvedExternalEnvironmentV1.parse(value)
    except ExternalEnvironmentError as exc:
        raise BoundaryModelError(
            f"component resolved external environment is invalid: {exc}"
        ) from exc
    result: dict[tuple[str, str, int | None], Mapping[str, object]] = {}
    for index, raw in enumerate(environment.payload["machine_import_contracts"]):
        row = object_(raw, f"resolved machine-import contract {index}")
        identity = object_(row.get("identity"), "resolved import identity")
        dll = identity.get("dll")
        symbol = identity.get("symbol")
        ordinal = identity.get("ordinal")
        if (
            not isinstance(dll, str)
            or not dll
            or (symbol is None) == (ordinal is None)
            or (symbol is not None and (not isinstance(symbol, str) or not symbol))
            or (
                ordinal is not None
                and (not isinstance(ordinal, int) or isinstance(ordinal, bool))
            )
        ):
            raise BoundaryModelError("resolved machine-import identity is invalid")
        # An environment may honestly contain unrelated unresolved imports.
        # Index only complete rows; selection below remains fail closed when a
        # component names one of the omitted contracts.
        if not isinstance(row.get("contract"), Mapping) or not isinstance(
            row.get("boundary"), Mapping
        ):
            continue
        key = (dll.lower(), "" if symbol is None else symbol, ordinal)
        if key in result:
            raise BoundaryModelError("resolved machine-import identity is duplicated")
        result[key] = row
    return result

def _resolved_interface_method_index(
    value: Mapping[str, object] | None,
) -> dict[str, Mapping[str, object]]:
    if value is None:
        return {}
    try:
        environment = ResolvedExternalEnvironmentV1.parse(value)
    except ExternalEnvironmentError as exc:
        raise BoundaryModelError(
            f"component resolved external environment is invalid: {exc}"
        ) from exc
    try:
        return resolved_interface_method_index_v1(environment)
    except ExternalEnvironmentError as exc:
        raise BoundaryModelError(str(exc)) from exc

def _external_identity_key(
    identity: Mapping[str, object],
) -> tuple[str, str, int | None]:
    dll = identity.get("dll")
    symbol = identity.get("symbol")
    ordinal = identity.get("ordinal")
    if (
        not isinstance(dll, str)
        or not dll
        or (symbol is None) == (ordinal is None)
        or (symbol is not None and (not isinstance(symbol, str) or not symbol))
        or (
            ordinal is not None
            and (not isinstance(ordinal, int) or isinstance(ordinal, bool))
        )
    ):
        raise BoundaryModelError("component external service identity is invalid")
    return dll.lower(), "" if symbol is None else symbol, ordinal

def _checked_call_stack_arguments(
    call: _Call,
    argument_words: int,
    *,
    context: str,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Check the event's logical arguments against its IA-32 stack frame."""

    argument_offsets = tuple(index * 4 for index in range(argument_words))
    event_offsets = tuple(
        offset for offset, width, _node in call.stack_inputs if width == 4
    )
    if (
        len(event_offsets) != len(call.stack_inputs)
        or event_offsets != tuple(sorted(set(event_offsets)))
        or any(offset not in argument_offsets for offset in event_offsets)
    ):
        raise BoundaryModelError(f"{context} stack frame is incompatible")
    # `argument_nodes` is the logical call-argument projection, not a second
    # register-passing convention.  When present, require it to be total and
    # require every word staged by this transfer to agree with the projection.
    # A transfer may stage only a sparse subset because predecessor units can
    # have written other checked argument words already.
    if call.argument_nodes:
        if len(call.argument_nodes) != argument_words:
            raise BoundaryModelError(
                f"{context} logical argument projection is incompatible"
            )
        for offset, _width, node in call.stack_inputs:
            if call.argument_nodes[offset // 4] != node:
                raise BoundaryModelError(
                    f"{context} logical argument projection disagrees with its stack frame"
                )
    return argument_offsets, event_offsets

def _operation_service_bindings(
    *,
    bundle: CompiledComponentInterfaceV5,
    operation: object,
    machine_projection: Mapping[str, object],
    transfer_index: Mapping[str, _Transfer],
    external_contract_index: Mapping[tuple[str, str, int | None], Mapping[str, object]],
    interface_method_index: Mapping[str, Mapping[str, object]],
) -> tuple[Mapping[str, object], ...]:
    service_index = {item.identity: item for item in bundle.interface.services}
    allowed = tuple(getattr(operation, "allowed_service_ids"))
    raw_bindings = machine_projection.get("service_bindings")
    if not isinstance(raw_bindings, list):
        raise BoundaryModelError("component service binding inventory is malformed")
    by_id: dict[str, Mapping[str, object]] = {}
    for index, raw in enumerate(raw_bindings):
        row = object_(raw, f"component service binding {index}")
        service_id = str(row.get("service_id", ""))
        if service_id in by_id:
            raise BoundaryModelError("component service binding is duplicated")
        by_id[service_id] = row
    if (
        len(allowed) != len(set(allowed))
        or not set(allowed) <= set(service_index)
        or set(by_id) != set(allowed)
    ):
        raise BoundaryModelError("component operation service binding is not total")
    result: list[Mapping[str, object]] = []
    for service_id in sorted(allowed):
        binding = by_id[service_id]
        provider = object_(binding.get("provider"), "component service provider")
        provider_kind = provider.get("kind")
        if binding.get("mediation") not in {
            "direct",
            "callback",
        } or provider_kind not in {
            "component_operation",
            "external_call",
            "interface_method",
        }:
            raise BoundaryModelError(
                "callback component services require checked code-capability bindings"
            )
        signature = bundle.intent.schema.signature_index[
            service_index[service_id].signature_id
        ]
        abi_sha256 = _signature_abi_sha256(bundle, signature)
        if provider_kind == "component_operation":
            provider_component = str(provider.get("component_id", ""))
            provider_operation = str(provider.get("operation_id", ""))
            if not provider_component or not provider_operation:
                raise BoundaryModelError(
                    "component service provider identity is incomplete"
                )
            event_references = [
                {
                    "unit_id": object_(
                        raw, "component-operation service event"
                    ).get("unit_id"),
                    "event_index": object_(
                        raw, "component-operation service event"
                    ).get("event_index"),
                }
                for raw in array(
                    provider.get("events"),
                    "component-operation service events",
                )
            ]
            event_calls = _checked_service_event_calls(
                event_references,
                transfer_index=transfer_index,
                expected_call_kind="internal_call",
            )
            result.append(
                {
                    "service_id": service_id,
                    "provider_kind": "component_operation",
                    "provider_component_id": provider_component,
                    "provider_operation_id": provider_operation,
                    "symbol": _logical_operation_symbol(
                        provider_component, provider_operation
                    ),
                    "abi_sha256": abi_sha256,
                    "events": [
                        {
                            "unit_id": unit_id,
                            "source_rva": transfer.rva_start,
                            "event_index": event_index,
                            "instruction_rva": call.instruction_rva,
                            "return_rva": call.return_rva,
                            "event_stack_offsets": [
                                offset
                                for offset, width, _node in call.stack_inputs
                                if width == 4
                            ],
                        }
                        for unit_id, event_index, transfer, call in event_calls
                    ],
                }
            )
            continue
        expected_call_kind = (
            "indirect_call"
            if provider_kind == "interface_method"
            or provider.get("target_projection") is not None
            else "external_call"
        )
        event_calls = _checked_service_event_calls(
            provider.get("events"),
            transfer_index=transfer_index,
            expected_call_kind=expected_call_kind,
        )
        if provider_kind == "interface_method":
            method_sha256 = str(provider.get("method_contract_sha256", ""))
            target = interface_method_index.get(method_sha256)
            if target is None:
                raise BoundaryModelError(
                    "component interface-method resolved contract is absent"
                )
            method = object_(target.get("method"), "resolved interface method")
            protocol = object_(
                method.get("external_protocol"),
                "resolved interface-method protocol",
            )
            receiver = object_(
                method.get("receiver_resource"),
                "resolved interface-method receiver",
            )
            slot = _uint(protocol.get("slot"), "interface-method slot")
            argument_words = _uint(
                method.get("argument_words"), "interface-method argument words"
            )
            receiver_argument = _uint(
                receiver.get("argument_index"),
                "interface-method receiver argument",
            )
            rendered_transducers, out_interfaces, argument_interfaces = (
                _checked_service_argument_transducers(
                    signature=signature,
                    types=bundle.intent.schema.type_index,
                    argument_words=argument_words,
                    value=provider.get("argument_transducers"),
                    relation_values=method.get("out_interfaces", []),
                    local_cell_values=method.get("local_cells", []),
                    argument_interface_values=method.get("argument_interfaces", []),
                    caller_memory_frame=method.get("caller_memory_frame"),
                    profile_sha256=target.get("profile_sha256"),
                    context="component interface-method",
                )
            )
            receiver_parameter = receiver_argument
            if rendered_transducers is not None:
                receiver_transducer = rendered_transducers[receiver_argument]
                receiver_parameter = _uint(
                    receiver_transducer.get("parameter_index"),
                    "interface-method logical receiver parameter",
                )
            if (
                protocol.get("kind") != "pe32-interface-method"
                or protocol.get("interface_id") != target.get("interface_id")
                or protocol.get("profile_sha256") != target.get("profile_sha256")
                or protocol.get("offset") != slot * 4
                or receiver.get("dispatch_slot") != slot
                or receiver.get("required_state") != "live"
                or method.get("callback_effect") != "none"
                or receiver_argument >= argument_words
                or receiver_parameter >= len(signature.parameters)
                or signature.parameters[receiver_parameter].interpretation != "resource"
                or (
                    rendered_transducers is not None
                    and rendered_transducers[receiver_argument].get("kind")
                    != "logical_argument"
                )
            ):
                raise BoundaryModelError(
                    "component interface-method service contract is incompatible"
                )
            rendered_events: list[dict[str, object]] = []
            argument_offsets: tuple[int, ...] | None = None
            for unit_id, event_index, transfer, call in event_calls:
                local_slot = _indirect_vtable_slot_offset(
                    transfer,
                    call,
                    receiver_node=(
                        call.argument_nodes[receiver_argument]
                        if receiver_argument < len(call.argument_nodes)
                        else None
                    ),
                )
                if local_slot is not None and local_slot != slot * 4:
                    raise BoundaryModelError(
                        "component interface-method call target uses another vtable slot"
                    )
                checked_offsets, event_offsets = _checked_call_stack_arguments(
                    call,
                    argument_words,
                    context="component interface-method",
                )
                if argument_offsets is not None and checked_offsets != argument_offsets:
                    raise BoundaryModelError(
                        "component interface-method events disagree on their ABI"
                    )
                argument_offsets = checked_offsets
                rendered_events.append(
                    {
                        "unit_id": unit_id,
                        "source_rva": transfer.rva_start,
                        "event_index": event_index,
                        "instruction_rva": call.instruction_rva,
                        "return_rva": call.return_rva,
                        "event_stack_offsets": list(event_offsets),
                    }
                )
            assert argument_offsets is not None
            result.append(
                {
                    "service_id": service_id,
                    "provider_kind": "interface_method",
                    "symbol": f"spx_component_interface_{_c_identifier(bundle.interface.identity)}_{_c_identifier(service_id)}",
                    "abi_sha256": abi_sha256,
                    "events": rendered_events,
                    "argument_offsets": list(argument_offsets),
                    "profile_sha256": target["profile_sha256"],
                    "interface_id": target["interface_id"],
                    "method": protocol.get("method"),
                    "method_contract_sha256": method_sha256,
                    "slot": slot,
                    "receiver_argument": receiver_argument,
                    "lifecycle_effect": receiver.get("lifecycle_effect"),
                    "argument_transducers": rendered_transducers,
                    "out_interfaces": out_interfaces,
                    "argument_interfaces": argument_interfaces,
                    "local_cells": method.get("local_cells", []),
                    "result_projection": provider.get("result_projection"),
                    "_signature": signature,
                }
            )
            continue
        identity = object_(
            provider.get("identity"), "component external service identity"
        )
        captured_target = provider.get("target_projection")
        if captured_target is None:
            for _unit_id, _event_index, _transfer, call in event_calls:
                if (
                    not isinstance(call.dll, str)
                    or not isinstance(identity.get("dll"), str)
                    or identity.get("dll").lower() != call.dll.lower()
                    or identity.get("symbol") != call.symbol
                    or identity.get("ordinal") != call.ordinal
                ):
                    raise BoundaryModelError(
                        "component external service import identity is stale"
                    )
        first_call = event_calls[0][3]
        contract_row = external_contract_index.get(_external_identity_key(identity))
        if contract_row is None:
            raise BoundaryModelError(
                "component external service resolved contract is absent"
            )
        contract = object_(contract_row.get("contract"), "resolved import contract")
        payload = object_(contract.get("payload"), "resolved import contract payload")
        try:
            external_behavior = resolved_import_contract_behavior(contract_row)
        except CheckedExternalSiteContractError as exc:
            raise BoundaryModelError(str(exc)) from exc
        argument_words = payload.get("argument_words")
        if argument_words is None:
            arity = object_(payload.get("arity"), "resolved import arity")
            if arity.get("kind") != "fixed":
                raise BoundaryModelError(
                    "component external service requires a fixed arity"
                )
            argument_words = arity.get("words")
        (
            normalized_transducers,
            normalized_local_cells,
            normalized_caller_memory_frame,
            normalized_result_projection,
        ) = _normalize_aggregate_result_binding(
            signature=signature,
            types=bundle.intent.schema.type_index,
            provider=provider,
            payload=payload,
            contract_row=contract_row,
            argument_words=argument_words,
            context="component external service",
        )
        rendered_transducers, out_interfaces, argument_interfaces = (
            _checked_service_argument_transducers(
                signature=signature,
                types=bundle.intent.schema.type_index,
                argument_words=argument_words,
                value=normalized_transducers,
                relation_values=payload.get("out_interface_relations", []),
                local_cell_values=normalized_local_cells,
                argument_interface_values=[],
                caller_memory_frame=normalized_caller_memory_frame,
                profile_sha256=contract.get("profile_sha256"),
                context="component external service",
            )
        )
        rendered_events = []
        argument_offsets = None
        for unit_id, event_index, transfer, call in event_calls:
            checked_offsets, event_offsets = _checked_call_stack_arguments(
                call,
                argument_words,
                context="component external service",
            )
            if argument_offsets is not None and checked_offsets != argument_offsets:
                raise BoundaryModelError(
                    "component external service events disagree on their ABI"
                )
            argument_offsets = checked_offsets
            rendered_events.append(
                {
                    "unit_id": unit_id,
                    "source_rva": transfer.rva_start,
                    "event_index": event_index,
                    "instruction_rva": call.instruction_rva,
                    "return_rva": call.return_rva,
                    "event_stack_offsets": list(event_offsets),
                    **({'checked_external_contract': bind_import_site(external_behavior,
                        argument_nodes=call.argument_nodes, tail_jump=call is external_tail_call(transfer)).payload()}
                       if external_behavior.world_effect in {'dynamicRanges', 'dynamicRangeRelease'} else {}),
                }
            )
        assert argument_offsets is not None
        result.append(
            {
                "service_id": service_id,
                "provider_kind": "external_call",
                "external_effect_contract": (external_behavior.profile_effect_payload()
                    if external_behavior.world_effect in {'dynamicRanges', 'dynamicRangeRelease'} else dict(payload)),
                "external_contract_identity_sha256": external_behavior.identity_sha256(),
                "symbol": f"spx_component_external_{_c_identifier(bundle.interface.identity)}_{_c_identifier(service_id)}",
                "abi_sha256": abi_sha256,
                "events": rendered_events,
                "dll": identity["dll"],
                "import_symbol": identity.get("symbol"),
                "ordinal": identity.get("ordinal"),
                "captured_target_projection": captured_target,
                **({"target_sampling": provider["target_sampling"]} if "target_sampling" in provider else {}),
                # The checked fixed-arity ABI determines the complete physical
                # frame. Transfer stack_inputs is intentionally only the sparse
                # subset staged by this transfer; predecessor-staged arguments
                # are still written by this thunk before native invocation.
                "argument_offsets": list(argument_offsets),
                "argument_transducers": rendered_transducers,
                "out_interfaces": out_interfaces,
                "argument_interfaces": argument_interfaces,
                "local_cells": normalized_local_cells,
                "abi_template": payload.get("abi_template"),
                "result_projection": normalized_result_projection,
                "_signature": signature,
            }
        )
    return tuple(result)


def _normalize_aggregate_result_binding(
    *,
    signature: object,
    types: Mapping[str, object],
    provider: Mapping[str, object],
    payload: Mapping[str, object],
    contract_row: Mapping[str, object],
    argument_words: object,
    context: str,
) -> tuple[object, list[object], object, object]:
    """Derive hidden-sret mechanics from the compiler-lowered ABI receipt."""

    value = provider.get("argument_transducers")
    if not isinstance(value, list) or not any(
        isinstance(item, Mapping) and item.get("kind") == "aggregate_result"
        for item in value
    ):
        return (
            value,
            list(array(payload.get("local_cells", []), f"{context} local cells")),
            payload.get("caller_memory_frame"),
            provider.get("result_projection"),
        )
    if len(value) != _uint(argument_words, f"{context} argument words"):
        raise BoundaryModelError(f"{context} aggregate-result arity is incompatible")
    aggregate_rows = [
        (index, object_(item, f"{context} aggregate-result transducer"))
        for index, item in enumerate(value)
        if isinstance(item, Mapping) and item.get("kind") == "aggregate_result"
    ]
    if len(aggregate_rows) != 1 or provider.get("result_projection") is not None:
        raise BoundaryModelError(
            f"{context} aggregate result must have one derived projection"
        )
    if len(signature.results) != 1:
        raise BoundaryModelError(f"{context} aggregate result is not singular")
    result = signature.results[0]
    logical_type = types.get(result.type_id)
    fields = () if logical_type is None else tuple(logical_type.body.get("fields", ()))
    if (
        result.interpretation != "value"
        or logical_type is None
        or logical_type.kind != "record"
        or not fields
        or any(not _logical_word_field(types, field) for field in fields)
    ):
        raise BoundaryModelError(
            f"{context} aggregate result must be a word-record value"
        )
    return normalize_aggregate_result_words(
        field_ids=[str(field["id"]) for field in fields], provider=provider,
        payload=payload, contract_row=contract_row,
        argument_words=argument_words, context=context)


def _logical_word_field(
    types: Mapping[str, object], field: Mapping[str, object]
) -> bool:
    value = types.get(str(field.get("type_id")))
    if value is None or field.get("bit_width") is not None:
        return False
    if value.kind == "integer":
        return value.body.get("width_bits") == 32
    if value.kind == "enum":
        underlying = types.get(str(value.body.get("underlying_type_id")))
        return (
            underlying is not None
            and underlying.kind == "integer"
            and underlying.body.get("width_bits") == 32
        )
    return value.kind == "pointer"

def _checked_service_event_calls(
    value: object,
    *,
    transfer_index: Mapping[str, _Transfer],
    expected_call_kind: str,
) -> tuple[tuple[str, int, _Transfer, object], ...]:
    raw_events = array(value, "component checked service events")
    if not raw_events:
        raise BoundaryModelError("component checked service has no machine events")
    result: list[tuple[str, int, _Transfer, object]] = []
    references: list[tuple[str, int]] = []
    for index, raw in enumerate(raw_events):
        event = object_(raw, f"component checked service event {index}")
        if set(event) != {"unit_id", "event_index"}:
            raise BoundaryModelError("component checked service event fields differ")
        unit_id = str(event.get("unit_id", ""))
        event_index = _uint(event.get("event_index"), "component external event index")
        transfer = transfer_index.get(unit_id)
        matching_calls = (
            []
            if transfer is None
            else [call for call in transfer.calls if call.call_index == event_index]
        )
        if (
            not unit_id
            or len(matching_calls) != 1
            or matching_calls[0].kind != expected_call_kind
        ):
            raise BoundaryModelError("component checked service call event is stale")
        references.append((unit_id, event_index))
        result.append((unit_id, event_index, transfer, matching_calls[0]))
    if references != sorted(set(references)):
        raise BoundaryModelError(
            "component checked service events are duplicated or noncanonical"
        )
    return tuple(result)

def _indirect_vtable_slot_offset(
    transfer: _Transfer,
    call: _Call,
    *,
    receiver_node: int | None = None,
) -> int | None:
    target_node = getattr(call, "target_node", None)
    if target_node is None or target_node < 0 or target_node >= len(transfer.nodes):
        return None
    target = transfer.nodes[target_node]
    if target.op != "load" or len(target.args) != 1:
        return None
    address_index = target.args[0]
    if address_index < 0 or address_index >= len(transfer.nodes):
        return None
    address = transfer.nodes[address_index]
    if address.op != "add32" or len(address.args) != 2:
        return None
    children = [
        transfer.nodes[index]
        for index in address.args
        if 0 <= index < len(transfer.nodes)
    ]
    if len(children) != 2:
        return None
    constants = [node for node in children if node.op == "const"]
    bases = [node for node in children if node.op != "const"]
    if len(constants) != 1 or len(bases) != 1:
        return None
    base = bases[0]
    if base.op == "reg":
        # Retain the direct checked shape used by small synthetic transfers.
        pass
    elif (
        base.op != "load"
        or len(base.args) != 1
        or receiver_node is None
        or base.args[0] != receiver_node
    ):
        return None
    offset = constants[0].immediate
    return offset if offset >= 0 and offset % 4 == 0 else None

def _service_setup_lines(
    *,
    bundle: CompiledComponentInterfaceV5,
    component: str,
    service_bindings: Sequence[Mapping[str, object]],
    context_expression: str,
    runtime_expression: str,
    state_expression: str,
    memory_fault_expression: str,
    fault_expression: str,
) -> list[str]:
    # The context also identifies the runtime for connected logical operations,
    # including service-free operations used through paired proof wrappers.
    by_id = {str(item["service_id"]): item for item in service_bindings}
    values = [
        (str(by_id[item.identity]["symbol"]) if item.identity in by_id else "0")
        for item in bundle.interface.services
    ]
    captures = []
    for index, service in enumerate(bundle.interface.services):
        binding = by_id.get(service.identity, {})
        target = binding.get("captured_target_projection")
        if external_target_sampling(binding.get("target_sampling", "service_call"), has_target=target is not None) == "operation_entry":
            captures.extend(_entry_target_capture_lines(target, index=index))
    return [
        "  spx_component_service_context_v1 service_context = {",
        f"    {runtime_expression}, {state_expression}, {memory_fault_expression},",
        f"    {fault_expression}, {{0, 0}}",
        "  };",
        *captures,
        f"  spx_{component}_services_v5 logical_services = {{",
        f"    &service_context, {', '.join(values) if values else '0'}",
        "  };",
        f"  ({context_expression})->services = &logical_services;",
    ]

def _signature_abi_sha256(
    bundle: CompiledComponentInterfaceV5, signature: object
) -> str:
    types = bundle.intent.schema.type_index
    return canonical_sha256_v3(
        {
            "result": _result_type(types, signature),
            "parameters": [
                _parameter_type(types, item) for item in signature.parameters
            ],
        }
    )

def _logical_operation_symbol(component_id: str, operation_id: str) -> str:
    return f"spx_component_logical_{_c_identifier(component_id)}_{_c_identifier(operation_id)}"

def _uint(value: object, context: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= 0xFFFFFFFF
    ):
        raise BoundaryModelError(f"{context} must fit u32")
    return value

def _c_identifier(value: str) -> str:
    result = value.replace("-", "_").replace(".", "_")
    if (
        not result
        or not (result[0].isalpha() or result[0] == "_")
        or any(not (character.isalnum() or character == "_") for character in result)
    ):
        raise BoundaryModelError("component overlay identity is not a C identifier")
    return result
