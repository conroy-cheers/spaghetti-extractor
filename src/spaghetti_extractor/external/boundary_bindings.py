"""One checked rule for binding typed service frames to machine contracts."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary import BoundarySchemaV1, TargetDataLayoutV1
from ..calls.frame import PhysicalCallFrameV3


def _slot_refines_authority(
    selected: Mapping[str, Any], authority: Mapping[str, Any]
) -> bool:
    if (
        selected.get("pass_mode") != authority.get("pass_mode")
        or selected.get("role") != authority.get("role")
    ):
        return False
    selected_fragments = selected.get("fragments")
    authority_fragments = authority.get("fragments")
    if (
        not isinstance(selected_fragments, list)
        or not isinstance(authority_fragments, list)
        or len(selected_fragments) != len(authority_fragments)
    ):
        return False
    for selected_fragment, authority_fragment in zip(
        selected_fragments, authority_fragments, strict=True
    ):
        if not isinstance(selected_fragment, Mapping) or not isinstance(
            authority_fragment, Mapping
        ):
            return False
        if (
            selected_fragment.get("location")
            != authority_fragment.get("location")
            or selected_fragment.get("location_offset_bits")
            != authority_fragment.get("location_offset_bits")
            or selected_fragment.get("logical_offset_bits")
            != authority_fragment.get("logical_offset_bits")
            or selected_fragment.get("representation")
            != authority_fragment.get("representation")
            or selected_fragment.get("specified")
            != authority_fragment.get("specified")
        ):
            return False
        selected_width = selected_fragment.get("width_bits")
        authority_width = authority_fragment.get("width_bits")
        if (
            isinstance(selected_width, bool)
            or not isinstance(selected_width, int)
            or isinstance(authority_width, bool)
            or not isinstance(authority_width, int)
            or not 0 < selected_width <= authority_width
        ):
            return False
    return True


def _transport_refines_machine_import(
    selected: Mapping[str, Any], authority: Mapping[str, Any]
) -> bool:
    for field in (
        "target", "abi_dialect", "calling_convention", "transfer_kind",
        "stack", "preserved_state", "clobbered_state", "outcomes",
    ):
        if selected.get(field) != authority.get(field):
            return False
    for field in ("arguments", "results"):
        selected_slots = selected.get(field)
        authority_slots = authority.get(field)
        if (
            not isinstance(selected_slots, list)
            or not isinstance(authority_slots, list)
            or len(selected_slots) != len(authority_slots)
            or not all(
                isinstance(selected_slot, Mapping)
                and isinstance(authority_slot, Mapping)
                and _slot_refines_authority(selected_slot, authority_slot)
                for selected_slot, authority_slot in zip(
                    selected_slots, authority_slots, strict=True
                )
            )
        ):
            return False
    return True


def _transport_matches_callback_protocol(
    transport: Mapping[str, Any], protocol: Mapping[str, Any]
) -> bool:
    signature = protocol.get("signature")
    subject = transport.get("subject")
    if (
        not isinstance(signature, Mapping)
        or not isinstance(subject, Mapping)
        or subject.get("kind") != "callback"
        or subject.get("id") != protocol.get("id")
        or transport.get("transfer_kind") != "callback"
    ):
        return False
    convention = {
        "pe32-cdecl-v1": "cdecl",
        "pe32-stdcall-v1": "stdcall",
    }.get(signature.get("abi_template"))
    argument_words = signature.get("argument_words")
    cleanup_bytes = signature.get("stack_cleanup_bytes")
    arguments = transport.get("arguments")
    stack = transport.get("stack")
    if (
        convention is None
        or transport.get("calling_convention") != convention
        or isinstance(argument_words, bool)
        or not isinstance(argument_words, int)
        or not isinstance(arguments, list)
        or len(arguments) != argument_words
        or not isinstance(stack, Mapping)
        or stack.get("cleanup_bytes") != cleanup_bytes
    ):
        return False
    for index, argument in enumerate(arguments):
        if not isinstance(argument, Mapping):
            return False
        fragments = argument.get("fragments")
        if not isinstance(fragments, list) or len(fragments) != 1:
            return False
        fragment = fragments[0]
        location = fragment.get("location") if isinstance(
            fragment, Mapping
        ) else None
        if (
            not isinstance(location, Mapping)
            or location.get("kind") != "stack"
            or location.get("phase") != "callee_entry"
            or location.get("stack_offset_bytes") != 4 + 4 * index
            or location.get("width_bits") != 32
            or fragment.get("width_bits") != 32
        ):
            return False
    results = transport.get("results")
    result = signature.get("result")
    if not isinstance(results, list) or not isinstance(result, Mapping):
        return False
    if result.get("kind") == "void":
        return results == []
    if result.get("kind") != "word" or len(results) != 1:
        return False
    fragments = results[0].get("fragments") if isinstance(
        results[0], Mapping
    ) else None
    if not isinstance(fragments, list) or len(fragments) != 1:
        return False
    fragment = fragments[0]
    location = fragment.get("location") if isinstance(fragment, Mapping) else None
    width = fragment.get("width_bits") if isinstance(fragment, Mapping) else None
    return (
        isinstance(location, Mapping)
        and location.get("kind") == "register"
        and location.get("phase") == "callee_exit"
        and location.get("name") == result.get("register")
        and location.get("width_bits") == 32
        and isinstance(width, int)
        and not isinstance(width, bool)
        and 0 < width <= 32
    )


def schema_frame_machine_bindings_v1(
    frame: PhysicalCallFrameV3,
    *,
    machine_imports: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Derive all selected-environment authorities for one typed frame."""

    transport = frame.transport.to_payload()
    frame_subject = transport["subject"]
    kind = frame_subject["kind"]
    identity = frame_subject["id"]
    bindings: list[dict[str, Any]] = []
    for row in machine_imports:
        contract = row.get("contract")
        machine_boundary = row.get("boundary")
        import_identity = row.get("identity")
        if (
            not isinstance(contract, Mapping)
            or not isinstance(machine_boundary, Mapping)
            or not isinstance(import_identity, Mapping)
        ):
            continue
        contract_payload = contract.get("payload")
        if not isinstance(contract_payload, Mapping):
            continue
        if kind == "import":
            symbol = import_identity.get("symbol")
            ordinal = import_identity.get("ordinal")
            external_id = (
                str(symbol) if isinstance(symbol, str)
                else f"ordinal-{ordinal}"
            )
            canonical_subject = f"{import_identity.get('dll')}.{external_id}"
            authority_frame = machine_boundary.get("physical_call_frame_v3")
            authority_transport = (
                authority_frame.get("transport")
                if isinstance(authority_frame, Mapping) else None
            )
            if (
                identity == canonical_subject
                and isinstance(authority_transport, Mapping)
                and _transport_refines_machine_import(
                    transport, authority_transport
                )
            ):
                bindings.append({
                    "kind": "machine_import_contract",
                    "identity": dict(import_identity),
                    "profile_id": contract.get("profile_id"),
                    "profile_sha256": contract.get("profile_sha256"),
                    "entry_key": contract.get("entry_key"),
                    "entry_index": contract.get("entry_index"),
                    "authority_frame_id": authority_frame.get("id"),
                })
        elif kind == "callback":
            callback = contract_payload.get("callback_protocol")
            if (
                isinstance(callback, Mapping)
                and identity == callback.get("id")
                and _transport_matches_callback_protocol(transport, callback)
            ):
                bindings.append({
                    "kind": "callback_protocol",
                    "protocol_id": callback.get("id"),
                    "protocol_sha256": canonical_sha256_v3(callback),
                    "registering_import": dict(import_identity),
                    "profile_id": contract.get("profile_id"),
                    "profile_sha256": contract.get("profile_sha256"),
                    "entry_key": contract.get("entry_key"),
                    "entry_index": contract.get("entry_index"),
                })
    return sorted(bindings, key=canonical_sha256_v3)


def _bound_parameter(
    schema: BoundarySchemaV1,
    frame: PhysicalCallFrameV3,
    argument_index: int,
):
    if not 0 <= argument_index < len(frame.transport.arguments):
        raise ValueError("callback source argument is outside its typed frame")
    slot_id = frame.transport.arguments[argument_index].identity
    binding = next(
        (item for item in frame.bindings if item.slot_id == slot_id), None
    )
    if (
        binding is None
        or binding.path.root != "parameter"
        or binding.path.fields
    ):
        raise ValueError(
            "callback source argument has no direct typed parameter binding"
        )
    signature = schema.signature_index[frame.signature_id]
    value = next(
        (
            item for item in signature.parameters
            if item.identity == binding.path.value_id
        ),
        None,
    )
    if value is None:
        raise ValueError("callback source parameter binding is stale")
    return value


def _callback_source_function_type(
    *,
    schema: BoundarySchemaV1,
    layout: TargetDataLayoutV1,
    registering_frame: PhysicalCallFrameV3,
    source: Mapping[str, Any],
) -> str:
    argument = source.get("argument")
    if isinstance(argument, bool) or not isinstance(argument, int):
        raise ValueError("callback source argument is malformed")
    value = _bound_parameter(schema, registering_frame, argument)
    value_type = schema.type_index[value.type_id]
    if value_type.kind != "pointer":
        raise ValueError("callback source parameter is not a pointer")
    pointee_id = str(value_type.body["pointee_type_id"])
    source_kind = source.get("kind")
    if source_kind == "argument_word":
        if value.interpretation != "callback":
            raise ValueError(
                "argument-word callback source lacks callback typing"
            )
        pointee = schema.type_index[pointee_id]
        if pointee.kind != "function":
            raise ValueError("callback source does not point to a function")
        return pointee.identity
    if source_kind != "argument_pointee":
        raise ValueError("callback source kind is unsupported")
    offset = source.get("offset")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("callback pointee offset is malformed")
    pointee = schema.type_index[pointee_id]
    if pointee.kind not in {"record", "union"}:
        raise ValueError("callback source pointee is not a structured object")
    pointee_layout = layout.index.get(pointee.identity)
    if pointee_layout is None:
        raise ValueError("callback source pointee has no target layout")
    extent = value.extent
    if (
        value.interpretation not in {"reference", "view"}
        or value.access not in {"read", "read_write"}
        or extent.get("kind") != "fixed"
        or not isinstance(extent.get("bytes"), int)
        or extent.get("bytes") * 8 < pointee_layout.size_bits
    ):
        raise ValueError(
            "callback source pointee lacks a complete readable typed view"
        )
    layout_field = next(
        (
            item for item in pointee_layout.fields
            if item.offset_bits == offset * 8
        ),
        None,
    )
    if layout_field is None:
        raise ValueError("callback source offset names no typed field")
    type_field = next(
        (
            item for item in pointee.body["fields"]
            if isinstance(item, Mapping)
            and item.get("id") == layout_field.identity
        ),
        None,
    )
    if type_field is None:
        raise ValueError("callback source layout field is stale")
    field_type = schema.type_index[str(type_field["type_id"])]
    if field_type.kind != "pointer":
        raise ValueError("callback source field is not a pointer")
    function = schema.type_index[str(field_type.body["pointee_type_id"])]
    if function.kind != "function":
        raise ValueError("callback source field does not point to a function")
    return function.identity


def schema_callback_links_v1(
    *,
    schema: BoundarySchemaV1,
    layout: TargetDataLayoutV1,
    frames: Mapping[str, PhysicalCallFrameV3],
    frame_bindings: Mapping[str, Sequence[Mapping[str, Any]]],
    machine_imports: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Bind registration sources to callbacks and report exact deficiencies.

    An authored schema can be structurally valid before every relationship has
    machine authority.  That is an ordinary incomplete state, not a codec
    failure.  Keep it serializable as a deterministic issue so the resolved
    environment can remain fail-closed and useful to the workbench.
    """

    links: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    for callback_name, callback_frame in sorted(frames.items()):
        callback_bindings = [
            item for item in frame_bindings.get(callback_name, ())
            if item.get("kind") == "callback_protocol"
        ]
        if not callback_bindings:
            continue
        if len(callback_bindings) != 1:
            issues.append({
                "category": "boundary_callback_relationship_ambiguous",
                "callback_frame_name": callback_name,
                "detail": "typed callback frame has ambiguous authority",
            })
            continue
        callback_binding = callback_bindings[0]
        registering_identity = callback_binding.get("registering_import")
        registering_names = [
            name for name, bindings in frame_bindings.items()
            if any(
                item.get("kind") == "machine_import_contract"
                and item.get("identity") == registering_identity
                for item in bindings
            )
        ]
        if len(registering_names) != 1:
            issues.append({
                "category": (
                    "boundary_callback_relationship_unresolved"
                    if not registering_names
                    else "boundary_callback_relationship_ambiguous"
                ),
                "callback_frame_name": callback_name,
                "protocol_id": callback_binding.get("protocol_id"),
                "registering_import": registering_identity,
                "detail": (
                    "typed callback frame has no registering import frame"
                    if not registering_names
                    else "typed callback frame has multiple registering "
                    "import frames"
                ),
            })
            continue
        registering_name = registering_names[0]
        try:
            protocol = None
            for row in machine_imports:
                contract = row.get("contract")
                payload = contract.get("payload") if isinstance(
                    contract, Mapping
                ) else None
                candidate = payload.get("callback_protocol") if isinstance(
                    payload, Mapping
                ) else None
                if (
                    row.get("identity") == registering_identity
                    and isinstance(candidate, Mapping)
                    and candidate.get("id")
                    == callback_binding.get("protocol_id")
                ):
                    protocol = candidate
                    break
            if protocol is None:
                raise ValueError(
                    "typed callback registration contract is stale"
                )
            protocol_parts = {
                field: protocol.get(field)
                for field in ("source", "instance", "lifetime", "delivery")
            }
            if not all(
                isinstance(value, Mapping)
                for value in protocol_parts.values()
            ):
                raise ValueError(
                    "typed callback registration relationship is malformed"
                )
            function_type_id = _callback_source_function_type(
                schema=schema,
                layout=layout,
                registering_frame=frames[registering_name],
                source=protocol_parts["source"],
            )
            callback_signature = schema.signature_index[
                callback_frame.signature_id
            ]
            if callback_signature.function_type_id != function_type_id:
                raise ValueError(
                    "callback source field and callback frame types disagree"
                )
            instance = protocol_parts["instance"]
            if isinstance(instance, Mapping) and instance.get("kind") == (
                "provider_resource"
            ):
                callback_argument = instance.get("callback_argument")
                if (
                    isinstance(callback_argument, bool)
                    or not isinstance(callback_argument, int)
                    or not 0 <= callback_argument < len(
                        callback_signature.parameters
                    )
                    or callback_signature.parameters[
                        callback_argument
                    ].interpretation != "resource"
                ):
                    raise ValueError(
                        "provider-resource callback instance lacks typed "
                        "resource"
                    )
            links.append({
                "protocol_id": protocol["id"],
                "protocol_sha256": canonical_sha256_v3(protocol),
                "registering_frame_name": registering_name,
                "callback_frame_name": callback_name,
                "source": dict(protocol_parts["source"]),
                "instance": dict(protocol_parts["instance"]),
                "lifetime": dict(protocol_parts["lifetime"]),
                "delivery": dict(protocol_parts["delivery"]),
            })
        except ValueError as exc:
            issues.append({
                "category": "boundary_callback_relationship_malformed",
                "callback_frame_name": callback_name,
                "protocol_id": callback_binding.get("protocol_id"),
                "registering_import": registering_identity,
                "registering_frame_name": registering_name,
                "detail": str(exc),
            })
    return (
        sorted(links, key=canonical_sha256_v3),
        sorted(issues, key=canonical_sha256_v3),
    )


__all__ = [
    "schema_callback_links_v1",
    "schema_frame_machine_bindings_v1",
]
