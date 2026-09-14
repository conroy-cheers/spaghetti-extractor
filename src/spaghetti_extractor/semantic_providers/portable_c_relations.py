"""Preflight authored relations against reviewed interaction contracts.

Normal-return facts are only recognized here; the provider postcondition checker
must derive them from the final paired proof before the relations facet passes.
"""
from pathlib import Path
from typing import Mapping
from ..components.interaction_contract import (
    InteractionContractCatalogV1, InteractionContractReceiptV1, contract_type_matches,
)
from ..components.relation_v5 import ComponentRelationIntentV1
from ..components.semantic_path_operations import _nonnull_minimum_remaining, _nullable_same_origin_input
from .portable_c_common import fail as _fail, load_json as _load_json
from .portable_c_postconditions import normal_exit_intent


def _interaction_expression(
    value: Mapping[str, object],
    *,
    interaction_id: str,
) -> dict[str, object]:
    """Specialize one reviewed portable interaction expression."""

    op = value.get("op")
    if not isinstance(op, str) or not op:
        _fail("reviewed interaction expression operation is malformed")
    if op == "port":
        direction = value.get("direction")
        identity = value.get("id")
        if (
            direction not in {"input", "output"}
            or not isinstance(identity, str)
            or not identity
        ):
            _fail("reviewed interaction port expression is malformed")
        return {
            "op": "logical",
            "args": [],
            "attributes": {
                "path": {
                    "root": "interaction",
                    "id": interaction_id,
                    "fields": [direction, identity],
                }
            },
        }
    if op == "const":
        return {
            "op": "const",
            "args": [],
            "attributes": {
                "value": value.get("value"),
                "width": value.get("width"),
            },
        }
    if op in {"true", "false"}:
        return {"op": op, "args": [], "attributes": {}}
    arguments = value.get("args")
    if not isinstance(arguments, list) or any(
        not isinstance(argument, Mapping) for argument in arguments
    ):
        _fail("reviewed interaction expression arguments are malformed")
    return {
        "op": op,
        "args": [
            _interaction_expression(argument, interaction_id=interaction_id)
            for argument in arguments
        ],
        "attributes": {},
    }


def _checked_relation_boundary_operations(
    *,
    component_id: str,
    bundle: object,
    portable: object,
    semantic_contract: Mapping[str, object],
    relation_intent: Path | None,
    interaction_contract_catalog: Path | None,
) -> tuple[dict[str, Mapping[str, object]], list[Mapping[str, object]]]:
    """Bind operator relation intent to unique reviewed provider contracts.

    The intent requests a relation but grants no authority.  Authority comes
    from a unique catalog contract matching the exact machine import and the
    logical service types, followed by contextual CBMC refinement.
    """

    if relation_intent is None:
        return {}, []
    intent = ComponentRelationIntentV1.parse(
        _load_json(
            Path(relation_intent),
            "component relation intent",
        )
    )
    if (
        intent.component_id != component_id
        or intent.status != "ready_for_check"
        or intent.blockers
    ):
        _fail("component relation intent is not ready for a checked proof")
    if any(requirement["relation"] == "normal_exit_postcondition"
           for operation in intent.operations for requirement in operation["requirements"]):
        try:
            normal_exit_intent(intent.to_payload(), bundle=bundle)
        except ValueError as error:
            _fail(str(error))
        # This is only preflight. The relations facet remains incomplete until
        # the requested facts are derived from the final checked paired proof.
        return {}, []
    if interaction_contract_catalog is None:
        _fail("component relation proof requires an interaction catalog")
    catalog = InteractionContractCatalogV1.parse(
        _load_json(
            Path(interaction_contract_catalog),
            "interaction contract catalog",
        )
    )

    operation_index = portable.operation_index()
    service_index = {service.identity: service for service in portable.services}
    type_index = portable.type_index()
    semantic_services = {
        str(row.get("service_id")): row
        for row in semantic_contract.get("services", [])
        if isinstance(row, Mapping)
    }
    boundary_operations: dict[str, Mapping[str, object]] = {}
    evidence: list[Mapping[str, object]] = []
    for operation in intent.operations:
        operation_id = str(operation["operation_id"])
        logical_operation = operation_index.get(operation_id)
        if logical_operation is None:
            _fail("relation intent names an unknown component operation")
        parameter_ids = {item.identity for item in logical_operation.parameters}
        interactions: list[dict[str, object]] = []
        for requirement in operation["requirements"]:
            if requirement["relation"] != "borrowed_interior_or_null":
                _fail("direct relation proof kind is unsupported")
            service_id = str(requirement["service_id"])
            service = service_index.get(service_id)
            semantic_service = semantic_services.get(service_id)
            if service is None or semantic_service is None:
                _fail("relation intent names an unbound component service")
            if str(requirement["origin_parameter_id"]) not in parameter_ids:
                _fail("relation intent origin is not an operation parameter")
            if (
                service.result_type_id is None
                or requirement["result_value_id"] != "result"
            ):
                _fail("relation intent result does not name the service result")
            provider = semantic_service.get("provider")
            if not isinstance(provider, Mapping) or provider.get("kind") != (
                "checked_external_call_events"
            ):
                _fail("relation proof currently requires a checked external service")
            events = provider.get("events")
            if (
                not isinstance(events, list)
                or len(events) != 1
                or not isinstance(events[0], Mapping)
            ):
                _fail("relation service has no unique checked machine event")
            event = events[0]
            identity = event.get("identity")
            if not isinstance(identity, Mapping):
                _fail("relation service machine identity is malformed")

            matches = []
            for contract in catalog.contracts:
                subject = contract.subject
                if (
                    subject.get("kind") != "external_import"
                    or str(subject.get("dll", "")).lower()
                    != str(identity.get("dll", "")).lower()
                    or subject.get("symbol") != identity.get("symbol")
                    or subject.get("ordinal") != identity.get("ordinal")
                ):
                    continue
                patterns = {item.identity: item for item in contract.type_parameters}
                matched_ports = True
                for port in contract.ports:
                    if port.direction == "input" and port.identity.startswith(
                        "argument."
                    ):
                        suffix = port.identity.removeprefix("argument.")
                        if not suffix.isdigit() or int(suffix) >= len(
                            service.parameter_type_ids
                        ):
                            matched_ports = False
                            break
                        logical_type_id = service.parameter_type_ids[int(suffix)]
                    elif port.direction == "output" and port.identity == "result":
                        logical_type_id = service.result_type_id
                    else:
                        matched_ports = False
                        break
                    if logical_type_id is None or not contract_type_matches(
                        patterns[port.type_parameter],
                        type_index[logical_type_id],
                        type_index,
                    ):
                        matched_ports = False
                        break
                if matched_ports:
                    matches.append(contract)
            if len(matches) != 1:
                _fail("relation service has no unique reviewed interaction contract")
            contract = matches[0]
            receipt = InteractionContractReceiptV1.create(contract)
            if not receipt.authorizing:
                _fail("relation service interaction contract is not reviewed")
            interaction_id = (
                f"service:{service_id}:{event['unit_id']}:{event['event_index']}"
            )
            ensures = [
                _interaction_expression(row, interaction_id=interaction_id)
                for row in contract.ensures
            ]
            input_index = _nullable_same_origin_input(ensures, interaction_id)
            if input_index is None:
                _fail(
                    "reviewed interaction contract omits the requested origin relation"
                )
            origin_type = type_index[service.parameter_type_ids[input_index]]
            result_type = type_index[service.result_type_id]
            result_permissions = {"read": 1, "write": 2, "read_write": 3}.get(
                result_type.access,
                0,
            )
            minimum_remaining = _nonnull_minimum_remaining(
                ensures,
                interaction_id,
            )
            interactions.append(
                {
                    "id": interaction_id,
                    "contract_id": contract.identity,
                    "machine_event": {
                        "unit_id": event["unit_id"],
                        "event_index": event["event_index"],
                        "event_sha256": event["event_sha256"],
                    },
                    "invoke_action": {"clause": {"ensures": ensures}},
                }
            )
            evidence.append(
                {
                    "operation_id": operation_id,
                    "requirement_id": requirement["id"],
                    "service_id": service_id,
                    "input_argument_index": input_index,
                    "relation": str(requirement["relation"]),
                    "origin_type": {
                        "kind": origin_type.kind,
                        "nul_terminated": bool(origin_type.nul_terminated),
                    },
                    "result_policy": {
                        "nullable": bool(result_type.nullable),
                        "allow_one_past": bool(result_type.allow_one_past),
                        "permissions": result_permissions,
                    },
                    "nonnull_min_remaining": (
                        None
                        if minimum_remaining is None
                        else {
                            "nonzero_argument_index": minimum_remaining[0],
                            "minimum": minimum_remaining[1],
                        }
                    ),
                    "contract_id": contract.identity,
                    "contract_sha256": contract.contract_sha256,
                    "contract_catalog_sha256": catalog.catalog_sha256,
                    "contract_receipt": receipt.to_payload(),
                    "contract_receipt_sha256": receipt.receipt_sha256,
                }
            )
        boundary_operations[operation_id] = {
            "operation_id": operation_id,
            "interactions": interactions,
        }
    return boundary_operations, evidence
