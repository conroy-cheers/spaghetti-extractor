"""Construct interaction-aware Relation IR from checked component evidence."""

from __future__ import annotations

import copy
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .formats import COMPONENT_RELATION_PROPOSAL_PACKAGE_V2_FORMAT
from .interaction_contract import (
    InteractionContractCatalogV1,
    InteractionContractError,
    InteractionContractReceiptV1,
    InteractionContractV1,
    contract_type_matches,
)
from .interaction_inventory import (
    ComponentInteractionInventoryV1,
    ComponentInteractionSiteV1,
    InteractionPortBindingV1,
)
from .interface_ir import LogicalTypeV1, PortableComponentInterfaceV2
from .machine_binding import (
    ComponentMachineBindingV1,
    MachineProjectionV1,
    OperationMachineBindingV1,
    ServiceMachineBindingV1,
)
from .relation_projection import (
    RelationProjectionError,
    _authority_call,
    _authority_id,
    _coerce_projection,
    _expression_places,
    _logical_sort,
    _machine_expression,
    _observe_projection,
    _operation_clauses,
    _ordered_places,
    _realize_projection,
    _true,
)
from .relation_ir import ComponentRelationIRError, ComponentRelationIRV1


class ComponentRelationProposalError(ValueError):
    """Checked inputs cannot form one complete interaction-aware relation."""


def build_component_relation_proposal_package(
    *,
    interaction_inventory: ComponentInteractionInventoryV1,
    contract_selections: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Expose exact sites and reusable candidates without claiming authority."""

    selections = dict(contract_selections or {})
    required = {
        site.identity
        for operation in interaction_inventory.operations
        for site in operation.sites
        if site.contract_candidates
    }
    rows = []
    for operation in interaction_inventory.operations:
        rows.append({
            "operation_id": operation.operation_id,
            "interactions": [
                {
                    "site_id": site.identity,
                    "primitive_id": site.primitive_id,
                    "subject": copy.deepcopy(dict(site.subject)),
                    "contract_candidates": list(site.contract_candidates),
                    "selected_contract_id": selections.get(site.identity),
                }
                for site in operation.sites
            ],
        })
    missing = sorted(required - set(selections))
    extra = sorted(set(selections) - required)
    core = {
        "format": COMPONENT_RELATION_PROPOSAL_PACKAGE_V2_FORMAT,
        "component_id": interaction_inventory.component_id,
        "interaction_inventory_sha256": interaction_inventory.inventory_sha256,
        "status": "ready" if not missing and not extra else "incomplete",
        "missing_site_ids": missing,
        "unknown_site_ids": extra,
        "operations": rows,
    }
    return {**core, "proposal_sha256": canonical_sha256_v3(core)}


def build_component_relation_proposal(
    *,
    interface: PortableComponentInterfaceV2,
    machine_binding: ComponentMachineBindingV1,
    semantic_contract_sha256: str,
    object_authority_sha256: str,
    interaction_inventory: ComponentInteractionInventoryV1,
    contract_catalog: InteractionContractCatalogV1,
    contract_selections: Mapping[str, str] | None = None,
) -> ComponentRelationIRV1:
    selections = dict(contract_selections or {})
    if interaction_inventory.component_id != machine_binding.identity:
        raise ComponentRelationProposalError("interaction inventory component changed")
    expected_bindings = {
        "interface_sha256": interface.sha256,
        "machine_binding_sha256": machine_binding.binding_sha256,
        "semantic_contract_sha256": semantic_contract_sha256,
        "machine_ir_sha256": machine_binding.machine_ir_sha256,
        "interaction_contract_catalog_sha256": contract_catalog.catalog_sha256,
    }
    for key, expected in expected_bindings.items():
        if interaction_inventory.bindings.get(key) != expected:
            raise ComponentRelationProposalError(
                f"interaction inventory binding {key!r} is stale"
            )
    operation_inventory = {
        item.operation_id: item for item in interaction_inventory.operations
    }
    operations = interface.operation_index()
    types = interface.type_index()
    service_bindings = {
        item.service_id: item for item in machine_binding.services
    }
    relation_operations: list[dict[str, object]] = []
    consumed_selections: set[str] = set()
    for bound in machine_binding.operations:
        logical = operations[bound.operation_id]
        inventory = operation_inventory.get(bound.operation_id)
        if inventory is None:
            raise ComponentRelationProposalError(
                f"interaction inventory omits operation {bound.operation_id!r}"
            )
        interactions = [
            _interaction_payload(
                site,
                bound=bound,
                operation=logical,
                interface=interface,
                types=types,
                service_bindings=service_bindings,
                contract_catalog=contract_catalog,
                selected_contract_id=selections.get(site.identity),
            )
            for site in inventory.sites
        ]
        consumed_selections.update(
            site.identity for site in inventory.sites if site.identity in selections
        )
        interaction_effects = {
            effect_id
            for item in interactions
            for effect_id in item["effect_ids"]
        }
        parameter_types = {item.identity: types[item.type_id] for item in logical.parameters}
        result_types = {item.identity: types[item.type_id] for item in logical.results}
        state_types = {item.identity: types[item.type_id] for item in interface.state}
        clauses = [
            item
            for item in _operation_clauses(
                bound,
                parameter_types=parameter_types,
                result_types=result_types,
                state_types=state_types,
            )
            if not (
                item["kind"] == "effect_link"
                and item["effect_id"] in interaction_effects
            )
        ]
        relation_operations.append(
            {
                "operation_id": bound.operation_id,
                "clauses": sorted(clauses, key=lambda item: str(item["id"])),
                "interactions": sorted(interactions, key=lambda item: str(item["id"])),
            }
        )
    unused = set(selections) - consumed_selections
    if unused:
        raise ComponentRelationProposalError(
            f"relation declaration selects unknown interaction sites {sorted(unused)!r}"
        )
    try:
        return ComponentRelationIRV1.create(
            component_id=machine_binding.identity,
            machine_backend="x86-pe32-v1",
            bindings={
                **expected_bindings,
                "interaction_inventory_sha256": interaction_inventory.inventory_sha256,
                "object_authority_sha256": object_authority_sha256,
            },
            operations=relation_operations,
        )
    except (ComponentRelationIRError, RelationProjectionError) as exc:
        raise ComponentRelationProposalError(
            f"checked component evidence cannot form a constructive relation: {exc}"
        ) from exc


def _interaction_payload(
    site: ComponentInteractionSiteV1,
    *,
    bound: OperationMachineBindingV1,
    operation: object,
    interface: PortableComponentInterfaceV2,
    types: Mapping[str, LogicalTypeV1],
    service_bindings: Mapping[str, ServiceMachineBindingV1],
    contract_catalog: InteractionContractCatalogV1,
    selected_contract_id: str | None,
) -> dict[str, object]:
    candidates = set(site.contract_candidates)
    contract: InteractionContractV1 | None = None
    receipt: InteractionContractReceiptV1 | None = None
    if candidates:
        if selected_contract_id is None:
            raise ComponentRelationProposalError(
                f"interaction {site.identity!r} requires explicit reusable-contract selection"
            )
        if selected_contract_id not in candidates:
            raise ComponentRelationProposalError(
                f"interaction {site.identity!r} selected an incompatible contract"
            )
        contract = contract_catalog.contract(selected_contract_id)
        receipt = InteractionContractReceiptV1.create(contract)
        if not receipt.authorizing:
            raise ComponentRelationProposalError(
                f"interaction contract {contract.identity!r} is not reviewed"
            )
    elif selected_contract_id is not None:
        raise ComponentRelationProposalError(
            f"interaction {site.identity!r} has no selectable reusable contract"
        )
    if contract is not None:
        _validate_contract_specialization(contract, site=site, types=types)
    contract_authorities = _contract_origin_authorities(
        contract=contract,
        site=site,
    )
    ports = [
        _port_clause(
            site,
            port,
            bound=bound,
            operation=operation,
            interface=interface,
            types=types,
            contract_authority=contract_authorities.get(
                (port.direction, port.identity)
            ),
            authority_selector=_service_argument_authority_selector(
                site=site,
                port=port,
                service_bindings=service_bindings,
            ),
        )
        for port in site.ports
    ]
    port_sorts = {
        (port.direction, port.identity): _logical_sort(types[port.type_id])
        for port in site.ports
    }
    requires: list[dict[str, object]] = []
    ensures: list[dict[str, object]] = []
    if contract is not None:
        requires = [
            _specialize_contract_expression(
                item,
                site_id=site.identity,
                port_sorts=port_sorts,
            )
            for item in contract.requires
        ]
        ensures = [
            _specialize_contract_expression(
                item,
                site_id=site.identity,
                port_sorts=port_sorts,
            )
            for item in contract.ensures
        ]
    return {
        "id": site.identity,
        "primitive_id": site.primitive_id,
        "machine_event": copy.deepcopy(dict(site.machine_event)),
        "contract_id": None if contract is None else contract.identity,
        "contract_sha256": None if contract is None else contract.contract_sha256,
        "contract_receipt_sha256": None if receipt is None else receipt.receipt_sha256,
        "ports": sorted(ports, key=lambda item: str(item["id"])),
        "requires": requires,
        "ensures": ensures,
        "effect_ids": list(site.effect_ids),
    }


def _port_clause(
    site: ComponentInteractionSiteV1,
    port: InteractionPortBindingV1,
    *,
    bound: OperationMachineBindingV1,
    operation: object,
    interface: PortableComponentInterfaceV2,
    types: Mapping[str, LogicalTypeV1],
    contract_authority: MachineProjectionV1 | None,
    authority_selector: str | None,
) -> dict[str, object]:
    logical_type = types[port.type_id]
    source = port.source
    kind = source.get("kind")
    phase = "event_before" if port.direction == "input" else "event_after"
    if kind == "projection":
        projection = MachineProjectionV1.parse(
            source.get("value"), f"interaction {site.identity} port {port.identity}"
        )
        observe = _rewrite_machine_phase(
            _observe_projection(projection, logical_type), phase
        )
        logical = _interaction_logical(
            site.identity, port.direction, port.identity, _logical_sort(logical_type)
        )
        realize = (
            []
            if port.direction == "input"
            else [
                _rewrite_write_phase(item, phase)
                for item in _realize_projection(projection, logical, logical_type)
            ]
        )
    elif kind == "expression":
        if port.direction != "input":
            raise ComponentRelationProposalError(
                "interaction expression sources are valid only for input ports"
            )
        observe = _observe_event_expression(
            source.get("value"),
            site=site,
            port=port,
            logical_type=logical_type,
            authority_template=contract_authority or _authority_template(
                bound=bound,
                operation=operation,
                interface=interface,
                type_id=port.type_id,
                authority_selector=authority_selector,
            ),
        )
        realize = []
    else:
        raise ComponentRelationProposalError(
            f"interaction {site.identity!r} port source kind is unsupported"
        )
    reads = dict(_expression_places(observe))
    for write in realize:
        reads.update(_expression_places(write["value"]))
        reads.update(_expression_places(write["guard"]))
    path = {
        "root": "interaction",
        "id": site.identity,
        "fields": [port.direction, port.identity],
    }
    return {
        "id": f"port.{port.direction}.{port.identity}",
        "kind": "binding",
        "phase": phase,
        "logical_path": path,
        "observe": observe,
        "realize": realize,
        "predicate": None,
        "effect_id": None,
        "machine_event": None,
        "reads": _ordered_places(list(reads.values())),
        "writes": _ordered_places([item["place"] for item in realize]),
    }


def _contract_origin_authorities(
    *,
    contract: InteractionContractV1 | None,
    site: ComponentInteractionSiteV1,
) -> dict[tuple[str, str], MachineProjectionV1]:
    """Propagate an exact checked origin through reusable same-origin clauses."""

    if contract is None:
        return {}
    authorities: dict[tuple[str, str], MachineProjectionV1] = {}
    for port in site.ports:
        source = port.source
        if source.get("kind") != "projection":
            continue
        projection = MachineProjectionV1.parse(
            source.get("value"),
            f"interaction {site.identity} port {port.identity}",
        )
        if projection.kind in {"reference", "view"}:
            authorities[(port.direction, port.identity)] = projection
    edges: list[tuple[tuple[str, str], tuple[str, str]]] = []
    for expression in contract.ensures:
        for row in _contract_expression_walk(expression):
            if row.get("op") != "same_origin":
                continue
            args = row.get("args")
            if not isinstance(args, list) or len(args) != 2:
                continue
            keys = []
            for item in args:
                if not isinstance(item, Mapping) or item.get("op") != "port":
                    break
                keys.append((str(item.get("direction")), str(item.get("id"))))
            if len(keys) == 2:
                edges.append((keys[0], keys[1]))
    changed = True
    while changed:
        changed = False
        for left, right in edges:
            if left in authorities and right not in authorities:
                authorities[right] = authorities[left]
                changed = True
            elif right in authorities and left not in authorities:
                authorities[left] = authorities[right]
                changed = True
    return authorities


def _contract_expression_walk(value: Mapping[str, object]):
    yield value
    for item in value.get("args", []):
        if isinstance(item, Mapping):
            yield from _contract_expression_walk(item)


def _observe_event_expression(
    expression: object,
    *,
    site: ComponentInteractionSiteV1,
    port: InteractionPortBindingV1,
    logical_type: LogicalTypeV1,
    authority_template: MachineProjectionV1 | None,
) -> dict[str, object]:
    raw_place = {
        "kind": "action_value",
        "phase": "event_before",
        "width": 32,
        "selector": {
            "site_id": site.identity,
            "port_id": port.identity,
            "expression": copy.deepcopy(expression),
        },
    }
    raw = _machine_expression(raw_place, {"kind": "bitvector", "width": 32})
    logical_sort = _logical_sort(logical_type)
    if logical_type.kind in {"scalar", "enum"}:
        return _coerce_projection(raw, logical_sort)
    if logical_type.kind in {"reference", "view"}:
        if authority_template is None:
            raise ComponentRelationProposalError(
                f"interaction {site.identity!r} port {port.identity!r} has no origin authority"
            )
        binding = _authority_id(authority_template)
        reference_sort = {
            "kind": "reference",
            "type_id": (
                logical_type.identity
                if logical_type.kind == "reference"
                else f"{logical_type.identity}.base"
            ),
        }
        resolved = _authority_call(
            primitive="origin.resolve",
            binding=binding,
            sort=reference_sort,
            arguments=[
                raw,
                {
                    "op": "const",
                    "sort": {"kind": "bitvector", "width": 32},
                    "args": [],
                    "attributes": {"value": 1},
                },
            ],
        )
        if logical_type.kind == "reference":
            return resolved
        return {
            "op": "make_view",
            "sort": logical_sort,
            "args": [
                resolved,
                {
                    "op": "ref_remaining",
                    "sort": {"kind": "bitvector", "width": 32},
                    "args": [resolved],
                    "attributes": {},
                },
            ],
            "attributes": {},
        }
    if logical_type.kind in {"resource", "callback"}:
        if authority_template is None:
            raise ComponentRelationProposalError(
                f"interaction {site.identity!r} capability port has no authority"
            )
        return _authority_call(
            primitive="capability.import",
            binding=_authority_id(authority_template),
            sort=logical_sort,
            arguments=[raw],
        )
    raise ComponentRelationProposalError(
        f"interaction expression cannot observe logical kind {logical_type.kind!r}"
    )


def _authority_template(
    *,
    bound: OperationMachineBindingV1,
    operation: object,
    interface: PortableComponentInterfaceV2,
    type_id: str,
    authority_selector: str | None = None,
) -> MachineProjectionV1 | None:
    parameter_types = {item.identity: item.type_id for item in getattr(operation, "parameters")}
    result_types = {item.identity: item.type_id for item in getattr(operation, "results")}
    state_types = {item.identity: item.type_id for item in interface.state}
    candidates = [
        item.projection
        for item in bound.parameters
        if parameter_types.get(item.identity) == type_id
    ] + [
        item.projection
        for item in bound.results
        if result_types.get(item.identity) == type_id
    ] + [
        item.entry
        for item in bound.state
        if state_types.get(item.identity) == type_id
    ]
    authority_candidates = [
        item
        for item in candidates
        if item.kind in {"reference", "view", "resource", "callback_handle", "atomic_object"}
    ]
    authorities = {}
    for item in authority_candidates:
        try:
            authorities.setdefault(_authority_id(item), item)
        except RelationProjectionError:
            continue
    if authority_selector is not None:
        return authorities.get(authority_selector)
    if len(authorities) == 1:
        return next(iter(authorities.values()))
    return None


def _service_argument_authority_selector(
    *,
    site: ComponentInteractionSiteV1,
    port: InteractionPortBindingV1,
    service_bindings: Mapping[str, ServiceMachineBindingV1],
) -> str | None:
    """Resolve an explicitly checked origin selector for one service argument."""

    if port.direction != "input" or not port.identity.startswith("argument."):
        return None
    service_id = site.machine_event.get("service_id")
    if not isinstance(service_id, str) and site.subject.get("kind") == "machine_service":
        service_id = site.subject.get("service_id")
    if not isinstance(service_id, str):
        return None
    service = service_bindings.get(service_id)
    if service is None:
        return None
    raw_selectors = service.provider.get("argument_authority_selectors")
    if not isinstance(raw_selectors, list):
        return None
    try:
        index = int(port.identity.removeprefix("argument."), 10)
    except ValueError:
        return None
    if index < 0 or index >= len(raw_selectors):
        return None
    selector = raw_selectors[index]
    return selector if isinstance(selector, str) else None


def _validate_contract_specialization(
    contract: InteractionContractV1,
    *,
    site: ComponentInteractionSiteV1,
    types: Mapping[str, LogicalTypeV1],
) -> None:
    if contract.primitive_id != site.primitive_id:
        raise ComponentRelationProposalError("interaction contract primitive differs")
    ports = {(item.direction, item.identity): item for item in site.ports}
    contract_ports = {item.key: item for item in contract.ports}
    if set(ports) != set(contract_ports):
        raise ComponentRelationProposalError("interaction contract port inventory differs")
    parameters = {item.identity: item for item in contract.type_parameters}
    for key, declared in contract_ports.items():
        actual = ports[key]
        pattern = parameters[declared.type_parameter]
        if not contract_type_matches(pattern, types[actual.type_id], types):
            raise ComponentRelationProposalError(
                f"interaction contract port {key!r} type is incompatible"
            )


def _specialize_contract_expression(
    value: Mapping[str, object],
    *,
    site_id: str,
    port_sorts: Mapping[tuple[str, str], Mapping[str, object]],
) -> dict[str, object]:
    op = str(value["op"])
    if op == "port":
        direction, identity = str(value["direction"]), str(value["id"])
        sort = port_sorts[(direction, identity)]
        return _interaction_logical(site_id, direction, identity, sort)
    if op in {"true", "false"}:
        return {"op": op, "sort": {"kind": "bool"}, "args": [], "attributes": {}}
    if op == "const":
        return {
            "op": "const",
            "sort": {"kind": "bitvector", "width": int(value["width"])},
            "args": [],
            "attributes": {"value": int(value["value"])},
        }
    args = [
        _specialize_contract_expression(
            item, site_id=site_id, port_sorts=port_sorts
        )
        for item in value["args"]  # type: ignore[index]
    ]
    if op in {"not", "and", "or", "eq", "ult", "ule", "ref_is_null", "same_origin"}:
        sort: Mapping[str, object] = {"kind": "bool"}
    elif op in {"ref_offset", "ref_remaining", "view_extent"}:
        sort = {"kind": "bitvector", "width": 64}
    else:
        raise InteractionContractError(f"cannot specialize contract operation {op!r}")
    return {"op": op, "sort": dict(sort), "args": args, "attributes": {}}


def _interaction_logical(
    site_id: str,
    direction: str,
    port_id: str,
    sort: Mapping[str, object],
) -> dict[str, object]:
    return {
        "op": "logical",
        "sort": dict(sort),
        "args": [],
        "attributes": {
            "path": {
                "root": "interaction",
                "id": site_id,
                "fields": [direction, port_id],
            }
        },
    }


def _rewrite_machine_phase(value: Mapping[str, object], phase: str) -> dict[str, object]:
    result = copy.deepcopy(dict(value))
    if result.get("op") == "machine":
        place = result.get("attributes", {}).get("place")
        if isinstance(place, dict):
            place["phase"] = phase
    result["args"] = [
        _rewrite_machine_phase(item, phase)
        if isinstance(item, Mapping)
        else copy.deepcopy(item)
        for item in result.get("args", [])
    ]
    return result


def _rewrite_write_phase(value: Mapping[str, object], phase: str) -> dict[str, object]:
    result = copy.deepcopy(dict(value))
    place = result.get("place")
    if isinstance(place, dict):
        place["phase"] = phase
    if isinstance(result.get("value"), Mapping):
        result["value"] = _rewrite_machine_phase(result["value"], phase)
    if isinstance(result.get("guard"), Mapping):
        result["guard"] = _rewrite_machine_phase(result["guard"], phase)
    return result


__all__ = [
    "ComponentRelationProposalError",
    "build_component_relation_proposal",
    "build_component_relation_proposal_package",
]
