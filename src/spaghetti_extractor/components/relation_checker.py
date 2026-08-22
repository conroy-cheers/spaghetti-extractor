"""Fail-closed obligations for interaction-aware component relations."""

from __future__ import annotations

from collections import Counter
from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from .boundary_primitives import BoundaryPrimitiveError, BoundaryPrimitiveRegistryV1, DEFAULT_BOUNDARY_PRIMITIVES
from .interaction_contract import InteractionContractCatalogV1, InteractionContractReceiptV1
from .interaction_inventory import ComponentInteractionInventoryV1
from .interface_ir import LogicalTypeV1, PortableComponentInterfaceV2
from .relation_ir import ComponentRelationIRV1, RelationClauseV1, RelationSortV1
from .relation_receipt import ComponentRelationReceiptV1
from .relation_solver import prove_binding_lens


def check_component_relation(
    *,
    relation: ComponentRelationIRV1,
    interface: PortableComponentInterfaceV2,
    interaction_inventory: ComponentInteractionInventoryV1,
    contract_catalog: InteractionContractCatalogV1,
    lean_artifact_sha256: str | None,
    primitive_registry: BoundaryPrimitiveRegistryV1 = DEFAULT_BOUNDARY_PRIMITIVES,
) -> ComponentRelationReceiptV1:
    """Check exact site coverage, reusable authority, lenses, and effects."""

    evidence = tuple(sorted({relation.relation_sha256, *relation.bindings.values()}))
    obligations: list[dict[str, object]] = []

    def add(identity: str, status: str, code: str) -> None:
        obligations.append({"id": identity, "status": status, "code": code, "evidence": list(evidence if status == "checked" else ())})

    bindings = {
        "interface_sha256": interface.sha256,
        "interaction_inventory_sha256": interaction_inventory.inventory_sha256,
        "interaction_contract_catalog_sha256": contract_catalog.catalog_sha256,
    }
    for name, expected in bindings.items():
        add(
            f"binding.{name.removesuffix('_sha256')}",
            "checked" if relation.bindings.get(name) == expected else "violated",
            f"{name.removesuffix('_sha256')}_binding_exact" if relation.bindings.get(name) == expected else f"{name.removesuffix('_sha256')}_binding_stale",
        )
    if interaction_inventory.bindings.get("interface_sha256") != interface.sha256:
        add("binding.inventory_interface", "violated", "interaction_inventory_interface_stale")
    else:
        add("binding.inventory_interface", "checked", "interaction_inventory_interface_exact")

    operation_index = interface.operation_index()
    relation_index = {item.operation_id: item for item in relation.operations}
    inventory_index = {item.operation_id: item for item in interaction_inventory.operations}
    exact_operations = set(operation_index) == set(relation_index) == set(inventory_index)
    add("coverage.operations", "checked" if exact_operations else "violated", "operation_inventory_exact" if exact_operations else "operation_inventory_differs")

    types = interface.type_index()
    for operation_id in sorted(set(operation_index) & set(relation_index) & set(inventory_index)):
        operation = operation_index[operation_id]
        bound = relation_index[operation_id]
        inventory = inventory_index[operation_id]
        clauses = [item for item in bound.clauses if item.kind == "binding"]
        actual = Counter((item.logical_path.root, item.logical_path.identity) for item in clauses if item.logical_path is not None)
        expected = Counter(
            [("parameter", item.identity) for item in operation.parameters]
            + [("result", item.identity) for item in operation.results]
            + [("state", item.identity) for item in interface.state]
        )
        add(f"coverage.{operation_id}.values", "checked" if actual == expected else "violated", "logical_value_coverage_exact" if actual == expected else "logical_value_coverage_differs")
        value_types = {
            **{("parameter", item.identity): types[item.type_id] for item in operation.parameters},
            **{("result", item.identity): types[item.type_id] for item in operation.results},
            **{("state", item.identity): types[item.type_id] for item in interface.state},
        }
        for clause in clauses:
            assert clause.logical_path is not None and clause.observe is not None
            logical_type = value_types.get((clause.logical_path.root, clause.logical_path.identity))
            typed = logical_type is not None and _sort_matches(clause.observe.sort, logical_type)
            add(f"typing.{operation_id}.{clause.identity}", "checked" if typed else "violated", "observer_sort_matches_logical_type" if typed else "observer_sort_differs_from_logical_type")
            constructive = clause.logical_path.root not in {"result", "state"} or bool(clause.realize)
            add(f"constructive.{operation_id}.{clause.identity}", "checked" if constructive else "violated", "boundary_binding_constructive" if constructive else "exported_value_has_no_realizer")
            proof = prove_binding_lens(clause)
            add(f"lens.{operation_id}.{clause.identity}", proof.status, proof.code)

        site_index = {item.identity: item for item in inventory.sites}
        relation_sites = {item.identity: item for item in bound.interactions}
        exact_sites = set(site_index) == set(relation_sites)
        add(f"coverage.{operation_id}.interactions", "checked" if exact_sites else "violated", "interaction_site_coverage_exact" if exact_sites else "interaction_site_coverage_differs")
        for site_id in sorted(set(site_index) & set(relation_sites)):
            site, interaction = site_index[site_id], relation_sites[site_id]
            exact_site = interaction.primitive_id == site.primitive_id and canonical_sha256_v3(interaction.machine_event) == canonical_sha256_v3(site.machine_event)
            add(f"site.{operation_id}.{site_id}", "checked" if exact_site else "violated", "interaction_site_exact" if exact_site else "interaction_site_changed")
            expected_ports = {(item.direction, item.identity): item for item in site.ports}
            actual_ports = {
                (str(item.logical_path.fields[0]), str(item.logical_path.fields[1])): item
                for item in interaction.ports if item.logical_path is not None
            }
            port_exact = set(expected_ports) == set(actual_ports)
            add(f"coverage.{operation_id}.{site_id}.ports", "checked" if port_exact else "violated", "interaction_port_coverage_exact" if port_exact else "interaction_port_coverage_differs")
            for key in sorted(set(expected_ports) & set(actual_ports)):
                port, clause = expected_ports[key], actual_ports[key]
                typed = clause.observe is not None and _sort_matches(clause.observe.sort, types[port.type_id])
                add(f"typing.{operation_id}.{site_id}.{key[0]}.{key[1]}", "checked" if typed else "violated", "interaction_port_type_exact" if typed else "interaction_port_type_differs")
                proof = prove_binding_lens(clause)
                add(f"lens.{operation_id}.{site_id}.{key[0]}.{key[1]}", proof.status, proof.code)

            if site.contract_candidates:
                selected = interaction.contract_id in site.contract_candidates
                try:
                    contract = contract_catalog.contract(str(interaction.contract_id)) if selected else None
                    receipt = None if contract is None else InteractionContractReceiptV1.create(contract)
                    exact_contract = bool(
                        receipt is not None and receipt.authorizing
                        and interaction.contract_sha256 == contract.contract_sha256
                        and interaction.contract_receipt_sha256 == receipt.receipt_sha256
                    )
                except Exception:
                    exact_contract = False
                add(f"contract.{operation_id}.{site_id}", "checked" if exact_contract else "violated", "reusable_interaction_contract_exact" if exact_contract else "reusable_interaction_contract_missing_or_stale")
            else:
                absent = interaction.contract_id is None and interaction.contract_sha256 is None and interaction.contract_receipt_sha256 is None
                add(f"contract.{operation_id}.{site_id}", "checked" if absent else "violated", "interaction_requires_no_external_contract" if absent else "interaction_contract_unauthorized")
            primitive_ok = True
            try:
                primitive = primitive_registry.primitive(interaction.primitive_id)
                primitive_ok = primitive.effect_class == "world_effect" and "event_before" in primitive.phases
            except BoundaryPrimitiveError:
                primitive_ok = False
            add(f"registry.{operation_id}.{site_id}", "checked" if primitive_ok else "violated", "interaction_primitive_registered" if primitive_ok else "interaction_primitive_invalid")

        linked_effects = {item.effect_id for item in bound.clauses if item.kind == "effect_link"}
        linked_effects.update(effect_id for item in bound.interactions for effect_id in item.effect_ids)
        required_effects = set(operation.effect_ids)
        add(f"coverage.{operation_id}.effects", "checked" if linked_effects == required_effects else "violated", "logical_effect_coverage_exact" if linked_effects == required_effects else "logical_effect_coverage_differs")

        all_clauses = tuple(bound.clauses) + tuple(port for item in bound.interactions for port in item.ports)
        primitive_failures: list[str] = []
        authority_calls = []
        reference_ops: set[str] = set()
        for clause in all_clauses:
            for root in _clause_expressions(clause):
                for expression in root.walk():
                    if expression.op in {"make_ref", "derive_ref", "pointer_difference", "view_address"}:
                        reference_ops.add(expression.op)
                    if expression.op == "authority_call":
                        authority_calls.append((clause, expression))
        for clause, expression in authority_calls:
            primitive_id = str(expression.attributes.get("primitive"))
            try:
                primitive_registry.primitive(primitive_id).validate_call(arguments=[item.sort for item in expression.arguments], result=expression.sort, phase=clause.phase)
            except BoundaryPrimitiveError as exc:
                primitive_failures.append(str(exc))
        add(f"registry.{operation_id}.boundary", "violated" if primitive_failures else "checked", "boundary_primitive_invalid:" + ";".join(sorted(primitive_failures)) if primitive_failures else "boundary_primitives_registered")
        reference_ops.update(str(expression.attributes.get("primitive")) for _clause, expression in authority_calls if str(expression.attributes.get("primitive")).startswith("origin."))
        authorized = not reference_ops or "object_authority_sha256" in relation.bindings
        add(f"authority.{operation_id}.origins", "checked" if authorized else "incomplete", "reference_origins_authorized" if authorized else "reference_origin_authority_missing")

    add("proof.lean", "checked" if lean_artifact_sha256 is not None else "incomplete", "lean_relation_certificate_checked" if lean_artifact_sha256 is not None else "lean_relation_certificate_missing")
    return ComponentRelationReceiptV1.create(relation=relation, obligations=sorted(obligations, key=lambda item: str(item["id"])), lean_artifact_sha256=lean_artifact_sha256)


def _sort_matches(sort: RelationSortV1, logical_type: LogicalTypeV1) -> bool:
    if logical_type.kind in {"scalar", "enum"}:
        assert logical_type.c_type is not None
        width = int(logical_type.c_type.removeprefix("uint").removeprefix("int").removesuffix("_t"))
        return sort.kind == "bitvector" and sort.width == width
    expected = "view" if logical_type.kind == "bytes" else logical_type.kind
    return sort.kind == expected and sort.type_id in {logical_type.identity, f"legacy.{expected}"}


def _clause_expressions(clause: RelationClauseV1):
    if clause.observe is not None:
        yield clause.observe
    if clause.predicate is not None:
        yield clause.predicate
    for write in clause.realize:
        yield write.value
        yield write.guard


__all__ = ["check_component_relation"]
