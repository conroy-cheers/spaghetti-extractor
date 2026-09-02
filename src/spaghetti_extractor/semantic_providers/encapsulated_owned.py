"""Conservative admission for representation-changing V6 providers.

This is deliberately not a second refinement engine.  It proves only the
structural premise that lets the existing contextual-refinement result be
lifted from an operation step to a persistent private representation: the
selected component owns every active transfer, its mapped state cells are
exact object partitions with no loader-visible anchors, and the module has one
process entry with no callback or concurrent ingress.  Broader ownership and
reentrancy shapes remain incomplete until the canonical semantic module can
prove them.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary._canonical import object_
from ..components.interface_package_v5 import CompiledComponentInterfaceV5
from ..components.machine_binding import MachineProjectionV1
from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from ..semantic_objects.object_authority import MachineObjectAuthorityV2
from ..transfer.model import _Node, _Transfer
from .slices_v2 import SemanticSliceV2


class EncapsulatedOwnedAdmissionError(ValueError):
    """The requested representation change lacks exclusive ownership."""


def _fail(message: str) -> None:
    raise EncapsulatedOwnedAdmissionError(message)


def _scalar_width(bundle: CompiledComponentInterfaceV5, type_id: str) -> int:
    value = bundle.intent.schema.type_index[type_id]
    while value.kind == "enum":
        underlying = value.body.get("underlying_type_id")
        if not isinstance(underlying, str):
            _fail("encapsulated-owned state enum has no underlying type")
        value = bundle.intent.schema.type_index[underlying]
    width = value.body.get("width_bits")
    if value.kind != "integer" or width not in {8, 16, 32}:
        _fail("encapsulated-owned state must be an IA-32 scalar integer")
    return int(width)


def _state_cells(
    operations: Sequence[Mapping[str, object]],
    bundle: CompiledComponentInterfaceV5,
) -> tuple[dict[str, int | str], ...]:
    if not bundle.interface.state:
        _fail("encapsulated-owned proof requires persistent state")
    expected_widths: dict[str, int] = {}
    for item in bundle.interface.state:
        if item.value.interpretation != "value":
            _fail("initial encapsulated-owned proof supports scalar state only")
        expected_widths[item.value.identity] = _scalar_width(
            bundle, item.value.type_id
        )

    catalog: tuple[dict[str, int | str], ...] | None = None
    for raw_operation in operations:
        operation = object_(raw_operation, "encapsulated-owned operation")
        projection = object_(
            object_(
                operation.get("machine_projection"),
                "encapsulated-owned machine projection",
            ).get("operation"),
            "encapsulated-owned operation projection",
        )
        raw_state = projection.get("state")
        if not isinstance(raw_state, list):
            _fail("encapsulated-owned state projection is absent")
        cells = []
        for index, raw in enumerate(raw_state):
            row = object_(raw, f"encapsulated-owned state projection {index}")
            identity = row.get("id")
            if not isinstance(identity, str) or identity not in expected_widths:
                _fail("encapsulated-owned state projection identity is stale")
            entry = MachineProjectionV1.parse(
                row.get("entry"), f"encapsulated-owned state {identity} entry"
            )
            exit_projection = MachineProjectionV1.parse(
                row.get("exit"), f"encapsulated-owned state {identity} exit"
            )
            width = expected_widths[identity]
            if (
                entry.kind != "static_slot"
                or exit_projection.kind != "static_slot"
                or entry.payload.get("at") != "entry"
                or exit_projection.payload.get("at") != "exit"
                or entry.payload.get("rva") != exit_projection.payload.get("rva")
                or entry.payload.get("width") != width
                or exit_projection.payload.get("width") != width
            ):
                _fail("encapsulated-owned state requires one stable static slot")
            cells.append({
                "state_id": identity,
                "rva": int(entry.payload["rva"]),
                "width_bits": width,
                "extent": width // 8,
            })
        normalized = tuple(sorted(cells, key=lambda item: str(item["state_id"])))
        if {str(item["state_id"]) for item in normalized} != set(expected_widths):
            _fail("encapsulated-owned state projection is not total")
        if catalog is None:
            catalog = normalized
        elif catalog != normalized:
            _fail("encapsulated-owned operations disagree on persistent storage")
    assert catalog is not None
    ranges = sorted(
        (int(row["rva"]), int(row["rva"]) + int(row["extent"]))
        for row in catalog
    )
    if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
        _fail("encapsulated-owned state cells overlap")
    return catalog


def _const_node(nodes: Sequence[_Node], index: int, seen: set[int]) -> int | None:
    if index < 0 or index >= len(nodes) or index in seen:
        return None
    seen = {*seen, index}
    node = nodes[index]
    if node.op == "const":
        return node.immediate & 0xFFFFFFFF
    if node.op in {"add32", "sub32", "and32", "or32", "xor32"} and len(node.args) == 2:
        left = _const_node(nodes, node.args[0], seen)
        right = _const_node(nodes, node.args[1], seen)
        if left is None or right is None:
            return None
        if node.op == "add32":
            return (left + right) & 0xFFFFFFFF
        if node.op == "sub32":
            return (left - right) & 0xFFFFFFFF
        if node.op == "and32":
            return left & right
        if node.op == "or32":
            return left | right
        return left ^ right
    return None


def _stack_address(nodes: Sequence[_Node], index: int, seen: set[int]) -> bool:
    if index < 0 or index >= len(nodes) or index in seen:
        return False
    seen = {*seen, index}
    node = nodes[index]
    if node.op == "reg":
        return node.aux == 7
    if node.op in {"add32", "sub32"} and len(node.args) == 2:
        return (
            _stack_address(nodes, node.args[0], seen)
            and _const_node(nodes, node.args[1], set()) is not None
        ) or (
            node.op == "add32"
            and _const_node(nodes, node.args[0], set()) is not None
            and _stack_address(nodes, node.args[1], seen)
        )
    return False


def _checked_transfer_memory(
    transfers: Sequence[_Transfer],
    cells: Sequence[Mapping[str, int | str]],
) -> list[dict[str, object]]:
    ranges = [
        (int(row["rva"]), int(row["rva"]) + int(row["extent"]), str(row["state_id"]))
        for row in cells
    ]
    observed: set[str] = set()
    accesses: list[dict[str, object]] = []

    def admit(transfer: _Transfer, address_node: int, width: int, kind: str) -> None:
        if width not in {1, 2, 4}:
            _fail("encapsulated-owned transfer has an unsupported memory width")
        address = _const_node(transfer.nodes, address_node, set())
        if address is None:
            if _stack_address(transfer.nodes, address_node, set()):
                accesses.append({
                    "unit_id": transfer.identity,
                    "kind": kind,
                    "storage": "captured_stack",
                    "width": width,
                })
                return
            _fail(
                "encapsulated-owned transfer has a non-stack memory alias "
                "outside its exact state partition"
            )
        end = address + width
        matches = [row for row in ranges if row[0] <= address and end <= row[1]]
        if len(matches) != 1:
            _fail("encapsulated-owned transfer accesses non-owned mapped storage")
        observed.add(matches[0][2])
        accesses.append({
            "unit_id": transfer.identity,
            "kind": kind,
            "storage": "owned_state",
            "state_id": matches[0][2],
            "rva": address,
            "width": width,
        })

    for transfer in transfers:
        if (
            transfer.calls
            or transfer.x87_nodes
            or transfer.x87_operations
            or transfer.exception_occurrences
        ):
            _fail("initial encapsulated-owned proof excludes calls, x87, and exceptions")
        for node in transfer.nodes:
            if node.op == "load":
                if len(node.args) != 1:
                    _fail("encapsulated-owned load node is malformed")
                admit(transfer, node.args[0], node.aux, "read")
        for action in transfer.actions:
            if action.op == "memory_write":
                if len(action.args) < 2:
                    _fail("encapsulated-owned memory write is malformed")
                admit(transfer, action.args[0], action.aux, "write")
            elif "atomic" in action.op:
                _fail("initial encapsulated-owned proof excludes shared atomics")
    if observed != {str(row["state_id"]) for row in cells}:
        _fail("encapsulated-owned state is not exercised by the owned transfer slice")
    return sorted(accesses, key=canonical_sha256_v3)


def check_encapsulated_owned_admission(
    *,
    component_id: str,
    proof_classification: str,
    operations: Sequence[Mapping[str, object]],
    semantic_slice: SemanticSliceV2,
    qualification_input_sha256: str,
    bundle: CompiledComponentInterfaceV5,
    linked: LinkedSemanticModuleV2,
    transfers: Sequence[_Transfer],
    authority: MachineObjectAuthorityV2,
) -> dict[str, object]:
    """Prove the conservative ownership premise for private persistent state."""

    if proof_classification != "encapsulated_owned":
        _fail("encapsulated-owned admission received another proof classification")
    if bundle.interface.effects or bundle.interface.services:
        _fail("initial encapsulated-owned proof excludes effects and services")
    for raw in operations:
        operation = object_(raw, "encapsulated-owned operation")
        if (
            operation.get("effect_ids") != []
            or operation.get("service_ids") != []
            or operation.get("callback_ids") != []
            or operation.get("pointer_views") != []
            or operation.get("object_authority_selectors") != []
            or operation.get("outcome_protocol_ids") != ["normal"]
        ):
            _fail("initial encapsulated-owned operation shape is not thread-confined")

    linked_transfer_definitions = {
        str(row["definition_id"]): str(row["symbol_id"])
        for row in linked.payload["definitions"]
        if row.get("definition_kind") == "transfer_v2"
    }
    slice_definition_ids = {
        str(row["definition_id"])
        for row in semantic_slice.payload["definitions"]
    }
    owned_definition_ids = {
        str(item)
        for row in operations
        for item in row["definition_ids"]
    }
    if (
        not linked_transfer_definitions
        or slice_definition_ids != set(linked_transfer_definitions)
        or owned_definition_ids != slice_definition_ids
    ):
        _fail("encapsulated-owned slice is not total over active transfers")
    owned_units = {
        str(item)
        for row in operations
        for item in row["unit_ids"]
    }
    if {
        symbol.removeprefix("original:function:")
        for symbol in linked_transfer_definitions.values()
        if symbol.startswith("original:function:")
    } != owned_units:
        _fail("encapsulated-owned unit ownership disagrees with the semantic module")
    transfer_index = {item.identity: item for item in transfers}
    if len(transfer_index) != len(transfers) or not owned_units <= set(transfer_index):
        _fail("encapsulated-owned transfer inventory is stale")

    callable_roots = [
        row for row in linked.payload["roots"]
        if row.get("kind") != "loader_storage"
    ]
    if (
        len(callable_roots) != 1
        or callable_roots[0].get("kind") != "process_entry"
        or callable_roots[0].get("target_symbol")
        not in set(linked_transfer_definitions.values())
    ):
        _fail("initial encapsulated-owned proof requires one process entry")
    forbidden_effects = {
        "callbacks", "code_capabilities", "exceptions", "export_capabilities",
        "external_contracts", "import_uses", "indirect_targets",
        "nonlocal_transitions",
    }
    effects = object_(linked.payload.get("effects"), "linked semantic effects")
    if any(effects.get(key) not in (None, []) for key in forbidden_effects):
        _fail("initial encapsulated-owned proof excludes callable or exceptional ingress")

    cells = _state_cells(operations, bundle)
    bound_cells = []
    for cell in cells:
        rva = int(cell["rva"])
        extent = int(cell["extent"])
        matches = [
            rule for rule in authority.rules
            if rule.locator.kind == "image_rva"
            and rule.locator.offset == rva
            and rule.extent == extent
        ]
        if (
            len(matches) != 1
            or matches[0].kind != "image"
            or matches[0].lifetime != "image"
            or matches[0].permissions & 3 != 3
            or matches[0].interior_pointers
        ):
            _fail("encapsulated-owned state lacks one exact private object partition")
        if any(anchor.rule_id == matches[0].identity for anchor in authority.data_export_anchors):
            _fail("encapsulated-owned state is exposed through a data anchor")
        bound_cells.append({**cell, "rule_id": matches[0].identity})

    accesses = _checked_transfer_memory(
        [transfer_index[unit] for unit in sorted(owned_units)], cells
    )
    core: dict[str, Any] = {
        "kind": "encapsulated-owned-admission-v1",
        "status": "checked",
        "component_id": component_id,
        "bindings": {
            "qualification_input_sha256": qualification_input_sha256,
            "semantic_slice_sha256": semantic_slice.identity,
            "linked_semantic_module_sha256": linked.identity,
            "executable_transfer_plan_sha256": linked.payload["bindings"][
                "executable_transfer_plan_sha256"
            ],
            "machine_object_authority_sha256": authority.authority_sha256,
        },
        "state_cells": bound_cells,
        "memory_accesses": accesses,
        "ownership": {
            "active_transfer_definitions_total": True,
            "outside_aliases": 0,
            "loader_visible_anchors": 0,
        },
        "threading": {
            "mode": "single_process_root_no_callable_ingress",
            "thread_confined": True,
        },
        "state_relation": {
            "kind": "scalar-value-bijection-v1",
            "initialization": "import_exact_mapped_cells_once",
            "step": "existing_contextual_refinement_per_operation",
            "persistence": "same_image_lifetime_private_context",
            "finalization": "trivial_image_lifetime_discard",
            "total": True,
        },
    }
    return {**core, "receipt_sha256": canonical_sha256_v3(core)}


__all__ = [
    "EncapsulatedOwnedAdmissionError",
    "check_encapsulated_owned_admission",
]
