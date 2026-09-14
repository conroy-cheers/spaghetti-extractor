"""Checked finite-control authority for executable transfer plans."""

from __future__ import annotations

from hashlib import sha256
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..reconstruction.control_jump_tables import (
    _immutable_byte_remap_shape,
    _indexed_load_shape,
)
from .model import TransferPlanError, _Transfer
from .values import _list, _nonnegative, _object, _sha256, _string, _u32

def _finite_control_routes(
    manifest: Mapping[str, Any],
    *,
    binary: Mapping[str, Any],
    transfers: Mapping[str, _Transfer],
    units: Mapping[str, Mapping[str, Any]],
    unit_inventory: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Project checked selector-to-target behavior into the canonical IR."""

    control = _object(manifest.get("control", {}), "machine-IR manifest control")
    inventories = _list(
        control.get("recovered_indirect_targets", []),
        "recovered indirect-target inventories",
    )
    result: list[dict[str, Any]] = []
    for raw in inventories:
        inventory = _object(raw, "recovered indirect-target inventory")
        unit_id = inventory.get("source_unit_id")
        transfer = transfers.get(str(unit_id))
        unit = units.get(str(unit_id))
        unit_binding = unit_inventory.get(str(unit_id))
        if transfer is None:
            continue
        if (
            inventory.get("status") != "recovered"
            or inventory.get("closure") != "checked_finite_target_inventory"
            or inventory.get("failure") is not None
        ):
            continue
        if unit is None or unit_binding is None:
            raise TransferPlanError(
                f"{unit_id}: finite-control source unit is absent",
                code="malformed_finite_control_routes",
            )
        semantics = _object(
            unit.get("semantics"), "finite-control source semantics"
        )
        outcome = _object(
            semantics.get("outcome"), "finite-control source outcome"
        )
        target_expression = _object(
            outcome.get("target"), "finite-control target expression"
        )
        recovered_expression = _object(
            inventory.get("target_expression"),
            "recovered finite-control target expression",
        )
        raw_shape = _indexed_load_shape(target_expression)
        index_domain = _object(
            inventory.get("index"), "finite-control index domain"
        )
        table = _object(inventory.get("table"), "finite-control table")
        if (
            outcome.get("kind") != "indirect_jump"
            or recovered_expression != target_expression
            or raw_shape is None
            or raw_shape[0] != table.get("address")
            or raw_shape[1] != index_domain.get("expression")
            or raw_shape[2] != table.get("expression_form")
        ):
            raise TransferPlanError(
                f"{unit_id}: finite-control recovery is not bound to its exact indexed load",
                code="malformed_finite_control_routes",
            )
        expression_binding = _finite_control_transfer_binding(transfer)
        if (
            expression_binding is None
            or expression_binding["table_address"] != table.get("address")
        ):
            raise TransferPlanError(
                f"{unit_id}: compiled finite-control outcome is not the recovered table load",
                code="malformed_finite_control_routes",
            )
        routes: list[dict[str, int]] = []
        table_bytes_by_rva: list[tuple[int, bytes]] = []
        table_inventory_bytes = bytearray()
        image_base = _u32(binary.get("image_base"), "finite-control image base")
        image_size = _nonnegative(
            binary.get("size_of_image"), "finite-control image size"
        )
        pe_sha256 = _sha256(binary.get("sha256"), "finite-control PE SHA-256")
        if image_size <= 0 or image_base + image_size > 0x100000000:
            raise TransferPlanError(
                f"{unit_id}: finite-control image geometry is malformed",
                code="malformed_finite_control_routes",
            )
        raw_remap = index_domain.get("remap")
        if raw_remap is None:
            index_provenance: dict[str, Any] = {"kind": "direct_index"}
        else:
            remap = _object(raw_remap, "finite-control index remap")
            remap_shape = _immutable_byte_remap_shape(raw_shape[1])
            remap_bytes = _list(
                remap.get("bytes_le"), "finite-control remap bytes"
            )
            source_upper_exclusive = _nonnegative(
                remap.get("source_upper_exclusive"),
                "finite-control remap source bound",
            )
            remap_address = _u32(
                remap.get("address"), "finite-control remap address"
            )
            remap_rva_start = _u32(
                remap.get("rva_start"), "finite-control remap start RVA"
            )
            remap_rva_end = _u32(
                remap.get("rva_end"), "finite-control remap end RVA"
            )
            possible_values = [
                _u32(value, "finite-control remap possible value")
                for value in _list(
                    remap.get("possible_values"),
                    "finite-control remap possible values",
                )
            ]
            compiled_remap_bindings = [
                row
                for row in expression_binding["u8_index_loads"]
                if row["address"] == remap_address
            ]
            if (
                remap_shape is None
                or remap.get("kind") != "immutable_u8_lookup"
                or remap_shape[0] != remap_address
                or remap_shape[1] != remap.get("source_expression")
                or remap_shape[2] != remap.get("expression_form")
                or source_upper_exclusive <= 0
                or len(remap_bytes) != source_upper_exclusive
                or any(
                    not isinstance(byte, int)
                    or isinstance(byte, bool)
                    or byte < 0
                    or byte > 0xFF
                    for byte in remap_bytes
                )
                or possible_values != sorted(set(remap_bytes))
                or remap_rva_end != remap_rva_start + source_upper_exclusive
                or remap_address != image_base + remap_rva_start
                or remap_rva_end > image_size
                or remap.get("bytes_sha256")
                != sha256(bytes(remap_bytes)).hexdigest()
                or len(compiled_remap_bindings) != 1
            ):
                raise TransferPlanError(
                    f"{unit_id}: finite-control remap evidence is stale or ambiguous",
                    code="malformed_finite_control_routes",
                )
            index_provenance = {
                "kind": "immutable_u8_remap",
                "source_expression_sha256": compiled_remap_bindings[0][
                    "source_expression_sha256"
                ],
                "source_upper_exclusive": source_upper_exclusive,
                "address": remap_address,
                "rva_start": remap_rva_start,
                "rva_end": remap_rva_end,
                "bytes_sha256": str(remap["bytes_sha256"]),
                "bytes_le": list(remap_bytes),
                "possible_values": possible_values,
            }
        for raw_entry in _list(
            inventory.get("entries"), "finite-control route entries"
        ):
            entry = _object(raw_entry, "finite-control route entry")
            selector_value = _u32(
                entry.get("index"), "finite-control selector value"
            )
            entry_address = _u32(
                entry.get("entry_address"), "finite-control table entry address"
            )
            entry_rva = _u32(
                entry.get("entry_rva"), "finite-control table entry RVA"
            )
            target_rva = _u32(
                entry.get("target_rva"), "finite-control target RVA"
            )
            target_address = _u32(
                entry.get("target_address"), "finite-control target address"
            )
            raw_bytes = _list(
                entry.get("bytes_le"), "finite-control table entry bytes"
            )
            if (
                len(raw_bytes) != 4
                or any(
                    not isinstance(byte, int)
                    or isinstance(byte, bool)
                    or byte < 0
                    or byte > 0xFF
                    for byte in raw_bytes
                )
            ):
                raise TransferPlanError(
                    f"{unit_id}: finite-control table entry bytes are malformed",
                    code="malformed_finite_control_routes",
                )
            encoded_target = bytes(raw_bytes)
            if entry_address != (
                (int(table["address"]) + selector_value * 4) & 0xFFFFFFFF
            ):
                raise TransferPlanError(
                    f"{unit_id}: finite-control table entry address is stale",
                    code="malformed_finite_control_routes",
                )
            if (
                entry_address != image_base + entry_rva
                or target_address != image_base + target_rva
                or entry_rva + 4 > image_size
                or target_rva >= image_size
                or int.from_bytes(encoded_target, "little") != target_address
            ):
                raise TransferPlanError(
                    f"{unit_id}: finite-control image/table binding is stale",
                    code="malformed_finite_control_routes",
                )
            table_bytes_by_rva.append((entry_rva, encoded_target))
            table_inventory_bytes.extend(selector_value.to_bytes(4, "little"))
            table_inventory_bytes.extend(encoded_target)
            routes.append(
                {
                    "selector_value": selector_value,
                    "entry_address": entry_address,
                    "entry_rva": entry_rva,
                    "bytes_le": list(encoded_target),
                    "target_rva": target_rva,
                    "target_address": target_address,
                }
            )
        routes.sort(key=lambda row: (
            row["selector_value"], row["entry_address"], row["target_rva"]
        ))
        index_values = [row["selector_value"] for row in routes]
        sorted_table_bytes = b"".join(
            raw for _entry_rva, raw in sorted(table_bytes_by_rva)
        )
        if (
            not routes
            or len({row["selector_value"] for row in routes}) != len(routes)
            or index_domain.get("values") != index_values
            or table.get("entry_width") != 4
            or table.get("entry_count") != len(routes)
            or table.get("index_values") != index_values
            or table.get("rva_start") != min(row["entry_rva"] for row in routes)
            or table.get("rva_end") != max(row["entry_rva"] for row in routes) + 4
            or table.get("bytes_sha256") != sha256(sorted_table_bytes).hexdigest()
            or table.get("inventory_sha256")
            != sha256(bytes(table_inventory_bytes)).hexdigest()
            or index_provenance["kind"] == "immutable_u8_remap"
            and index_provenance["possible_values"] != index_values
        ):
            raise TransferPlanError(
                f"{unit_id}: finite-control table/domain evidence is stale or ambiguous",
                code="malformed_finite_control_routes",
            )
        core = {
            "unit_id": str(unit_id),
            "source_rva": _u32(
                inventory.get("source_rva"), "finite-control source RVA"
            ),
            "source_unit_ir_sha256": _sha256(
                unit_binding.get("unit_ir_sha256"),
                "finite-control source unit SHA-256",
            ),
            "outcome_expression_sha256": expression_binding[
                "outcome_expression_sha256"
            ],
            "index_expression_sha256": expression_binding[
                "index_expression_sha256"
            ],
            "selector_domain_sha256": canonical_sha256_v3(index_domain),
            "index_provenance": index_provenance,
            "pe_sha256": pe_sha256,
            "image_base": image_base,
            "image_size": image_size,
            "table": {
                "address": int(table["address"]),
                "rva_start": int(table["rva_start"]),
                "rva_end": int(table["rva_end"]),
                "entry_width": 4,
                "bytes_sha256": str(table["bytes_sha256"]),
                "inventory_sha256": str(table["inventory_sha256"]),
            },
            "routes": routes,
        }
        if (
            core["source_rva"] != transfer.rva_start
            or transfer.actions[-1].op != "outcome_indirect"
        ):
            raise TransferPlanError(
                f"{unit_id}: finite-control routes do not bind an indirect transfer",
                code="malformed_finite_control_routes",
            )
        result.append({
            **core,
            "route_inventory_sha256": canonical_sha256_v3(core),
        })
    result.sort(key=lambda row: (row["source_rva"], row["unit_id"]))
    _validate_finite_control_routes(
        result,
        transfers=transfers,
        unit_inventory=unit_inventory,
        pe_sha256=_sha256(binary.get("sha256"), "finite-control PE SHA-256"),
    )
    return result


def _finite_control_transfer_binding(
    transfer: _Transfer,
) -> dict[str, object] | None:
    """Bind one finite-route inventory to its compiled indexed table load."""

    if (
        not transfer.actions
        or transfer.actions[-1].op != "outcome_indirect"
        or len(transfer.actions[-1].args) != 1
    ):
        return None
    root_index = transfer.actions[-1].args[0]

    def tree(index: int) -> dict[str, object]:
        node = transfer.nodes[index]
        return {
            "op": node.op,
            "args": [tree(argument) for argument in node.args],
            "aux": node.aux,
            "immediate": node.immediate,
            "identity": node.identity,
        }

    def u8_index_loads(index: int) -> list[dict[str, object]]:
        node = transfer.nodes[index]
        result: list[dict[str, object]] = []
        if node.op == "load" and node.aux == 1 and len(node.args) == 1:
            address = transfer.nodes[node.args[0]]
            if address.op == "add32" and len(address.args) == 2:
                for constant_index, source_index in (
                    (address.args[0], address.args[1]),
                    (address.args[1], address.args[0]),
                ):
                    constant = transfer.nodes[constant_index]
                    if constant.op == "const":
                        result.append({
                            "address": constant.immediate,
                            "source_expression_sha256": canonical_sha256_v3(
                                tree(source_index)
                            ),
                        })
        return result

    root = transfer.nodes[root_index]
    if root.op != "load" or root.aux != 4 or len(root.args) != 1:
        return None
    address = transfer.nodes[root.args[0]]
    if address.op != "add32" or len(address.args) != 2:
        return None
    candidates: list[tuple[int, int]] = []
    for constant_index, scaled_index in (
        (address.args[0], address.args[1]),
        (address.args[1], address.args[0]),
    ):
        constant = transfer.nodes[constant_index]
        scaled = transfer.nodes[scaled_index]
        if constant.op != "const":
            continue
        if scaled.op == "shl32" and len(scaled.args) == 2:
            shift = transfer.nodes[scaled.args[1]]
            if shift.op == "const" and shift.immediate == 2:
                candidates.append((constant.immediate, scaled.args[0]))
            continue
        if scaled.op != "mul32" or len(scaled.args) != 2:
            continue
        for index_node, scale_node in (
            (scaled.args[0], scaled.args[1]),
            (scaled.args[1], scaled.args[0]),
        ):
            scale = transfer.nodes[scale_node]
            if scale.op == "const" and scale.immediate == 4:
                candidates.append((constant.immediate, index_node))
    if len(candidates) != 1:
        return None
    table_address, index_node = candidates[0]
    load_bindings = {
        (int(row["address"]), str(row["source_expression_sha256"]))
        for node_index in range(len(transfer.nodes))
        for row in u8_index_loads(node_index)
    }
    return {
        "table_address": table_address,
        "outcome_expression_sha256": canonical_sha256_v3(tree(root_index)),
        "index_expression_sha256": canonical_sha256_v3(tree(index_node)),
        # A multi-instruction transfer may preserve the terminator's index as
        # a register node while the preceding write contains the remap load.
        # Bind against the whole exact transfer and canonicalize duplicate
        # occurrences from its action/effect projections.
        "u8_index_loads": [
            {"address": address, "source_expression_sha256": source_sha256}
            for address, source_sha256 in sorted(load_bindings)
        ],
    }


def _validate_finite_control_routes(
    rows: list[Any],
    *,
    transfers: Mapping[str, _Transfer],
    unit_inventory: Mapping[str, Mapping[str, Any]],
    pe_sha256: str | None = None,
) -> None:
    keys: list[tuple[int, str]] = []
    for raw in rows:
        row = _object(raw, "finite-control route inventory")
        if set(row) != {
            "unit_id",
            "source_rva",
            "source_unit_ir_sha256",
            "outcome_expression_sha256",
            "index_expression_sha256",
            "selector_domain_sha256",
            "index_provenance",
            "pe_sha256",
            "image_base",
            "image_size",
            "table",
            "routes",
            "route_inventory_sha256",
        }:
            raise TransferPlanError(
                "finite-control route inventory fields are incomplete",
                code="malformed_finite_control_routes",
            )
        unit_id = _string(row.get("unit_id"), "finite-control unit ID")
        source_rva = _u32(row.get("source_rva"), "finite-control source RVA")
        source_unit_ir_sha256 = _sha256(
            row.get("source_unit_ir_sha256"), "finite-control source unit SHA-256"
        )
        outcome_expression_sha256 = _sha256(
            row.get("outcome_expression_sha256"),
            "finite-control outcome expression SHA-256",
        )
        index_expression_sha256 = _sha256(
            row.get("index_expression_sha256"),
            "finite-control index expression SHA-256",
        )
        selector_domain_sha256 = _sha256(
            row.get("selector_domain_sha256"),
            "finite-control selector domain SHA-256",
        )
        index_provenance = _object(
            row.get("index_provenance"), "finite-control index provenance"
        )
        bound_pe_sha256 = _sha256(
            row.get("pe_sha256"), "finite-control PE SHA-256"
        )
        image_base = _u32(row.get("image_base"), "finite-control image base")
        image_size = _nonnegative(
            row.get("image_size"), "finite-control image size"
        )
        if (
            image_size <= 0
            or image_base + image_size > 0x100000000
            or pe_sha256 is not None
            and bound_pe_sha256 != pe_sha256
        ):
            raise TransferPlanError(
                "finite-control image binding is malformed or stale",
                code="malformed_finite_control_routes",
            )
        table = _object(row.get("table"), "finite-control table")
        if set(table) != {
            "address",
            "rva_start",
            "rva_end",
            "entry_width",
            "bytes_sha256",
            "inventory_sha256",
        }:
            raise TransferPlanError(
                "finite-control table fields are incomplete",
                code="malformed_finite_control_routes",
            )
        table_address = _u32(table.get("address"), "finite-control table address")
        table_rva_start = _u32(
            table.get("rva_start"), "finite-control table start RVA"
        )
        table_rva_end = _u32(
            table.get("rva_end"), "finite-control table end RVA"
        )
        if table.get("entry_width") != 4 or table_rva_end <= table_rva_start:
            raise TransferPlanError(
                "finite-control table geometry is malformed",
                code="malformed_finite_control_routes",
            )
        table_bytes_sha256 = _sha256(
            table.get("bytes_sha256"), "finite-control table bytes SHA-256"
        )
        table_inventory_sha256 = _sha256(
            table.get("inventory_sha256"),
            "finite-control table inventory SHA-256",
        )
        routes = _list(row.get("routes"), "finite-control routes")
        normalized = []
        for raw_route in routes:
            route = _object(raw_route, "finite-control route")
            if set(route) != {
                "selector_value",
                "entry_address",
                "entry_rva",
                "bytes_le",
                "target_rva",
                "target_address",
            }:
                raise TransferPlanError(
                    "finite-control route fields are incomplete",
                    code="malformed_finite_control_routes",
                )
            raw_bytes = _list(
                route.get("bytes_le"), "finite-control table entry bytes"
            )
            if (
                len(raw_bytes) != 4
                or any(
                    not isinstance(byte, int)
                    or isinstance(byte, bool)
                    or byte < 0
                    or byte > 0xFF
                    for byte in raw_bytes
                )
            ):
                raise TransferPlanError(
                    "finite-control table entry bytes are malformed",
                    code="malformed_finite_control_routes",
                )
            normalized.append({
                "selector_value": _u32(
                    route.get("selector_value"), "finite-control selector value"
                ),
                "entry_address": _u32(
                    route.get("entry_address"),
                    "finite-control table entry address",
                ),
                "entry_rva": _u32(
                    route.get("entry_rva"), "finite-control table entry RVA"
                ),
                "bytes_le": list(raw_bytes),
                "target_rva": _u32(
                    route.get("target_rva"), "finite-control target RVA"
                ),
                "target_address": _u32(
                    route.get("target_address"),
                    "finite-control target address",
                ),
            })
        if (
            not normalized
            or normalized != sorted(
                normalized,
                key=lambda item: (
                    item["selector_value"],
                    item["entry_address"],
                    item["target_rva"],
                    item["target_address"],
                ),
            )
            or len({item["selector_value"] for item in normalized})
            != len(normalized)
        ):
            raise TransferPlanError(
                "finite-control routes are empty, unordered, or ambiguous",
                code="malformed_finite_control_routes",
            )
        for route in normalized:
            if (
                route["entry_address"]
                != ((table_address + route["selector_value"] * 4) & 0xFFFFFFFF)
                or route["entry_address"] != image_base + route["entry_rva"]
                or route["target_address"] != image_base + route["target_rva"]
                or route["entry_rva"] + 4 > image_size
                or route["target_rva"] >= image_size
                or int.from_bytes(bytes(route["bytes_le"]), "little")
                != route["target_address"]
            ):
                raise TransferPlanError(
                    "finite-control route does not bind the checked image/table",
                    code="malformed_finite_control_routes",
                )
        table_bytes = b"".join(
            bytes(route["bytes_le"])
            for route in sorted(normalized, key=lambda item: item["entry_rva"])
        )
        inventory_bytes = b"".join(
            route["selector_value"].to_bytes(4, "little")
            + bytes(route["bytes_le"])
            for route in normalized
        )
        if (
            table_rva_start != min(route["entry_rva"] for route in normalized)
            or table_rva_end
            != max(route["entry_rva"] for route in normalized) + 4
            or table_bytes_sha256 != sha256(table_bytes).hexdigest()
            or table_inventory_sha256 != sha256(inventory_bytes).hexdigest()
        ):
            raise TransferPlanError(
                "finite-control route table digest or range is stale",
                code="malformed_finite_control_routes",
            )
        transfer = transfers.get(unit_id)
        binding = None if transfer is None else _finite_control_transfer_binding(transfer)
        unit_binding = unit_inventory.get(unit_id)
        provenance_kind = index_provenance.get("kind")
        if provenance_kind == "direct_index":
            if set(index_provenance) != {"kind"}:
                raise TransferPlanError(
                    "direct finite-control index provenance is malformed",
                    code="malformed_finite_control_routes",
                )
        elif provenance_kind == "immutable_u8_remap":
            if set(index_provenance) != {
                "kind",
                "source_expression_sha256",
                "source_upper_exclusive",
                "address",
                "rva_start",
                "rva_end",
                "bytes_sha256",
                "bytes_le",
                "possible_values",
            }:
                raise TransferPlanError(
                    "remapped finite-control index provenance is incomplete",
                    code="malformed_finite_control_routes",
                )
            source_expression_sha256 = _sha256(
                index_provenance.get("source_expression_sha256"),
                "finite-control remap source expression SHA-256",
            )
            source_upper_exclusive = _nonnegative(
                index_provenance.get("source_upper_exclusive"),
                "finite-control remap source bound",
            )
            remap_address = _u32(
                index_provenance.get("address"),
                "finite-control remap address",
            )
            remap_rva_start = _u32(
                index_provenance.get("rva_start"),
                "finite-control remap start RVA",
            )
            remap_rva_end = _u32(
                index_provenance.get("rva_end"),
                "finite-control remap end RVA",
            )
            remap_bytes = _list(
                index_provenance.get("bytes_le"),
                "finite-control remap bytes",
            )
            possible_values = [
                _u32(value, "finite-control remap possible value")
                for value in _list(
                    index_provenance.get("possible_values"),
                    "finite-control remap possible values",
                )
            ]
            matching_bindings = [] if binding is None else [
                item
                for item in binding["u8_index_loads"]
                if item["address"] == remap_address
                and item["source_expression_sha256"]
                == source_expression_sha256
            ]
            if (
                source_upper_exclusive <= 0
                or len(remap_bytes) != source_upper_exclusive
                or any(
                    not isinstance(byte, int)
                    or isinstance(byte, bool)
                    or byte < 0
                    or byte > 0xFF
                    for byte in remap_bytes
                )
                or possible_values != sorted(set(remap_bytes))
                or possible_values
                != [item["selector_value"] for item in normalized]
                or remap_address != image_base + remap_rva_start
                or remap_rva_end != remap_rva_start + source_upper_exclusive
                or remap_rva_end > image_size
                or index_provenance.get("bytes_sha256")
                != sha256(bytes(remap_bytes)).hexdigest()
                or len(matching_bindings) != 1
            ):
                raise TransferPlanError(
                    "finite-control remap provenance is malformed or stale",
                    code="malformed_finite_control_routes",
                )
        else:
            raise TransferPlanError(
                "finite-control index provenance kind is unsupported",
                code="malformed_finite_control_routes",
            )
        if (
            transfer is None
            or transfer.rva_start != source_rva
            or binding is None
            or binding["table_address"] != table_address
            or binding["outcome_expression_sha256"]
            != outcome_expression_sha256
            or binding["index_expression_sha256"] != index_expression_sha256
            or unit_binding is None
            or unit_binding.get("unit_ir_sha256") != source_unit_ir_sha256
            or any(
                route["target_rva"]
                not in {candidate.rva_start for candidate in transfers.values()}
                for route in normalized
            )
        ):
            raise TransferPlanError(
                "finite-control route authority is not bound to its exact transfer",
                code="malformed_finite_control_routes",
            )
        core = {
            "unit_id": unit_id,
            "source_rva": source_rva,
            "source_unit_ir_sha256": source_unit_ir_sha256,
            "outcome_expression_sha256": outcome_expression_sha256,
            "index_expression_sha256": index_expression_sha256,
            "selector_domain_sha256": selector_domain_sha256,
            "index_provenance": dict(index_provenance),
            "pe_sha256": bound_pe_sha256,
            "image_base": image_base,
            "image_size": image_size,
            "table": {
                "address": table_address,
                "rva_start": table_rva_start,
                "rva_end": table_rva_end,
                "entry_width": 4,
                "bytes_sha256": table_bytes_sha256,
                "inventory_sha256": table_inventory_sha256,
            },
            "routes": normalized,
        }
        if row.get("route_inventory_sha256") != canonical_sha256_v3(core):
            raise TransferPlanError(
                "finite-control route inventory digest is stale",
                code="stale_executable_transfer_plan",
            )
        keys.append((source_rva, unit_id))
    if keys != sorted(set(keys)):
        raise TransferPlanError(
            "finite-control route inventories are duplicated or unordered",
            code="malformed_finite_control_routes",
        )
