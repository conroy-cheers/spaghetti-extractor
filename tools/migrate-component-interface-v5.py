#!/usr/bin/env python3
"""One-time V2--V4 review migration into canonical V5 interface intent.

This tool is deliberately outside production codecs.  Production V5 readers
never accept the retired interface formats.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Mapping

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.interface_package_v5 import (
    ComponentInterfaceIntentV1,
)
from spaghetti_extractor.util import write_json


def migrate(component_id: str, interface: Mapping[str, object]) -> ComponentInterfaceIntentV1:
    old_types = {str(item["id"]): item for item in interface["types"]}
    types: list[dict[str, object]] = [{"id": "unit", "kind": "void"}]
    if "u8" not in old_types and any(item["kind"] == "bytes" for item in old_types.values()):
        types.append({"id": "u8", "kind": "integer", "width_bits": 8, "signed": False})
    for type_id, row in old_types.items():
        kind = row["kind"]
        if kind == "scalar":
            width, signed = _scalar(str(row["c_type"]))
            types.append({"id": type_id, "kind": "integer", "width_bits": width, "signed": signed})
        elif kind == "enum":
            width, signed = _scalar(str(row["c_type"]))
            underlying = f"{type_id}-underlying"
            types.extend([
                {"id": underlying, "kind": "integer", "width_bits": width, "signed": signed},
                {"id": type_id, "kind": "enum", "underlying_type_id": underlying, "enumerators": []},
            ])
        elif kind in {"bytes", "view", "reference"}:
            element = "u8" if kind == "bytes" else str(row["element_type_id"])
            types.append({"id": type_id, "kind": "pointer", "pointee_type_id": element, "qualifiers": []})
        elif kind == "resource":
            types.append({"id": type_id, "kind": "opaque", "nominal_id": f"{component_id}.{type_id}"})
        elif kind == "callback":
            function_id = f"{type_id}-function"
            types.extend([
                {
                    "id": function_id,
                    "kind": "function",
                    "result_type_id": str(row.get("result_type_id") or "unit"),
                    "parameter_type_ids": list(row["parameter_type_ids"]),
                    "variadic": False,
                    "calling_convention": "cdecl",
                },
                {"id": type_id, "kind": "pointer", "pointee_type_id": function_id, "qualifiers": []},
            ])
        else:
            raise ValueError(f"unsupported legacy type kind {kind!r}")
    signatures: list[dict[str, object]] = []
    for operation in interface["operations"]:
        function_id = f"operation.{operation['id']}.function"
        result_types = [str(item["type_id"]) for item in operation["results"]]
        if len(result_types) > 1:
            raise ValueError("V5 migration requires a reviewed aggregate result for multi-result operations")
        types.append({
            "id": function_id,
            "kind": "function",
            "result_type_id": result_types[0] if result_types else "unit",
            "parameter_type_ids": [str(item["type_id"]) for item in operation["parameters"]],
            "variadic": False,
            "calling_convention": "cdecl",
        })
        signatures.append({
            "id": f"operation.{operation['id']}",
            "function_type_id": function_id,
            "parameters": [_value(item, old_types, component_id) for item in operation["parameters"]],
            "results": [_value(item, old_types, component_id) for item in operation["results"]],
        })
    for service in interface.get("services", []):
        function_id = f"service.{service['id']}.function"
        result_type = str(service.get("result_type_id") or "unit")
        types.append({
            "id": function_id,
            "kind": "function",
            "result_type_id": result_type,
            "parameter_type_ids": list(service["parameter_type_ids"]),
            "variadic": False,
            "calling_convention": "cdecl",
        })
        service_parameters = [
            _value({"id": f"argument-{index:04d}", "type_id": type_id}, old_types, component_id)
            for index, type_id in enumerate(service["parameter_type_ids"])
        ]
        # Legacy service signatures did not name parameters, so an extent keyed
        # by an operation parameter cannot be rebound without invention.
        for value in service_parameters:
            if value["extent"]["kind"] == "value":
                value["extent"] = {"kind": "none", "bytes": None, "value_id": None}
        signatures.append({
            "id": f"service.{service['id']}",
            "function_type_id": function_id,
            "parameters": service_parameters,
            "results": [] if result_type == "unit" else [
                _value({"id": "result", "type_id": result_type}, old_types, component_id)
            ],
        })
    schema = BoundarySchemaV1.create(
        schema_id=f"component.{component_id}", types=types, signatures=signatures
    )
    state = [
        {"value": _value(item, old_types, component_id), "initial": item["initial"]}
        for item in interface.get("state", [])
    ]
    state_values = [item["value"] for item in state]
    operations: list[dict[str, object]] = []
    for operation in interface["operations"]:
        source_values = [
            _value(item, old_types, component_id)
            for item in [*operation["parameters"], *operation["results"]]
        ]
        parameter_ids = {str(item["id"]) for item in operation["parameters"]}
        entries = [
            {
                "source_id": value["id"],
                "target": {
                    "root": "parameter" if value["id"] in parameter_ids else "result",
                    "value_id": value["id"],
                    "fields": [],
                },
            }
            for value in source_values
        ]
        lifecycle, checked = _lifecycles(
            component_id, operation, old_types, state_values
        )
        operations.append({
            "id": operation["id"],
            "signature_id": f"operation.{operation['id']}",
            "source_values": source_values,
            "projection_entries": entries,
            "lifecycle_bindings": lifecycle,
            "lifecycle_additional_roots": {"state": state_values},
            "checked_interaction_contract_ids": checked,
            "effect_ids": operation["effect_ids"],
            "allowed_service_ids": operation["allowed_service_ids"],
            "pre_states": operation["pre_states"],
            "post_states": operation["post_states"],
        })
    effect_operation = {
        effect_id: str(operation["id"])
        for operation in interface["operations"]
        for effect_id in operation["effect_ids"]
    }
    service_effects = {
        str(effect_id): str(service["id"])
        for service in interface.get("services", [])
        for effect_id in service["effect_ids"]
    }
    for effect_id, service_id in service_effects.items():
        owners = [
            str(operation["id"])
            for operation in interface["operations"]
            if service_id in operation["allowed_service_ids"]
        ]
        if len(owners) == 1:
            effect_operation.setdefault(effect_id, owners[0])
    effects = []
    for effect in interface.get("effects", []):
        operation_id = effect_operation.get(str(effect["id"]))
        if operation_id is None:
            raise ValueError(f"effect {effect['id']!r} is not owned by an operation")
        target_id = effect.get("target_id")
        target = None
        if target_id is not None:
            operation = next(item for item in interface["operations"] if item["id"] == operation_id)
            target = {
                "root": _root(str(target_id), operation, interface.get("state", [])),
                "value_id": target_id,
                "fields": [],
            }
        effects.append({
            "id": effect["id"], "kind": effect["kind"],
            "operation": operation_id, "target": target,
        })
    services = [
        {
            "id": service["id"],
            "signature_id": f"service.{service['id']}",
            "effect_ids": service["effect_ids"],
            "interaction_contract_id": f"component-service.{component_id}.{service['id']}",
        }
        for service in interface.get("services", [])
    ]
    return ComponentInterfaceIntentV1.create(
        component_id=component_id,
        schema=schema,
        state=state,
        operations=operations,
        effects=effects,
        services=services,
        protocol_states=interface["protocol"]["states"],
        initial_protocol_state=interface["protocol"]["initial_state"],
    )


def _scalar(c_type: str) -> tuple[int, bool]:
    match = re.fullmatch(r"(u?)int(8|16|32|64)_t", c_type)
    if match is None:
        raise ValueError(f"unsupported scalar C type {c_type!r}")
    return int(match.group(2)), not bool(match.group(1))


def _value(row: Mapping[str, object], types: Mapping[str, Mapping[str, object]], component_id: str) -> dict[str, object]:
    type_id = str(row["type_id"])
    node = types[type_id]
    kind = str(node["kind"])
    interpretation = {
        "bytes": "view", "view": "view", "reference": "reference",
        "resource": "resource", "callback": "callback",
    }.get(kind, "value")
    access = str(node.get("access", "none")) if interpretation in {"view", "reference"} else "none"
    extent: dict[str, object] = {"kind": "none", "bytes": None, "value_id": None}
    if kind == "bytes":
        if node.get("nul_terminated"):
            extent["kind"] = "nul_terminated"
        elif node.get("extent_parameter_id") is not None:
            extent.update({"kind": "value", "value_id": node["extent_parameter_id"]})
    elif kind == "view":
        old_extent = node["extent"]
        if old_extent["kind"] == "nul_terminated":
            extent["kind"] = "nul_terminated"
        elif old_extent["kind"] == "parameter":
            extent.update({"kind": "value", "value_id": old_extent["parameter_id"]})
    return {
        "id": row["id"], "type_id": type_id, "interpretation": interpretation,
        "nullable": bool(node.get("nullable", False)), "access": access,
        "extent": extent,
        "resource_kind": node.get("resource_kind") if kind == "resource" else None,
        "provider_domain": f"component-environment.{component_id}" if kind == "resource" else None,
    }


def _lifecycles(component_id: str, operation: Mapping[str, object], types: Mapping[str, Mapping[str, object]], state_values: list[Mapping[str, object]]) -> tuple[list[dict[str, object]], list[str]]:
    bindings: list[dict[str, object]] = []
    checked: set[str] = set()
    services = list(operation["allowed_service_ids"])
    for root, values in (("parameter", operation["parameters"]), ("result", operation["results"])):
        for value in values:
            node = types[str(value["type_id"])]
            kind = str(node["kind"])
            if kind not in {"bytes", "view", "reference", "resource", "callback"}:
                continue
            transition = "borrow_mutable" if node.get("access") in {"write", "read_write"} else "borrow_shared"
            service_id = None
            contract_id = None
            if kind == "callback" and node.get("ownership") == "retained":
                if not services:
                    raise ValueError("retained callback migration requires an allowed service")
                transition = "escape_callback"
                service_id = str(services[0])
                contract_id = f"component-service.{component_id}.{service_id}"
                checked.add(contract_id)
            bindings.append({
                "id": f"{root}.{value['id']}",
                "path": {"root": root, "value_id": value["id"], "fields": []},
                "transition": transition,
                "resource_kind": str(node.get("resource_kind") or ("code-capability" if kind == "callback" else "memory-view")),
                "provider_domain": f"component-environment.{component_id}",
                "service_id": service_id,
                "interaction_contract_id": contract_id,
                "condition": None,
            })
    return bindings, sorted(checked)


def _root(target_id: str, operation: Mapping[str, object], state: list[Mapping[str, object]]) -> str:
    if target_id in {str(item["id"]) for item in operation["parameters"]}:
        return "parameter"
    if target_id in {str(item["id"]) for item in operation["results"]}:
        return "result"
    if target_id in {str(item["id"]) for item in state}:
        return "state"
    raise ValueError(f"effect target {target_id!r} is unknown")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--operator-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    catalog = json.loads(args.catalog.read_text())
    args.out.mkdir(parents=True, exist_ok=True)
    index = {"components": [], "blockers": []}
    for component in [*catalog.get("components", []), *catalog.get("groups", [])]:
        review_name = component.get("interface_review")
        if review_name is None:
            index["blockers"].append({"component_id": component["id"], "code": "v5_interface_intent_missing"})
            continue
        review = json.loads((args.operator_root / review_name).read_text())
        interface = review.get("overrides", {}).get("portable_interface_ir")
        if interface is None:
            index["blockers"].append({"component_id": component["id"], "code": "v5_interface_intent_missing"})
            continue
        intent = migrate(str(component["id"]), interface)
        relative = f"{component['id']}.json"
        write_json(args.out / relative, intent.to_payload())
        index["components"].append({"component_id": component["id"], "interface_intent": relative, "intent_sha256": intent.intent_sha256})
    write_json(args.out / "index.json", index)


if __name__ == "__main__":
    main()
