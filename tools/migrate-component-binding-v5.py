#!/usr/bin/env python3
"""One-time migration of reviewed machine selectors into V5 binding intent."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from spaghetti_extractor.components.binding_intent import (
    ComponentMachineBindingIntentV1,
)
from spaghetti_extractor.components.interface_package_v5 import (
    ComponentInterfaceIntentV1,
    compile_component_interface_v5,
)
from spaghetti_extractor.util import write_json


def _entry_rva(unit_id: str) -> int:
    match = re.search(r"original-cutpoint-([0-9a-fA-F]{8})", unit_id)
    if match is None:
        raise ValueError(f"machine unit {unit_id!r} has no stable original RVA")
    return int(match.group(1), 16)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--operator-root", type=Path, required=True)
    parser.add_argument("--interface-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    catalog = json.loads(args.catalog.read_text())
    args.out.mkdir(parents=True, exist_ok=True)
    index: dict[str, list[dict[str, object]]] = {"components": [], "blockers": []}
    for component in [*catalog.get("components", []), *catalog.get("groups", [])]:
        component_id = str(component["id"])
        interface_path = args.interface_root / f"{component_id}.json"
        binding_name = component.get("machine_binding")
        if not interface_path.is_file():
            index["blockers"].append({"component_id": component_id, "code": "v5_interface_intent_missing"})
            continue
        if binding_name is None:
            index["blockers"].append({"component_id": component_id, "code": "v5_machine_binding_intent_missing"})
            continue
        interface_intent = ComponentInterfaceIntentV1.parse(json.loads(interface_path.read_text()))
        bundle = compile_component_interface_v5(interface_intent)
        binding = json.loads((args.operator_root / binding_name).read_text())
        review = json.loads((args.operator_root / component["interface_review"]).read_text())
        overrides = review.get("overrides", {})
        operations_by_id = {str(item["operation_id"]): item for item in binding["operations"]}
        intent_operations: list[dict[str, object]] = []
        for operation in bundle.interface.operations:
            machine = operations_by_id.get(operation.identity)
            if machine is None:
                raise ValueError(f"binding lacks interface operation {operation.identity!r}")
            # A portable operation atomically subsumes its body, then returns to
            # the generated faithful continuation.  A logical control result
            # also subsumes the exact branch/jump exit which consumes that
            # result; ordinary register-result exits stay in the preserved
            # transfer inventory only.
            transfer_ids = sorted(set(binding["unit_ids"]))
            entry_ids = set(machine["entry_unit_ids"])
            result_kinds = {
                item["projection"]["kind"] for item in machine["results"]
            }
            replaces_control_exit = bool(
                result_kinds & {"control_condition", "finite_control_target"}
            )
            faithful_exits = (
                set() if replaces_control_exit else set(machine["exit_unit_ids"]) - entry_ids
            )
            unit_ids = [item for item in transfer_ids if item not in faithful_exits]
            pointer_views = [
                {
                    "parameter_id": item["id"],
                    "memory_view": item["memory_view"],
                    "machine_source": item.get("machine_source"),
                }
                for item in overrides.get("parameters", [])
                if item.get("memory_view") is not None
            ]
            intent_operations.append({
                "id": operation.identity,
                "kind": "operation",
                "unit_ids": unit_ids,
                "entry_rvas": sorted(set(_entry_rva(item) for item in machine["entry_unit_ids"])),
                "transfer_ids": transfer_ids,
                "effect_ids": list(operation.effect_ids),
                "service_ids": list(operation.allowed_service_ids),
                "callback_ids": list(machine.get("callback_operation_ids", [])),
                "outcome_protocol_ids": ["normal"],
                "machine_projection": {
                    "operation": machine,
                    "service_bindings": binding.get("services", []),
                    "preserved_unit_inventory": binding.get("unit_ids", []),
                },
                "object_authority_selectors": overrides.get("objects", []),
                "pointer_views": pointer_views,
                "relation_receipt_sha256s": [],
                "induction_evidence_sha256": None,
            })
        intent = ComponentMachineBindingIntentV1.create(
            component_id=component_id, operations=intent_operations
        )
        relative = f"{component_id}.json"
        write_json(args.out / relative, intent.to_payload())
        index["components"].append({
            "component_id": component_id,
            "binding_intent": relative,
            "intent_sha256": intent.intent_sha256,
        })
    write_json(args.out / "index.json", index)


if __name__ == "__main__":
    main()
