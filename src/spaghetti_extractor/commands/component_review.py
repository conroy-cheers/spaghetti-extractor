"""Normalize edited component inputs without conferring proof authority."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Mapping

from ..boundary import BoundarySchemaV1
from ..components.binding_intent import ComponentMachineBindingIntentV1
from ..components.bisimulation import ComponentBisimulationIntentV1
from ..components.formats import COMPONENT_PROPOSAL_INSPECTION_V1_FORMAT
from ..components.indexes_v5 import ComponentIntentIndexV5
from ..components.interface_package_v5 import ComponentInterfaceIntentV1
from ..components.lifting_intent import ComponentLiftingIntentV1
from ..components.machine_binding import OperationMachineBindingV1
from .component_start import safe_package_file


def _read(root: Path, name: str) -> dict:
    value = json.loads(safe_package_file(root, name, "component review").read_text())
    if not isinstance(value, dict):
        raise ValueError(f"component review {name} must be an object")
    return value


def reviewed_seed_identity(root: Path) -> str:
    inspection = _read(root, "component-proposal-inspection.json")
    if (inspection.get("format") != COMPONENT_PROPOSAL_INSPECTION_V1_FORMAT
            or inspection.get("authority") is not False):
        raise ValueError("component review must contain a non-authorizing seed inspection")
    proposal = inspection.get("proposal")
    identity = proposal.get("id") if isinstance(proposal, dict) else None
    if not isinstance(identity, str):
        raise ValueError("component review has no proposal identity")
    return identity


def _interface(value: dict) -> ComponentInterfaceIntentV1:
    # Only derived self-digests may be absent/stale in editable canonical inputs.
    # Reparse the complete result to reject extra fields and unsupported formats.
    schema = dict(value["schema"])
    rebuilt = BoundarySchemaV1.create(schema_id=schema["schema_id"],
                                     types=schema["types"], signatures=schema["signatures"])
    schema["schema_sha256"] = rebuilt.schema_sha256
    value = {**value, "schema": BoundarySchemaV1.parse(schema).to_payload()}
    protocol = value["protocol"]
    intent = ComponentInterfaceIntentV1.create(
        component_id=value["id"], schema=rebuilt, state=value["state"],
        operations=value["operations"], effects=value["effects"], services=value["services"],
        protocol_states=protocol["states"], initial_protocol_state=protocol["initial_state"],
    )
    return ComponentInterfaceIntentV1.parse({**value, "intent_sha256": intent.intent_sha256})


def _reviewed_bisimulation(
    draft: Path, *, component_id: str, operation_id: str, unit_ids: set[str],
) -> ComponentBisimulationIntentV1 | None:
    path = draft / "bisimulation.json"
    if not path.exists() and not path.is_symlink():
        return None
    raw = _read(draft, "bisimulation.json")
    try:
        rebuilt = ComponentBisimulationIntentV1.create(
            component_id=raw["component_id"], operations=raw["operations"])
    except (KeyError, TypeError) as exc:
        raise ValueError(f"component review has incomplete bisimulation input: {exc}") from exc
    intent = ComponentBisimulationIntentV1.parse(
        {**raw, "intent_sha256": rebuilt.intent_sha256})
    if intent.component_id != component_id:
        raise ValueError("reviewed bisimulation names a different component")
    if [row.operation_id for row in intent.operations] != [operation_id]:
        raise ValueError("reviewed bisimulation names different operations")
    if any(sync.exact_unit_id not in unit_ids for row in intent.operations for sync in row.syncs):
        raise ValueError("reviewed bisimulation cut is outside the selected boundary")
    return intent


def reviewed_component_inputs(*, draft: Path, proposal: Mapping, program_id: str) -> dict[str, dict]:
    inspection = _read(draft, "component-proposal-inspection.json")
    reviewed_seed_identity(draft)
    if inspection.get("proposal") != proposal:
        raise ValueError("component review proposal is stale or differs from the selected boundary")
    try:
        interface = _interface(_read(draft, "interface.json"))
        raw = _read(draft, "binding.json")
        for operation in raw["operations"]:
            projection = operation["machine_projection"].get("operation", {})
            # Value bindings are maps represented as canonical arrays. Their
            # order is derived, unlike C signature parameter order or codec operands.
            for field in ("parameters", "results", "state"):
                rows = projection.get(field)
                if isinstance(rows, list) and all(
                    isinstance(row, dict) and isinstance(row.get("id"), str) for row in rows
                ):
                    projection[field] = sorted(rows, key=lambda row: row["id"])
        binding = ComponentMachineBindingIntentV1.create(
            component_id=raw["component_id"], operations=raw["operations"], blockers=raw["blockers"])
        binding = ComponentMachineBindingIntentV1.parse(
            {**raw, "intent_sha256": binding.intent_sha256, "status": binding.status})
    except (KeyError, TypeError) as exc:
        raise ValueError(f"component review has incomplete canonical input: {exc}") from exc
    if interface.component_id != binding.component_id:
        raise ValueError("reviewed interface and binding name different components")
    if len(binding.operations) != 1 or len(interface.operations) != 1:
        raise ValueError("seed review requires one operation over the selected boundary")
    operation = binding.operations[0].semantics
    if operation.operation_id != interface.operations[0]["id"]:
        raise ValueError("reviewed interface and binding name different operations")
    projection = OperationMachineBindingV1.parse(
        operation.machine_projection.get("operation"), "reviewed operation projection")
    continuation_ids = set(projection.continuation_unit_ids)
    if (set(operation.unit_ids) != set(proposal["membership"]["unit_ids"])
            or continuation_ids & set(operation.unit_ids)
            or set(operation.transfer_ids) != set(operation.unit_ids) | continuation_ids
            or set(operation.entry_rvas) != {row["rva"] for row in proposal["boundary"]["entries"]}):
        raise ValueError("reviewed binding changes the selected boundary")
    if (projection.operation_id != operation.operation_id
            or set(projection.entry_unit_ids) != {row["unit_id"] for row in proposal["boundary"]["entries"]}
            or set(projection.exit_unit_ids) != {row["source_unit_id"] for row in proposal["boundary"]["exits"]}):
        raise ValueError("reviewed projection changes the selected boundary entries or exits")
    signature = interface.schema.signature_index[interface.operations[0]["signature_id"]]
    for label, expected, actual in (
        ("parameters", {row.identity for row in signature.parameters},
         {row.identity for row in projection.parameters}),
        ("results", {row.identity for row in signature.results},
         {row.identity for row in projection.results}),
        ("state", {row["value"]["id"] for row in interface.state},
         {row.identity for row in projection.state}),
    ):
        if expected != actual:
            raise ValueError(f"reviewed {label} do not match the interface")
    identity = interface.component_id
    bisimulation = _reviewed_bisimulation(
        draft, component_id=identity, operation_id=operation.operation_id,
        unit_ids=set(operation.unit_ids))
    component = {"id": identity, "label": identity}
    if bisimulation is not None:
        component["bisimulation_intent"] = f"bisimulation/{identity}.json"
    # These are the existing canonical inputs. No new executable/provider format
    # and no candidate selection are produced by reviewing an interface.
    lifting = ComponentLiftingIntentV1.create(
        program_id=program_id, components=[component], groups=[],
        configurations=[{"id": "draft", "label": "Reviewed component draft", "selections": [
            {"id": identity, "kind": "component", "activation": "draft"}]}])
    result = {"components.json": lifting.to_payload()}
    if bisimulation is not None:
        result[str(component["bisimulation_intent"])] = bisimulation.to_payload()
    for kind, directory, field, intent in (
        ("interface", "interfaces-v5", "interface_intent", interface),
        ("machine_binding", "bindings-v5", "binding_intent", binding),
    ):
        blockers = [] if kind == "interface" else [
            {"component_id": identity, "code": code}
            for code in sorted({row["code"] for row in binding.blockers})]
        index = ComponentIntentIndexV5.create(kind=kind, components=[{
            "component_id": identity, field: identity + ".json",
            "intent_sha256": intent.intent_sha256}], blockers=blockers)
        result[f"{directory}/{identity}.json"] = intent.to_payload()
        result[f"{directory}/index.json"] = index.to_payload()
    return result


def write_reviewed_component_inputs(*, draft: Path, proposal: Mapping,
                                   program_id: str, output: Path,
                                   expected_component_id: str | None = None) -> None:
    payloads = reviewed_component_inputs(draft=draft, proposal=proposal, program_id=program_id)
    if (expected_component_id is not None
            and payloads["components.json"]["components"][0]["id"] != expected_component_id):
        raise ValueError("reviewed component identity differs from the configured seed")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("component review output must be a new or empty directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".component-review-", dir=output.parent) as temporary:
        staging = Path(temporary) / "inputs"
        staging.mkdir()
        for relative, payload in payloads.items():
            path = staging / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        os.replace(staging, output)
